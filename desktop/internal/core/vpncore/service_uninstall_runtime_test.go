package vpncore

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestUninstallServiceRemovesRootOwnedRuntimeAfterForget(t *testing.T) {
	// Only the quarantined original dev/ino is recursively removed after confirmed forget; its internal symlink target survives.
	cfg := runtimeUninstallConfig(t)
	target := filepath.Join(t.TempDir(), "capture")
	writeRuntimeTestFile(t, target)
	if err := os.Symlink(target, filepath.Join(cfg.RuntimeDir, "capture-link")); err != nil {
		t.Fatal(err)
	}
	expected := runtimeTestStat(t, cfg.RuntimeDir)
	commands := withRuntimeUninstallCommands(t, cfg)
	commands.loadedPrints = 1
	if err := UninstallService(cfg); err != nil {
		t.Fatal(err)
	}
	quarantine := commands.quarantines[0]
	want := [][]string{
		{"launchctl", "bootout", launchctlTarget(cfg.Label)},
		{"launchctl", "print", launchctlTarget(cfg.Label)},
		{"launchctl", "print", launchctlTarget(cfg.Label)},
		{"rm", "-f", cfg.PlistPath, cfg.SocketPath},
		{commands.executable, "_quarantine-runtime", cfg.Label, strconv.FormatUint(uint64(expected.Dev), 10), strconv.FormatUint(expected.Ino, 10)},
		{"rm", "-rf", quarantine},
		{"rm", "-rf", cfg.HelperDir, privateSocketDir(cfg)},
	}
	if !reflect.DeepEqual(commands.calls, want) {
		t.Fatalf("commands = %v, want %v", commands.calls, want)
	}
	if _, err := os.Lstat(cfg.RuntimeDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runtime Lstat = %v, want absence", err)
	}
	if len(commands.removedIdentities) != 1 || commands.removedIdentities[0].Dev != expected.Dev || commands.removedIdentities[0].Ino != expected.Ino {
		t.Fatalf("removed identities = %v, want original dev=%d ino=%d", commands.removedIdentities, expected.Dev, expected.Ino)
	}
	if _, err := os.Lstat(quarantine); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("quarantine Lstat = %v, want absence", err)
	}
	assertRuntimeTestFile(t, target)
	if err := verifyServicePathsAbsent(cfg); err != nil {
		t.Fatalf("verifyServicePathsAbsent() = %v", err)
	}
}

func TestUninstallServiceAcceptsAbsentRuntime(t *testing.T) {
	// An absent runtime triggers no runtime removal command and uninstall succeeds.
	cfg := testInstallConfig(t)
	cfg.RuntimeDir = filepath.Join(filepath.Dir(cfg.HelperDir), "absent-runtime")
	commands := withRuntimeUninstallCommands(t, cfg)
	if err := UninstallService(cfg); err != nil {
		t.Fatal(err)
	}
	if got := commands.runtimeCalls(cfg); len(got) != 0 {
		t.Fatalf("commands naming absent runtime = %v", got)
	}
}

func TestUninstallServiceUnlinksUnexpectedRuntimeSymlink(t *testing.T) {
	// A runtime symlink is removed only with rm -f on the link, its target survives unnamed by commands, and uninstall reports the removed unexpected entry.
	cfg := testInstallConfig(t)
	cfg.RuntimeDir = filepath.Join(filepath.Dir(cfg.HelperDir), "runtime-link")
	target := t.TempDir()
	marker := filepath.Join(target, "sensitive-config")
	writeRuntimeTestFile(t, marker)
	if err := os.Symlink(target, cfg.RuntimeDir); err != nil {
		t.Fatal(err)
	}
	commands := withRuntimeUninstallCommands(t, cfg)
	err := UninstallService(cfg)
	for _, fragment := range []string{cfg.RuntimeDir, "symlink", "removed"} {
		if err == nil || !strings.Contains(err.Error(), fragment) {
			t.Errorf("uninstall error = %v, want %q", err, fragment)
		}
	}
	if got, want := commands.runtimeCalls(cfg), [][]string{{"rm", "-f", cfg.RuntimeDir}}; !reflect.DeepEqual(got, want) {
		t.Errorf("runtime commands = %v, want %v", got, want)
	}
	if got := commands.naming(target); len(got) != 0 {
		t.Errorf("commands name symlink target: %v", got)
	}
	if _, err := os.Lstat(cfg.RuntimeDir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("runtime symlink Lstat = %v, want absence", err)
	}
	assertRuntimeTestFile(t, marker)
}

func TestUninstallServiceRefusesUnexpectedRuntimeTypeOrOwner(t *testing.T) {
	// Foreign-owned directories and regular files of either owner survive uninstall, with path, type and numeric owner in the error and no rm on that path.
	for _, tc := range []struct {
		name string
		dir  bool
		uid  uint32
		kind string
	}{
		{name: "foreign-directory", dir: true, uid: 501, kind: "directory"},
		{name: "foreign-file", uid: 501, kind: "regular file"},
		{name: "root-file", uid: 0, kind: "regular file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testInstallConfig(t)
			cfg.RuntimeDir = filepath.Join(filepath.Dir(cfg.HelperDir), "runtime")
			marker := cfg.RuntimeDir
			if tc.dir {
				if err := os.Mkdir(cfg.RuntimeDir, 0o711); err != nil {
					t.Fatal(err)
				}
				marker = filepath.Join(cfg.RuntimeDir, "sensitive-config")
			}
			writeRuntimeTestFile(t, marker)
			commands := withRuntimeUninstallCommands(t, cfg)
			withInstallVerification(t, func(path string, _ *unix.Stat_t) (uint32, error) {
				if path == cfg.RuntimeDir {
					return tc.uid, nil
				}
				return 0, nil
			}, func(string, int) error { return nil })
			err := UninstallService(cfg)
			owner := "uid 0"
			if tc.uid == 501 {
				owner = "uid 501"
			}
			for _, fragment := range []string{cfg.RuntimeDir, tc.kind, owner, cfg.RuntimeDir + " still exists"} {
				if err == nil || !strings.Contains(err.Error(), fragment) {
					t.Errorf("uninstall error = %v, want %q", err, fragment)
				}
			}
			if got := commands.runtimeCalls(cfg); len(got) != 0 {
				t.Errorf("commands name refused runtime: %v", got)
			}
			assertRuntimeTestFile(t, marker)
		})
	}
}

func TestUninstallServiceEmptyRuntimePreservesCommands(t *testing.T) {
	// An empty RuntimeDir leaves the prior launchd, plist/socket and helper/private-socket removal sequence unchanged.
	cfg := testInstallConfig(t)
	commands := withRuntimeUninstallCommands(t, cfg)
	if err := UninstallService(cfg); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"launchctl", "bootout", launchctlTarget(cfg.Label)},
		{"launchctl", "print", launchctlTarget(cfg.Label)},
		{"rm", "-f", cfg.PlistPath, cfg.SocketPath},
		{"rm", "-rf", cfg.HelperDir, privateSocketDir(cfg)},
	}
	if !reflect.DeepEqual(commands.calls, want) {
		t.Fatalf("commands = %v, want %v", commands.calls, want)
	}
}

func TestUninstallServiceFailsWhenRuntimeRemains(t *testing.T) {
	// A runtime recreated at the source after quarantine removal still fails final pathname absence verification.
	cfg := runtimeUninstallConfig(t)
	commands := withRuntimeUninstallCommands(t, cfg)
	commands.retainRuntime = true
	err := UninstallService(cfg)
	if err == nil || !strings.Contains(err.Error(), cfg.RuntimeDir+" still exists") {
		t.Fatalf("uninstall error = %v, want runtime still exists", err)
	}
	if got := commands.runtimeCalls(cfg); len(got) != 1 || got[0][1] != "_quarantine-runtime" {
		t.Fatalf("runtime commands = %v, want one quarantine move", got)
	}
	assertRuntimeTestFile(t, filepath.Join(cfg.RuntimeDir, "session", "config"))
}

func TestUninstallServiceKeepsRuntimeWhenForgetFails(t *testing.T) {
	// A failed launchd forget step prevents runtime removal and preserves session data while uninstall reports failure.
	cfg := runtimeUninstallConfig(t)
	commands := withRuntimeUninstallCommands(t, cfg)
	commands.forgetFails = true
	withExpiredInstallClock(t)
	err := UninstallService(cfg)
	if err == nil || !strings.Contains(err.Error(), "did not forget") {
		t.Fatalf("uninstall error = %v, want forget failure", err)
	}
	if got := commands.runtimeCalls(cfg); len(got) != 0 {
		t.Fatalf("runtime commands before confirmed forget = %v", got)
	}
	assertRuntimeTestFile(t, filepath.Join(cfg.RuntimeDir, "session", "config"))
}

func TestUninstallServiceCompatibilityRuntimeDirectories(t *testing.T) {
	// Shared runtimes are removed once after both forget steps; shared or distinct retained runtimes each produce exactly one path-absence error.
	for _, tc := range []struct {
		name   string
		shared bool
		retain bool
	}{
		{name: "shared", shared: true},
		{name: "distinct"},
		{name: "shared-retained", shared: true, retain: true},
		{name: "distinct-retained", retain: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := runtimeUninstallConfig(t)
			legacy := runtimeUninstallConfig(t)
			legacy.Label = "works.relux.test-legacy"
			if tc.shared {
				legacy.RuntimeDir = cfg.RuntimeDir
			}
			previous := compatibilityServiceConfigsVPNCore
			compatibilityServiceConfigsVPNCore = func(candidate ServiceConfig) []compatibilityConfig {
				if !sameServiceConfig(candidate, cfg) {
					return nil
				}
				return []compatibilityConfig{{ServiceConfig: legacy}}
			}
			t.Cleanup(func() { compatibilityServiceConfigsVPNCore = previous })
			commands := withRuntimeUninstallCommands(t, cfg, legacy)
			commands.retainRuntime = tc.retain
			err := UninstallService(cfg)
			if !tc.retain && err != nil {
				t.Fatal(err)
			}
			verified := make(map[string]bool)
			for _, service := range []ServiceConfig{cfg, legacy} {
				if verified[service.RuntimeDir] {
					continue
				}
				verified[service.RuntimeDir] = true
				if got := commands.runtimeCalls(service); len(got) != 1 || got[0][1] != "_quarantine-runtime" {
					t.Errorf("runtime commands = %v, want one quarantine move", got)
				}
				if tc.retain {
					if err == nil || strings.Count(err.Error(), service.RuntimeDir+" still exists") != 1 {
						t.Errorf("uninstall error = %v, want exactly one absence error for %s", err, service.RuntimeDir)
					}
					assertRuntimeTestFile(t, filepath.Join(service.RuntimeDir, "session", "config"))
					continue
				}
				if err := verifyServicePathsAbsent(service); err != nil {
					t.Errorf("verifyServicePathsAbsent(%s) = %v", service.Label, err)
				}
			}
			if tc.shared {
				moveIndex, primaryForgetIndex := -1, -1
				for i, call := range commands.calls {
					if len(call) > 1 && call[1] == "_quarantine-runtime" {
						moveIndex = i
					}
					if reflect.DeepEqual(call, []string{"launchctl", "print", launchctlTarget(cfg.Label)}) {
						primaryForgetIndex = i
					}
				}
				if moveIndex <= primaryForgetIndex || primaryForgetIndex < 0 {
					t.Fatalf("shared runtime moved before primary forget: %v", commands.calls)
				}
			}
		})
	}
}

func runtimeUninstallConfig(t *testing.T) ServiceConfig {
	t.Helper()
	cfg := testInstallConfig(t)
	cfg.RuntimeDir = filepath.Join(filepath.Dir(cfg.HelperDir), "runtime")
	if err := os.MkdirAll(filepath.Join(cfg.RuntimeDir, "session"), 0o711); err != nil {
		t.Fatal(err)
	}
	writeRuntimeTestFile(t, filepath.Join(cfg.RuntimeDir, "session", "config"))
	return cfg
}

type runtimeUninstallCommands struct {
	duringMove        bool
	printedQuarantine string
	calls             [][]string
	loadedPrints      int
	forgetFails       bool
	failedLabels      map[string]bool
	retainRuntime     bool
	retainQuarantine  bool
	quarantines       []string
	executable        string
	beforeMove        func(source, destination string)
	beforeRename      func(source, destination string)
	removedIdentities []unix.Stat_t
}

func withRuntimeUninstallCommands(t *testing.T, configs ...ServiceConfig) *runtimeUninstallCommands {
	t.Helper()
	commands := &runtimeUninstallCommands{failedLabels: make(map[string]bool), executable: filepath.Join(t.TempDir(), "vpn-core-fixture")}
	withInstallVerification(t, func(string, *unix.Stat_t) (uint32, error) { return 0, nil }, func(string, int) error { return nil })
	previousExecutable, previousRename, previousRandom := runtimeExecutableVPNCore, runtimeRenameatVPNCore, runtimeQuarantineRandomVPNCore
	previousConfig, previousEUID, previousChown, previousDeps := runtimeQuarantineConfigVPNCore, runtimeQuarantineEUIDVPNCore, runtimeQuarantineFchownVPNCore, runtimeQuarantineDepsVPNCore
	runtimeQuarantineConfigVPNCore = func(label string) (ServiceConfig, string, error) {
		for _, cfg := range configs {
			if label == cfg.Label || label == "" {
				return cfg, filepath.Dir(cfg.RuntimeDir), nil
			}
		}
		return ServiceConfig{}, "", fmt.Errorf("unknown fixture label %q", label)
	}
	runtimeQuarantineEUIDVPNCore = func() int { return 0 }
	runtimeQuarantineFchownVPNCore = func(fd, uid, gid int) error {
		if uid != 0 || gid != 0 {
			t.Fatalf("fchown = %d:%d, want root:wheel", uid, gid)
		}
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
			t.Fatalf("fchown fd not directory: %v", err)
		}
		return nil
	}
	runtimeQuarantineDepsVPNCore = func() verificationDependencies { return installVerificationDepsVPNCore() }
	runtimeExecutableVPNCore = func() (string, error) { return commands.executable, nil }
	var moveSource, moveDestination string
	runtimeRenameatVPNCore = func(sourceFD int, source string, destinationFD int, destination string) error {
		if commands.beforeRename != nil {
			commands.beforeRename(moveSource, moveDestination)
		}
		return unix.Renameat(sourceFD, source, destinationFD, destination)
	}
	t.Cleanup(func() {
		runtimeExecutableVPNCore, runtimeRenameatVPNCore, runtimeQuarantineRandomVPNCore = previousExecutable, previousRename, previousRandom
		runtimeQuarantineConfigVPNCore, runtimeQuarantineEUIDVPNCore, runtimeQuarantineFchownVPNCore, runtimeQuarantineDepsVPNCore = previousConfig, previousEUID, previousChown, previousDeps
	})
	moves := make(map[string]string)
	withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
		command := append([]string{name}, args...)
		commands.calls = append(commands.calls, command)
		for _, cfg := range configs {
			if reflect.DeepEqual(command, []string{"launchctl", "bootout", launchctlTarget(cfg.Label)}) {
				return nil, nil
			}
			if reflect.DeepEqual(command, []string{"launchctl", "print", launchctlTarget(cfg.Label)}) {
				if commands.forgetFails || commands.failedLabels[cfg.Label] || commands.loadedPrints > 0 {
					commands.loadedPrints--
					return []byte("still loaded"), nil
				}
				return nil, launchctlTestError(113, nil)
			}
			if cfg.RuntimeDir != "" && (reflect.DeepEqual(command, []string{"rm", "-rf", cfg.RuntimeDir}) || reflect.DeepEqual(command, []string{"rm", "-f", cfg.RuntimeDir})) {
				return nil, performFakeInstall(name, args, nil)
			}
			if reflect.DeepEqual(command, []string{"rm", "-f", cfg.PlistPath, cfg.SocketPath}) || reflect.DeepEqual(command, []string{"rm", "-rf", cfg.HelperDir, privateSocketDir(cfg)}) {
				return nil, performFakeInstall(name, args, nil)
			}
			if name == commands.executable && len(args) == 4 && args[0] == "_quarantine-runtime" && args[1] == cfg.Label {
				moveSource = cfg.RuntimeDir
				if commands.beforeMove != nil {
					commands.beforeMove(moveSource, "")
				}
				previousRandom := runtimeQuarantineRandomVPNCore
				runtimeQuarantineRandomVPNCore = func() string {
					suffix := previousRandom()
					moveDestination = filepath.Join(cfg.HelperDir+".uninstall-"+suffix, "runtime")
					return suffix
				}
				commands.duringMove = true
				var output bytes.Buffer
				err := RunRuntimeQuarantineMove(args[1:], &output)
				commands.duringMove = false
				runtimeQuarantineRandomVPNCore = previousRandom
				quarantine := strings.TrimSuffix(output.String(), "\n")
				if quarantine != "" {
					commands.quarantines = append(commands.quarantines, quarantine)
				}
				if err == nil {
					moves[quarantine] = moveSource
				}
				if commands.printedQuarantine != "" {
					return []byte(commands.printedQuarantine), err
				}
				return output.Bytes(), err
			}
		}
		for _, quarantine := range commands.quarantines {
			if reflect.DeepEqual(command, []string{"rm", "-rf", quarantine}) {
				commands.removedIdentities = append(commands.removedIdentities, runtimeTestStat(t, filepath.Join(quarantine, "runtime")))
				if commands.retainQuarantine {
					return nil, nil
				}
				if err := os.RemoveAll(quarantine); err != nil {
					return nil, err
				}
				if commands.retainRuntime {
					source := moves[quarantine]
					if err := os.MkdirAll(filepath.Join(source, "session"), 0o711); err != nil {
						return nil, err
					}
					writeRuntimeTestFile(t, filepath.Join(source, "session", "config"))
				}
				return nil, nil
			}
		}
		t.Fatalf("unexpected privileged command (never executed): %v", command)
		return nil, errors.New("unreachable")
	})
	return commands
}

func runtimeTestStat(t *testing.T, path string) unix.Stat_t {
	t.Helper()
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		t.Fatal(err)
	}
	return stat
}

// runtimeCalls maps label-only move invocations back to the fixture service.
func (commands *runtimeUninstallCommands) runtimeCalls(cfg ServiceConfig) [][]string {
	matches := commands.naming(cfg.RuntimeDir)
	for _, command := range commands.calls {
		if len(command) == 5 && command[0] == commands.executable && command[1] == "_quarantine-runtime" && command[2] == cfg.Label {
			matches = append(matches, command)
		}
	}
	return matches
}

func (commands *runtimeUninstallCommands) naming(path string) [][]string {
	var matches [][]string
	for _, command := range commands.calls {
		for _, arg := range command[1:] {
			if arg == path {
				matches = append(matches, command)
				break
			}
		}
	}
	return matches
}

func writeRuntimeTestFile(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("private session data"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertRuntimeTestFile(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "private session data" {
		t.Fatalf("private fixture %s = %q, %v; want original contents", path, data, err)
	}
}

func TestUninstallServiceRuntimeSubstitutionFailsClosed(t *testing.T) {
	// Substitution just before renameat never deletes the parked original or a replacement, and never reports success.
	for _, variant := range []string{"absent", "symlink", "foreign-directory", "moved-directory"} {
		t.Run(variant, func(t *testing.T) {
			cfg := runtimeUninstallConfig(t)
			original := runtimeTestStat(t, cfg.RuntimeDir)
			parked := cfg.RuntimeDir + ".parked"
			other := filepath.Join(filepath.Dir(cfg.RuntimeDir), "other")
			if err := os.Mkdir(other, 0o711); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(other, "sensitive-config")
			writeRuntimeTestFile(t, marker)
			commands := withRuntimeUninstallCommands(t, cfg)
			var replacement unix.Stat_t
			commands.beforeRename = func(source, destination string) {
				if err := os.Rename(source, parked); err != nil {
					t.Fatal(err)
				}
				switch variant {
				case "symlink":
					if err := os.Symlink(other, source); err != nil {
						t.Fatal(err)
					}
				case "foreign-directory":
					if err := os.Mkdir(source, 0o711); err != nil {
						t.Fatal(err)
					}
					writeRuntimeTestFile(t, filepath.Join(source, "sensitive-config"))
				case "moved-directory":
					if err := os.Rename(other, source); err != nil {
						t.Fatal(err)
					}
				}
				if variant != "absent" {
					replacement = runtimeTestStat(t, source)
				}
			}
			if variant == "foreign-directory" {
				withInstallVerification(t, func(_ string, stat *unix.Stat_t) (uint32, error) {
					if replacement.Ino != 0 && stat.Ino == replacement.Ino {
						return 501, nil
					}
					return 0, nil
				}, func(string, int) error { return nil })
			}
			err := UninstallService(cfg)
			quarantine := commands.quarantines[0]
			for _, fragment := range []string{cfg.RuntimeDir, "could not be removed safely", quarantine, "may still exist under another name", "quarantine retained"} {
				if err == nil || !strings.Contains(err.Error(), fragment) {
					t.Errorf("error = %v, want %q", err, fragment)
				}
			}
			if variant != "absent" {
				for _, fragment := range []string{"expected dev=", "found dev=", "ino="} {
					if err == nil || !strings.Contains(err.Error(), fragment) {
						t.Errorf("error = %v, want %q", err, fragment)
					}
				}
				found := runtimeTestStat(t, filepath.Join(quarantine, "runtime"))
				if found.Dev != replacement.Dev || found.Ino != replacement.Ino {
					t.Errorf("replacement identity changed: %v, want %v", found, replacement)
				}
			}
			if variant == "foreign-directory" || variant == "moved-directory" {
				assertRuntimeTestFile(t, filepath.Join(quarantine, "runtime", "sensitive-config"))
			}
			if variant != "moved-directory" {
				assertRuntimeTestFile(t, marker)
			}
			if len(commands.removedIdentities) != 0 {
				t.Errorf("recursive removal of unverified runtime identities: %v", commands.removedIdentities)
			}
			if got := commands.naming(quarantine); len(got) != 0 {
				t.Errorf("quarantine should be retained, never removed: %v", got)
			}
			assertRuntimeTestFile(t, filepath.Join(parked, "session", "config"))
			foundOriginal := runtimeTestStat(t, parked)
			if foundOriginal.Dev != original.Dev || foundOriginal.Ino != original.Ino {
				t.Fatal("parked original identity changed")
			}
		})
	}
}

func TestUninstallServiceRefusesUnsafeRuntimeQuarantine(t *testing.T) {
	// Empty HelperDir or cross-device parents refuse quarantine/removal and preserve the inspected runtime.
	for _, variant := range []string{"empty-helper", "cross-device"} {
		t.Run(variant, func(t *testing.T) {
			cfg := runtimeUninstallConfig(t)
			commands := withRuntimeUninstallCommands(t, cfg)
			if variant == "empty-helper" {
				cfg.HelperDir = ""
			}
			if variant == "cross-device" {
				parent := filepath.Join(filepath.Dir(cfg.RuntimeDir), "runtime-parent")
				if err := os.Mkdir(parent, 0o755); err != nil {
					t.Fatal(err)
				}
				next := filepath.Join(parent, "runtime")
				if err := os.Rename(cfg.RuntimeDir, next); err != nil {
					t.Fatal(err)
				}
				cfg.RuntimeDir = next
				previous := runtimeRemovalLstatVPNCore
				runtimeRemovalLstatVPNCore = func(path string, stat *unix.Stat_t) error {
					err := unix.Lstat(path, stat)
					if path == parent && err == nil {
						stat.Dev++
					}
					return err
				}
				t.Cleanup(func() { runtimeRemovalLstatVPNCore = previous })
			}
			err := UninstallService(cfg)
			fragment := "helper directory is required"
			if variant == "cross-device" {
				fragment = "different devices"
			}
			for _, want := range []string{cfg.RuntimeDir, "could not be removed safely", fragment} {
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Errorf("error = %v, want %q", err, want)
				}
			}
			if len(commands.quarantines) != 0 || len(commands.runtimeCalls(cfg)) != 0 {
				t.Errorf("unsafe runtime commands: %v", commands.calls)
			}
			assertRuntimeTestFile(t, filepath.Join(cfg.RuntimeDir, "session", "config"))
		})
	}
}

func TestUninstallServiceFailsWhenQuarantineRemains(t *testing.T) {
	// A successful rm status with the verified quarantine still present cannot satisfy uninstall.
	cfg := runtimeUninstallConfig(t)
	commands := withRuntimeUninstallCommands(t, cfg)
	commands.retainQuarantine = true
	err := UninstallService(cfg)
	if err == nil || !strings.Contains(err.Error(), "quarantine "+commands.quarantines[0]+" still exists") {
		t.Fatalf("error = %v, want retained quarantine", err)
	}
	assertRuntimeTestFile(t, filepath.Join(commands.quarantines[0], "runtime", "session", "config"))
}

func TestUninstallServicePreservesRuntimeAfterAnySharedForgetFailure(t *testing.T) {
	// A failed compatibility forget preserves the shared runtime even after the primary or a later compatibility service confirms forget.
	for _, variant := range []string{"primary-shares", "compatibilities-share"} {
		t.Run(variant, func(t *testing.T) {
			cfg := runtimeUninstallConfig(t)
			first := runtimeUninstallConfig(t)
			first.Label = "works.relux.first-legacy"
			second := runtimeUninstallConfig(t)
			second.Label = "works.relux.second-legacy"
			compatibilities := []compatibilityConfig{{ServiceConfig: first}}
			if variant == "primary-shares" {
				first.RuntimeDir = cfg.RuntimeDir
				compatibilities[0].ServiceConfig = first
			} else {
				second.RuntimeDir = first.RuntimeDir
				compatibilities = append(compatibilities, compatibilityConfig{ServiceConfig: second})
			}
			previous := compatibilityServiceConfigsVPNCore
			compatibilityServiceConfigsVPNCore = func(ServiceConfig) []compatibilityConfig { return compatibilities }
			t.Cleanup(func() { compatibilityServiceConfigsVPNCore = previous })
			commands := withRuntimeUninstallCommands(t, cfg, first, second)
			commands.failedLabels[first.Label] = true
			withExpiredInstallClock(t)
			err := UninstallService(cfg)
			for _, fragment := range []string{first.Label, first.RuntimeDir, "preserve runtime directory", "not all services confirmed forget"} {
				if err == nil || !strings.Contains(err.Error(), fragment) {
					t.Errorf("error = %v, want %q", err, fragment)
				}
			}
			if got := commands.naming(first.RuntimeDir); len(got) != 0 {
				t.Errorf("shared runtime removal despite failed user forget: %v", got)
			}
			assertRuntimeTestFile(t, filepath.Join(first.RuntimeDir, "session", "config"))
			last := cfg
			if variant == "compatibilities-share" {
				last = second
				if _, statErr := os.Lstat(cfg.RuntimeDir); !errors.Is(statErr, os.ErrNotExist) {
					t.Errorf("independent primary runtime not removed: %v", statErr)
				}
			}
			if len(commands.naming(launchctlTarget(last.Label))) != 2 {
				t.Errorf("last runtime user did not confirm forget: %v", commands.calls)
			}
		})
	}
}

func TestRuntimeQuarantineRenamePrecheckRejectsReplacement(t *testing.T) {
	// A changed identity before fstatat is rejected without moving or removing the replacement or parked original.
	cfg := runtimeUninstallConfig(t)
	commands := withRuntimeUninstallCommands(t, cfg)
	parked := cfg.RuntimeDir + ".parked"
	commands.beforeMove = func(source, destination string) {
		if err := os.Rename(source, parked); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(source, 0o711); err != nil {
			t.Fatal(err)
		}
		writeRuntimeTestFile(t, filepath.Join(source, "other"))
	}
	err := UninstallService(cfg)
	if err == nil || !strings.Contains(err.Error(), "runtime identity changed before rename") {
		t.Fatalf("error = %v, want pre-rename identity refusal", err)
	}
	assertRuntimeTestFile(t, filepath.Join(parked, "session", "config"))
	assertRuntimeTestFile(t, filepath.Join(cfg.RuntimeDir, "other"))
	if len(commands.removedIdentities) != 0 {
		t.Fatal("unexpected recursive runtime removal")
	}
}

func TestRuntimeQuarantineRenameNeverCopiesOnEXDEV(t *testing.T) {
	// A renameat EXDEV error is propagated without copying, deleting or reporting success.
	cfg := runtimeUninstallConfig(t)
	commands := withRuntimeUninstallCommands(t, cfg)
	previous := runtimeRenameatVPNCore
	runtimeRenameatVPNCore = func(int, string, int, string) error { return unix.EXDEV }
	t.Cleanup(func() { runtimeRenameatVPNCore = previous })
	err := UninstallService(cfg)
	if !errors.Is(err, unix.EXDEV) || err == nil || !strings.Contains(err.Error(), "never copy") {
		t.Fatalf("error = %v, want rename-only EXDEV failure", err)
	}
	assertRuntimeTestFile(t, filepath.Join(cfg.RuntimeDir, "session", "config"))
	if _, err := os.Lstat(filepath.Join(commands.quarantines[0], "runtime")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("destination = %v, want absent", err)
	}
	if len(commands.removedIdentities) != 0 {
		t.Fatal("unexpected recursive runtime removal")
	}
}

func TestRunRuntimeQuarantineMoveRejectsInvalidArgumentsAndNonRoot(t *testing.T) {
	// Malformed arguments and simulated non-root invocation cannot move a valid configured fixture.
	cfg := runtimeUninstallConfig(t)
	commands := withRuntimeUninstallCommands(t, cfg)
	original := runtimeTestStat(t, cfg.RuntimeDir)
	for _, args := range [][]string{nil, {"invalid", "1"}, {cfg.Label, "1", "invalid"}} {
		if err := RunRuntimeQuarantineMove(args, &bytes.Buffer{}); err == nil {
			t.Fatalf("accepted malformed args %v", args)
		}
	}
	runtimeQuarantineEUIDVPNCore = func() int { return 501 }
	err := RunRuntimeQuarantineMove([]string{cfg.Label, strconv.FormatUint(uint64(original.Dev), 10), strconv.FormatUint(original.Ino, 10)}, &bytes.Buffer{})
	if err == nil || err.Error() != "quarantine move requires root" {
		t.Fatalf("error = %v, want root rejection", err)
	}
	assertRuntimeTestFile(t, filepath.Join(cfg.RuntimeDir, "session", "config"))
	if len(commands.quarantines) != 0 {
		t.Fatal("non-root created quarantine")
	}
}

func TestRuntimeQuarantineSecureChecksRunInsidePrivilegedMove(t *testing.T) {
	// Quarantine descriptor/ACL checks run inside the privileged seam; an unsafe ACL prevents rename and preserves runtime data.
	for _, unsafe := range []bool{false, true} {
		t.Run(strconv.FormatBool(unsafe), func(t *testing.T) {
			cfg := runtimeUninstallConfig(t)
			commands := withRuntimeUninstallCommands(t, cfg)
			checks := 0
			withInstallVerification(t, func(string, *unix.Stat_t) (uint32, error) { return 0, nil }, func(path string, _ int) error {
				if !strings.HasPrefix(path, cfg.HelperDir+".uninstall-") {
					return nil
				}
				checks++
				if !commands.duringMove {
					t.Error("0711 quarantine opened outside privileged runner")
				}
				if unsafe {
					return errors.New("fixture writable ACL")
				}
				return nil
			})
			err := UninstallService(cfg)
			if checks != 1 {
				t.Errorf("quarantine secure checks = %d, want 1", checks)
			}
			if !unsafe && err != nil {
				t.Fatal(err)
			}
			if unsafe {
				if err == nil || !strings.Contains(err.Error(), "fixture writable ACL") {
					t.Fatalf("error = %v, want ACL rejection", err)
				}
				assertRuntimeTestFile(t, filepath.Join(cfg.RuntimeDir, "session", "config"))
				if len(commands.removedIdentities) != 0 {
					t.Fatal("unsafe quarantine permitted recursive removal")
				}
			}
		})
	}
}
