package vpncore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func runtimeFixtureMoveArgs(t *testing.T, cfg ServiceConfig) []string {
	t.Helper()
	stat := runtimeTestStat(t, cfg.RuntimeDir)
	return []string{cfg.Label, strconv.FormatUint(uint64(stat.Dev), 10), strconv.FormatUint(stat.Ino, 10)}
}

func TestRunRuntimeQuarantineMoveConfinesArgvPaths(t *testing.T) {
	// Under simulated root, extra source/destination argv cannot move either an unrelated tree or the configured runtime; label-only invocation moves only the configured tree.
	for _, variant := range []string{"source-only", "destination-only", "old-interface", "extra-source", "extra-destination", "valid-label", "valid-primary"} {
		t.Run(variant, func(t *testing.T) {
			cfg := runtimeUninstallConfig(t)
			withRuntimeUninstallCommands(t, cfg)
			other := runtimeUninstallConfig(t)
			args := runtimeFixtureMoveArgs(t, cfg)
			original := runtimeTestStat(t, cfg.RuntimeDir)
			unrelated := runtimeTestStat(t, other.RuntimeDir)
			destination := other.RuntimeDir + ".relocated"
			switch variant {
			case "source-only":
				args[0] = other.RuntimeDir
			case "destination-only":
				args[0] = destination
			case "old-interface":
				args = []string{other.RuntimeDir, destination, strconv.FormatUint(uint64(unrelated.Dev), 10), strconv.FormatUint(unrelated.Ino, 10)}
			case "extra-source":
				args[1], args[2] = strconv.FormatUint(uint64(unrelated.Dev), 10), strconv.FormatUint(unrelated.Ino, 10)
				args = append(args, other.RuntimeDir)
			case "extra-destination":
				args = append(args, destination)
			case "valid-primary":
				args = args[1:]
			}
			var stdout bytes.Buffer
			err := RunRuntimeQuarantineMove(args, &stdout)
			valid := strings.HasPrefix(variant, "valid-")
			if valid {
				if err != nil {
					t.Fatal(err)
				}
				quarantine := strings.TrimSuffix(stdout.String(), "\n")
				if !validRuntimeQuarantinePath(cfg, quarantine) {
					t.Fatalf("invalid output %q", stdout.String())
				}
				found := runtimeTestStat(t, filepath.Join(quarantine, "runtime"))
				if found.Dev != original.Dev || found.Ino != original.Ino {
					t.Fatal("moved wrong identity")
				}
				if _, err := os.Lstat(cfg.RuntimeDir); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("source remains: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("accepted argv path: %v", args)
				}
				if stdout.Len() != 0 {
					t.Errorf("unexpected quarantine output %q", stdout.String())
				}
				assertRuntimeTestFile(t, filepath.Join(cfg.RuntimeDir, "session", "config"))
			}
			found := runtimeTestStat(t, other.RuntimeDir)
			if found.Dev != unrelated.Dev || found.Ino != unrelated.Ino {
				t.Fatal("unrelated tree changed")
			}
			assertRuntimeTestFile(t, filepath.Join(other.RuntimeDir, "session", "config"))
			if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("argv destination created: %v", err)
			}
		})
	}
}

func TestRunRuntimeQuarantineMoveRejectsUnknownLabel(t *testing.T) {
	// The production label resolver rejects unknown/path labels; the known primary resolves and the shipped legacy config is refused because its runtime/helper are empty.
	previousEUID := runtimeQuarantineEUIDVPNCore
	runtimeQuarantineEUIDVPNCore = func() int { return 0 }
	t.Cleanup(func() { runtimeQuarantineEUIDVPNCore = previousEUID })
	for _, label := range []string{"unknown-service", "/Library/PrivilegedHelperTools/other-service"} {
		var stdout bytes.Buffer
		err := RunRuntimeQuarantineMove([]string{label, "1", "1"}, &stdout)
		if err == nil || !strings.Contains(err.Error(), "unknown runtime service label") || stdout.Len() != 0 {
			t.Fatalf("label=%q error=%v output=%q", label, err, stdout.String())
		}
	}
	for _, label := range []string{"", DefaultServiceConfig().Label} {
		cfg, parent, err := configuredRuntimeQuarantine(label)
		if err != nil || !sameServiceConfig(cfg, DefaultServiceConfig()) || parent != filepath.Dir(defaultServiceRuntimeDir) {
			t.Fatalf("primary config: %+v %q %v", cfg, parent, err)
		}
	}
	err := RunRuntimeQuarantineMove([]string{legacyOpenConnectHelperLabel, "1", "1"}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "must be non-empty") {
		t.Fatalf("legacy error=%v", err)
	}
}

func TestRunRuntimeQuarantineMoveNeverReusesQuarantine(t *testing.T) {
	// A pre-existing directory or symlink at a generated name yields EEXIST without reusing it, changing its contents, or moving the runtime.
	for _, symlink := range []bool{false, true} {
		t.Run(strconv.FormatBool(symlink), func(t *testing.T) {
			cfg := runtimeUninstallConfig(t)
			withRuntimeUninstallCommands(t, cfg)
			token := strings.Repeat("A", 26)
			previous := runtimeQuarantineRandomVPNCore
			runtimeQuarantineRandomVPNCore = func() string { return token }
			t.Cleanup(func() { runtimeQuarantineRandomVPNCore = previous })
			quarantine := cfg.HelperDir + ".uninstall-" + token
			markerParent := quarantine
			if symlink {
				markerParent = t.TempDir()
				if err := os.Symlink(markerParent, quarantine); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Mkdir(quarantine, 0o711); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(markerParent, "existing")
			writeRuntimeTestFile(t, marker)
			before := runtimeTestStat(t, quarantine)
			var stdout bytes.Buffer
			err := RunRuntimeQuarantineMove(runtimeFixtureMoveArgs(t, cfg), &stdout)
			if !errors.Is(err, unix.EEXIST) || stdout.Len() != 0 {
				t.Fatalf("error=%v output=%q, want exclusive EEXIST", err, stdout.String())
			}
			after := runtimeTestStat(t, quarantine)
			if before.Dev != after.Dev || before.Ino != after.Ino {
				t.Fatal("existing quarantine replaced")
			}
			assertRuntimeTestFile(t, marker)
			assertRuntimeTestFile(t, filepath.Join(cfg.RuntimeDir, "session", "config"))
			if _, err := os.Lstat(filepath.Join(markerParent, "runtime")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("existing destination populated: %v", err)
			}
		})
	}
}

func TestUninstallServiceRejectsUnconfinedPrintedQuarantine(t *testing.T) {
	// Out-of-parent, wrong-prefix, malformed-token, unclean and extra-line output cannot authorize recursive deletion; the actual moved original remains quarantined.
	for _, variant := range []string{"outside", "wrong-prefix", "short-token", "invalid-token", "unclean", "extra-line"} {
		t.Run(variant, func(t *testing.T) {
			cfg := runtimeUninstallConfig(t)
			commands := withRuntimeUninstallCommands(t, cfg)
			path := cfg.HelperDir + ".uninstall-" + strings.Repeat("A", 26)
			switch variant {
			case "outside":
				path = filepath.Join(t.TempDir(), filepath.Base(path))
			case "wrong-prefix":
				path = filepath.Join(filepath.Dir(path), "other.uninstall-"+strings.Repeat("A", 26))
			case "short-token":
				path = cfg.HelperDir + ".uninstall-A"
			case "invalid-token":
				path = cfg.HelperDir + ".uninstall-" + strings.Repeat("a", 26)
			case "unclean":
				path = filepath.Dir(path) + "/../" + filepath.Base(filepath.Dir(path)) + "/" + filepath.Base(path)
			case "extra-line":
				path += "\n" + path
			}
			commands.printedQuarantine = path + "\n"
			err := UninstallService(cfg)
			if err == nil || !strings.Contains(err.Error(), "invalid printed quarantine path") {
				t.Fatalf("error=%v, want printed path refusal", err)
			}
			if len(commands.removedIdentities) != 0 {
				t.Fatal("invalid output authorized deletion")
			}
			assertRuntimeTestFile(t, filepath.Join(commands.quarantines[0], "runtime", "session", "config"))
			if got := commands.naming(path); len(got) != 0 {
				t.Fatalf("commands name rejected output: %v", got)
			}
		})
	}
}

func TestRunRuntimeQuarantineMoveRejectsInvalidDerivedConfig(t *testing.T) {
	// Empty/unclean config paths and a runtime under an unexpected parent are refused before creating quarantine or moving fixture data.
	for _, variant := range []string{"empty-runtime", "empty-helper", "unexpected-parent", "relative-runtime", "root-runtime", "unclean-helper"} {
		t.Run(variant, func(t *testing.T) {
			cfg := runtimeUninstallConfig(t)
			withRuntimeUninstallCommands(t, cfg)
			args := runtimeFixtureMoveArgs(t, cfg)
			derived, parent := cfg, filepath.Dir(cfg.RuntimeDir)
			switch variant {
			case "empty-runtime":
				derived.RuntimeDir = ""
			case "empty-helper":
				derived.HelperDir = ""
			case "unexpected-parent":
				parent += "/unexpected"
			case "relative-runtime":
				derived.RuntimeDir = "relative"
			case "root-runtime":
				derived.RuntimeDir = "/"
			case "unclean-helper":
				derived.HelperDir += "/../other"
			}
			runtimeQuarantineConfigVPNCore = func(string) (ServiceConfig, string, error) { return derived, parent, nil }
			var stdout bytes.Buffer
			err := RunRuntimeQuarantineMove(args, &stdout)
			want := "clean absolute non-root"
			if strings.HasPrefix(variant, "empty-") {
				want = "must be non-empty"
			}
			if variant == "unexpected-parent" {
				want = "differs from expected"
			}
			if err == nil || !strings.Contains(err.Error(), want) || stdout.Len() != 0 {
				t.Fatalf("config error=%v output=%q, want %q", err, stdout.String(), want)
			}
			assertRuntimeTestFile(t, filepath.Join(cfg.RuntimeDir, "session", "config"))
		})
	}
}

func TestRunRuntimeQuarantineMoveRejectsMismatchedIdentity(t *testing.T) {
	// Either wrong dev or wrong ino is refused before rename; the real configured tree survives in place.
	for _, index := range []int{1, 2} {
		t.Run(strconv.Itoa(index), func(t *testing.T) {
			cfg := runtimeUninstallConfig(t)
			withRuntimeUninstallCommands(t, cfg)
			args := runtimeFixtureMoveArgs(t, cfg)
			value, _ := strconv.ParseUint(args[index], 10, 64)
			args[index] = strconv.FormatUint(value+1, 10)
			var stdout bytes.Buffer
			err := RunRuntimeQuarantineMove(args, &stdout)
			if err == nil || !strings.Contains(err.Error(), "runtime identity changed before rename") {
				t.Fatalf("error=%v", err)
			}
			quarantine := strings.TrimSuffix(stdout.String(), "\n")
			if !validRuntimeQuarantinePath(cfg, quarantine) {
				t.Fatalf("missing retained quarantine path %q", stdout.String())
			}
			if _, err := os.Lstat(filepath.Join(quarantine, "runtime")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("moved mismatched identity: %v", err)
			}
			assertRuntimeTestFile(t, filepath.Join(cfg.RuntimeDir, "session", "config"))
		})
	}
}

func TestRuntimeQuarantineRejectsUnsafeParents(t *testing.T) {
	// Source-parent symlinks, helper-parent symlinks and writable helper parents refuse entrypoint movement and preserve runtime data.
	for _, variant := range []string{"source-parent-symlink", "helper-parent-symlink", "writable-helper-parent"} {
		t.Run(variant, func(t *testing.T) {
			cfg := runtimeUninstallConfig(t)
			withRuntimeUninstallCommands(t, cfg)
			args := runtimeFixtureMoveArgs(t, cfg)
			derived := cfg
			want := "open runtime parent"
			link := filepath.Join(t.TempDir(), "parent-link")
			switch variant {
			case "source-parent-symlink":
				if err := os.Symlink(filepath.Dir(cfg.RuntimeDir), link); err != nil {
					t.Fatal(err)
				}
				derived.RuntimeDir = filepath.Join(link, filepath.Base(cfg.RuntimeDir))
			case "helper-parent-symlink":
				if err := os.Symlink(filepath.Dir(cfg.HelperDir), link); err != nil {
					t.Fatal(err)
				}
				derived.HelperDir = filepath.Join(link, filepath.Base(cfg.HelperDir))
				want = "open quarantine parent"
			case "writable-helper-parent":
				if err := os.Chmod(filepath.Dir(cfg.HelperDir), 0o777); err != nil {
					t.Fatal(err)
				}
				want = "group/world-writable"
			}
			runtimeQuarantineConfigVPNCore = func(string) (ServiceConfig, string, error) { return derived, filepath.Dir(derived.RuntimeDir), nil }
			err := RunRuntimeQuarantineMove(args, &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("error=%v, want %q", err, want)
			}
			assertRuntimeTestFile(t, filepath.Join(cfg.RuntimeDir, "session", "config"))
		})
	}
}

func TestRunRuntimeQuarantineMoveRefusesPreparationFailures(t *testing.T) {
	// Fchown/ACL errors, wrong verified owner/group and an occupied destination prevent rename and preserve the original fixture.
	for _, variant := range []string{"fchown", "acl", "owner", "group", "occupied-destination"} {
		t.Run(variant, func(t *testing.T) {
			cfg := runtimeUninstallConfig(t)
			withRuntimeUninstallCommands(t, cfg)
			previousClear := runtimeQuarantineClearACLVPNCore
			t.Cleanup(func() { runtimeQuarantineClearACLVPNCore = previousClear })
			deps := installVerificationDepsVPNCore()
			want := "root:wheel"
			switch variant {
			case "fchown":
				runtimeQuarantineFchownVPNCore = func(int, int, int) error { return errors.New("fixture fchown denied") }
				want = "fixture fchown denied"
			case "acl":
				runtimeQuarantineClearACLVPNCore = func(int) error { return errors.New("fixture ACL denied") }
				want = "fixture ACL denied"
			case "owner":
				deps.owner = func(path string, stat *unix.Stat_t) (uint32, error) {
					if strings.Contains(path, ".uninstall-") {
						return 501, nil
					}
					return 0, nil
				}
			case "group":
				deps.group = func(path string, stat *unix.Stat_t) (uint32, error) {
					if strings.Contains(path, ".uninstall-") {
						return 1, nil
					}
					return 0, nil
				}
			case "occupied-destination":
				runtimeQuarantineClearACLVPNCore = func(fd int) error {
					childFD, err := unix.Openat(fd, "runtime", unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY, 0o600)
					if err != nil {
						t.Fatal(err)
					}
					return unix.Close(childFD)
				}
				want = "quarantine destination must be absent"
			}
			runtimeQuarantineDepsVPNCore = func() verificationDependencies { return deps }
			var stdout bytes.Buffer
			err := RunRuntimeQuarantineMove(runtimeFixtureMoveArgs(t, cfg), &stdout)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("error=%v, want %q", err, want)
			}
			quarantine := strings.TrimSuffix(stdout.String(), "\n")
			if !validRuntimeQuarantinePath(cfg, quarantine) {
				t.Fatalf("missing quarantine path: %q", stdout.String())
			}
			assertRuntimeTestFile(t, filepath.Join(cfg.RuntimeDir, "session", "config"))
			if variant == "occupied-destination" {
				found := runtimeTestStat(t, filepath.Join(quarantine, "runtime"))
				if found.Mode&unix.S_IFMT != unix.S_IFREG {
					t.Fatal("occupied destination replaced")
				}
			}
		})
	}
}

func TestUninstallServiceRejectsDifferentCallerConfig(t *testing.T) {
	// A caller config differing from the label's configured runtime/helper is rejected without moving either tree.
	cfg := runtimeUninstallConfig(t)
	commands := withRuntimeUninstallCommands(t, cfg)
	other := runtimeUninstallConfig(t)
	runtimeQuarantineConfigVPNCore = func(string) (ServiceConfig, string, error) { return other, filepath.Dir(other.RuntimeDir), nil }
	err := UninstallService(cfg)
	if err == nil || !strings.Contains(err.Error(), "caller runtime/helper config differs") {
		t.Fatalf("error=%v", err)
	}
	if len(commands.runtimeCalls(cfg)) != 0 {
		t.Fatal("mismatched config invoked privileged move")
	}
	assertRuntimeTestFile(t, filepath.Join(cfg.RuntimeDir, "session", "config"))
	assertRuntimeTestFile(t, filepath.Join(other.RuntimeDir, "session", "config"))
}
