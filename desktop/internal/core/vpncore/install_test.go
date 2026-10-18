package vpncore

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestInstallServiceRefusesDigestMismatchBeforePrivilege(t *testing.T) {
	// This proves a validly shaped but incorrect digest triggers no sudo check or privileged command.
	binary := writeInstallTestBinary(t)
	var privileged []string
	sudoChecks := 0
	withInstallSeams(t, func() error { sudoChecks++; return nil }, func(name string, args ...string) ([]byte, error) {
		privileged = append(privileged, strings.Join(append([]string{name}, args...), " "))
		return nil, nil
	})
	err := InstallService(testInstallConfig(t), binary, 501, 20, strings.Repeat("0", 64))
	if err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("InstallService() error = %v, want digest mismatch", err)
	}
	if sudoChecks != 0 || len(privileged) != 0 {
		t.Fatalf("privileged work occurred before refusal: sudo=%d commands=%v", sudoChecks, privileged)
	}
}

func TestInstallServiceRefusesMalformedDigestBeforePrivilege(t *testing.T) {
	// This proves malformed uppercase/short digests are rejected before any privileged seam is entered.
	binary := writeInstallTestBinary(t)
	called := false
	withInstallSeams(t, func() error { called = true; return nil }, func(string, ...string) ([]byte, error) {
		called = true
		return nil, nil
	})
	for _, value := range []string{"", "abc", strings.Repeat("A", 64)} {
		if err := InstallService(testInstallConfig(t), binary, 501, 20, value); err == nil {
			t.Fatalf("InstallService(%q) error = nil", value)
		}
	}
	if called {
		t.Fatal("malformed digest reached a privileged seam")
	}
}

func TestInstallServiceInstallsPackageAndReplacesLaunchServiceInOrder(t *testing.T) {
	// This proves a secure helper parent permits the exact staged install and bounded launchd replacement sequence.
	binary := writeInstallTestBinary(t)
	digest, err := InstallDigest(binary)
	if err != nil {
		t.Fatalf("InstallDigest() error = %v", err)
	}
	var commands []string
	printCalls := 0
	withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
		commands = append(commands, strings.Join(append([]string{name}, args...), " "))
		if err := performFakeInstall(name, args, nil); err != nil {
			return nil, err
		}
		if name == "launchctl" && len(args) > 0 && args[0] == "print" {
			printCalls++
			if printCalls == 2 {
				return nil, launchctlTestError(113, nil)
			}
		}
		return nil, nil
	})
	previousSleep := installSleepVPNCore
	installSleepVPNCore = func(_ time.Duration) {}
	t.Cleanup(func() { installSleepVPNCore = previousSleep })
	cfg := testInstallConfig(t)
	withInstallVerification(t, func(string, *unix.Stat_t) (uint32, error) { return 0, nil }, func(string, int) error { return nil })
	if err := InstallService(cfg, binary, 501, 20, digest); err != nil {
		t.Fatalf("InstallService() error = %v", err)
	}
	if len(commands) != 11 {
		t.Fatalf("commands = %v, want 11 ordered commands", commands)
	}
	wantKinds := []string{"rm -rf", "install -d", "chmod -N", "install -o", "install -o", "install -o", "launchctl bootout", "launchctl print", "launchctl print", "launchctl enable", "launchctl bootstrap"}
	gotKinds := make([]string, 0, len(wantKinds))
	for _, command := range commands {
		for _, prefix := range wantKinds {
			if strings.HasPrefix(command, prefix) {
				gotKinds = append(gotKinds, prefix)
				break
			}
		}
	}
	if !reflect.DeepEqual(gotKinds, wantKinds) {
		t.Fatalf("command order = %v, want %v; raw=%v", gotKinds, wantKinds, commands)
	}
	for index, want := range []string{
		"rm -rf " + cfg.HelperDir,
		"install -d -o root -g wheel -m 0755 " + cfg.HelperDir,
		"chmod -N " + cfg.HelperDir,
		" -m 0755 ",
		" -m 0644 ",
		" -m 0644 ",
	} {
		if !strings.Contains(commands[index], want) {
			t.Fatalf("commands[%d] = %q, want fragment %q", index, commands[index], want)
		}
	}
	if !strings.HasSuffix(commands[3], " "+cfg.BinaryPath()) || !strings.HasSuffix(commands[4], " "+cfg.ManifestPath()) || !strings.HasSuffix(commands[5], " "+cfg.PlistPath) {
		t.Fatalf("installed destinations are wrong: %v", commands[:6])
	}
	for index, want := range []string{
		"launchctl bootout system/" + cfg.Label,
		"launchctl print system/" + cfg.Label,
		"launchctl print system/" + cfg.Label,
		"launchctl enable system/" + cfg.Label,
		"launchctl bootstrap system " + cfg.PlistPath,
	} {
		if commands[index+6] != want {
			t.Fatalf("commands[%d] = %q, want %q", index+6, commands[index+6], want)
		}
	}
}

func TestCompatibilityCleanupStillTargetsLegacyService(t *testing.T) {
	// This proves hardened installation retains the exact legacy launchd/socket cleanup without touching the new helper directory.
	var commands []string
	withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
		commands = append(commands, strings.Join(append([]string{name}, args...), " "))
		if name == "launchctl" && len(args) > 0 && args[0] == "print" {
			return nil, launchctlTestError(113, nil)
		}
		return nil, nil
	})
	if err := cleanupCompatibilityServices(DefaultServiceConfig()); err != nil {
		t.Fatalf("cleanupCompatibilityServices() error = %v", err)
	}
	want := []string{
		"launchctl bootout system/" + legacyOpenConnectHelperLabel,
		"launchctl print system/" + legacyOpenConnectHelperLabel,
		"rm -f " + legacyOpenConnectHelperPlistPath + " " + legacyOpenConnectHelperSocketPath,
	}
	if !reflect.DeepEqual(commands, want) {
		t.Fatalf("legacy cleanup commands = %v, want %v", commands, want)
	}
}

func writeInstallTestBinary(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vpn-core")
	if err := os.WriteFile(path, []byte("test vpn-core binary\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func testInstallConfig(t *testing.T) ServiceConfig {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "run"), 0o755); err != nil {
		t.Fatal(err)
	}
	return ServiceConfig{
		Label:      "works.relux.test-vpn-core",
		PlistPath:  filepath.Join(root, "service.plist"),
		SocketPath: filepath.Join(root, "run", "service.sock"),
		HelperDir:  filepath.Join(root, "helper"),
	}
}

func withInstallSeams(t *testing.T, ensure func() error, run func(string, ...string) ([]byte, error)) {
	t.Helper()
	previousEnsure := ensureSudoCredentialsVPNCore
	previousRun := runPrivilegedCommandVPNCore
	ensureSudoCredentialsVPNCore = ensure
	runPrivilegedCommandVPNCore = run
	t.Cleanup(func() {
		ensureSudoCredentialsVPNCore = previousEnsure
		runPrivilegedCommandVPNCore = previousRun
	})
}

// performFakeInstall emulates `install` for the recorded privileged commands so
// the post-install verification reads real destination files. tamper, when set,
// rewrites the copied bytes for destinations whose base name it returns true for.
func performFakeInstall(name string, args []string, tamper func(dest string) []byte) error {
	if name == "rm" {
		for _, path := range args[1:] {
			if err := os.RemoveAll(path); err != nil {
				return err
			}
		}
		return nil
	}
	if name != "install" || len(args) < 2 || args[0] == "-d" {
		if name == "install" && len(args) > 0 && args[0] == "-d" {
			return os.MkdirAll(args[len(args)-1], 0o755)
		}
		return nil
	}
	source, dest := args[len(args)-2], args[len(args)-1]
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	if tamper != nil {
		if replaced := tamper(dest); replaced != nil {
			data = replaced
		}
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dest, data, 0o644)
}

func withInstallVerification(t *testing.T, owner ownerLookup, checkACL func(string, int) error) {
	t.Helper()
	previous := installVerificationDepsVPNCore
	installVerificationDepsVPNCore = func() verificationDependencies {
		return verificationDependencies{owner: owner, checkACL: checkACL}
	}
	t.Cleanup(func() { installVerificationDepsVPNCore = previous })
}

func launchctlTestError(exitCode int, output []byte) error {
	return &commandError{Name: "launchctl", Args: []string{"print"}, ExitCode: exitCode, Output: output, Err: errors.New("exit status")}
}

func TestInstallServiceRefusesSymlinkedHelperParentBeforePrivilege(t *testing.T) {
	// This proves a symlinked intermediate helper parent is refused before any privileged command runs.
	binary := writeInstallTestBinary(t)
	digest, err := InstallDigest(binary)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testInstallConfig(t)
	realParent := filepath.Join(filepath.Dir(cfg.HelperDir), "real-parent")
	if err := os.Mkdir(realParent, 0o755); err != nil {
		t.Fatal(err)
	}
	linkedParent := filepath.Join(filepath.Dir(cfg.HelperDir), "linked-parent")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Fatal(err)
	}
	cfg.HelperDir = filepath.Join(linkedParent, "helper")
	withInstallVerification(t, func(string, *unix.Stat_t) (uint32, error) { return 0, nil }, func(string, int) error { return nil })
	var commands []string
	withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
		commands = append(commands, strings.Join(append([]string{name}, args...), " "))
		return nil, nil
	})
	if err := InstallService(cfg, binary, 501, 20, digest); err == nil || !strings.Contains(err.Error(), "without following symlinks") {
		t.Fatalf("InstallService() error = %v, want symlinked-parent refusal", err)
	}
	if len(commands) != 0 {
		t.Fatalf("privileged commands = %v, want none", commands)
	}
}

func TestUninstallServiceRefusesUnsafeHelperParentBeforePrivilege(t *testing.T) {
	// These cases prove group-writable and non-root helper parents are refused before any privileged command runs.
	for _, test := range []struct {
		name  string
		setup func(t *testing.T, cfg ServiceConfig) ownerLookup
		want  string
	}{
		{
			name: "group-writable",
			setup: func(t *testing.T, cfg ServiceConfig) ownerLookup {
				if err := os.Chmod(filepath.Dir(cfg.HelperDir), 0o775); err != nil {
					t.Fatal(err)
				}
				return func(string, *unix.Stat_t) (uint32, error) { return 0, nil }
			},
			want: "group/world-writable",
		},
		{
			name: "non-root",
			setup: func(_ *testing.T, cfg ServiceConfig) ownerLookup {
				return func(path string, _ *unix.Stat_t) (uint32, error) {
					if path == filepath.Dir(cfg.HelperDir) {
						return 501, nil
					}
					return 0, nil
				}
			},
			want: "want root",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := testInstallConfig(t)
			withInstallVerification(t, test.setup(t, cfg), func(string, int) error { return nil })
			var commands []string
			withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
				commands = append(commands, strings.Join(append([]string{name}, args...), " "))
				return nil, nil
			})
			if err := UninstallService(cfg); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("UninstallService() error = %v, want %q", err, test.want)
			}
			if len(commands) != 0 {
				t.Fatalf("privileged commands = %v, want none", commands)
			}
		})
	}
}

// A staged file swapped between hashing and the privileged copy is caught on
// the root-owned destination; launchd is never touched and the files are removed.
func TestInstallServiceRefusesSwappedStagedFiles(t *testing.T) {
	for _, target := range []string{"vpn-core", "manifest.json", "service.plist"} {
		t.Run(target, func(t *testing.T) {
			binary := writeInstallTestBinary(t)
			digest, err := InstallDigest(binary)
			if err != nil {
				t.Fatalf("InstallDigest() error = %v", err)
			}
			cfg := testInstallConfig(t)
			withInstallVerification(t, func(string, *unix.Stat_t) (uint32, error) { return 0, nil }, func(string, int) error { return nil })
			var commands []string
			withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
				commands = append(commands, strings.Join(append([]string{name}, args...), " "))
				return nil, performFakeInstall(name, args, func(dest string) []byte {
					if filepath.Base(dest) == target {
						return []byte("attacker payload\n")
					}
					return nil
				})
			})
			err = InstallService(cfg, binary, 501, 20, digest)
			if err == nil || !strings.Contains(err.Error(), "nothing was bootstrapped") {
				t.Fatalf("InstallService() error = %v, want verification refusal", err)
			}
			joined := strings.Join(commands, "\n")
			if strings.Contains(joined, "launchctl") {
				t.Fatalf("launchctl was invoked after a failed verification: %v", commands)
			}
			if !strings.Contains(joined, "rm -rf "+cfg.HelperDir) || !strings.Contains(joined, "rm -f "+cfg.PlistPath) {
				t.Fatalf("installed files were not removed: %v", commands)
			}
		})
	}
}

// Destinations that end up owned by a non-root user are refused the same way.
func TestInstallServiceRefusesNonRootOwnedDestinations(t *testing.T) {
	binary := writeInstallTestBinary(t)
	digest, err := InstallDigest(binary)
	if err != nil {
		t.Fatalf("InstallDigest() error = %v", err)
	}
	cfg := testInstallConfig(t)
	withInstallVerification(t, func(path string, _ *unix.Stat_t) (uint32, error) {
		if path == cfg.HelperDir {
			return 501, nil
		}
		return 0, nil
	}, func(string, int) error { return nil })
	var commands []string
	withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
		commands = append(commands, strings.Join(append([]string{name}, args...), " "))
		return nil, performFakeInstall(name, args, nil)
	})
	err = InstallService(cfg, binary, 501, 20, digest)
	if err == nil || !strings.Contains(err.Error(), "want root") {
		t.Fatalf("InstallService() error = %v, want root-owner refusal", err)
	}
	if strings.Contains(strings.Join(commands, "\n"), "launchctl bootstrap") {
		t.Fatalf("bootstrap ran despite failed verification: %v", commands)
	}
}

func TestInstallServiceRefusesHelperSymlinkThatSurvivesPrivilegedPreparation(t *testing.T) {
	// This proves a pre-existing helper symlink cannot survive preparation and reach launchctl even if the privileged removal seam is subverted.
	binary := writeInstallTestBinary(t)
	digest, err := InstallDigest(binary)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testInstallConfig(t)
	target := t.TempDir()
	if err := os.Symlink(target, cfg.HelperDir); err != nil {
		t.Fatal(err)
	}
	withInstallVerification(t, func(string, *unix.Stat_t) (uint32, error) { return 0, nil }, func(string, int) error { return nil })
	var commands []string
	withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
		commands = append(commands, strings.Join(append([]string{name}, args...), " "))
		if name == "rm" && len(args) > 1 && args[0] == "-rf" && args[1] == cfg.HelperDir {
			return nil, nil
		}
		return nil, performFakeInstall(name, args, nil)
	})
	err = InstallService(cfg, binary, 501, 20, digest)
	if err == nil || !strings.Contains(err.Error(), "without following symlinks") {
		t.Fatalf("InstallService() error = %v, want symlink refusal", err)
	}
	joined := strings.Join(commands, "\n")
	if !strings.Contains(joined, "rm -rf "+cfg.HelperDir) {
		t.Fatalf("final helper symlink was refused before intended removal: %v", commands)
	}
	if strings.Contains(joined, "launchctl") {
		t.Fatalf("launchctl was invoked for symlinked helper: %v", commands)
	}
}

func TestInstallServiceRefusesWriteACLOnHelperDirectory(t *testing.T) {
	// This proves a write ACL on the freshly created helper directory aborts installation and cleanup before launchctl.
	binary := writeInstallTestBinary(t)
	digest, err := InstallDigest(binary)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testInstallConfig(t)
	withInstallVerification(t, func(string, *unix.Stat_t) (uint32, error) { return 0, nil }, func(path string, _ int) error {
		if path == cfg.HelperDir {
			return errors.New("write-capable ACL entry")
		}
		return nil
	})
	var commands []string
	withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
		commands = append(commands, strings.Join(append([]string{name}, args...), " "))
		return nil, performFakeInstall(name, args, nil)
	})
	err = InstallService(cfg, binary, 501, 20, digest)
	if err == nil || !strings.Contains(err.Error(), "write-capable ACL") {
		t.Fatalf("InstallService() error = %v, want ACL refusal", err)
	}
	if strings.Contains(strings.Join(commands, "\n"), "launchctl") {
		t.Fatalf("launchctl was invoked for ACL failure: %v", commands)
	}
}

func TestInstallServiceFailsWhenBootoutLeavesServiceLoaded(t *testing.T) {
	// This proves a failed bootout cannot be ignored when launchd continues to report the service loaded, and bootstrap never runs.
	binary := writeInstallTestBinary(t)
	digest, err := InstallDigest(binary)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testInstallConfig(t)
	withInstallVerification(t, func(string, *unix.Stat_t) (uint32, error) { return 0, nil }, func(string, int) error { return nil })
	withExpiredInstallClock(t)
	var commands []string
	withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
		commands = append(commands, strings.Join(append([]string{name}, args...), " "))
		if name == "launchctl" && args[0] == "bootout" {
			return nil, errors.New("bootout refused")
		}
		if name == "launchctl" && args[0] == "print" {
			return []byte("still loaded"), nil
		}
		return nil, performFakeInstall(name, args, nil)
	})
	err = InstallService(cfg, binary, 501, 20, digest)
	if err == nil || !strings.Contains(err.Error(), "did not forget") {
		t.Fatalf("InstallService() error = %v, want loaded-service failure", err)
	}
	if strings.Contains(strings.Join(commands, "\n"), "launchctl bootstrap") {
		t.Fatalf("bootstrap ran while old service stayed loaded: %v", commands)
	}
}

func TestUninstallServiceFailsWhenBootoutLeavesServiceLoaded(t *testing.T) {
	// This proves uninstall reports a bootout failure when launchd retains the label even if path cleanup succeeds.
	cfg := testInstallConfig(t)
	if err := os.Mkdir(cfg.HelperDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.PlistPath, []byte("plist"), 0o644); err != nil {
		t.Fatal(err)
	}
	withInstallVerification(t, func(string, *unix.Stat_t) (uint32, error) { return 0, nil }, func(string, int) error { return nil })
	withExpiredInstallClock(t)
	withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
		if name == "launchctl" && args[0] == "bootout" {
			return nil, errors.New("bootout refused")
		}
		if name == "launchctl" && args[0] == "print" {
			return []byte("still loaded"), nil
		}
		return nil, performFakeInstall(name, args, nil)
	})
	if err := UninstallService(cfg); err == nil || !strings.Contains(err.Error(), "did not forget") {
		t.Fatalf("UninstallService() error = %v, want loaded-service failure", err)
	}
}

func TestUninstallServiceToleratesVerifiedAbsentState(t *testing.T) {
	// This proves bootout/removal command failures are tolerated only when launchd and every configured service path are verified absent.
	cfg := testInstallConfig(t)
	withInstallVerification(t, func(string, *unix.Stat_t) (uint32, error) { return 0, nil }, func(string, int) error { return nil })
	withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
		if name == "launchctl" && args[0] == "print" {
			return nil, launchctlTestError(113, nil)
		}
		return nil, errors.New("already absent")
	})
	if err := UninstallService(cfg); err != nil {
		t.Fatalf("UninstallService() error = %v for verified absent state", err)
	}
}

func TestForgetLaunchdLabelRecognizesOnlyExplicitAbsence(t *testing.T) {
	// These cases prove only exit 113 or launchd's service-not-found output is classified as absence.
	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "exit-113", err: launchctlTestError(113, []byte("other output"))},
		{name: "service-not-found-output", err: launchctlTestError(1, []byte("Could not find service \"system/example\""))},
	} {
		t.Run(test.name, func(t *testing.T) {
			withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
				if name == "launchctl" && args[0] == "print" {
					return nil, test.err
				}
				return nil, nil
			})
			if err := forgetLaunchdLabel("works.relux.test"); err != nil {
				t.Fatalf("forgetLaunchdLabel() error = %v", err)
			}
		})
	}
}

func TestForgetLaunchdLabelKeepsPollingAfterNonAbsentError(t *testing.T) {
	// This proves a transient non-absence print error keeps polling and can be followed by confirmed absence.
	previousNow := installNowVPNCore
	previousSleep := installSleepVPNCore
	base := time.Unix(1, 0)
	installNowVPNCore = func() time.Time { return base }
	installSleepVPNCore = func(time.Duration) {}
	t.Cleanup(func() {
		installNowVPNCore = previousNow
		installSleepVPNCore = previousSleep
	})
	printCalls := 0
	withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
		if name == "launchctl" && args[0] == "print" {
			printCalls++
			if printCalls == 1 {
				return nil, launchctlTestError(1, []byte("Operation not permitted"))
			}
			return nil, launchctlTestError(113, nil)
		}
		return nil, nil
	})
	if err := forgetLaunchdLabel("works.relux.test"); err != nil {
		t.Fatalf("forgetLaunchdLabel() error = %v", err)
	}
	if printCalls != 2 {
		t.Fatalf("launchctl print calls = %d, want 2", printCalls)
	}
}

func TestInstallServicePropagatesLaunchctlPrintPermissionFailure(t *testing.T) {
	// This proves install fails instead of treating a non-absence launchctl print error as a forgotten service.
	binary := writeInstallTestBinary(t)
	digest, err := InstallDigest(binary)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testInstallConfig(t)
	withInstallVerification(t, func(string, *unix.Stat_t) (uint32, error) { return 0, nil }, func(string, int) error { return nil })
	withExpiredInstallClock(t)
	withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
		if name == "launchctl" && args[0] == "print" {
			return nil, launchctlTestError(1, []byte("Operation not permitted"))
		}
		return nil, performFakeInstall(name, args, nil)
	})
	err = InstallService(cfg, binary, 501, 20, digest)
	if err == nil || !strings.Contains(err.Error(), "Operation not permitted") || !strings.Contains(err.Error(), "did not forget") {
		t.Fatalf("InstallService() error = %v, want bounded permission failure", err)
	}
}

func TestUninstallServicePropagatesLaunchctlPrintPermissionFailure(t *testing.T) {
	// This proves uninstall fails after the bounded poll when launchctl print reports a non-absence error.
	cfg := testInstallConfig(t)
	withInstallVerification(t, func(string, *unix.Stat_t) (uint32, error) { return 0, nil }, func(string, int) error { return nil })
	withExpiredInstallClock(t)
	withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
		if name == "launchctl" && args[0] == "print" {
			return nil, launchctlTestError(1, []byte("Operation not permitted"))
		}
		return nil, performFakeInstall(name, args, nil)
	})
	err := UninstallService(cfg)
	if err == nil || !strings.Contains(err.Error(), "Operation not permitted") || !strings.Contains(err.Error(), "did not forget") {
		t.Fatalf("UninstallService() error = %v, want bounded permission failure", err)
	}
}

func TestRunCommandPreservesFailureOutputAndExitCode(t *testing.T) {
	// This proves command failures retain raw output and the process exit code for launchd absence classification.
	output, err := runCommand("/bin/sh", "-c", "printf 'Could not find service'; exit 113")
	var commandErr *commandError
	if !errors.As(err, &commandErr) {
		t.Fatalf("runCommand() error = %T %v, want *commandError", err, err)
	}
	if commandErr.ExitCode != 113 || string(commandErr.Output) != "Could not find service" || string(output) != "Could not find service" {
		t.Fatalf("runCommand() = (%q, exit=%d, raw=%q), want preserved output and exit 113", output, commandErr.ExitCode, commandErr.Output)
	}
}

func withExpiredInstallClock(t *testing.T) {
	t.Helper()
	previousNow := installNowVPNCore
	previousSleep := installSleepVPNCore
	base := time.Unix(1, 0)
	calls := 0
	installNowVPNCore = func() time.Time {
		calls++
		if calls == 1 {
			return base
		}
		return base.Add(launchctlForgetTimeout)
	}
	installSleepVPNCore = func(time.Duration) {}
	t.Cleanup(func() {
		installNowVPNCore = previousNow
		installSleepVPNCore = previousSleep
	})
}
