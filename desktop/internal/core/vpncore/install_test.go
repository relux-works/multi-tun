package vpncore

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
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
	// This proves the digest emitted for a binary authorizes the exact staged install and bounded launchd replacement sequence.
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
				return nil, errors.New("service absent")
			}
		}
		return nil, nil
	})
	previousSleep := installSleepVPNCore
	installSleepVPNCore = func(_ time.Duration) {}
	t.Cleanup(func() { installSleepVPNCore = previousSleep })
	cfg := testInstallConfig(t)
	withRootOwner(t, 0)
	if err := InstallService(cfg, binary, 501, 20, digest); err != nil {
		t.Fatalf("InstallService() error = %v", err)
	}
	if len(commands) != 9 {
		t.Fatalf("commands = %v, want 9 ordered commands", commands)
	}
	wantKinds := []string{"install -d", "install -o", "install -o", "install -o", "launchctl bootout", "launchctl print", "launchctl print", "launchctl enable", "launchctl bootstrap"}
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
		"install -d -o root -g wheel -m 0755 " + cfg.HelperDir,
		" -m 0755 ",
		" -m 0644 ",
		" -m 0644 ",
	} {
		if !strings.Contains(commands[index], want) {
			t.Fatalf("commands[%d] = %q, want fragment %q", index, commands[index], want)
		}
	}
	if !strings.HasSuffix(commands[1], " "+cfg.BinaryPath()) || !strings.HasSuffix(commands[2], " "+cfg.ManifestPath()) || !strings.HasSuffix(commands[3], " "+cfg.PlistPath) {
		t.Fatalf("installed destinations are wrong: %v", commands[:4])
	}
	for index, want := range []string{
		"launchctl bootout system/" + cfg.Label,
		"launchctl print system/" + cfg.Label,
		"launchctl print system/" + cfg.Label,
		"launchctl enable system/" + cfg.Label,
		"launchctl bootstrap system " + cfg.PlistPath,
	} {
		if commands[index+4] != want {
			t.Fatalf("commands[%d] = %q, want %q", index+4, commands[index+4], want)
		}
	}
}

func TestCompatibilityCleanupStillTargetsLegacyService(t *testing.T) {
	// This proves hardened installation retains the exact legacy launchd/socket cleanup without touching the new helper directory.
	var commands []string
	withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
		commands = append(commands, strings.Join(append([]string{name}, args...), " "))
		return nil, nil
	})
	cleanupCompatibilityServices(DefaultServiceConfig())
	want := []string{
		"launchctl bootout system/" + legacyOpenConnectHelperLabel,
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
	root := t.TempDir()
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

func withRootOwner(t *testing.T, uid uint32) {
	t.Helper()
	previous := installedOwnerUIDVPNCore
	installedOwnerUIDVPNCore = func(string) (uint32, error) { return uid, nil }
	t.Cleanup(func() { installedOwnerUIDVPNCore = previous })
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
			withRootOwner(t, 0)
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
			if !strings.Contains(joined, "rm -f "+cfg.BinaryPath()) {
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
	withRootOwner(t, 501)
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
