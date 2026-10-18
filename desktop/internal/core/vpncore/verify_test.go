package vpncore

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

type verificationFixture struct {
	cfg          ServiceConfig
	binarySHA    string
	manifestSHA  string
	binaryPath   string
	extraPath    string
	dependencies verificationDependencies
}

func TestVerifyDaemonInstallationAcceptsVerifiedRootOwnedTree(t *testing.T) {
	// This proves a matching manifest, binary, secure path, ownership model, and ACL policy pass together.
	fixture := newVerificationFixture(t)
	if err := verifyDaemonInstallation(fixture.cfg, fixture.binarySHA, fixture.manifestSHA, fixture.dependencies); err != nil {
		t.Fatalf("verifyDaemonInstallation() error = %v", err)
	}
}

func TestVerifyDaemonInstallationRejectsTamperedManifestEntry(t *testing.T) {
	// This proves a listed file changed after manifest creation prevents daemon startup.
	fixture := newVerificationFixture(t)
	if err := os.WriteFile(fixture.extraPath, []byte("tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := verifyDaemonInstallation(fixture.cfg, fixture.binarySHA, fixture.manifestSHA, fixture.dependencies)
	if err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("verifyDaemonInstallation() error = %v, want entry sha mismatch", err)
	}
}

func TestVerifyDaemonInstallationRejectsGroupWritableFile(t *testing.T) {
	// This proves matching content is insufficient when a manifest entry can be modified by its group.
	fixture := newVerificationFixture(t)
	if err := os.Chmod(fixture.extraPath, 0o660); err != nil {
		t.Fatal(err)
	}
	err := verifyDaemonInstallation(fixture.cfg, fixture.binarySHA, fixture.manifestSHA, fixture.dependencies)
	if err == nil || !strings.Contains(err.Error(), "group/world-writable") {
		t.Fatalf("verifyDaemonInstallation() error = %v, want writable-mode refusal", err)
	}
}

func TestVerifyDaemonInstallationRejectsNonRootOwner(t *testing.T) {
	// This proves the injectable ownership lookup still enforces uid 0 for every installed entry.
	fixture := newVerificationFixture(t)
	fixture.dependencies.owner = func(path string, _ *unix.Stat_t) (uint32, error) {
		if path == fixture.extraPath {
			return 501, nil
		}
		return 0, nil
	}
	err := verifyDaemonInstallation(fixture.cfg, fixture.binarySHA, fixture.manifestSHA, fixture.dependencies)
	if err == nil || !strings.Contains(err.Error(), "owned by uid 501") {
		t.Fatalf("verifyDaemonInstallation() error = %v, want non-root refusal", err)
	}
}

func TestVerifyDaemonInstallationRejectsSymlinkedPathComponent(t *testing.T) {
	// This proves O_NOFOLLOW path walking refuses an otherwise matching helper reached through a symlinked directory.
	fixture := newVerificationFixture(t)
	linkRoot := filepath.Join(filepath.Dir(fixture.cfg.HelperDir), "helper-link")
	if err := os.Symlink(fixture.cfg.HelperDir, linkRoot); err != nil {
		t.Fatal(err)
	}
	fixture.cfg.HelperDir = linkRoot
	fixture.dependencies.executable = func() (string, error) { return fixture.binaryPath, nil }
	err := verifyDaemonInstallation(fixture.cfg, fixture.binarySHA, fixture.manifestSHA, fixture.dependencies)
	if err == nil || !strings.Contains(err.Error(), "without following symlinks") {
		t.Fatalf("verifyDaemonInstallation() error = %v, want symlink refusal", err)
	}
}

func TestVerifyDaemonInstallationRejectsWriteACL(t *testing.T) {
	// This proves ACL inspection fails closed even when ownership, modes, and hashes are valid.
	fixture := newVerificationFixture(t)
	fixture.dependencies.checkACL = func(path string, _ int) error {
		if path == fixture.extraPath {
			return errors.New("write-capable ACL entry")
		}
		return nil
	}
	err := verifyDaemonInstallation(fixture.cfg, fixture.binarySHA, fixture.manifestSHA, fixture.dependencies)
	if err == nil || !strings.Contains(err.Error(), "write-capable ACL") {
		t.Fatalf("verifyDaemonInstallation() error = %v, want ACL refusal", err)
	}
}

func newVerificationFixture(t *testing.T) verificationFixture {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	helperDir := filepath.Join(root, "helper")
	socketDir := filepath.Join(root, "run")
	if err := os.MkdirAll(filepath.Join(helperDir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(socketDir, 0o755); err != nil {
		t.Fatal(err)
	}
	binaryPath := filepath.Join(helperDir, "vpn-core")
	extraPath := filepath.Join(helperDir, "bin", "future-snapshot")
	if err := os.WriteFile(binaryPath, []byte("verified binary\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(extraPath, []byte("verified extension point\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	binarySHA, err := hashFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	extraSHA, err := hashFile(extraPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest := Manifest{Version: manifestVersion, Files: []ManifestFile{
		{Path: "vpn-core", SHA256: binarySHA},
		{Path: "bin/future-snapshot", SHA256: extraSHA},
	}}
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	manifestData = append(manifestData, '\n')
	manifestPath := filepath.Join(helperDir, "manifest.json")
	if err := os.WriteFile(manifestPath, manifestData, 0o644); err != nil {
		t.Fatal(err)
	}
	return verificationFixture{
		cfg: ServiceConfig{
			Label:      "test",
			PlistPath:  filepath.Join(root, "service.plist"),
			SocketPath: filepath.Join(socketDir, "vpn-core.sock"),
			HelperDir:  helperDir,
		},
		binarySHA:   binarySHA,
		manifestSHA: sha256Hex(manifestData),
		binaryPath:  binaryPath,
		extraPath:   extraPath,
		dependencies: verificationDependencies{
			executable: func() (string, error) { return binaryPath, nil },
			owner:      func(string, *unix.Stat_t) (uint32, error) { return 0, nil },
			checkACL:   func(string, int) error { return nil },
		},
	}
}
