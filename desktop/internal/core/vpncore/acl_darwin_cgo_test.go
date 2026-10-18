//go:build darwin && cgo

package vpncore

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCheckWriteACLAcceptsFileWithoutExtendedACL(t *testing.T) {
	// This proves the Darwin cgo ACL reader accepts an ordinary secure file instead of failing every startup.
	path := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(path, []byte("plain\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkWriteACL(path); err != nil {
		t.Fatalf("checkWriteACL() error = %v", err)
	}
}

func TestCheckWriteACLRejectsWriteCapableExtendedACL(t *testing.T) {
	// This control plants a real macOS write ACL and proves the cgo checker detects the intended violation.
	path := filepath.Join(t.TempDir(), "acl-write")
	if err := os.WriteFile(path, []byte("plain\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("chmod", "+a", "everyone allow write", path).CombinedOutput(); err != nil {
		t.Fatalf("plant write ACL: %v (%s)", err, output)
	}
	if err := checkWriteACL(path); err == nil {
		t.Fatal("checkWriteACL() error = nil for write ACL")
	}
}
