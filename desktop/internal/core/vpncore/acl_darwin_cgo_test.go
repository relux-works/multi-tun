//go:build darwin && cgo

package vpncore

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCheckWriteACLAcceptsFileWithoutExtendedACL(t *testing.T) {
	// This proves the Darwin cgo ACL reader accepts an ordinary secure file instead of failing every startup.
	path := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(path, []byte("plain\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fd := openACLTestPath(t, path, false)
	if err := checkWriteACL(path, fd); err != nil {
		t.Fatalf("checkWriteACL() error = %v", err)
	}
}

func TestCheckWriteACLRejectsEveryMutatingExtendedACLPermission(t *testing.T) {
	// These controls prove every Darwin ACL permission that can mutate content, children, metadata, security, or ownership is refused.
	for _, test := range []struct {
		permission string
		directory  bool
	}{
		{"write", false},
		{"add_file", true},
		{"append", false},
		{"add_subdirectory", true},
		{"delete", false},
		{"delete_child", true},
		{"writeattr", false},
		{"writeextattr", false},
		{"writesecurity", false},
		{"chown", false},
	} {
		t.Run(test.permission, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "acl-target")
			if test.directory {
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, []byte("plain\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if output, err := exec.Command("chmod", "+a", "everyone allow "+test.permission, path).CombinedOutput(); err != nil {
				t.Fatalf("plant %s ACL: %v (%s)", test.permission, err, output)
			}
			fd := openACLTestPath(t, path, test.directory)
			if err := checkWriteACL(path, fd); err == nil {
				t.Fatalf("checkWriteACL() error = nil for %s ACL", test.permission)
			}
		})
	}
}

func TestCheckWriteACLAcceptsReadOnlyExtendedACL(t *testing.T) {
	// This positive control proves a real read-only Darwin ACL is not mistaken for mutation authority.
	path := filepath.Join(t.TempDir(), "acl-read")
	if err := os.WriteFile(path, []byte("plain\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("chmod", "+a", "everyone allow read,readattr,readextattr,readsecurity", path).CombinedOutput(); err != nil {
		t.Fatalf("plant read-only ACL: %v (%s)", err, output)
	}
	fd := openACLTestPath(t, path, false)
	if err := checkWriteACL(path, fd); err != nil {
		t.Fatalf("checkWriteACL() error = %v for read-only ACL", err)
	}
}

func openACLTestPath(t *testing.T, path string, directory bool) int {
	t.Helper()
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	if directory {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Open(path, flags, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}

// aclEntryLine matches an ACL entry printed by `ls -le` (" 0: group:everyone allow read"),
// not the clock time on the file line, which can also contain "0:".
var aclEntryLine = regexp.MustCompile(`(?m)^ *[0-9]+: `)

func TestRuntimeQuarantineClearACLRemovesExtendedEntries(t *testing.T) {
	// Descriptor ACL clearing removes planted read, write and deny ACLs from temporary directories; plain directories also succeed.
	for _, rule := range []string{"", "everyone allow read", "everyone allow add_file", "everyone deny read"} {
		t.Run(rule, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "quarantine")
			if err := os.Mkdir(path, 0o711); err != nil {
				t.Fatal(err)
			}
			fd := openACLTestPath(t, path, true)
			t.Cleanup(func() { _ = clearRuntimeQuarantineACL(fd) })
			if rule != "" {
				if output, err := exec.Command("chmod", "+a", rule, path).CombinedOutput(); err != nil {
					t.Fatalf("plant ACL: %v (%s)", err, output)
				}
				output, err := exec.Command("ls", "-lde", path).CombinedOutput()
				if err != nil || !aclEntryLine.Match(output) {
					t.Fatalf("ACL control not planted: %v (%s)", err, output)
				}
			}
			if err := clearRuntimeQuarantineACL(fd); err != nil {
				t.Fatal(err)
			}
			output, err := exec.Command("ls", "-lde", path).CombinedOutput()
			if err != nil || aclEntryLine.Match(output) {
				t.Fatalf("ACL not empty: %v (%s)", err, output)
			}
			var stat unix.Stat_t
			if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&0o777 != 0o711 {
				t.Fatalf("mode changed: %#o %v", stat.Mode, err)
			}
		})
	}
	if err := clearRuntimeQuarantineACL(-1); err == nil {
		t.Fatal("invalid descriptor accepted")
	}
}
