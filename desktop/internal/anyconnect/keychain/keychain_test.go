package keychain

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

type testExit int

func (e testExit) Error() string { return "security failed" }
func (e testExit) ExitCode() int { return int(e) }

func offlineKeychain(t *testing.T) string {
	t.Helper()
	previousExec, previousDir := securityExecFunc, fallbackKeysDirFunc
	dir := filepath.Join(t.TempDir(), "keys")
	fallbackKeysDirFunc = func() (string, error) { return dir, nil }
	securityExecFunc = func(...string) ([]byte, []byte, error) {
		return nil, []byte("SecKeychainSearchCopyNext: User interaction is not allowed."), testExit(36)
	}
	t.Cleanup(func() { securityExecFunc, fallbackKeysDirFunc = previousExec, previousDir })
	return dir
}

func TestHeadlessFallbackRoundTripAndDelete(t *testing.T) {
	dir := offlineKeychain(t)
	if err := SetWithOptions("tunnel/password", "secret-value", SetOptions{Label: "Offline", Kind: "password", Comment: "test"}); err != nil {
		t.Fatal(err)
	}
	for path, mode := range map[string]os.FileMode{dir: 0o700, filepath.Join(dir, "tunnel__password.key"): 0o600} {
		info, err := os.Lstat(path)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("path mode mismatch: %v", err)
		}
	}
	if got, err := Get("tunnel/password"); err != nil || got != "secret-value" {
		t.Fatalf("fallback round trip failed: %v", err)
	}
	if err := Delete("tunnel/password"); err != nil {
		t.Fatal(err)
	}
	if _, err := Get("tunnel/password"); err == nil {
		t.Fatal("deleted fallback was returned")
	}
}

func TestHeadlessClassificationAndItemNotFound(t *testing.T) {
	for _, test := range []struct {
		name, stderr string
		code         int
		allowed      bool
	}{
		{"exit36", "SecKeychainSearchCopyNext: User interaction is not allowed.", 36, true},
		{"exit36-empty", "", 36, true}, {"interaction", "USER INTERACTION IS NOT ALLOWED", 1, true},
		{"symbol", "errSecInteractionNotAllowed", 1, true}, {"number", "error -25308", 1, true},
		{"missing", "item not found", 44, true}, {"denied", "secret-value", 1, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			offlineKeychain(t)
			if err := Set("account", "secret-value"); err != nil {
				t.Fatal(err)
			}
			securityExecFunc = func(...string) ([]byte, []byte, error) { return nil, []byte(test.stderr), testExit(test.code) }
			value, err := Get("account")
			if test.allowed {
				if err != nil || value != "secret-value" {
					t.Fatalf("valid fallback refused: %v", err)
				}
			} else if err == nil || value != "" || strings.Contains(err.Error(), "secret-value") {
				t.Fatal("unexpected fallback or secret disclosure")
			}
		})
	}
}

func TestKeychainSuccessReplacesFallbackAndPreservesOptions(t *testing.T) {
	dir := offlineKeychain(t)
	if err := Set("account", "old"); err != nil {
		t.Fatal(err)
	}
	var captured []string
	securityExecFunc = func(args ...string) ([]byte, []byte, error) {
		captured = append([]string(nil), args...)
		return []byte("primary\n"), nil, nil
	}
	if err := SetWithOptions("account", "new", SetOptions{Label: "Label", Kind: "Kind", Comment: "Comment"}); err != nil {
		t.Fatal(err)
	}
	args := strings.Join(captured, "|")
	for _, want := range []string{"add-generic-password|-U", "-l|Label", "-D|Kind", "-j|Comment", "-w|new"} {
		if !strings.Contains(args, want) {
			t.Fatalf("missing option %s", want)
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, "account.key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("stale fallback survived")
	}
	if got, err := Get("account"); err != nil || got != "primary" {
		t.Fatalf("primary lookup failed: %v", err)
	}
}

func TestFallbackRefusesUnsafeFilesAndDirectories(t *testing.T) {
	for _, kind := range []string{"symlink-file", "file-0644", "file-0400", "directory-file", "fifo", "symlink-dir", "dir-0755"} {
		t.Run(kind, func(t *testing.T) {
			dir := offlineKeychain(t)
			if err := Set("account", "secret-value"); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "account.key")
			switch kind {
			case "symlink-file":
				target := filepath.Join(t.TempDir(), "target")
				if err := os.Rename(path, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "file-0644":
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			case "file-0400":
				if err := os.Chmod(path, 0o400); err != nil {
					t.Fatal(err)
				}
			case "directory-file":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0o600); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := syscall.Mkfifo(path, 0o600); err != nil {
					t.Fatal(err)
				}
			case "symlink-dir":
				target := filepath.Join(t.TempDir(), "keys")
				if err := os.Rename(dir, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, dir); err != nil {
					t.Fatal(err)
				}
			case "dir-0755":
				if err := os.Chmod(dir, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if got, err := Get("account"); err == nil || got != "" || strings.Contains(err.Error(), "secret-value") {
				t.Fatal("unsafe fallback read or secret disclosure")
			}
			if err := Set("account", "replacement"); err == nil {
				t.Fatal("unsafe fallback write accepted")
			}
		})
	}
}

func TestInvalidAccountsNeverReachSecurity(t *testing.T) {
	offlineKeychain(t)
	securityExecFunc = func(...string) ([]byte, []byte, error) {
		t.Fatal("invalid account reached Keychain")
		return nil, nil, nil
	}
	for _, account := range []string{"", "..", "../escape", "a/../escape", "a\\b", "a\x00b", "a\nb"} {
		if err := Set(account, "secret"); err == nil {
			t.Fatal("invalid account set")
		}
		if _, err := Get(account); err == nil {
			t.Fatal("invalid account get")
		}
		if err := Delete(account); err == nil {
			t.Fatal("invalid account delete")
		}
	}
}

func TestFallbackWriteIsAtomicAndDoesNotLeakCommandErrors(t *testing.T) {
	dir := offlineKeychain(t)
	if err := Set("account", "first"); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(filepath.Join(dir, "account.key"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := Set("account", "second"); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(filepath.Join(dir, "account.key"))
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, after) {
		t.Fatal("fallback replaced in place")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatal("temporary key left behind")
	}
	securityExecFunc = func(...string) ([]byte, []byte, error) {
		return []byte("secret"), []byte("secret"), errors.New("secret")
	}
	for _, err := range []error{Set("account", "secret"), Delete("account")} {
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("command failure disclosed secret")
		}
	}
}

func TestFallbackAccountSanitizationHasNoAlias(t *testing.T) {
	offlineKeychain(t)
	for _, account := range []string{"a/b", "a__b", "a%b", "a b", "пример/key"} {
		if err := Set(account, "value-for-"+account); err != nil {
			t.Fatal(err)
		}
	}
	for _, account := range []string{"a/b", "a__b", "a%b", "a b", "пример/key"} {
		got, err := Get(account)
		if err != nil || got != "value-for-"+account {
			t.Fatalf("account alias or invalid sanitization: %v", err)
		}
	}
}
