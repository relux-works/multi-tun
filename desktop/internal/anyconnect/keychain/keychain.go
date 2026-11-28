package keychain

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unicode"
)

const serviceName = "multi-tun"

// These seams keep offline callers away from the login Keychain and real home.
var securityExecFunc = func(args ...string) ([]byte, []byte, error) {
	cmd := exec.Command("/usr/bin/security", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}
var fallbackKeysDirFunc = func() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "openconnect-tun", "keys"), nil
}

type SetOptions struct{ Label, Kind, Comment string }

func securityExit(err error, code int) bool {
	var exit interface{ ExitCode() int }
	return errors.As(err, &exit) && exit.ExitCode() == code
}
func interactionNotAllowed(stderr []byte, err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(string(stderr))
	return securityExit(err, 36) || strings.Contains(message, "user interaction is not allowed") || strings.Contains(message, "errsecinteractionnotallowed") || strings.Contains(message, "-25308")
}

func Set(account, value string) error { return SetWithOptions(account, value, SetOptions{}) }

func SetWithOptions(account, value string, options SetOptions) error {
	if _, _, err := fallbackKeyPath(account); err != nil {
		return err
	}
	args := []string{"add-generic-password", "-U", "-a", account, "-s", serviceName}
	for _, option := range []struct{ flag, value string }{{"-l", options.Label}, {"-D", options.Kind}, {"-j", options.Comment}} {
		if value := strings.TrimSpace(option.value); value != "" {
			args = append(args, option.flag, value)
		}
	}
	args = append(args, "-w", value)
	_, stderr, err := securityExecFunc(args...)
	if interactionNotAllowed(stderr, err) {
		return writeFallbackKey(account, value)
	}
	if err != nil {
		return errors.New("keychain set failed")
	}
	return removeFallbackKey(account)
}

func Get(account string) (string, error) {
	if _, _, err := fallbackKeyPath(account); err != nil {
		return "", err
	}
	out, stderr, err := securityExecFunc("find-generic-password", "-a", account, "-s", serviceName, "-w")
	if err == nil {
		return strings.TrimSpace(string(out)), nil
	}
	if interactionNotAllowed(stderr, err) || securityExit(err, 44) {
		return readFallbackKey(account)
	}
	return "", errors.New("keychain get failed")
}

func Delete(account string) error {
	if _, _, err := fallbackKeyPath(account); err != nil {
		return err
	}
	_, stderr, err := securityExecFunc("delete-generic-password", "-a", account, "-s", serviceName)
	fallbackErr := removeFallbackKey(account)
	if err != nil && !interactionNotAllowed(stderr, err) && !securityExit(err, 44) {
		return errors.Join(errors.New("keychain delete failed"), fallbackErr)
	}
	return fallbackErr
}

func Exists(account string) bool { _, err := Get(account); return err == nil }

func fallbackKeyPath(account string) (string, string, error) {
	if account == "" || strings.Contains(account, "..") || strings.ContainsAny(account, `\`) || strings.IndexFunc(account, unicode.IsControl) >= 0 {
		return "", "", errors.New("invalid keychain account")
	}
	// Encode literal underscores too: a/b and a__b must never share a secret.
	var filename strings.Builder
	for _, char := range []byte(account) {
		switch {
		case char == '/':
			filename.WriteString("__")
		case char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-' || char == '.':
			filename.WriteByte(char)
		default:
			fmt.Fprintf(&filename, "%%%02x", char)
		}
	}
	name := filename.String() + ".key"
	if len(name) > 255 {
		return "", "", errors.New("fallback filename is too long")
	}
	if strings.ContainsAny(name, `/\`) {
		return "", "", errors.New("invalid fallback filename")
	}
	dir, err := fallbackKeysDirFunc()
	if err != nil || dir == "" || !filepath.IsAbs(dir) {
		return "", "", errors.New("fallback keys directory unavailable")
	}
	dir = filepath.Clean(dir)
	path := filepath.Join(dir, name)
	rel, err := filepath.Rel(dir, path)
	if err != nil || rel == "." || !filepath.IsLocal(rel) || filepath.Dir(rel) != "." {
		return "", "", errors.New("invalid fallback key path")
	}
	return dir, path, nil
}

func checkFallbackDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("fallback keys directory must be a non-symlink 0700 directory")
	}
	return nil
}

// Pin operations to a verified directory descriptor so renaming the directory
// cannot redirect a later file open, removal, or atomic replacement.
func openFallbackRoot(dir string) (*os.Root, error) {
	if err := checkFallbackDir(dir); err != nil {
		return nil, err
	}
	before, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	after, err := root.Stat(".")
	if err != nil || !os.SameFile(before, after) || !after.IsDir() || after.Mode().Perm() != 0o700 {
		root.Close()
		return nil, errors.New("fallback keys directory changed")
	}
	return root, nil
}

func readFallbackKey(account string) (string, error) {
	dir, path, err := fallbackKeyPath(account)
	if err != nil {
		return "", err
	}
	root, err := openFallbackRoot(dir)
	if err != nil {
		return "", errors.New("fallback keys directory unavailable or insecure")
	}
	defer root.Close()
	name := filepath.Base(path)
	before, err := root.Lstat(name)
	if err != nil {
		return "", errors.New("fallback key unavailable")
	}
	if !before.Mode().IsRegular() || before.Mode().Perm() != 0o600 {
		return "", errors.New("fallback key must be a regular 0600 file")
	}
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", errors.New("fallback key could not be opened securely")
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || after.Mode().Perm() != 0o600 || !os.SameFile(before, after) {
		return "", errors.New("fallback key changed or has insecure permissions")
	}
	value, err := io.ReadAll(file)
	if err != nil {
		return "", errors.New("fallback key could not be read")
	}
	directory, err := root.Stat(".")
	if err != nil || directory.Mode().Perm() != 0o700 {
		return "", errors.New("fallback keys directory changed")
	}
	return strings.TrimSpace(string(value)), nil
}

func writeFallbackKey(account, value string) error {
	dir, path, err := fallbackKeyPath(account)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return errors.New("create fallback keys directory failed")
	}
	root, err := openFallbackRoot(dir)
	if err != nil {
		return errors.New("fallback keys directory unavailable or insecure")
	}
	defer root.Close()
	name := filepath.Base(path)
	if info, err := root.Lstat(name); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			return errors.New("refusing insecure existing fallback key")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("inspect fallback key failed")
	}
	// CreateTemp chooses a unique name. Reopen through the pinned directory and
	// compare identities before writing any secret to the temporary file.
	temp, err := os.CreateTemp(dir, ".key-*")
	if err != nil {
		return errors.New("create fallback key failed")
	}
	tempName := filepath.Base(temp.Name())
	defer root.Remove(tempName)
	before, statErr := temp.Stat()
	file, openErr := root.OpenFile(tempName, os.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	closeErr := temp.Close()
	if statErr != nil || openErr != nil || closeErr != nil {
		if file != nil {
			file.Close()
		}
		return errors.New("open temporary fallback key failed")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() {
		file.Close()
		return errors.New("temporary fallback key changed")
	}
	err = file.Chmod(0o600)
	if err == nil {
		_, err = io.WriteString(file, value)
	}
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err == nil {
		directory, statErr := root.Stat(".")
		if statErr != nil || directory.Mode().Perm() != 0o700 {
			err = errors.New("fallback keys directory changed")
		}
	}
	if err == nil {
		err = root.Rename(tempName, name)
	}
	if err != nil {
		return errors.New("write fallback key failed")
	}
	return nil
}

func removeFallbackKey(account string) error {
	dir, path, err := fallbackKeyPath(account)
	if err != nil {
		return err
	}
	root, err := openFallbackRoot(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.New("fallback keys directory unavailable or insecure")
	}
	defer root.Close()
	if err := root.Remove(filepath.Base(path)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("remove fallback key failed")
	}
	return nil
}

func TunnelKey(tunnelName, key string) string {
	return tunnelName + "/" + key
}

func GetTunnelCred(tunnelName, key string) (string, error) {
	return Get(TunnelKey(tunnelName, key))
}

var AnyConnectKeys = []string{"username", "password", "totp_secret"}
