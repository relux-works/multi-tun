package amnezia

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unicode"

	"golang.org/x/term"
)

type KeychainSpec struct {
	Service, FallbackService, Account string
}

func (s KeychainSpec) Normalize() KeychainSpec {
	if s.Service == "" {
		s.Service = DefaultKeychainService
	}
	if s.Account == "" {
		s.Account = DefaultKeychainAccount
	}
	if s.FallbackService == "" {
		s.FallbackService = FallbackKeychainService
	}
	if s.FallbackService == "-" || s.FallbackService == s.Service {
		// The primary service is a stable disabled sentinel, including when a
		// normalized spec is passed to another entry point and normalized again.
		s.FallbackService = s.Service
	}
	return s
}

type CommandResult struct {
	Stdout, Stderr []byte
	ExitCode       int
	Err            error
}

type CommandRunner func(ctx context.Context, name string, args []string, stdin []byte) CommandResult

// KeychainStore may be shared by callers provided its configuration is not
// mutated and the injected Runner supports concurrent calls.
type KeychainStore struct {
	Runner          CommandRunner
	SecurityBinary  string
	ClipboardBinary string
	// FallbackKeyFile, when non-empty, is a strict 0600 file inside a 0700
	// directory used when macOS Keychain refuses headless access (exit 36:
	// "User interaction is not allowed").
	FallbackKeyFile string
}

// DefaultFallbackKeyFile returns ~/.config/vless-tun/keys/amnezia.key.
func DefaultFallbackKeyFile() string {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return ""
	}
	return filepath.Join(home, ".config", "vless-tun", "keys", "amnezia.key")
}

func DefaultKeychainStore() *KeychainStore {
	return &KeychainStore{
		Runner:          runCommand,
		SecurityBinary:  "/usr/bin/security",
		ClipboardBinary: "/usr/bin/pbpaste",
		FallbackKeyFile: DefaultFallbackKeyFile(),
	}
}

func runCommand(ctx context.Context, name string, args []string, stdin []byte) CommandResult {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	result := CommandResult{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), Err: err}
	if err != nil {
		result.ExitCode = -1
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			result.ExitCode = exit.ExitCode()
		}
	}
	return result
}

func (s *KeychainStore) command(ctx context.Context, clipboard bool, args []string, stdin []byte) CommandResult {
	if err := ctx.Err(); err != nil {
		return CommandResult{ExitCode: -1, Err: err}
	}
	runner := s.Runner
	if runner == nil {
		runner = runCommand
	}
	name := s.SecurityBinary
	if name == "" {
		name = "/usr/bin/security"
	}
	if clipboard {
		name = s.ClipboardBinary
		if name == "" {
			name = "/usr/bin/pbpaste"
		}
	}
	result := runner(ctx, name, args, stdin)
	if err := ctx.Err(); err != nil {
		result.Err, result.ExitCode = err, -1
	}
	return result
}

func itemNotFound(r CommandResult) bool {
	if interactionNotAllowed(r) {
		return false
	}
	stderr := strings.ToLower(string(r.Stderr))
	return r.ExitCode == 44 || strings.Contains(stderr, "could not be found in the keychain") ||
		strings.Contains(stderr, "seckeychainsearchcopynext")
}

func interactionNotAllowed(r CommandResult) bool {
	stderr := strings.ToLower(string(r.Stderr))
	return r.ExitCode == 36 ||
		strings.Contains(stderr, "user interaction is not allowed") ||
		strings.Contains(stderr, "errsecinteractionnotallowed") ||
		strings.Contains(stderr, "-25308")
}

// Interactive security can report failures solely through stderr with exit 0.
// Admit only a clean exit without diagnostics; never echo diagnostics to users.
func commandFailed(r CommandResult) bool {
	return r.Err != nil || r.ExitCode != 0 || len(bytes.TrimSpace(r.Stderr)) != 0
}

func accessDenied(r CommandResult) error {
	cause := r.Err
	if cause == nil {
		cause = fmt.Errorf("security command failed (exit %d)", r.ExitCode)
	}
	return WrapRefusal(CodeKeychainAccessDenied, "Keychain access failed", cause)
}

func writeFallbackKeyFile(path, secret string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return WrapRefusal(CodeKeychainAccessDenied, "fallback key directory unavailable", err)
	}
	dirInfo, err := os.Lstat(dir)
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 {
		return NewRefusal(CodeKeychainAccessDenied, "fallback key directory must be a private directory")
	}
	if dirInfo.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return WrapRefusal(CodeKeychainAccessDenied, "fallback key directory permissions must be 0700", err)
		}
		dirInfo, err = os.Lstat(dir)
		if err != nil || !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 || dirInfo.Mode().Perm()&0o077 != 0 {
			return NewRefusal(CodeKeychainAccessDenied, "fallback key directory permissions must be 0700")
		}
	}
	if existing, err := os.Lstat(path); err == nil {
		if !existing.Mode().IsRegular() {
			return NewRefusal(CodeKeychainAccessDenied, "fallback key file must be a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return WrapRefusal(CodeKeychainAccessDenied, "cannot inspect fallback key file", err)
	}
	f, err := os.CreateTemp(dir, ".amnezia-key-*")
	if err != nil {
		return WrapRefusal(CodeKeychainAccessDenied, "cannot create fallback key file", err)
	}
	tmpPath := f.Name()
	cleanup := func() {
		_ = f.Close()
		_ = os.Remove(tmpPath)
	}
	if err := f.Chmod(0o600); err != nil {
		cleanup()
		return WrapRefusal(CodeKeychainAccessDenied, "cannot protect fallback key file", err)
	}
	if _, err := io.WriteString(f, secret+"\n"); err != nil {
		cleanup()
		return WrapRefusal(CodeKeychainAccessDenied, "cannot write fallback key file", err)
	}
	if err := f.Sync(); err != nil {
		cleanup()
		return WrapRefusal(CodeKeychainAccessDenied, "cannot sync fallback key file", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return WrapRefusal(CodeKeychainAccessDenied, "cannot close fallback key file", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return WrapRefusal(CodeKeychainAccessDenied, "cannot install fallback key file", err)
	}
	finalInfo, err := os.Lstat(path)
	if err != nil || !finalInfo.Mode().IsRegular() || finalInfo.Mode().Perm() != 0o600 {
		return NewRefusal(CodeKeychainAccessDenied, "fallback key file permissions must be 0600")
	}
	return nil
}

func readFallbackKeyFile(path string) (string, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, WrapRefusal(CodeKeychainAccessDenied, "cannot inspect fallback key file", err)
	}
	if !info.Mode().IsRegular() {
		return "", true, NewRefusal(CodeKeychainAccessDenied, "fallback key file must be a regular file")
	}
	if info.Mode().Perm() != 0o600 {
		return "", true, NewRefusal(CodeKeychainAccessDenied, "fallback key file permissions must be 0600")
	}
	dirInfo, err := os.Lstat(filepath.Dir(path))
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 || dirInfo.Mode().Perm()&0o077 != 0 {
		return "", true, NewRefusal(CodeKeychainAccessDenied, "fallback key directory permissions must be 0700")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		return "", true, WrapRefusal(CodeKeychainAccessDenied, "cannot open fallback key file", err)
	}
	defer f.Close()
	fdInfo, err := f.Stat()
	if err != nil || !fdInfo.Mode().IsRegular() || fdInfo.Mode().Perm() != 0o600 {
		return "", true, NewRefusal(CodeKeychainAccessDenied, "fallback key file permissions must be 0600")
	}
	const limit = 4 << 20
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return "", true, WrapRefusal(CodeKeychainAccessDenied, "cannot read fallback key file", err)
	}
	if len(data) > limit {
		return "", true, NewRefusal(CodeKeyInvalid, "fallback key file exceeds 4 MiB")
	}
	return strings.TrimSpace(string(data)), true, nil
}

func removeFallbackKeyFile(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, WrapRefusal(CodeKeychainAccessDenied, "cannot inspect fallback key file", err)
	}
	if !info.Mode().IsRegular() {
		return false, NewRefusal(CodeKeychainAccessDenied, "fallback key file must be a regular file")
	}
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, WrapRefusal(CodeKeychainAccessDenied, "cannot delete fallback key file", err)
	}
	return true, nil
}

type KeychainResult struct {
	Secret, Service, Account string
	UsedFallback             bool
}

func LookupKey(ctx context.Context, spec KeychainSpec) (KeychainResult, error) {
	return DefaultKeychainStore().LookupKey(ctx, spec)
}

func (s *KeychainStore) LookupKey(ctx context.Context, spec KeychainSpec) (KeychainResult, error) {
	result, err := s.lookupKey(ctx, spec)
	if err != nil {
		result.Secret = ""
	}
	return result, err
}

func (s *KeychainStore) lookupKey(ctx context.Context, spec KeychainSpec) (KeychainResult, error) {
	spec = spec.Normalize()
	result := KeychainResult{Service: spec.Service, Account: spec.Account}
	for {
		r := s.command(ctx, false, []string{"find-generic-password", "-s", result.Service, "-a", result.Account, "-w"}, nil)
		// Cancellation always wins over stale not-found diagnostics.
		if ctx.Err() != nil {
			return result, accessDenied(r)
		}
		if itemNotFound(r) {
			if !result.UsedFallback && spec.FallbackService != "" && spec.FallbackService != spec.Service {
				result.Service, result.UsedFallback = spec.FallbackService, true
				continue
			}
			if s.FallbackKeyFile != "" {
				secret, found, err := readFallbackKeyFile(s.FallbackKeyFile)
				if err != nil {
					return result, err
				}
				if found {
					result.Secret = secret
					result.UsedFallback = true
					return result, validateSecret(result.Secret, false)
				}
			}
			return result, NewRefusal(CodeKeyMissing, "Amnezia key is missing from Keychain")
		}
		if interactionNotAllowed(r) && s.FallbackKeyFile != "" {
			secret, found, err := readFallbackKeyFile(s.FallbackKeyFile)
			if err != nil {
				return result, err
			}
			if found {
				result.Secret = secret
				result.UsedFallback = true
				return result, validateSecret(result.Secret, false)
			}
		}
		if commandFailed(r) {
			return result, accessDenied(r)
		}
		result.Secret = strings.TrimSpace(string(r.Stdout))
		return result, validateSecret(result.Secret, false)
	}
}

type StoreOptions struct {
	Service, Account, Secret, Label string
	AllowPlaceholder                bool
}

func validateSecret(secret string, allowPlaceholder bool) error {
	if secret == "" {
		return NewRefusal(CodeKeyEmpty, "Amnezia key is empty")
	}
	if secret == PlaceholderKey && !allowPlaceholder {
		return NewRefusal(CodeKeyPlaceholder, "Replace the Amnezia placeholder key")
	}
	return nil
}

func StoreKey(ctx context.Context, options StoreOptions) error {
	return DefaultKeychainStore().StoreKey(ctx, options)
}

func (s *KeychainStore) StoreKey(ctx context.Context, options StoreOptions) error {
	if options.Service == "" {
		options.Service = DefaultKeychainService
	}
	if options.Account == "" {
		options.Account = DefaultKeychainAccount
	}
	if options.Label == "" {
		options.Label = options.Service + " (" + options.Account + ")"
	}
	options.Secret = strings.TrimSpace(options.Secret)
	if err := validateSecret(options.Secret, options.AllowPlaceholder); err != nil {
		return err
	}
	for _, value := range []string{options.Service, options.Account, options.Label} {
		if strings.ContainsFunc(value, func(r rune) bool { return unicode.IsControl(r) || r == '"' }) {
			return NewRefusal(CodeKeyInvalid, "Keychain metadata contains a control character or double quote")
		}
	}
	// Escape literal backslashes so metadata cannot escape its closing quote.
	quote := func(value string) string { return `"` + strings.ReplaceAll(value, `\`, `\\`) + `"` }
	line := "add-generic-password -a " + quote(options.Account) + " -s " + quote(options.Service) +
		" -l " + quote(options.Label) + " -T /usr/bin/security -X " + hex.EncodeToString([]byte(options.Secret)) + "\n"
	// Apple's SecurityTool/macOS/security.c reads interactive commands into a
	// 4096-byte buffer. Include the newline and leave room for its NUL byte;
	// refuse before deletion rather than risk storing a truncated secret.
	if len(line) > 4095 {
		return NewRefusal(CodeKeyInvalid, "Keychain input exceeds the security interactive command limit")
	}
	delRes := s.command(ctx, false, []string{"delete-generic-password", "-s", options.Service, "-a", options.Account}, nil)
	if ctx.Err() != nil {
		return accessDenied(delRes)
	}
	if interactionNotAllowed(delRes) && s.FallbackKeyFile != "" {
		return writeFallbackKeyFile(s.FallbackKeyFile, options.Secret)
	}
	if !itemNotFound(delRes) && commandFailed(delRes) {
		return accessDenied(delRes)
	}
	r := s.command(ctx, false, []string{"-i"}, []byte(line))
	if ctx.Err() != nil {
		return accessDenied(r)
	}
	if interactionNotAllowed(r) && s.FallbackKeyFile != "" {
		return writeFallbackKeyFile(s.FallbackKeyFile, options.Secret)
	}
	if commandFailed(r) {
		return accessDenied(r)
	}
	if s.FallbackKeyFile != "" {
		_, _ = removeFallbackKeyFile(s.FallbackKeyFile)
	}
	return nil
}

func DeleteKey(ctx context.Context, service, account string) (bool, error) {
	return DefaultKeychainStore().DeleteKey(ctx, service, account)
}

func (s *KeychainStore) DeleteKey(ctx context.Context, service, account string) (bool, error) {
	if service == "" {
		service = DefaultKeychainService
	}
	if account == "" {
		account = DefaultKeychainAccount
	}
	r := s.command(ctx, false, []string{"delete-generic-password", "-s", service, "-a", account}, nil)
	if ctx.Err() != nil {
		return false, accessDenied(r)
	}
	if interactionNotAllowed(r) && s.FallbackKeyFile != "" {
		return removeFallbackKeyFile(s.FallbackKeyFile)
	}
	if itemNotFound(r) {
		if s.FallbackKeyFile != "" {
			return removeFallbackKeyFile(s.FallbackKeyFile)
		}
		return false, nil
	}
	if commandFailed(r) {
		return false, accessDenied(r)
	}
	if s.FallbackKeyFile != "" {
		_, _ = removeFallbackKeyFile(s.FallbackKeyFile)
	}
	return true, nil
}

// KeyStatus deliberately has no field capable of carrying the key itself.
type KeyStatus struct {
	State, Service, Account, RefusalCode, Message string
	UsedFallback                                  bool
	ByteLength                                    int
}

func CheckKey(ctx context.Context, spec KeychainSpec) KeyStatus {
	return DefaultKeychainStore().CheckKey(ctx, spec)
}

func (s *KeychainStore) CheckKey(ctx context.Context, spec KeychainSpec) KeyStatus {
	result, err := s.lookupKey(ctx, spec)
	status := KeyStatus{State: "present", Service: result.Service, Account: result.Account,
		UsedFallback: result.UsedFallback, ByteLength: len(result.Secret), Message: "Amnezia key is present"}
	if err != nil {
		status.RefusalCode, status.Message = RefusalCode(err), err.Error()
		switch status.RefusalCode {
		case CodeKeyPlaceholder:
			status.State = "placeholder"
		case CodeKeyMissing:
			status.State = "missing"
		case CodeKeyEmpty:
			status.State = "empty"
		default:
			status.State = "access_denied"
		}
	}
	return status
}

type ReadSecretOptions struct {
	FromStdin, FromClipboard bool
	Stdin                    io.Reader
	IsTTY                    func() bool
	ReadPassword             func() ([]byte, error)
	PromptWriter             io.Writer
	ClipboardReader          func(ctx context.Context) ([]byte, error)
}

func ReadSecretInput(ctx context.Context, options ReadSecretOptions) (string, error) {
	return DefaultKeychainStore().ReadSecretInput(ctx, options)
}

// ReadSecretInput uses the store's runner for clipboard input unless the caller
// supplies ClipboardReader. Inject all terminal hooks for offline callers.
func (s *KeychainStore) ReadSecretInput(ctx context.Context, options ReadSecretOptions) (string, error) {
	if options.FromStdin && options.FromClipboard {
		return "", NewRefusal(CodeKeyInvalid, "Choose either --stdin or --clipboard")
	}
	if err := ctx.Err(); err != nil {
		return "", WrapRefusal(CodeKeyInvalid, "Secret input was canceled", err)
	}
	var data []byte
	var err error
	switch {
	case options.FromStdin:
		reader := options.Stdin
		if reader == nil {
			reader = os.Stdin
		}
		const limit = 4 << 20
		data, err = io.ReadAll(io.LimitReader(reader, limit+1))
		if err == nil && len(data) > limit {
			return "", NewRefusal(CodeKeyInvalid, "Secret input exceeds 4 MiB")
		}
	case options.FromClipboard:
		if options.ClipboardReader != nil {
			data, err = options.ClipboardReader(ctx)
		} else {
			r := s.command(ctx, true, nil, nil)
			data = r.Stdout
			if commandFailed(r) {
				err = r.Err
				if err == nil {
					err = errors.New("clipboard command failed")
				}
			}
		}
	default:
		isTTY := options.IsTTY
		if isTTY == nil {
			isTTY = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }
		}
		if !isTTY() {
			return "", NewRefusal(CodeKeyInvalid, "Interactive input requires a TTY; pass --stdin or --clipboard")
		}
		writer := options.PromptWriter
		if writer == nil {
			writer = os.Stderr
		}
		if _, err = fmt.Fprint(writer, "Amnezia key: "); err != nil {
			break
		}
		readPassword := options.ReadPassword
		if readPassword == nil {
			readPassword = func() ([]byte, error) { return term.ReadPassword(int(os.Stdin.Fd())) }
		}
		data, err = readPassword()
		_, newlineErr := fmt.Fprintln(writer)
		if err == nil {
			err = newlineErr
		}
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		return "", WrapRefusal(CodeKeyInvalid, "Could not read secret input", err)
	}
	secret := strings.TrimSpace(string(data))
	if secret == "" {
		return "", NewRefusal(CodeKeyEmpty, "Amnezia key is empty")
	}
	return secret, nil
}
