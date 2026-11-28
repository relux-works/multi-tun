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
	"strings"
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
}

func DefaultKeychainStore() *KeychainStore {
	return &KeychainStore{
		Runner: runCommand, SecurityBinary: "/usr/bin/security", ClipboardBinary: "/usr/bin/pbpaste",
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
	stderr := strings.ToLower(string(r.Stderr))
	return r.ExitCode == 44 || strings.Contains(stderr, "could not be found in the keychain") ||
		strings.Contains(stderr, "seckeychainsearchcopynext")
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
			return result, NewRefusal(CodeKeyMissing, "Amnezia key is missing from Keychain")
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
	if _, err := s.DeleteKey(ctx, options.Service, options.Account); err != nil {
		return err
	}
	r := s.command(ctx, false, []string{"-i"}, []byte(line))
	if commandFailed(r) {
		return accessDenied(r)
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
	if ctx.Err() == nil && itemNotFound(r) {
		return false, nil
	}
	if commandFailed(r) {
		return false, accessDenied(r)
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
