package amnezia

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// Every command in these tests is intercepted here or by an explicit fake.
// Unexpected commands fail rather than delegating to a real executable.
type commandCall struct {
	name  string
	args  []string
	stdin []byte
}

type scriptedRunner struct {
	mu      sync.Mutex
	results []CommandResult
	calls   []commandCall
	t       *testing.T
}

func fakeStore(t *testing.T, results ...CommandResult) (*KeychainStore, *scriptedRunner) {
	t.Helper()
	fake := &scriptedRunner{t: t, results: results}
	return &KeychainStore{Runner: fake.run}, fake
}

func (f *scriptedRunner) run(_ context.Context, name string, args []string, stdin []byte) CommandResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, commandCall{name, append([]string(nil), args...), bytes.Clone(stdin)})
	if len(f.results) == 0 {
		f.t.Error("unexpected command: all command results must be injected")
		return CommandResult{ExitCode: -1, Err: errors.New("unexpected command")}
	}
	r := f.results[0]
	f.results = f.results[1:]
	return r
}

func (f *scriptedRunner) assertCalls(t *testing.T, want ...commandCall) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if !reflect.DeepEqual(f.calls, want) {
		t.Errorf("command calls differ: got %#v, want %#v", f.calls, want)
	}
	if len(f.results) != 0 {
		t.Errorf("%d scripted command results were not consumed", len(f.results))
	}
}

func findCall(service, account string) commandCall {
	return commandCall{name: "/usr/bin/security", args: []string{"find-generic-password", "-s", service, "-a", account, "-w"}}
}

func deleteCall(service, account string) commandCall {
	return commandCall{name: "/usr/bin/security", args: []string{"delete-generic-password", "-s", service, "-a", account}}
}

func missingResult() CommandResult { return CommandResult{ExitCode: 44} }

func requireCode(t *testing.T, err error, code string) {
	t.Helper()
	if code == "" {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	if !IsRefusalCode(err, code) {
		t.Fatalf("got error %v, want refusal %s", err, code)
	}
	var refusal *RefusalError
	if !errors.As(err, &refusal) {
		t.Fatalf("error is not a RefusalError: %T", err)
	}
}

func TestKeychainSpecNormalize(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		in   KeychainSpec
		want KeychainSpec
	}{
		{"defaults", KeychainSpec{}, KeychainSpec{"tun-wave", "multi-tun", "amnezia/key"}},
		{"custom", KeychainSpec{"primary", "legacy", "key"}, KeychainSpec{"primary", "legacy", "key"}},
		{"dash disables", KeychainSpec{FallbackService: "-"}, KeychainSpec{"tun-wave", "tun-wave", "amnezia/key"}},
		{"same disables", KeychainSpec{FallbackService: "tun-wave"}, KeychainSpec{"tun-wave", "tun-wave", "amnezia/key"}},
		{"default fallback equals primary", KeychainSpec{Service: "multi-tun"}, KeychainSpec{"multi-tun", "multi-tun", "amnezia/key"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.in.Normalize()
			if got != tc.want || got.Normalize() != got {
				t.Fatalf("normalization got %#v, want stable %#v", got, tc.want)
			}
		})
	}
	store := DefaultKeychainStore()
	if store.Runner == nil || store.SecurityBinary != "/usr/bin/security" || store.ClipboardBinary != "/usr/bin/pbpaste" {
		t.Fatal("default store configuration is incomplete")
	}
}

func TestLookupKeyPrimaryAndFallback(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		spec    KeychainSpec
		results []CommandResult
		want    KeychainResult
		calls   []commandCall
	}{
		{"primary", KeychainSpec{}, []CommandResult{{Stdout: []byte(" \tprimary-secret\r\n")}},
			KeychainResult{"primary-secret", "tun-wave", "amnezia/key", false}, []commandCall{findCall("tun-wave", "amnezia/key")}},
		{"fallback", KeychainSpec{}, []CommandResult{missingResult(), {Stdout: []byte(" fallback-secret\n")}},
			KeychainResult{"fallback-secret", "multi-tun", "amnezia/key", true}, []commandCall{findCall("tun-wave", "amnezia/key"), findCall("multi-tun", "amnezia/key")}},
		{"custom", KeychainSpec{"current", "legacy", "account"}, []CommandResult{missingResult(), {Stdout: []byte("custom-secret")}},
			KeychainResult{"custom-secret", "legacy", "account", true}, []commandCall{findCall("current", "account"), findCall("legacy", "account")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, fake := fakeStore(t, tc.results...)
			got, err := store.LookupKey(context.Background(), tc.spec)
			requireCode(t, err, "")
			if got != tc.want {
				t.Fatalf("lookup got %#v, want %#v", got, tc.want)
			}
			fake.assertCalls(t, tc.calls...)
		})
	}
}

func TestLookupKeyNotFoundClassification(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		result CommandResult
	}{
		{"exit 44", missingResult()},
		{"phrase", CommandResult{ExitCode: 1, Stderr: []byte("The specified item COULD NOT BE FOUND IN THE KEYCHAIN.")}},
		{"API marker", CommandResult{ExitCode: 1, Stderr: []byte("security: SecKeychainSearchCopyNext: missing")}},
		{"API case", CommandResult{ExitCode: 1, Stderr: []byte("SECKEYCHAINSEARCHCOPYNEXT")}},
		{"zero exit diagnostic", CommandResult{Stderr: []byte("could not be found in the keychain")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, fake := fakeStore(t, tc.result, CommandResult{Stdout: []byte("fallback-secret")})
			got, err := store.LookupKey(context.Background(), KeychainSpec{})
			requireCode(t, err, "")
			if !got.UsedFallback || got.Secret != "fallback-secret" {
				t.Fatal("recognized not-found did not use fallback")
			}
			fake.assertCalls(t, findCall("tun-wave", "amnezia/key"), findCall("multi-tun", "amnezia/key"))
		})
	}
}

func TestLookupKeyFailsClosedWithoutFallback(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		result CommandResult
		code   string
	}{
		{"interaction", CommandResult{ExitCode: 36, Stderr: []byte("User interaction is not allowed")}, CodeKeychainAccessDenied},
		{"canceled", CommandResult{ExitCode: 128, Stderr: []byte("canceled")}, CodeKeychainAccessDenied},
		{"locked", CommandResult{ExitCode: 1, Stderr: []byte("keychain is locked")}, CodeKeychainAccessDenied},
		{"unexpected", CommandResult{ExitCode: 7}, CodeKeychainAccessDenied},
		{"launch error", CommandResult{Err: errors.New("launch-secret")}, CodeKeychainAccessDenied},
		{"cancellation error", CommandResult{Err: context.Canceled}, CodeKeychainAccessDenied},
		{"deadline error", CommandResult{Err: context.DeadlineExceeded}, CodeKeychainAccessDenied},
		{"stderr only", CommandResult{Stdout: []byte("partial-secret"), Stderr: []byte("unexpected error: partial-secret")}, CodeKeychainAccessDenied},
		{"vague missing", CommandResult{ExitCode: 1, Stderr: []byte("not found")}, CodeKeychainAccessDenied},
		{"stdout not found is secret", CommandResult{Stdout: []byte("could not be found in the keychain")}, ""},
		{"empty", CommandResult{}, CodeKeyEmpty},
		{"whitespace", CommandResult{Stdout: []byte(" \t\r\n")}, CodeKeyEmpty},
		{"placeholder", CommandResult{Stdout: []byte(" \n" + PlaceholderKey + "\t")}, CodeKeyPlaceholder},
		{"near placeholder", CommandResult{Stdout: []byte(PlaceholderKey + "x")}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, fake := fakeStore(t, tc.result)
			got, err := store.LookupKey(context.Background(), KeychainSpec{})
			requireCode(t, err, tc.code)
			if got.UsedFallback || (err != nil && got.Secret != "") {
				t.Fatal("failure fell back or exposed a secret")
			}
			if err != nil {
				for _, secret := range []string{"launch-secret", "partial-secret", PlaceholderKey} {
					if strings.Contains(err.Error(), secret) {
						t.Fatal("error exposed secret material")
					}
				}
			}
			fake.assertCalls(t, findCall("tun-wave", "amnezia/key"))
		})
	}
}

func TestLookupKeyMissingAndDisabledFallback(t *testing.T) {
	t.Parallel()
	for _, spec := range []KeychainSpec{{}, {FallbackService: "-"}, {FallbackService: "tun-wave"}, {Service: "multi-tun"}, (KeychainSpec{FallbackService: "-"}).Normalize()} {
		normalized := spec.Normalize()
		results := []CommandResult{missingResult()}
		calls := []commandCall{findCall(normalized.Service, normalized.Account)}
		fallback := normalized.FallbackService != "" && normalized.FallbackService != normalized.Service
		if fallback {
			results = append(results, missingResult())
			calls = append(calls, findCall(normalized.FallbackService, normalized.Account))
		}
		store, fake := fakeStore(t, results...)
		got, err := store.LookupKey(context.Background(), spec)
		requireCode(t, err, CodeKeyMissing)
		if got.UsedFallback != fallback || got.Secret != "" {
			t.Fatal("missing result has incorrect metadata")
		}
		fake.assertCalls(t, calls...)
	}
}

func TestLookupKeyFallbackRefusals(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		result CommandResult
		code   string
	}{
		{CommandResult{ExitCode: 36, Stderr: []byte("User interaction is not allowed")}, CodeKeychainAccessDenied},
		{CommandResult{ExitCode: 128}, CodeKeychainAccessDenied},
		{CommandResult{}, CodeKeyEmpty},
		{CommandResult{Stdout: []byte(PlaceholderKey)}, CodeKeyPlaceholder},
	} {
		store, fake := fakeStore(t, missingResult(), tc.result)
		got, err := store.LookupKey(context.Background(), KeychainSpec{})
		requireCode(t, err, tc.code)
		if !got.UsedFallback || got.Service != "multi-tun" || got.Secret != "" {
			t.Fatal("fallback failure has incorrect metadata")
		}
		fake.assertCalls(t, findCall("tun-wave", "amnezia/key"), findCall("multi-tun", "amnezia/key"))
	}
}

func TestStoreKeyCommandContract(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		options StoreOptions
		line    string
	}{
		{"defaults", StoreOptions{Secret: " \tsecret\r\n"}, "add-generic-password -a \"amnezia/key\" -s \"tun-wave\" -l \"tun-wave (amnezia/key)\" -T /usr/bin/security -X 736563726574\n"},
		{"custom", StoreOptions{Service: "custom service", Account: "custom account", Label: "Custom label", Secret: "\x00é\n'\"\\$()"}, "add-generic-password -a \"custom account\" -s \"custom service\" -l \"Custom label\" -T /usr/bin/security -X 00c3a90a27225c242829\n"},
		{"metadata literals", StoreOptions{Service: `team\service`, Account: "account; $() `cmd`", Label: `label\path`, Secret: "secret"}, "add-generic-password -a \"account; $() `cmd`\" -s \"team\\\\service\" -l \"label\\\\path\" -T /usr/bin/security -X 736563726574\n"},
		{"allowed placeholder", StoreOptions{Secret: PlaceholderKey, AllowPlaceholder: true}, "add-generic-password -a \"amnezia/key\" -s \"tun-wave\" -l \"tun-wave (amnezia/key)\" -T /usr/bin/security -X " + hex.EncodeToString([]byte(PlaceholderKey)) + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, deleteResult := range []CommandResult{{}, missingResult(), {ExitCode: 1, Stderr: []byte("could not be found in the keychain")}} {
				store, fake := fakeStore(t, deleteResult, CommandResult{})
				requireCode(t, store.StoreKey(context.Background(), tc.options), "")
				service, account := tc.options.Service, tc.options.Account
				if service == "" {
					service = "tun-wave"
				}
				if account == "" {
					account = "amnezia/key"
				}
				fake.assertCalls(t, deleteCall(service, account), commandCall{name: "/usr/bin/security", args: []string{"-i"}, stdin: []byte(tc.line)})
				for _, call := range fake.calls {
					for _, arg := range call.args {
						if strings.Contains(arg, strings.TrimSpace(tc.options.Secret)) || strings.Contains(arg, hex.EncodeToString([]byte(strings.TrimSpace(tc.options.Secret)))) {
							t.Fatal("secret material appeared in argv")
						}
					}
				}
			}
		})
	}
}

func TestStoreKeyValidationBeforeAnyEffects(t *testing.T) {
	t.Parallel()
	for _, options := range []StoreOptions{{}, {Secret: " \n"}, {Secret: PlaceholderKey}, {Secret: " \n" + PlaceholderKey + "\t"}} {
		store, fake := fakeStore(t)
		code := CodeKeyEmpty
		if strings.TrimSpace(options.Secret) == PlaceholderKey {
			code = CodeKeyPlaceholder
		}
		requireCode(t, store.StoreKey(context.Background(), options), code)
		fake.assertCalls(t)
	}
	for _, field := range []string{"service", "account", "label"} {
		for _, invalid := range []string{"bad\nvalue", "bad\rvalue", "bad\tvalue", "bad\x00value", "bad\x1bvalue", "bad\x7fvalue", "bad\u0085value", `bad"value`} {
			options := StoreOptions{Secret: "secret"}
			switch field {
			case "service":
				options.Service = invalid
			case "account":
				options.Account = invalid
			case "label":
				options.Label = invalid
			}
			store, fake := fakeStore(t)
			requireCode(t, store.StoreKey(context.Background(), options), CodeKeyInvalid)
			fake.assertCalls(t)
		}
	}
}

func TestStoreKeyFailuresAndPartialEffects(t *testing.T) {
	t.Parallel()
	secret := "private-test-value"
	for _, bad := range []CommandResult{
		{ExitCode: 36, Stderr: []byte("User interaction is not allowed")},
		{ExitCode: 128, Err: errors.New(secret)},
		{ExitCode: 1, Stdout: []byte(secret), Stderr: []byte(secret)},
		{Stderr: []byte("security: SecKeychainItemCreateFromContent: " + secret)},
		{Stderr: []byte("error: " + hex.EncodeToString([]byte(secret)))},
		{Err: errors.New(secret)},
	} {
		for _, failOnWrite := range []bool{false, true} {
			results := []CommandResult{bad}
			calls := []commandCall{deleteCall("tun-wave", "amnezia/key")}
			if failOnWrite {
				results = []CommandResult{{}, bad}
				calls = append(calls, commandCall{name: "/usr/bin/security", args: []string{"-i"}, stdin: []byte("add-generic-password -a \"amnezia/key\" -s \"tun-wave\" -l \"tun-wave (amnezia/key)\" -T /usr/bin/security -X " + hex.EncodeToString([]byte(secret)) + "\n")})
			}
			store, fake := fakeStore(t, results...)
			err := store.StoreKey(context.Background(), StoreOptions{Secret: secret})
			requireCode(t, err, CodeKeychainAccessDenied)
			if errors.Unwrap(err) == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), hex.EncodeToString([]byte(secret))) {
				t.Fatal("write refusal lost its cause or leaked secret material")
			}
			// A failed delete must never write; a failed write must not retry,
			// restore stale ACLs or pretend that deletion was rolled back.
			fake.assertCalls(t, calls...)
		}
	}
}

func TestStoreKeyCommandSizeLimit(t *testing.T) {
	t.Parallel()
	// An independent literal command pins the macOS parser's buffer boundary.
	prefix := "add-generic-password -a \"amnezia/key\" -s \"tun-wave\" -l \""
	suffix := "\" -T /usr/bin/security -X 78\n"
	label := strings.Repeat("l", 4095-len(prefix)-len(suffix))
	store, fake := fakeStore(t, CommandResult{}, CommandResult{})
	requireCode(t, store.StoreKey(context.Background(), StoreOptions{Secret: "x", Label: label}), "")
	fake.assertCalls(t, deleteCall("tun-wave", "amnezia/key"), commandCall{
		name: "/usr/bin/security", args: []string{"-i"}, stdin: []byte(prefix + label + suffix),
	})
	for _, options := range []StoreOptions{
		{Secret: "x", Label: label + "l"},
		{Secret: strings.Repeat("x", 2048)},
		{Secret: "x", Account: strings.Repeat("a", 4096)},
	} {
		store, fake := fakeStore(t)
		requireCode(t, store.StoreKey(context.Background(), options), CodeKeyInvalid)
		fake.assertCalls(t)
	}
}

func TestDeleteKey(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		result CommandResult
		want   bool
		code   string
	}{
		{CommandResult{}, true, ""},
		{missingResult(), false, ""},
		{CommandResult{ExitCode: 1, Stderr: []byte("COULD NOT BE FOUND IN THE KEYCHAIN")}, false, ""},
		{CommandResult{ExitCode: 1, Stderr: []byte("SecKeychainSearchCopyNext")}, false, ""},
		{CommandResult{ExitCode: 36}, false, CodeKeychainAccessDenied},
		{CommandResult{ExitCode: 128}, false, CodeKeychainAccessDenied},
		{CommandResult{Err: errors.New("secret")}, false, CodeKeychainAccessDenied},
		{CommandResult{Stderr: []byte("error: secret")}, false, CodeKeychainAccessDenied},
	} {
		for _, custom := range []bool{false, true} {
			service, account := "", ""
			if custom {
				service, account = "custom", "account"
			}
			store, fake := fakeStore(t, tc.result)
			got, err := store.DeleteKey(context.Background(), service, account)
			requireCode(t, err, tc.code)
			if got != tc.want {
				t.Fatalf("delete returned %v, want %v", got, tc.want)
			}
			if !custom {
				service, account = "tun-wave", "amnezia/key"
			}
			fake.assertCalls(t, deleteCall(service, account))
		}
	}
}

func TestCheckKeyRedactedStates(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, secret, state, code string
		result                    CommandResult
	}{
		{"present", "é-secret", "present", "", CommandResult{Stdout: []byte(" \né-secret\t")}},
		{"placeholder", PlaceholderKey, "placeholder", CodeKeyPlaceholder, CommandResult{Stdout: []byte(" " + PlaceholderKey + "\n")}},
		{"missing", "", "missing", CodeKeyMissing, missingResult()},
		{"empty", "", "empty", CodeKeyEmpty, CommandResult{Stdout: []byte(" \t\n")}},
		{"ACL", "", "access_denied", CodeKeychainAccessDenied, CommandResult{ExitCode: 36, Stderr: []byte("leaked-secret"), Err: errors.New("leaked-secret")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, fallback := range []bool{false, true} {
				results := []CommandResult{tc.result}
				calls := []commandCall{findCall("tun-wave", "amnezia/key")}
				service := "tun-wave"
				if fallback {
					results = append([]CommandResult{missingResult()}, results...)
					calls = append(calls, findCall("multi-tun", "amnezia/key"))
					service = "multi-tun"
				}
				store, fake := fakeStore(t, results...)
				spec := KeychainSpec{FallbackService: "-"}
				if fallback {
					spec.FallbackService = "multi-tun"
				}
				got := store.CheckKey(context.Background(), spec)
				if got.State != tc.state || got.RefusalCode != tc.code || got.Service != service || got.Account != "amnezia/key" || got.UsedFallback != fallback || got.ByteLength != len(tc.secret) || got.Message == "" {
					t.Fatalf("incorrect redacted status: %+v", got)
				}
				encoded, err := json.Marshal(got)
				if err != nil {
					t.Fatal(err)
				}
				for _, forbidden := range []string{"é-secret", PlaceholderKey, "leaked-secret", `"Secret"`} {
					if strings.Contains(string(encoded), forbidden) || strings.Contains(fmt.Sprintf("%+v", got), forbidden) {
						t.Fatal("status leaked secret material")
					}
				}
				fake.assertCalls(t, calls...)
			}
		})
	}
}

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

type failingWriter struct{ calls int }

func (w *failingWriter) Write(p []byte) (int, error) {
	w.calls++
	return 0, errors.New("writer-secret")
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func TestReadSecretInputStdin(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		input io.Reader
		want  string
		code  string
	}{
		{"trim", strings.NewReader(" \tstdin-secret\r\n"), "stdin-secret", ""},
		{"multiline", strings.NewReader(" [Interface]\nPrivateKey = fake\n"), "[Interface]\nPrivateKey = fake", ""},
		{"empty", strings.NewReader(" \t\r\n"), "", CodeKeyEmpty},
		{"placeholder validation belongs to store", strings.NewReader(PlaceholderKey), PlaceholderKey, ""},
		{"reader error", failingReader{errors.New("reader-secret")}, "", CodeKeyInvalid},
		{"limit", strings.NewReader(strings.Repeat("x", 4<<20)), strings.Repeat("x", 4<<20), ""},
		{"oversize", strings.NewReader(strings.Repeat("x", (4<<20)+1)), "", CodeKeyInvalid},
		{"oversize whitespace", strings.NewReader(strings.Repeat(" ", (4<<20)+1)), "", CodeKeyInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, fake := fakeStore(t)
			got, err := store.ReadSecretInput(context.Background(), ReadSecretOptions{FromStdin: true, Stdin: tc.input,
				IsTTY:           func() bool { t.Fatal("stdin probed TTY"); return false },
				ReadPassword:    func() ([]byte, error) { t.Fatal("stdin read terminal"); return nil, nil },
				ClipboardReader: func(context.Context) ([]byte, error) { t.Fatal("stdin read clipboard"); return nil, nil }})
			requireCode(t, err, tc.code)
			if got != tc.want {
				t.Fatalf("unexpected secret input (length %d, wanted %d)", len(got), len(tc.want))
			}
			if err != nil && strings.Contains(err.Error(), "reader-secret") {
				t.Fatal("input error leaked secret")
			}
			fake.assertCalls(t)
		})
	}
}

func TestReadSecretInputClipboard(t *testing.T) {
	t.Parallel()
	type contextKey struct{}
	ctx := context.WithValue(context.Background(), contextKey{}, "sentinel")
	for _, tc := range []struct {
		result CommandResult
		want   string
		code   string
	}{
		{CommandResult{Stdout: []byte(" \nclipboard-secret\t")}, "clipboard-secret", ""},
		{CommandResult{Stdout: []byte(" \t")}, "", CodeKeyEmpty},
		{CommandResult{ExitCode: 1, Stdout: []byte("partial-secret")}, "", CodeKeyInvalid},
		{CommandResult{Err: errors.New("clipboard-secret")}, "", CodeKeyInvalid},
		{CommandResult{Stderr: []byte("error: clipboard-secret")}, "", CodeKeyInvalid},
	} {
		store, fake := fakeStore(t, tc.result)
		got, err := store.ReadSecretInput(ctx, ReadSecretOptions{FromClipboard: true})
		requireCode(t, err, tc.code)
		if got != tc.want || (err != nil && strings.Contains(err.Error(), "clipboard-secret")) {
			t.Fatal("incorrect or unredacted clipboard result")
		}
		fake.assertCalls(t, commandCall{name: "/usr/bin/pbpaste"})
	}
	for _, readErr := range []error{nil, errors.New("clipboard-secret")} {
		store, fake := fakeStore(t)
		got, err := store.ReadSecretInput(ctx, ReadSecretOptions{FromClipboard: true, ClipboardReader: func(got context.Context) ([]byte, error) {
			if got.Value(contextKey{}) != "sentinel" {
				t.Fatal("clipboard reader did not receive caller context")
			}
			return []byte(" clipboard-secret\n"), readErr
		}})
		code := ""
		if readErr != nil {
			code = CodeKeyInvalid
			if got != "" || strings.Contains(err.Error(), "clipboard-secret") {
				t.Fatal("failed clipboard reader leaked secret")
			}
		} else if got != "clipboard-secret" {
			t.Fatal("clipboard hook was not trimmed")
		}
		requireCode(t, err, code)
		fake.assertCalls(t)
	}
}

func TestReadSecretInputInteractive(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		tty  bool
		data string
		err  error
		code string
	}{
		{"TTY", true, " \nterminal-secret\t", nil, ""},
		{"non TTY", false, "", nil, CodeKeyInvalid},
		{"empty", true, " \t\n", nil, CodeKeyEmpty},
		{"password failure", true, "terminal-secret", errors.New("terminal-secret"), CodeKeyInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, fake := fakeStore(t)
			var prompt bytes.Buffer
			reads := 0
			got, err := store.ReadSecretInput(context.Background(), ReadSecretOptions{IsTTY: func() bool { return tc.tty }, PromptWriter: &prompt,
				ReadPassword: func() ([]byte, error) {
					reads++
					if prompt.String() != "Amnezia key: " {
						t.Error("password read occurred before prompt")
					}
					return []byte(tc.data), tc.err
				}})
			requireCode(t, err, tc.code)
			if tc.tty {
				if reads != 1 || prompt.String() != "Amnezia key: \n" {
					t.Fatal("interactive input did not prompt/read/print newline once")
				}
			} else if reads != 0 || prompt.Len() != 0 || !strings.Contains(err.Error(), "--stdin") || !strings.Contains(err.Error(), "--clipboard") {
				t.Fatal("non-TTY input did not refuse before prompting/reading")
			}
			if err == nil && got != strings.TrimSpace(tc.data) {
				t.Fatal("terminal secret not trimmed")
			}
			if strings.Contains(prompt.String(), "terminal-secret") || (err != nil && (got != "" || strings.Contains(err.Error(), "terminal-secret"))) {
				t.Fatal("interactive input leaked secret material")
			}
			fake.assertCalls(t)
		})
	}
	store, fake := fakeStore(t)
	writer := &failingWriter{}
	_, err := store.ReadSecretInput(context.Background(), ReadSecretOptions{IsTTY: func() bool { return true }, PromptWriter: writer,
		ReadPassword: func() ([]byte, error) { t.Fatal("password read after prompt failure"); return nil, nil }})
	requireCode(t, err, CodeKeyInvalid)
	if strings.Contains(err.Error(), "writer-secret") || writer.calls != 1 {
		t.Fatal("prompt writer failure was not redacted")
	}
	fake.assertCalls(t)
}

func TestReadSecretInputConflictingModes(t *testing.T) {
	t.Parallel()
	store, fake := fakeStore(t)
	_, err := store.ReadSecretInput(context.Background(), ReadSecretOptions{FromStdin: true, FromClipboard: true,
		Stdin: failingReader{errors.New("must not read")}, IsTTY: func() bool { t.Fatal("conflicting modes probed TTY"); return true }})
	requireCode(t, err, CodeKeyInvalid)
	fake.assertCalls(t)
}

func TestReadSecretInputDiscardsPartialResults(t *testing.T) {
	t.Parallel()
	store, fake := fakeStore(t)
	_, err := store.ReadSecretInput(context.Background(), ReadSecretOptions{FromStdin: true,
		Stdin: readerFunc(func(p []byte) (int, error) {
			return copy(p, "partial-secret"), errors.New("partial-secret")
		})})
	requireCode(t, err, CodeKeyInvalid)
	if strings.Contains(err.Error(), "partial-secret") {
		t.Fatal("partial reader failure leaked secret material")
	}
	for _, mode := range []string{"stdin", "clipboard", "TTY"} {
		ctx, cancel := context.WithCancel(context.Background())
		options := ReadSecretOptions{}
		switch mode {
		case "stdin":
			options.FromStdin = true
			options.Stdin = readerFunc(func(p []byte) (int, error) {
				cancel()
				return copy(p, "partial-secret"), io.EOF
			})
		case "clipboard":
			options.FromClipboard = true
			options.ClipboardReader = func(context.Context) ([]byte, error) {
				cancel()
				return []byte("partial-secret"), nil
			}
		case "TTY":
			options.IsTTY = func() bool { return true }
			options.PromptWriter = io.Discard
			options.ReadPassword = func() ([]byte, error) {
				cancel()
				return []byte("partial-secret"), nil
			}
		}
		got, err := store.ReadSecretInput(ctx, options)
		cancel()
		requireCode(t, err, CodeKeyInvalid)
		if got != "" || !errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "partial-secret") {
			t.Fatal("canceled input returned partial secret material or lost cancellation")
		}
	}
	writes := 0
	got, err := store.ReadSecretInput(context.Background(), ReadSecretOptions{
		IsTTY: func() bool { return true }, ReadPassword: func() ([]byte, error) { return []byte("partial-secret"), nil },
		PromptWriter: writerFunc(func(p []byte) (int, error) {
			writes++
			if writes == 2 {
				return 0, errors.New("partial-secret")
			}
			return len(p), nil
		}),
	})
	requireCode(t, err, CodeKeyInvalid)
	if got != "" || writes != 2 || strings.Contains(err.Error(), "partial-secret") {
		t.Fatal("newline output failure returned partial secret material")
	}
	fake.assertCalls(t)
}

func TestDeadlineExceededHasNoSideEffects(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	store, fake := fakeStore(t)
	_, err := store.LookupKey(ctx, KeychainSpec{})
	requireCode(t, err, CodeKeychainAccessDenied)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("lookup did not retain deadline cause")
	}
	_, err = store.ReadSecretInput(ctx, ReadSecretOptions{FromClipboard: true})
	requireCode(t, err, CodeKeyInvalid)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("input did not retain deadline cause")
	}
	fake.assertCalls(t)
}

func TestCanceledContextsHaveNoSideEffects(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store, fake := fakeStore(t)
	_, err := store.LookupKey(ctx, KeychainSpec{})
	requireCode(t, err, CodeKeychainAccessDenied)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("lookup did not retain cancellation cause")
	}
	requireCode(t, store.StoreKey(ctx, StoreOptions{Secret: "secret"}), CodeKeychainAccessDenied)
	deleted, err := store.DeleteKey(ctx, "", "")
	requireCode(t, err, CodeKeychainAccessDenied)
	if deleted {
		t.Fatal("canceled deletion reported success")
	}
	if got := store.CheckKey(ctx, KeychainSpec{}); got.State != "access_denied" || got.UsedFallback {
		t.Fatal("canceled status did not fail closed")
	}
	for _, options := range []ReadSecretOptions{{FromStdin: true, Stdin: failingReader{errors.New("must not read")}}, {FromClipboard: true}, {IsTTY: func() bool { t.Fatal("canceled input probed TTY"); return true }}} {
		_, err := store.ReadSecretInput(ctx, options)
		requireCode(t, err, CodeKeyInvalid)
		if !errors.Is(err, context.Canceled) {
			t.Fatal("input did not retain cancellation cause")
		}
	}
	fake.assertCalls(t)
	// The package wrappers can be exercised safely only with a canceled context:
	// the default runner must never be invoked by these calls.
	_, err = LookupKey(ctx, KeychainSpec{})
	requireCode(t, err, CodeKeychainAccessDenied)
	requireCode(t, StoreKey(ctx, StoreOptions{Secret: "secret"}), CodeKeychainAccessDenied)
	_, err = DeleteKey(ctx, "", "")
	requireCode(t, err, CodeKeychainAccessDenied)
	if CheckKey(ctx, KeychainSpec{}).State != "access_denied" {
		t.Fatal("package status wrapper did not propagate cancellation")
	}
	_, err = ReadSecretInput(ctx, ReadSecretOptions{FromClipboard: true})
	requireCode(t, err, CodeKeyInvalid)
}

func TestCancellationDuringCommands(t *testing.T) {
	t.Parallel()
	for _, operation := range []string{"lookup", "store", "delete", "clipboard"} {
		t.Run(operation, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			store := &KeychainStore{Runner: func(context.Context, string, []string, []byte) CommandResult {
				calls++
				cancel()
				return CommandResult{ExitCode: 44, Stderr: []byte("could not be found in the keychain")}
			}}
			var err error
			switch operation {
			case "lookup":
				_, err = store.LookupKey(ctx, KeychainSpec{})
			case "store":
				err = store.StoreKey(ctx, StoreOptions{Secret: "secret"})
			case "delete":
				_, err = store.DeleteKey(ctx, "", "")
			case "clipboard":
				_, err = store.ReadSecretInput(ctx, ReadSecretOptions{FromClipboard: true})
			}
			code := CodeKeychainAccessDenied
			if operation == "clipboard" {
				code = CodeKeyInvalid
			}
			requireCode(t, err, code)
			if calls != 1 || !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation did not stop subsequent effects")
			}
		})
	}
}

func TestConfiguredBinariesAndContext(t *testing.T) {
	t.Parallel()
	type contextKey struct{}
	ctx := context.WithValue(context.Background(), contextKey{}, "value")
	store, fake := fakeStore(t, CommandResult{Stdout: []byte("secret")}, CommandResult{Stdout: []byte("clipboard")})
	store.SecurityBinary, store.ClipboardBinary = "/fake/security", "/fake/pbpaste"
	store.Runner = func(got context.Context, name string, args []string, stdin []byte) CommandResult {
		if got.Value(contextKey{}) != "value" {
			t.Fatal("runner lost caller context")
		}
		return fake.run(got, name, args, stdin)
	}
	_, err := store.LookupKey(ctx, KeychainSpec{})
	requireCode(t, err, "")
	_, err = store.ReadSecretInput(ctx, ReadSecretOptions{FromClipboard: true})
	requireCode(t, err, "")
	call := findCall("tun-wave", "amnezia/key")
	call.name = "/fake/security"
	fake.assertCalls(t, call, commandCall{name: "/fake/pbpaste"})
}

func TestConcurrentStoreUse(t *testing.T) {
	t.Parallel()
	var calls atomic.Int64
	store := &KeychainStore{Runner: func(_ context.Context, _ string, args []string, _ []byte) CommandResult {
		calls.Add(1)
		switch args[0] {
		case "find-generic-password":
			return CommandResult{Stdout: []byte("concurrent-secret")}
		case "delete-generic-password", "-i":
			return CommandResult{}
		default:
			t.Error("unexpected command")
			return CommandResult{ExitCode: -1}
		}
	}}
	const workers = 32
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx := context.Background()
			// Different accounts avoid claiming atomic replacement of one item:
			// delete-then-add is explicitly not a Keychain transaction.
			account := fmt.Sprintf("offline-key-%d", i)
			if err := store.StoreKey(ctx, StoreOptions{Account: account, Secret: "concurrent-secret"}); err != nil {
				t.Error(err)
			}
			if got, err := store.LookupKey(ctx, KeychainSpec{Account: account}); err != nil || got.Secret != "concurrent-secret" {
				t.Error("concurrent lookup failed")
			}
			if got := store.CheckKey(ctx, KeychainSpec{Account: account}); got.State != "present" {
				t.Error("concurrent status failed")
			}
			if deleted, err := store.DeleteKey(ctx, "", account); !deleted || err != nil {
				t.Error("concurrent deletion failed")
			}
		}(i)
	}
	wg.Wait()
	if calls.Load() != workers*5 || store.SecurityBinary != "" || store.ClipboardBinary != "" {
		t.Fatal("concurrent calls were lost or mutated shared default configuration")
	}
}

func TestDefaultFallbackKeyFilePath(t *testing.T) {
	t.Parallel()
	store := DefaultKeychainStore()
	if !strings.HasSuffix(store.FallbackKeyFile, filepath.Join(".config", "vless-tun", "keys", "amnezia.key")) {
		t.Fatalf("unexpected default fallback key path: %q", store.FallbackKeyFile)
	}
}

func TestKeychainExit36FallbackKeyFileLifecycle(t *testing.T) {
	t.Parallel()
	keyPath := filepath.Join(t.TempDir(), "keys", "amnezia.key")
	secret := "synthetic-headless-amnezia-key"
	lockedDelete := CommandResult{ExitCode: 36, Stderr: []byte("User interaction is not allowed.")}
	lockedInteractive := CommandResult{ExitCode: 0, Stderr: []byte("security: SecKeychainItemCreateFromContent (<default>): User interaction is not allowed.")}
	lockedLookup := CommandResult{ExitCode: 36, Stderr: []byte("security: SecKeychainSearchCopyNext: User interaction is not allowed.")}

	// 1. Lookup on locked Keychain without existing fallback file still fails closed.
	store, _ := fakeStore(t, lockedLookup)
	store.FallbackKeyFile = keyPath
	if _, err := store.LookupKey(context.Background(), KeychainSpec{}); !IsRefusalCode(err, CodeKeychainAccessDenied) {
		t.Fatalf("expected access denied without fallback file, got %v", err)
	}

	// 2. StoreKey falling back on interactive security exit 0 + stderr writes strict 0700/0600 file.
	store, _ = fakeStore(t, missingResult(), lockedInteractive)
	store.FallbackKeyFile = keyPath
	if err := store.StoreKey(context.Background(), StoreOptions{Secret: secret}); err != nil {
		t.Fatalf("StoreKey fallback failed: %v", err)
	}
	dirInfo, err := os.Lstat(filepath.Dir(keyPath))
	if err != nil || dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("fallback key dir mode = %o, want 0700", dirInfo.Mode().Perm())
	}
	fileInfo, err := os.Lstat(keyPath)
	if err != nil || fileInfo.Mode().Perm() != 0o600 {
		t.Fatalf("fallback key file mode = %o, want 0600", fileInfo.Mode().Perm())
	}

	// 3. LookupKey on locked Keychain reads from the 0600 fallback file.
	store, _ = fakeStore(t, lockedLookup)
	store.FallbackKeyFile = keyPath
	got, err := store.LookupKey(context.Background(), KeychainSpec{})
	if err != nil || got.Secret != secret || !got.UsedFallback {
		t.Fatalf("LookupKey fallback failed: got=%+v err=%v", got, err)
	}

	// 4. LookupKey when Keychain later unlocks (not found in Keychain) still reads fallback file.
	store, _ = fakeStore(t, missingResult(), missingResult())
	store.FallbackKeyFile = keyPath
	got, err = store.LookupKey(context.Background(), KeychainSpec{})
	if err != nil || got.Secret != secret || !got.UsedFallback {
		t.Fatalf("LookupKey not-found fallback failed: got=%+v err=%v", got, err)
	}

	// 5. StoreKey falling back on delete-generic-password exit 36 overwrites atomically with 0600.
	updated := "synthetic-headless-amnezia-key-v2"
	store, _ = fakeStore(t, lockedDelete)
	store.FallbackKeyFile = keyPath
	if err := store.StoreKey(context.Background(), StoreOptions{Secret: updated}); err != nil {
		t.Fatalf("StoreKey delete-locked fallback failed: %v", err)
	}
	store, _ = fakeStore(t, lockedLookup)
	store.FallbackKeyFile = keyPath
	got, err = store.LookupKey(context.Background(), KeychainSpec{})
	if err != nil || got.Secret != updated {
		t.Fatalf("LookupKey after overwrite failed: got=%+v err=%v", got, err)
	}

	// 6. DeleteKey on locked Keychain removes the fallback file cleanly.
	store, _ = fakeStore(t, lockedDelete)
	store.FallbackKeyFile = keyPath
	deleted, err := store.DeleteKey(context.Background(), "", "")
	if err != nil || !deleted {
		t.Fatalf("DeleteKey fallback failed: deleted=%v err=%v", deleted, err)
	}
	if _, err := os.Lstat(keyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fallback key file still exists after delete: %v", err)
	}

	// 7. Unlocked Keychain StoreKey cleans up any stale fallback file.
	if err := writeFallbackKeyFile(keyPath, secret); err != nil {
		t.Fatal(err)
	}
	store, _ = fakeStore(t, missingResult(), CommandResult{})
	store.FallbackKeyFile = keyPath
	if err := store.StoreKey(context.Background(), StoreOptions{Secret: secret}); err != nil {
		t.Fatalf("unlocked StoreKey failed: %v", err)
	}
	if _, err := os.Lstat(keyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale fallback key file was not removed on unlocked Keychain write: %v", err)
	}
}

func TestFallbackKeyFileRefusesInsecurePermissionsAndSymlinks(t *testing.T) {
	t.Parallel()
	secret := "synthetic-secret-must-not-leak"
	locked := CommandResult{ExitCode: 36, Stderr: []byte("User interaction is not allowed.")}

	// Non-0600 file permissions must be refused.
	for _, perm := range []os.FileMode{0o644, 0o640, 0o604, 0o400, 0o666} {
		dir := filepath.Join(t.TempDir(), "keys")
		keyPath := filepath.Join(dir, "amnezia.key")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath, []byte(secret+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(keyPath, perm); err != nil {
			t.Fatal(err)
		}
		store, _ := fakeStore(t, locked)
		store.FallbackKeyFile = keyPath
		got, err := store.LookupKey(context.Background(), KeychainSpec{})
		if !IsRefusalCode(err, CodeKeychainAccessDenied) || got.Secret != "" || strings.Contains(err.Error(), secret) {
			t.Fatalf("perm %o was not refused cleanly: got=%+v err=%v", perm, got, err)
		}
	}

	// Group/world-accessible parent dir must be refused on read.
	dir := filepath.Join(t.TempDir(), "keys")
	keyPath := filepath.Join(dir, "amnezia.key")
	if err := writeFallbackKeyFile(keyPath, secret); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	store, _ := fakeStore(t, locked)
	store.FallbackKeyFile = keyPath
	if got, err := store.LookupKey(context.Background(), KeychainSpec{}); !IsRefusalCode(err, CodeKeychainAccessDenied) || got.Secret != "" {
		t.Fatalf("0755 parent dir was not refused: got=%+v err=%v", got, err)
	}

	// Symlink at fallback key path must be refused on both read and write.
	symDir := filepath.Join(t.TempDir(), "keys")
	if err := os.MkdirAll(symDir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(symDir, "real.key")
	if err := os.WriteFile(target, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	symPath := filepath.Join(symDir, "amnezia.key")
	if err := os.Symlink(target, symPath); err != nil {
		t.Fatal(err)
	}
	store, _ = fakeStore(t, locked)
	store.FallbackKeyFile = symPath
	if got, err := store.LookupKey(context.Background(), KeychainSpec{}); !IsRefusalCode(err, CodeKeychainAccessDenied) || got.Secret != "" {
		t.Fatalf("symlink read was not refused: got=%+v err=%v", got, err)
	}
	store, _ = fakeStore(t, locked)
	store.FallbackKeyFile = symPath
	if err := store.StoreKey(context.Background(), StoreOptions{Secret: secret}); !IsRefusalCode(err, CodeKeychainAccessDenied) {
		t.Fatalf("symlink write was not refused: %v", err)
	}
}
