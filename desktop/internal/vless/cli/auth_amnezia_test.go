package cli

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"multi-tun/desktop/internal/core/vpncore"
	"multi-tun/desktop/internal/vless/amnezia"
	"multi-tun/desktop/internal/vless/awg"
	"multi-tun/desktop/internal/vless/config"
	"multi-tun/desktop/internal/vless/model"
	"multi-tun/desktop/internal/vless/session"
	"multi-tun/desktop/internal/vless/subscription"
)

// Fail closed even if a new test forgets to inject its own store. This guard is
// installed before any tests (including parallel tests) can run.
func init() {
	amneziaStoreFunc = func() *amnezia.KeychainStore {
		return &amnezia.KeychainStore{Runner: func(context.Context, string, []string, []byte) amnezia.CommandResult {
			return amnezia.CommandResult{Err: errors.New("unmocked credential operation"), ExitCode: -1}
		}}
	}
}

type amneziaCommand struct {
	name  string
	args  []string
	stdin string
}
type amneziaFake struct {
	mu        sync.Mutex
	items     map[string]string
	calls     []amneziaCommand
	clipboard string
	failure   *amnezia.CommandResult
}

func installAmneziaFake(t *testing.T) *amneziaFake {
	t.Helper()
	f := &amneziaFake{items: make(map[string]string)}
	previousStore, previousInput := amneziaStoreFunc, amneziaStdin
	previousTTY, previousPassword := amneziaIsTTY, amneziaReadPassword
	previousFetch := amneziaFetchFunc
	amneziaStoreFunc = func() *amnezia.KeychainStore { return &amnezia.KeychainStore{Runner: f.run} }
	amneziaStdin = strings.NewReader("")
	amneziaIsTTY = func() bool { return false }
	amneziaReadPassword = func() ([]byte, error) { t.Fatal("unexpected password read"); return nil, nil }
	amneziaFetchFunc = func(context.Context, string, subscription.FetchOptions) ([]byte, error) {
		t.Error("unexpected subscription fetch")
		return nil, errors.New("offline guard")
	}
	t.Cleanup(func() {
		amneziaStoreFunc, amneziaStdin = previousStore, previousInput
		amneziaIsTTY, amneziaReadPassword = previousTTY, previousPassword
		amneziaFetchFunc = previousFetch
	})
	return f
}

func (f *amneziaFake) run(_ context.Context, name string, args []string, input []byte) amnezia.CommandResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, amneziaCommand{name, append([]string(nil), args...), string(input)})
	if f.failure != nil {
		return *f.failure
	}
	if name == "/usr/bin/pbpaste" {
		return amnezia.CommandResult{Stdout: []byte(f.clipboard)}
	}
	if name != "/usr/bin/security" {
		return amnezia.CommandResult{ExitCode: 1, Err: errors.New("unexpected command")}
	}
	if reflect.DeepEqual(args, []string{"-i"}) {
		// The production store must keep the secret out of argv and grant the
		// security tool ownership. Only decode the fixed test metadata grammar.
		line := string(input)
		value := func(flag string) string {
			_, rest, ok := strings.Cut(line, flag+` "`)
			if !ok {
				return ""
			}
			s, _, _ := strings.Cut(rest, `"`)
			return s
		}
		_, raw, ok := strings.Cut(strings.TrimSpace(line), " -X ")
		decoded, err := hex.DecodeString(raw)
		if !ok || err != nil || !strings.Contains(line, " -T /usr/bin/security -X ") {
			return amnezia.CommandResult{ExitCode: 1, Err: errors.New("invalid secure store command")}
		}
		f.items[value("-s")+"/"+value("-a")] = string(decoded)
		return amnezia.CommandResult{}
	}
	if len(args) < 5 {
		return amnezia.CommandResult{ExitCode: 1}
	}
	key := args[2] + "/" + args[4]
	secret, found := f.items[key]
	if !found {
		return amnezia.CommandResult{ExitCode: 44}
	}
	switch args[0] {
	case "find-generic-password":
		return amnezia.CommandResult{Stdout: []byte(secret + "\n")}
	case "delete-generic-password":
		delete(f.items, key)
		return amnezia.CommandResult{}
	default:
		return amnezia.CommandResult{ExitCode: 1}
	}
}

func runAmneziaCLI(t *testing.T, want int, secrets []string, args ...string) string {
	t.Helper()
	var out, errOut bytes.Buffer
	code := NewWithName(&out, &errOut, "tun-wave").Run(args)
	text := out.String() + errOut.String()
	for _, secret := range secrets {
		if secret != "" && strings.Contains(text, secret) {
			t.Fatal("secret leaked through CLI output")
		}
	}
	if code != want {
		t.Fatalf("exit = %d, want %d; output: %s", code, want, text)
	}
	return text
}

const amneziaTestURI = "vless://11111111-2222-3333-4444-555555555555@203.0.113.2:443?type=tcp&security=reality&pbk=public-example&fp=chrome&sni=example.com&sid=aabb#USA"

func TestAuthAmneziaStoreInputModes(t *testing.T) {
	for _, mode := range []string{"stdin", "clipboard", "interactive"} {
		t.Run(mode, func(t *testing.T) {
			f := installAmneziaFake(t)
			args := []string{"auth", "amnezia", "--service", "custom", "--account", "key"}
			switch mode {
			case "stdin":
				amneziaStdin = strings.NewReader(amneziaTestURI + "\n")
				args = append(args, "--stdin")
			case "clipboard":
				f.clipboard = amneziaTestURI
				args = append(args, "--clipboard")
			case "interactive":
				amneziaIsTTY = func() bool { return true }
				amneziaReadPassword = func() ([]byte, error) { return []byte(amneziaTestURI), nil }
			}
			out := runAmneziaCLI(t, 0, []string{amneziaTestURI}, args...)
			for _, want := range []string{"stored: true", "detected_format: vless", "detected_protocol: vless", "detected_profiles: 1", "detected_countries: US"} {
				if !strings.Contains(out, want) {
					t.Fatalf("missing %q in %s", want, out)
				}
			}
			if f.items["custom/key"] != amneziaTestURI {
				t.Fatal("key was not stored under requested metadata")
			}
			for _, call := range f.calls {
				if strings.Contains(strings.Join(call.args, " "), amneziaTestURI) {
					t.Fatal("secret in process argv")
				}
			}
			if mode == "interactive" && !strings.Contains(out, "Amnezia key:") {
				t.Fatal("masked prompt not used")
			}
		})
	}
}

func TestAuthAmneziaCheckStates(t *testing.T) {
	for _, tc := range []struct {
		name, secret, service, state, code string
		missing, denied                    bool
	}{
		{name: "present", secret: "opaque-secret", service: "tun-wave", state: "present"},
		{name: "placeholder", secret: amnezia.PlaceholderKey, service: "tun-wave", state: "placeholder", code: amnezia.CodeKeyPlaceholder},
		{name: "missing", missing: true, state: "missing", service: "multi-tun", code: amnezia.CodeKeyMissing},
		{name: "empty", service: "tun-wave", state: "empty", code: amnezia.CodeKeyEmpty},
		{name: "denied", denied: true, service: "tun-wave", state: "access_denied", code: amnezia.CodeKeychainAccessDenied},
		{name: "fallback", secret: "fallback-secret", service: "multi-tun", state: "present"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := installAmneziaFake(t)
			if !tc.missing {
				f.items[tc.service+"/amnezia/key"] = tc.secret
			}
			if tc.denied {
				f.failure = &amnezia.CommandResult{ExitCode: 36, Stderr: []byte("credential-error-secret")}
			}
			want := 1
			if tc.state == "present" {
				want = 0
			}
			out := runAmneziaCLI(t, want, []string{tc.secret, "credential-error-secret"}, "auth", "amnezia", "--check")
			for _, line := range []string{"state: " + tc.state, "service: " + tc.service, "account: amnezia/key", "refusal_code: " + tc.code, fmt.Sprintf("used_fallback: %t", tc.service == "multi-tun"), fmt.Sprintf("bytes: %d", len(tc.secret))} {
				if !strings.Contains(out, line+"\n") {
					t.Fatalf("missing %q in %s", line, out)
				}
			}
		})
	}
}

func TestAuthAmneziaDelete(t *testing.T) {
	f := installAmneziaFake(t)
	f.items["custom/key"] = "delete-secret"
	f.items["multi-tun/key"] = "legacy-secret"
	for _, deleted := range []bool{true, false} {
		out := runAmneziaCLI(t, 0, []string{"delete-secret", "legacy-secret"}, "auth", "amnezia", "--delete", "--service", "custom", "--account", "key")
		if !strings.Contains(out, fmt.Sprintf("deleted: %t", deleted)) {
			t.Fatal("wrong delete status")
		}
	}
	if f.items["multi-tun/key"] != "legacy-secret" {
		t.Fatal("delete affected fallback service")
	}
}

func TestAuthAmneziaCheckCustomFallback(t *testing.T) {
	f := installAmneziaFake(t)
	f.items["previous/key"] = "custom-fallback-secret"
	out := runAmneziaCLI(t, 0, []string{"custom-fallback-secret"}, "auth", "amnezia", "--check", "--service", "current", "--fallback-service", "previous", "--account", "key")
	for _, want := range []string{"service: previous", "account: key", "used_fallback: true"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing custom fallback status %q", want)
		}
	}
}

func TestAuthAmneziaRejectsArgumentsAndConflictsBeforeIO(t *testing.T) {
	for index, args := range [][]string{
		{amneziaTestURI}, {"--stdin", amneziaTestURI}, {"--check", amneziaTestURI},
		{"--help", amneziaTestURI},
		{"--stdin", "--clipboard"}, {"--check", "--delete"}, {"--check", "--stdin"}, {"--check", "--clipboard"}, {"--delete", "--stdin"}, {"--delete", "--clipboard"},
		{"--stdin=" + amneziaTestURI}, {"--unknown=" + amneziaTestURI},
	} {
		t.Run(fmt.Sprintf("case-%d", index), func(t *testing.T) {
			f := installAmneziaFake(t)
			out := runAmneziaCLI(t, 2, []string{amneziaTestURI}, append([]string{"auth", "amnezia"}, args...)...)
			if strings.Contains(strings.Join(args, " "), amneziaTestURI) && !strings.Contains(out, "Raw keys MUST NOT") {
				t.Fatal("missing argument safety warning")
			}
			if len(f.calls) != 0 {
				t.Fatal("rejected arguments touched credential tools")
			}
		})
	}
}

func TestAuthAmneziaPlaceholderPolicy(t *testing.T) {
	f := installAmneziaFake(t)
	amneziaStdin = strings.NewReader(amnezia.PlaceholderKey)
	out := runAmneziaCLI(t, 1, []string{amnezia.PlaceholderKey}, "auth", "amnezia", "--stdin")
	if !strings.Contains(out, amnezia.CodeKeyPlaceholder) || len(f.calls) != 0 {
		t.Fatal("placeholder did not fail before Keychain access")
	}
	amneziaStdin = strings.NewReader(amnezia.PlaceholderKey)
	runAmneziaCLI(t, 0, []string{amnezia.PlaceholderKey}, "auth", "amnezia", "--stdin", "--allow-placeholder")
	if f.items["tun-wave/amnezia/key"] != amnezia.PlaceholderKey {
		t.Fatal("explicit placeholder scaffolding failed")
	}
}

func TestAuthAmneziaRedactsInputAndToolFailures(t *testing.T) {
	for _, mode := range []string{"no-tty", "empty", "password-error", "clipboard-error", "write-error", "delete-error"} {
		t.Run(mode, func(t *testing.T) {
			f := installAmneziaFake(t)
			args := []string{"auth", "amnezia"}
			switch mode {
			case "empty":
				args = append(args, "--stdin")
			case "password-error":
				amneziaIsTTY = func() bool { return true }
				amneziaReadPassword = func() ([]byte, error) { return nil, errors.New("failure-secret") }
			case "clipboard-error":
				args = append(args, "--clipboard")
				f.failure = &amnezia.CommandResult{ExitCode: 1, Err: errors.New("failure-secret")}
			case "write-error":
				args = append(args, "--stdin")
				amneziaStdin = strings.NewReader(amneziaTestURI)
				f.failure = &amnezia.CommandResult{ExitCode: 36, Stderr: []byte("failure-secret")}
			case "delete-error":
				args = append(args, "--delete")
				f.failure = &amnezia.CommandResult{ExitCode: 36, Stderr: []byte("failure-secret")}
			}
			runAmneziaCLI(t, 1, []string{amneziaTestURI, "failure-secret"}, args...)
		})
	}
}

func amneziaVPNFixture(t *testing.T, countries ...string) string {
	t.Helper()
	servers := make([]any, 0, len(countries))
	for i, country := range countries {
		xray := map[string]any{"outbounds": []any{map[string]any{
			"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{
				"address": fmt.Sprintf("203.0.113.%d", i+1), "port": 443,
				"users": []any{map[string]any{"id": "11111111-2222-3333-4444-555555555555", "encryption": "none"}},
			}}},
			"streamSettings": map[string]any{"network": "tcp", "security": "tls", "tlsSettings": map[string]any{"serverName": "example.com"}},
		}}}
		servers = append(servers, map[string]any{"description": "Example " + country, "country_code": country, "containers": []any{map[string]any{"container": "amnezia-xray", "xray": map[string]any{"last_config": xray}}}})
	}
	body, err := json.Marshal(map[string]any{"servers": servers})
	if err != nil {
		t.Fatal(err)
	}
	key, err := amnezia.EncodeVPNURI(body)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func setupAmneziaConfig(t *testing.T, extra ...string) (string, config.ProjectConfig) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	args := append([]string{"setup", "--config", path, "--source-mode", "amnezia"}, extra...)
	out := runAmneziaCLI(t, 0, nil, args...)
	if !strings.Contains(out, "tun-wave auth amnezia") {
		t.Fatal("setup lacks credential hint")
	}
	cfg, _, err := loadEffectiveConfig(path, config.SelectionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return path, cfg
}

// The full CLI path exercises the real decoder, country selection, cache and
// renderer; only external boundaries (credentials, probes and sessions) are fake.
func TestAmneziaOfflineCLIWorkflow(t *testing.T) {
	f := installAmneziaFake(t)
	installProbeSelectionSeams(t, nil, false)
	previousDial := profileProbeDialContext
	profileProbeDialContext = func(context.Context, string, string) (net.Conn, error) {
		a, b := net.Pipe()
		_ = b.Close()
		return a, nil
	}
	t.Cleanup(func() { profileProbeDialContext = previousDial })
	t.Setenv("DANCEVPN_SUBSCRIPTION_URL", "https://example.invalid/ambient-secret")
	path, cfg := setupAmneziaConfig(t)
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Current.Server != "amnezia" || loaded.Current.Profile != "us" || cfg.SourceURL() != "" {
		t.Fatal("wrong Amnezia setup defaults")
	}
	profile := loaded.Servers["amnezia"].Profiles["us"]
	if profile.Match == nil || profile.Match.Country != "US" || profile.Pick != "probe" {
		t.Fatal("country alias not scaffolded")
	}
	key := amneziaVPNFixture(t, "DE", "US")
	f.items["tun-wave/amnezia/key"] = key
	secrets := []string{key, "ambient-secret", "11111111-2222-3333-4444-555555555555"}
	runAmneziaCLI(t, 0, secrets, "refresh", "--config", path)
	out := runAmneziaCLI(t, 0, secrets, "list", "--config", path)
	if !strings.Contains(out, "Example US") || !strings.Contains(out, "Example DE") {
		t.Fatal("multi-country profiles missing")
	}
	out = runAmneziaCLI(t, 0, secrets, "render", "--config", path, "amnezia", "us")
	if !strings.Contains(out, "resolved: amnezia/us -> Example US") {
		t.Fatalf("wrong resolution: %s", out)
	}
	data, err := os.ReadFile(cfg.SingboxConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := vpncore.ValidateSingBoxConfig(data); err != nil {
		t.Fatalf("helper schema: %v", err)
	}
	out = runAmneziaCLI(t, 0, secrets, "diagnose", "config", "--config", path)
	for _, want := range []string{"keychain_service: tun-wave", "keychain_account: amnezia/key", "keychain_state: present", "resolved: amnezia/us"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %s", want, out)
		}
	}
	snapshot, err := subscription.LoadCache(cfg.CacheDir)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Raw != "" || snapshot.SourceURL != "keychain://tun-wave/amnezia/key" || snapshot.SourceMode != "amnezia" || len(snapshot.Profiles) != 2 || snapshot.Profiles[1].CountryCode != "US" {
		t.Fatal("wrong redacted snapshot or country metadata")
	}
	for _, name := range []string{"snapshot.json", "subscription.txt"} {
		data, err := os.ReadFile(filepath.Join(cfg.CacheDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte(key)) || bytes.Contains(data, []byte("ambient-secret")) {
			t.Fatal("secret persisted in cache")
		}
		if name == "subscription.txt" && len(data) != 0 {
			t.Fatal("raw payload persisted")
		}
	}

	h := installReconnectHarness(t)
	runAmneziaCLI(t, 0, secrets, "reconnect", "--config", path)
	if strings.Join(h.events, ",") != "stop,start" || len(h.startOptions) != 1 || h.startOptions[0].ResolvedServer != "amnezia" || h.startOptions[0].ResolvedAlias != "us" {
		t.Fatal("reconnect did not hand the resolved Amnezia profile to the fake session")
	}
	previousState, previousInterface := currentSessionStateStatus, interfaceStateStatus
	currentSessionStateStatus = func(string, config.PrivilegedLaunchConfig) (*session.CurrentSession, string, bool, error) {
		return &session.CurrentSession{ID: "fake-running"}, "active", true, nil
	}
	interfaceStateStatus = func(string) (bool, []string, error) { return true, []string{"172.19.0.1/30"}, nil }
	t.Cleanup(func() { currentSessionStateStatus, interfaceStateStatus = previousState, previousInterface })
	out = runAmneziaCLI(t, 0, secrets, "status", "--config", path, "--refresh", "amnezia", "us")
	if !strings.Contains(out, "connection: up") || !strings.Contains(out, "selected_profile:") || !strings.Contains(out, "Example US") {
		t.Fatalf("status did not select the Amnezia country profile: %s", out)
	}
}

func TestAmneziaRegionRefusalDoesNotMaskAmbiguityOrProbeFailure(t *testing.T) {
	f := installAmneziaFake(t)
	installProbeSelectionSeams(t, nil, false)
	path, cfg := setupAmneziaConfig(t)
	f.items["tun-wave/amnezia/key"] = amneziaVPNFixture(t, "US", "US")
	previousDial := profileProbeDialContext
	profileProbeDialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("offline probe failure")
	}
	t.Cleanup(func() { profileProbeDialContext = previousDial })
	for _, pick := range []string{"only", "probe"} {
		_, err := New(io.Discard, io.Discard).prepareStart(cfg, startOptions{
			configPath: path, serverName: "amnezia", configProfile: "us", refresh: true, refreshSet: true,
			match: &config.ProfileMatch{Country: "US"}, pick: pick,
		})
		if err == nil || amnezia.RefusalCode(err) != "" {
			t.Fatalf("%s error was misclassified as a region refusal: %v", pick, err)
		}
	}
}

func TestAmneziaSetupPreservesExplicitAliases(t *testing.T) {
	installAmneziaFake(t)
	path, _ := setupAmneziaConfig(t, "--server", "custom", "--config-profile", "region")
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Current.Server != "custom" || cfg.Current.Profile != "region" {
		t.Fatal("explicit setup aliases were overwritten")
	}
}

func TestAmneziaAllRefusalsLeaveRunningSessionUntouched(t *testing.T) {
	unsupported, _ := amnezia.EncodeVPNURI([]byte(`{"containers":[{"container":"amnezia-openvpn"}]}`))
	gateway, _ := amnezia.EncodeVPNURI([]byte(`{"api_endpoint":"https://example.invalid/api","api_key":"gateway-secret"}`))
	awg := "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.5:51820\n"
	for _, tc := range []struct {
		code, key       string
		missing, denied bool
	}{
		{code: amnezia.CodeKeyMissing, missing: true},
		{code: amnezia.CodeKeyEmpty},
		{code: amnezia.CodeKeyPlaceholder, key: amnezia.PlaceholderKey},
		{code: amnezia.CodeKeychainAccessDenied, denied: true},
		{code: amnezia.CodeKeyInvalid, key: "vpn://invalid-secret"},
		{code: amnezia.CodeProtocolUnsupported, key: unsupported},
		{code: amnezia.CodeRegionUnmatched, key: amneziaVPNFixture(t, "DE")},
		{code: amnezia.CodeEngineUnavailable, key: awg},
		{code: amnezia.CodeGatewayUnimplemented, key: gateway},
	} {
		t.Run(tc.code, func(t *testing.T) {
			f := installAmneziaFake(t)
			installProbeSelectionSeams(t, &session.CurrentSession{ID: "running", ResolvedServer: "amnezia", ResolvedAlias: "us"}, true)
			h := installReconnectHarness(t)
			path, cfg := setupAmneziaConfig(t)
			if tc.code == amnezia.CodeEngineUnavailable {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				// AWG is runnable with sing-box now; an explicit incompatible
				// engine remains a hard refusal before cache/session changes.
				data = bytes.ReplaceAll(data, []byte(`"sing-box"`), []byte(`"xray"`))
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if !tc.missing {
				f.items["tun-wave/amnezia/key"] = tc.key
			}
			if tc.denied {
				f.failure = &amnezia.CommandResult{ExitCode: 36, Stderr: []byte("tool-error-secret")}
			}
			if err := os.MkdirAll(filepath.Dir(cfg.SingboxConfigPath()), 0o700); err != nil {
				t.Fatal(err)
			}
			previous := []byte("previous-rendered-config")
			if err := os.WriteFile(cfg.SingboxConfigPath(), previous, 0o600); err != nil {
				t.Fatal(err)
			}
			// A valid old cache must never rescue a refused key on reconnect.
			seedReconnectCache(t, cfg.CacheDir)
			before, err := os.ReadFile(filepath.Join(cfg.CacheDir, "snapshot.json"))
			if err != nil {
				t.Fatal(err)
			}
			out := runAmneziaCLI(t, 1, []string{tc.key, "tool-error-secret", "gateway-secret"}, "reconnect", "--config", path)
			if !strings.Contains(out, tc.code) || !strings.Contains(out, "running sessions were left untouched") || len(h.events) != 0 {
				t.Fatalf("refusal or preservation missing: %s, events=%v", out, h.events)
			}
			after, err := os.ReadFile(cfg.SingboxConfigPath())
			if err != nil || !bytes.Equal(after, previous) {
				t.Fatal("running config was modified")
			}
			if tc.code != amnezia.CodeRegionUnmatched {
				after, err = os.ReadFile(filepath.Join(cfg.CacheDir, "snapshot.json"))
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("key refusal modified cache")
				}
			}
		})
	}
}

func TestAmneziaSubscriptionURLCacheAndErrorsAreRedacted(t *testing.T) {
	for _, mode := range []string{"success", "transport", "invalid", "malformed-vless"} {
		t.Run(mode, func(t *testing.T) {
			f := installAmneziaFake(t)
			_, cfg := setupAmneziaConfig(t)
			secret := "https://example.invalid/subscription?key=url-secret"
			f.items["multi-tun/amnezia/key"] = secret
			amneziaFetchFunc = func(_ context.Context, url string, options subscription.FetchOptions) ([]byte, error) {
				if url != secret {
					t.Error("incorrect secret URL")
				}
				switch mode {
				case "transport":
					return nil, &subscription.TransientFetchError{Err: errors.New(secret)}
				case "invalid":
					return []byte("invalid-url-secret"), nil
				case "malformed-vless":
					return []byte("vless://url-secret%invalid"), nil
				default:
					return []byte(amneziaTestURI), nil
				}
			}
			snapshot, err := refreshSource(cfg)
			if mode != "success" {
				if err == nil || strings.Contains(err.Error(), "url-secret") || amnezia.RefusalCode(err) != amnezia.CodeKeyInvalid {
					t.Fatal("fetch/parser error was not redacted and classified")
				}
				if _, statErr := os.Stat(cfg.CacheDir); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatal("failed fetch touched cache")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if snapshot.SourceURL != "keychain://multi-tun/amnezia/key" || snapshot.Raw != "" || snapshot.Profiles[0].CountryCode != "US" || snapshot.PayloadFormat != "subscription_url" {
				t.Fatal("invalid subscription cache metadata")
			}
			for _, name := range []string{"snapshot.json", "subscription.txt"} {
				data, err := os.ReadFile(filepath.Join(cfg.CacheDir, name))
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(data, []byte("url-secret")) {
					t.Fatal("subscription secret leaked to cache")
				}
			}
		})
	}
}

func TestDiagnoseAmneziaMissingKeyIsRedacted(t *testing.T) {
	installAmneziaFake(t)
	path, _ := setupAmneziaConfig(t)
	out := runAmneziaCLI(t, 1, nil, "diagnose", "config", "--config", path)
	if !strings.Contains(out, "keychain_state: missing") || !strings.Contains(out, "keychain_refusal_code: "+amnezia.CodeKeyMissing) {
		t.Fatal("missing key status")
	}
}

func TestNewWithNameUsage(t *testing.T) {
	for _, name := range []string{"tun-wave", "vless-tun", ""} {
		var out bytes.Buffer
		if NewWithName(&out, io.Discard, name).Run([]string{"--help"}) != 0 {
			t.Fatal("help failed")
		}
		if name == "" {
			name = "tun-wave"
		}
		for _, want := range []string{"  " + name + " setup", "  " + name + " auth amnezia", "VLESS, Xray, and Amnezia VPN", "vless-tun symlink compatibility", "~/.config/tun-wave/config.json", "~/.config/vless-tun/config.json", "TUN_WAVE_CONFIG", "VLESS_TUN_CONFIG"} {
			if !strings.Contains(out.String(), want) {
				t.Fatalf("usage missing %q", want)
			}
		}
	}
	var out bytes.Buffer
	New(&out, io.Discard).Run([]string{"--help"})
	if !strings.Contains(out.String(), "  vless-tun setup") {
		t.Fatal("New lost legacy invocation name")
	}
}

const cliGatewayAPIKey = "synthetic-cli-gateway-api-key"

func cliVPNJSON(t *testing.T, v any) string {
	t.Helper()
	body, err := json.Marshal(v)
	if err != nil {
		t.Fatal("encode fixture JSON")
	}
	key, err := amnezia.EncodeVPNURI(body)
	if err != nil {
		t.Fatal("encode fixture VPN URI")
	}
	return key
}

func cliGatewayToken(t *testing.T, protocol string) string {
	t.Helper()
	return cliVPNJSON(t, map[string]any{"config_version": 2,
		"api_config": map[string]any{"service_type": "amnezia-premium", "service_protocol": protocol, "user_country_code": "us"},
		"auth_data":  map[string]any{"api_key": cliGatewayAPIKey},
	})
}

func cliAWGExport(t *testing.T, private string) string {
	t.Helper()
	c := syntheticCLIAWG()
	raw := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 192.0.2.2/32
Jc = 4
Jmin = 40
Jmax = 70
S1 = 10
S2 = 20
S3 = 30
S4 = 40
H1 = 100-200
H2 = 300
H3 = 400
H4 = 500
I1 = <b 0x01>
I2 = <b 0x02>
I3 = <b 0x03>
I4 = <b 0x04>
I5 = <b 0x05>
HeaderProtectionKey = %s
ContentPaddingAddition = 10-20
RekeyAfterTime = 120-140
RekeyTimeout = 5-7
RejectAfterTime = 180-200
KeepaliveTimeout = 10-15
MaxHandshakeAttempts = 18-20
RandomTrailers = true
DisableCookies = false
[Peer]
PublicKey = %s
PresharedKey = %s
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 203.0.113.9:51820
PersistentKeepalive = 25-35
`, private, c.HeaderProtectionKey, c.PublicKey, c.PresharedKey)
	return cliVPNJSON(t, map[string]any{
		"description": "USA East", "country_code": "US",
		"dns1": "1.1.1.1", "dns2": "9.9.9.9",
		"api_config": map[string]any{"server_country_code": "us-east", "server_country_code_l10n": "us", "server_country_name": "USA East"},
		"containers": []any{map[string]any{"container": "amnezia-awg", "awg": map[string]any{"last_config": map[string]any{"config": raw}}}},
	})
}

// Uses the real encrypted gateway protocol against loopback. No production
// endpoint, credential tool, TUN device or AWG device is reachable from this seam.
func installCLIGateway(t *testing.T, respond func(string, map[string]any) any) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("generate fixture RSA key")
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal("marshal fixture public key")
	}
	pub := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var envelope map[string]string
		if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&envelope) != nil {
			t.Error("invalid gateway fixture request")
			w.WriteHeader(400)
			return
		}
		wrapped, err := base64.StdEncoding.DecodeString(envelope["key_payload"])
		if err != nil {
			t.Error("invalid fixture key envelope")
			w.WriteHeader(400)
			return
		}
		plainKeys, err := rsa.DecryptPKCS1v15(rand.Reader, key, wrapped)
		if err != nil {
			t.Error("cannot decrypt fixture keys")
			w.WriteHeader(400)
			return
		}
		var keys map[string][]byte
		if json.Unmarshal(plainKeys, &keys) != nil || len(keys["aes_iv"]) != 32 || len(keys["aes_key"]) != 32 {
			t.Error("invalid fixture key material")
			w.WriteHeader(400)
			return
		}
		block, err := aes.NewCipher(keys["aes_key"])
		if err != nil {
			t.Error("invalid AES fixture key")
			w.WriteHeader(400)
			return
		}
		ct, err := base64.StdEncoding.DecodeString(envelope["api_payload"])
		if err != nil || len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
			t.Error("invalid fixture ciphertext")
			w.WriteHeader(400)
			return
		}
		cipher.NewCBCDecrypter(block, keys["aes_iv"][:16]).CryptBlocks(ct, ct)
		pad := int(ct[len(ct)-1])
		if pad < 1 || pad > 16 || !bytes.Equal(ct[len(ct)-pad:], bytes.Repeat([]byte{byte(pad)}, pad)) {
			t.Error("invalid fixture padding")
			w.WriteHeader(400)
			return
		}
		var request map[string]any
		if json.Unmarshal(ct[:len(ct)-pad], &request) != nil {
			t.Error("invalid gateway request JSON")
			w.WriteHeader(400)
			return
		}
		auth, ok := request["auth_data"].(map[string]any)
		if !ok || auth["api_key"] != cliGatewayAPIKey {
			t.Error("gateway request lost authentication")
		}
		response, err := json.Marshal(respond(r.URL.Path, request))
		if err != nil {
			t.Error("cannot encode fixture response")
			w.WriteHeader(500)
			return
		}
		pad = aes.BlockSize - len(response)%aes.BlockSize
		response = append(response, bytes.Repeat([]byte{byte(pad)}, pad)...)
		cipher.NewCBCEncrypter(block, keys["aes_iv"][:16]).CryptBlocks(response, response)
		_, _ = w.Write(response)
	}))
	t.Cleanup(srv.Close)
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != strings.TrimPrefix(srv.URL, "http://") {
			t.Error("non-loopback gateway request refused")
			return nil, errors.New("offline guard")
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}}
	t.Cleanup(transport.CloseIdleConnections)
	client := &amnezia.GatewayClient{Endpoint: srv.URL, PublicKeyPEM: pub,
		HTTPClient:         &http.Client{Transport: transport, Timeout: 2 * time.Second},
		S3PrimaryEndpoints: []string{}, S3FallbackEndpoints: []string{}}
	previous := amneziaGatewayClientFunc
	amneziaGatewayClientFunc = func() *amnezia.GatewayClient { return client }
	t.Cleanup(func() { amneziaGatewayClientFunc = previous })
}

func cliGatewayCatalog(protocol string) any {
	return map[string]any{"http_status": 200, "available_countries": []any{
		map[string]any{"server_country_code": "us-west", "server_country_code_l10n": "us", "server_country_name": "USA West", "available_protocols": []string{protocol}},
		map[string]any{"server_country_code": "de", "server_country_name": "Germany", "available_protocols": []string{protocol}},
		map[string]any{"server_country_code": "us-east", "server_country_code_l10n": "us", "server_country_name": "USA East", "available_protocols": []string{protocol}},
	}}
}

func assertCLIHasNoSecrets(t *testing.T, data []byte, secrets []string) {
	t.Helper()
	for _, secret := range secrets {
		if secret != "" && bytes.Contains(data, []byte(secret)) {
			t.Fatal("secret persisted or printed")
		}
	}
}

func TestAmneziaGatewayAWGOfflineCLIWorkflow(t *testing.T) {
	f := installAmneziaFake(t)
	dials := installProbeSelectionSeams(t, nil, false)
	path, cfg := setupAmneziaConfig(t)
	token := cliGatewayToken(t, "awg")
	f.items["tun-wave/amnezia/key"] = token
	export := cliAWGExport(t, "$WIREGUARD_CLIENT_PRIVATE_KEY")
	var mu sync.Mutex
	var installation string
	var advertised []string
	accountRequests, configRequests := 0, 0
	installCLIGateway(t, func(path string, request map[string]any) any {
		mu.Lock()
		defer mu.Unlock()
		uuid, _ := request["installation_uuid"].(string)
		if uuid == "" || installation != "" && installation != uuid {
			t.Error("installation UUID missing or changed")
		}
		installation = uuid
		if path == "/v1/account_info" {
			accountRequests++
			return cliGatewayCatalog("awg")
		}
		if path != "/v1/config" || request["server_country_code"] != "us-east" || request["service_protocol"] != "awg" {
			t.Error("incorrect negotiation request")
		}
		configRequests++
		public, _ := request["public_key"].(string)
		advertised = append(advertised, public)
		return map[string]any{"http_status": 201, "config": export}
	})
	secrets := []string{token, cliGatewayAPIKey, syntheticAWGKey(1), syntheticAWGKey(3), syntheticAWGKey(4)}
	var output strings.Builder
	for _, command := range []string{"refresh", "list"} {
		out := runAmneziaCLI(t, 0, secrets, command, "--config", path)
		output.WriteString(out)
		if command == "list" && (!strings.Contains(out, "USA East") || !strings.Contains(out, "USA West")) {
			t.Fatal("gateway catalog missing")
		}
	}
	mu.Lock()
	issued := configRequests
	mu.Unlock()
	if issued != 0 {
		t.Fatal("refresh/list consumed a device slot")
	}
	out := runAmneziaCLI(t, 0, secrets, "render", "--config", path, "amnezia/us")
	output.WriteString(out)
	if !strings.Contains(out, "rendered_awg: "+cfg.AWGConfigPath()) || !strings.Contains(out, "resolved: amnezia/us -> USA East") {
		t.Fatal("AWG render metadata missing")
	}
	runtime, err := awg.ReadRuntimeConfig(cfg.AWGConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if runtime.PrivateKey == "" || runtime.PrivateKey == syntheticAWGKey(1) || runtime.Endpoint != "203.0.113.9:51820" || !reflect.DeepEqual(runtime.DNS, []string{"1.1.1.1", "9.9.9.9"}) || runtime.PersistentKeepalive != "25-35" || runtime.S4 != 40 || runtime.I5 != "<b 0x05>" || runtime.HeaderProtectionKey != syntheticAWGKey(4) || runtime.RekeyAfterTime != "120-140" {
		t.Fatal("negotiated AWG runtime fields missing")
	}
	info, err := os.Stat(cfg.AWGConfigPath())
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("AWG runtime file is not private")
	}
	privateBytes, _ := base64.StdEncoding.DecodeString(runtime.PrivateKey)
	private, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		t.Fatal("invalid negotiated private key")
	}
	mu.Lock()
	public := advertised[0]
	mu.Unlock()
	if base64.StdEncoding.EncodeToString(private.PublicKey().Bytes()) != public {
		t.Fatal("client private key differs from negotiated keypair")
	}
	secrets = append(secrets, runtime.PrivateKey)
	assertAWGFrontend(t, cfg)

	h := installReconnectHarness(t)
	output.WriteString(runAmneziaCLI(t, 0, secrets, "reconnect", "--config", path, "amnezia/us"))
	if strings.Join(h.events, ",") != "stop,start" || len(h.startOptions) != 1 || h.startOptions[0].Engine != config.EngineAWG || h.startOptions[0].ResolvedID != "amnezia-us-east" {
		t.Fatal("AWG session metadata missing")
	}
	opts := h.startOptions[0]
	exe, err := defaultAWGSidecarExecutable()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(opts.Sidecars, []session.SidecarOptions{{Name: "amnezia-awg", Executable: exe, Args: []string{"_awg-proxy", "-c", cfg.AWGConfigPath()}}}) {
		t.Fatal("AWG sidecar launch contract missing")
	}
	second, err := awg.ReadRuntimeConfig(cfg.AWGConfigPath())
	if err != nil || second.PrivateKey == runtime.PrivateKey {
		t.Fatal("reconnect did not generate fresh client key")
	}
	secrets = append(secrets, second.PrivateKey)
	previousState, previousInterface := currentSessionStateStatus, interfaceStateStatus
	currentSessionStateStatus = func(string, config.PrivilegedLaunchConfig) (*session.CurrentSession, string, bool, error) {
		return &session.CurrentSession{ID: "fake-awg"}, "active", true, nil
	}
	interfaceStateStatus = func(string) (bool, []string, error) { return true, []string{"172.19.0.1/30"}, nil }
	t.Cleanup(func() { currentSessionStateStatus, interfaceStateStatus = previousState, previousInterface })
	for _, args := range [][]string{{"status", "--config", path, "--refresh", "amnezia/us"}, {"diagnose", "config", "--config", path, "amnezia/us"}} {
		out := runAmneziaCLI(t, 0, secrets, args...)
		output.WriteString(out)
		if !strings.Contains(out, "USA East") || !strings.Contains(out, "awg_config: "+cfg.AWGConfigPath()+" (present)") {
			t.Fatal("status/diagnose did not resolve AWG country alias")
		}
	}
	for _, name := range []string{"snapshot.json", "subscription.txt"} {
		data, err := os.ReadFile(filepath.Join(cfg.CacheDir, name))
		if err != nil {
			t.Fatal(err)
		}
		assertCLIHasNoSecrets(t, data, append(secrets, "api_key", "PrivateKey", "PresharedKey", "HeaderProtectionKey", "private_key", "preshared_key", "header_protection_key"))
	}
	assertCLIHasNoSecrets(t, []byte(output.String()), secrets)
	if dials.Load() != 0 {
		t.Fatal("gateway catalog endpoint was TCP probed")
	}
	mu.Lock()
	defer mu.Unlock()
	if accountRequests < 2 || configRequests != 2 {
		t.Fatal("status/diagnose unexpectedly negotiated or workflow did not negotiate")
	}
}

func assertAWGFrontend(t *testing.T, cfg config.ProjectConfig) {
	t.Helper()
	data, err := os.ReadFile(cfg.SingboxConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := vpncore.ValidateSingBoxConfig(data); err != nil {
		t.Fatalf("AWG frontend helper schema: %v", err)
	}
	var doc struct {
		Outbounds []struct {
			Type   string `json:"type"`
			Server string `json:"server"`
			Port   int    `json:"server_port"`
		} `json:"outbounds"`
		Inbounds []struct {
			Excludes []string `json:"route_exclude_address"`
		} `json:"inbounds"`
		Route struct {
			Rules []struct {
				ProcessNames []string `json:"process_name"`
			} `json:"rules"`
		} `json:"route"`
	}
	if json.Unmarshal(data, &doc) != nil {
		t.Fatal("invalid frontend JSON")
	}
	socks, excluded, processes := false, false, false
	for _, outbound := range doc.Outbounds {
		if outbound.Type == "socks" && outbound.Server == "127.0.0.1" && outbound.Port == 20809 {
			socks = true
		}
	}
	for _, inbound := range doc.Inbounds {
		for _, address := range inbound.Excludes {
			if address == "203.0.113.9/32" {
				excluded = true
			}
		}
	}
	for _, rule := range doc.Route.Rules {
		if reflect.DeepEqual(rule.ProcessNames, []string{"tun-wave", "vless-tun", "openconnect"}) {
			processes = true
		}
	}
	if !socks || !excluded || !processes {
		t.Fatal("AWG frontend lost SOCKS or loop prevention")
	}
}

func TestAmneziaAWGDirectCacheAndRuntime(t *testing.T) {
	f := installAmneziaFake(t)
	dials := installProbeSelectionSeams(t, nil, false)
	path, cfg := setupAmneziaConfig(t)
	key := cliAWGExport(t, syntheticAWGKey(1))
	f.items["tun-wave/amnezia/key"] = key
	secrets := []string{key, syntheticAWGKey(1), syntheticAWGKey(3), syntheticAWGKey(4)}
	snapshot, err := refreshAmneziaSource(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Profiles) != 1 {
		t.Fatal("direct AWG profile missing")
	}
	p := snapshot.Profiles[0]
	if len(p.ID) != 12 || p.Host != "203.0.113.9" || p.Port != 51820 || p.Protocol != "amnezia-awg" || p.Network != "udp" || p.CountryCode != "US" {
		t.Fatal("invalid direct AWG catalog metadata")
	}
	again, err := refreshAmneziaSource(cfg)
	if err != nil || again.Profiles[0].ID != p.ID {
		t.Fatal("AWG profile identity not stable")
	}
	data, err := os.ReadFile(filepath.Join(cfg.CacheDir, "snapshot.json"))
	if err != nil {
		t.Fatal(err)
	}
	assertCLIHasNoSecrets(t, data, append(secrets, "PrivateKey", "PresharedKey", "HeaderProtectionKey"))
	runAmneziaCLI(t, 0, secrets, "render", "--config", path)
	runtime, err := awg.ReadRuntimeConfig(cfg.AWGConfigPath())
	if err != nil || runtime.PrivateKey != syntheticAWGKey(1) {
		t.Fatal("direct AWG runtime did not re-read key")
	}
	if dials.Load() != 0 {
		t.Fatal("direct AWG endpoint was TCP probed")
	}
}

func TestAmneziaSkipTCPProbeFilters(t *testing.T) {
	awgProfile := model.Profile{ID: "awg", Name: "USA East", CountryCode: "US", Protocol: "amnezia-awg", Network: "udp"}
	vlessProfile := model.Profile{ID: "vless", Name: "USA West", CountryCode: "US", Protocol: "vless", Network: "tcp"}
	gatewayVLESS := vlessProfile
	gatewayVLESS.Query = map[string]string{"amnezia_gateway": "v2", "amnezia_server_country_code": "us-west", "amnezia_service_protocol": "vless"}
	for _, tc := range []struct {
		name     string
		profiles []model.Profile
		match    *config.ProfileMatch
		want     bool
	}{
		{"AWG", []model.Profile{awgProfile}, &config.ProfileMatch{Country: "US"}, true},
		{"gateway", []model.Profile{gatewayVLESS}, &config.ProfileMatch{Country: "US"}, true},
		{"VLESS", []model.Profile{vlessProfile}, &config.ProfileMatch{Country: "US"}, false},
		{"mixed", []model.Profile{awgProfile, vlessProfile}, &config.ProfileMatch{Country: "US"}, false},
		{"name", []model.Profile{awgProfile, vlessProfile}, &config.ProfileMatch{NamePattern: "East"}, true},
		{"exclude", []model.Profile{awgProfile, vlessProfile}, &config.ProfileMatch{Country: "US", Exclude: []string{"East"}}, false},
		{"transport", []model.Profile{awgProfile, vlessProfile}, &config.ProfileMatch{Transport: "udp"}, true},
		{"unmatched", []model.Profile{awgProfile}, &config.ProfileMatch{Country: "DE"}, false},
		{"invalid", []model.Profile{awgProfile}, &config.ProfileMatch{NamePattern: "["}, false},
		{"empty", nil, &config.ProfileMatch{Country: "US"}, false},
		{"nil", []model.Profile{awgProfile}, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if amneziaShouldSkipTCPProbe(tc.profiles, tc.match) != tc.want {
				t.Fatal("incorrect probe skip decision")
			}
		})
	}
}

func TestResolveAmneziaGatewayVLESSAndCredentialMismatch(t *testing.T) {
	f := installAmneziaFake(t)
	_, cfg := setupAmneziaConfig(t)
	f.items["tun-wave/amnezia/key"] = cliGatewayToken(t, "vless")
	export := amneziaVPNFixture(t, "US")
	installCLIGateway(t, func(path string, request map[string]any) any {
		if path != "/v1/config" || request["service_protocol"] != "vless" {
			t.Error("incorrect VLESS negotiation request")
		}
		return map[string]any{"http_status": 201, "config": export}
	})
	info := amnezia.AccountInfo{AvailableCountries: []amnezia.AvailableCountry{{ServerCountryCode: "us-east", ServerCountryName: "USA East", AvailableProtocols: []string{"vless"}}}}
	p := info.CatalogProfiles("vless")[0]
	resolved, awgCfg, err := resolveAmneziaRuntime(context.Background(), cfg, p)
	if err != nil || awgCfg != nil || resolved.Protocol != "vless" || resolved.Host != "203.0.113.1" || resolved.Port != 443 {
		t.Fatal("gateway VLESS runtime was not resolved")
	}
	f.items["tun-wave/amnezia/key"] = cliAWGExport(t, syntheticAWGKey(1))
	if _, _, err := resolveAmneziaRuntime(context.Background(), cfg, p); !amnezia.IsRefusalCode(err, amnezia.CodeKeyInvalid) {
		t.Fatal("stale gateway catalog accepted non-gateway credentials")
	}
	f.items["tun-wave/amnezia/key"] = amneziaTestURI
	ordinary := model.Profile{ID: "ordinary", Protocol: "vless"}
	actual, c, err := resolveAmneziaRuntime(context.Background(), cfg, ordinary)
	if err != nil || c != nil || !reflect.DeepEqual(actual, ordinary) {
		t.Fatal("ordinary VLESS passthrough changed")
	}
}

func TestAmneziaGatewayRefusalsPreserveSessionAndFiles(t *testing.T) {
	for _, stage := range []string{"account-api", "account-transport", "negotiate", "invalid-export", "executable", "helper-schema"} {
		t.Run(stage, func(t *testing.T) {
			f := installAmneziaFake(t)
			installProbeSelectionSeams(t, &session.CurrentSession{ResolvedServer: "amnezia", ResolvedAlias: "us"}, true)
			h := installReconnectHarness(t)
			path, cfg := setupAmneziaConfig(t)
			token := cliGatewayToken(t, "awg")
			f.items["tun-wave/amnezia/key"] = token
			export := cliAWGExport(t, "$WIREGUARD_CLIENT_PRIVATE_KEY")
			installCLIGateway(t, func(path string, request map[string]any) any {
				if path == "/v1/account_info" {
					if stage == "account-api" {
						return map[string]any{"http_status": 403, "error": cliGatewayAPIKey}
					}
					return cliGatewayCatalog("awg")
				}
				if stage == "negotiate" {
					return map[string]any{"http_status": 403, "error": cliGatewayAPIKey}
				}
				if stage == "invalid-export" {
					return map[string]any{"http_status": 201, "config": "vpn://malformed-secret"}
				}
				return map[string]any{"http_status": 201, "config": export}
			})
			if stage == "account-transport" {
				// A transport error wrapped as transient must still be a hard
				// gateway refusal rather than rescue the start with a stale cache.
				client := amneziaGatewayClientFunc()
				client.HTTPClient = &http.Client{Transport: cliRoundTripper(func(*http.Request) (*http.Response, error) {
					return nil, &subscription.TransientFetchError{Err: errors.New(cliGatewayAPIKey)}
				})}
			}
			if stage == "executable" {
				previous := awgSidecarExecutableFunc
				awgSidecarExecutableFunc = func() (string, error) { return "", errors.New(cliGatewayAPIKey) }
				t.Cleanup(func() { awgSidecarExecutableFunc = previous })
			}
			if stage == "helper-schema" {
				resolveLaunchModeCLI = func(string, config.PrivilegedLaunchConfig) (string, error) { return config.LaunchModeHelper, nil }
				previous := validateHelperConfigCLI
				validateHelperConfigCLI = func([]byte) error { return errors.New("synthetic helper refusal") }
				t.Cleanup(func() { validateHelperConfigCLI = previous })
			}
			for _, p := range []string{cfg.SingboxConfigPath(), cfg.AWGConfigPath()} {
				if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte("previous runtime bytes"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			seedReconnectCache(t, cfg.CacheDir)
			oldCache, err := os.ReadFile(filepath.Join(cfg.CacheDir, "snapshot.json"))
			if err != nil {
				t.Fatal(err)
			}
			out := runAmneziaCLI(t, 1, []string{token, cliGatewayAPIKey, syntheticAWGKey(1), syntheticAWGKey(3), syntheticAWGKey(4)}, "reconnect", "--config", path)
			code := amnezia.CodeGatewayError
			if stage == "executable" {
				code = amnezia.CodeEngineUnavailable
			}
			if stage != "helper-schema" && !strings.Contains(out, code) || !strings.Contains(out, "running sessions were left untouched") || len(h.events) != 0 || strings.Contains(out, "using cached snapshot") {
				t.Fatal("gateway refusal modified session or fell back to cache")
			}
			for _, p := range []string{cfg.SingboxConfigPath(), cfg.AWGConfigPath()} {
				data, err := os.ReadFile(p)
				if err != nil || string(data) != "previous runtime bytes" {
					t.Fatal("refusal did not restore all runtime configs")
				}
			}
			if strings.HasPrefix(stage, "account-") {
				data, err := os.ReadFile(filepath.Join(cfg.CacheDir, "snapshot.json"))
				if err != nil || !bytes.Equal(data, oldCache) {
					t.Fatal("account refusal modified cached snapshot")
				}
			}
		})
	}
}

type cliRoundTripper func(*http.Request) (*http.Response, error)

func (f cliRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestUnifiedSourceSecretModes(t *testing.T) {
	for _, sourceMode := range []string{config.SourceModeDirect, config.SourceModeProxy, config.SourceModeAmnezia} {
		for _, storage := range []string{"keychain", "file0600", "file0644", "symlink", "empty"} {
			t.Run(sourceMode+"/"+storage, func(t *testing.T) {
				fake := installAmneziaFake(t)
				cfg := config.Default()
				cfg.CacheDir = filepath.Join(t.TempDir(), "cache")
				cfg.Source = config.SourceConfig{Mode: sourceMode}
				cfg.SubscriptionURL = ""
				secret := amneziaTestURI
				if sourceMode == config.SourceModeProxy {
					secret = "https://subscription.example/token-sensitive"
				}
				auth := &config.SourceAuthConfig{Mode: "keychain", Record: "sample/key"}
				fake.items["tun-wave/sample/key"] = secret
				if storage != "keychain" {
					path := filepath.Join(t.TempDir(), "key")
					value := secret
					if storage == "empty" {
						value = " \n"
					}
					if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
						t.Fatal(err)
					}
					if storage == "file0644" {
						if err := os.Chmod(path, 0o644); err != nil {
							t.Fatal(err)
						}
					}
					if storage == "symlink" {
						link := path + ".link"
						if err := os.Symlink(path, link); err != nil {
							t.Fatal(err)
						}
						path = link
					}
					auth = &config.SourceAuthConfig{Mode: "file", Path: path}
				}
				cfg.Source.Auth = auth
				got, ref, err := resolveConfiguredSourceSecret(context.Background(), cfg)
				good := storage == "keychain" || storage == "file0600"
				if good {
					if err != nil || got != secret || strings.Contains(ref, secret) {
						t.Fatalf("configured lookup ref=%s err=%v", ref, err)
					}
					if storage == "file0600" && ref != "file://"+auth.Path {
						t.Fatal("incorrect file reference")
					}
				} else {
					if err == nil || got != "" || strings.Contains(err.Error(), secret) {
						t.Fatal("unsafe file was accepted or contents leaked")
					}
				}
				if sourceMode == config.SourceModeAmnezia {
					snapshot, err := refreshAmneziaSource(cfg)
					if good {
						if err != nil || snapshot.SourceURL != ref || snapshot.Raw != "" {
							t.Fatalf("Amnezia file/keychain refresh %v", err)
						}
						if _, _, err := resolveAmneziaRuntime(context.Background(), cfg, snapshot.Profiles[0]); err != nil {
							t.Fatal(err)
						}
					} else if err == nil {
						t.Fatal("Amnezia refresh bypassed AuthStore refusal")
					}
				}
			})
		}
	}
}
func TestUnifiedSecretRefreshCachesAreRedacted(t *testing.T) {
	for _, sourceMode := range []string{config.SourceModeDirect, config.SourceModeProxy} {
		for _, storage := range []string{"file", "keychain"} {
			t.Run(sourceMode+"/"+storage, func(t *testing.T) {
				fake := installAmneziaFake(t)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, amneziaTestURI) }))
				defer server.Close()
				secret := amneziaTestURI
				if sourceMode == config.SourceModeProxy {
					secret = server.URL + "/sensitive-token"
				}
				cfg := config.Default()
				cfg.CacheDir = filepath.Join(t.TempDir(), "cache")
				cfg.Source = config.SourceConfig{Mode: sourceMode, Auth: &config.SourceAuthConfig{Mode: storage, Record: "sample/key"}}
				cfg.SubscriptionURL = ""
				if storage == "file" {
					path := filepath.Join(t.TempDir(), "key")
					if err := os.WriteFile(path, []byte(secret), 0o600); err != nil {
						t.Fatal(err)
					}
					cfg.Source.Auth.Path = path
				} else {
					fake.items["tun-wave/sample/key"] = secret
				}
				snap, err := refreshSource(cfg)
				if err != nil || snap.Raw != "" || snap.SourceURL == secret || !strings.HasPrefix(snap.SourceURL, storage+"://") {
					t.Fatalf("redacted refresh ref=%s err=%v", snap.SourceURL, err)
				}
				for _, name := range []string{"snapshot.json", "subscription.txt"} {
					raw, err := os.ReadFile(filepath.Join(cfg.CacheDir, name))
					if err != nil || bytes.Contains(raw, []byte(secret)) {
						t.Fatal("source secret reached cache")
					}
				}
			})
		}
	}
}
func TestAuthMigrateClearsPlaintextAndCachedRaw(t *testing.T) {
	fake := installAmneziaFake(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	cfg := config.Default()
	cfg.CacheDir = filepath.Join(dir, "cache")
	cfg.Current = &config.CurrentConfig{Server: "phantombot", Profile: "us"}
	cfg.Servers = map[string]config.ServerConfig{"phantombot": {Engine: &config.EngineConfig{Type: config.EngineVLESS}, Source: config.SourceConfig{Mode: config.SourceModeDirect, URL: amneziaTestURI}, CacheDir: cfg.CacheDir, Profiles: map[string]config.ProfileConfig{"us": {Selector: "USA"}}}}
	if _, err := config.SaveConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	if err := subscription.SaveCache(cfg.CacheDir, subscription.CacheSnapshot{SourceURL: amneziaTestURI, Raw: amneziaTestURI}); err != nil {
		t.Fatal(err)
	}
	runAmneziaCLI(t, 0, []string{amneziaTestURI}, "auth", "migrate", "--config", path)
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	source := loaded.Servers["phantombot"].Source
	if source.URL != "" || source.Auth == nil || source.Auth.Mode != "keychain" || source.Auth.Record != "phantombot/key" || fake.items["tun-wave/phantombot/key"] != amneziaTestURI {
		t.Fatal("migration did not store and rewrite source")
	}
	snap, err := subscription.LoadCache(cfg.CacheDir)
	if err != nil || snap.Raw != "" || snap.SourceURL != "keychain://tun-wave/phantombot/key" {
		t.Fatalf("migration failed to redact cache: %+v %v", snap, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || bytes.Contains(raw, []byte(amneziaTestURI)) {
		t.Fatal("plaintext credential remains in config")
	}
	runAmneziaCLI(t, 0, []string{amneziaTestURI}, "auth", "migrate", "--config", path)
}
func TestAuthNonAmneziaServerLifecycle(t *testing.T) {
	fake := installAmneziaFake(t)
	amneziaStdin = strings.NewReader(amneziaTestURI)
	runAmneziaCLI(t, 0, []string{amneziaTestURI}, "auth", "phantombot", "--stdin")
	if fake.items["tun-wave/phantombot/key"] != amneziaTestURI {
		t.Fatal("wrong server record")
	}
	runAmneziaCLI(t, 0, []string{amneziaTestURI}, "auth", "phantombot", "--check")
	runAmneziaCLI(t, 0, []string{amneziaTestURI}, "auth", "phantombot", "--delete")
	runAmneziaCLI(t, 1, []string{amneziaTestURI}, "auth", "phantombot", "--check")
}
