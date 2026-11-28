package cli

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"multi-tun/desktop/internal/core/vpncore"
	"multi-tun/desktop/internal/vless/amnezia"
	"multi-tun/desktop/internal/vless/config"
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
