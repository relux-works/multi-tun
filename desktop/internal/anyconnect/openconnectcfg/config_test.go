package openconnectcfg

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDefaultSelectionPrefersRemasteredDefaultBlock(t *testing.T) {
	t.Parallel()

	cfg := Config{
		Default: DefaultSelection{
			ServerURL: "vpn-gw2.corp.example/outside",
			Profile:   "Ural Outside extended",
		},
		DefaultServer:  "legacy-server",
		DefaultProfile: "Legacy Profile",
	}

	selection := cfg.DefaultSelection()
	if selection.ServerURL != "vpn-gw2.corp.example/outside" {
		t.Fatalf("selection.ServerURL = %q, want %q", selection.ServerURL, "vpn-gw2.corp.example/outside")
	}
	if selection.Profile != "Ural Outside extended" {
		t.Fatalf("selection.Profile = %q, want %q", selection.Profile, "Ural Outside extended")
	}
}

func TestEffectiveModeUsesNestedProfileMode(t *testing.T) {
	t.Parallel()

	cfg := Config{
		DefaultMode: "full",
		Servers: map[string]ServerConfig{
			"vpn-gw2.corp.example/outside": {
				Profiles: map[string]ProfileConfig{
					"Ural Outside extended": {
						Mode: "split-include",
					},
				},
			},
		},
	}

	if got := cfg.EffectiveMode("vpn-gw2.corp.example/outside", "Ural Outside extended"); got != "split-include" {
		t.Fatalf("EffectiveMode() = %q, want %q", got, "split-include")
	}
}

func TestResolveServerURLForProfileUsesConfiguredNestedProfile(t *testing.T) {
	t.Parallel()

	cfg := Config{
		Servers: map[string]ServerConfig{
			"vpn-gw2.corp.example/outside": {
				Profiles: map[string]ProfileConfig{
					"Ural Outside extended": {},
				},
			},
		},
	}

	serverURL, ok, err := cfg.ResolveServerURLForProfile("Ural Outside extended")
	if err != nil {
		t.Fatalf("ResolveServerURLForProfile() error = %v", err)
	}
	if !ok {
		t.Fatal("ResolveServerURLForProfile() ok = false, want true")
	}
	if serverURL != "vpn-gw2.corp.example/outside" {
		t.Fatalf("ResolveServerURLForProfile() = %q, want %q", serverURL, "vpn-gw2.corp.example/outside")
	}
}

func TestResolveServerURLForProfileRejectsAmbiguousNestedProfiles(t *testing.T) {
	t.Parallel()

	cfg := Config{
		Servers: map[string]ServerConfig{
			"vpn-gw2.corp.example/outside": {
				Profiles: map[string]ProfileConfig{
					"Ural Outside extended": {},
				},
			},
			"vpn-gw3.corp.example/outside": {
				Profiles: map[string]ProfileConfig{
					"Ural Outside extended": {},
				},
			},
		},
	}

	_, ok, err := cfg.ResolveServerURLForProfile("Ural Outside extended")
	if err == nil {
		t.Fatal("ResolveServerURLForProfile() error = nil, want ambiguity")
	}
	if ok {
		t.Fatal("ResolveServerURLForProfile() ok = true, want false")
	}
	if !strings.Contains(err.Error(), "multiple configured servers") {
		t.Fatalf("ResolveServerURLForProfile() error = %v, want ambiguity message", err)
	}
}

func TestEffectiveAuthUsesServerSpecificOverrideWithGlobalFallback(t *testing.T) {
	t.Parallel()

	cfg := Config{
		Auth: AuthConfig{
			UsernameKeychainAccount: "global/username",
			PasswordKeychainAccount: "global/password",
			SecondFactor: &SecondFactorConfig{
				Mode:                SecondFactorModeTOTPAuto,
				TOTPKeychainAccount: "global/totp_secret",
			},
		},
		Servers: map[string]ServerConfig{
			"vpn-gw2.corp.example/outside": {
				Auth: &AuthConfig{
					UsernameKeychainAccount: "server/username",
					PasswordKeychainAccount: "server/password",
					SecondFactor: &SecondFactorConfig{
						Mode: SecondFactorModeManualOTP,
					},
				},
			},
		},
	}

	got := cfg.EffectiveAuth("vpn-gw2.corp.example/outside")
	if got.UsernameKeychainAccount != "server/username" {
		t.Fatalf("UsernameKeychainAccount = %q, want %q", got.UsernameKeychainAccount, "server/username")
	}
	if got.PasswordKeychainAccount != "server/password" {
		t.Fatalf("PasswordKeychainAccount = %q, want %q", got.PasswordKeychainAccount, "server/password")
	}
	if got.SecondFactor == nil {
		t.Fatal("SecondFactor = nil, want merged config")
	}
	if got.SecondFactor.Mode != SecondFactorModeManualOTP {
		t.Fatalf("SecondFactor.Mode = %q, want %q", got.SecondFactor.Mode, SecondFactorModeManualOTP)
	}
	if got.SecondFactor.TOTPKeychainAccount != "global/totp_secret" {
		t.Fatalf("SecondFactor.TOTPKeychainAccount = %q, want %q", got.SecondFactor.TOTPKeychainAccount, "global/totp_secret")
	}
}

func TestEffectiveClientMimicryUsesServerSpecificConfig(t *testing.T) {
	t.Parallel()

	cfg := Config{
		Servers: map[string]ServerConfig{
			"vpn-gw2.corp.example/outside": {
				ClientMimicry: &ClientMimicryConfig{
					UserAgent:     "AnyConnect",
					Version:       "4.10.08029",
					OS:            "mac-intel",
					LocalHostname: "Alexis-M1-Max",
					AuthMethods:   []string{"single-sign-on-v2", "single-sign-on-external-browser"},
					HTTPHeaders: map[string]string{
						"X-Support-HTTP-Auth": "true",
					},
				},
			},
		},
	}

	got := cfg.EffectiveClientMimicry("vpn-gw2.corp.example/outside")
	if got.UserAgent != "AnyConnect" {
		t.Fatalf("UserAgent = %q, want AnyConnect", got.UserAgent)
	}
	if got.Version != "4.10.08029" {
		t.Fatalf("Version = %q, want 4.10.08029", got.Version)
	}
	if got.OS != "mac-intel" {
		t.Fatalf("OS = %q, want mac-intel", got.OS)
	}
	if got.LocalHostname != "Alexis-M1-Max" {
		t.Fatalf("LocalHostname = %q, want Alexis-M1-Max", got.LocalHostname)
	}
	if !reflect.DeepEqual(got.AuthMethods, []string{"single-sign-on-v2", "single-sign-on-external-browser"}) {
		t.Fatalf("AuthMethods = %#v", got.AuthMethods)
	}
	if got.HTTPHeaders["X-Support-HTTP-Auth"] != "true" {
		t.Fatalf("HTTPHeaders = %#v, want X-Support-HTTP-Auth", got.HTTPHeaders)
	}

	got.AuthMethods[0] = "mutated"
	got.HTTPHeaders["X-Support-HTTP-Auth"] = "mutated"
	again := cfg.EffectiveClientMimicry("vpn-gw2.corp.example/outside")
	if again.AuthMethods[0] != "single-sign-on-v2" || again.HTTPHeaders["X-Support-HTTP-Auth"] != "true" {
		t.Fatalf("EffectiveClientMimicry returned aliased data: %#v %#v", again.AuthMethods, again.HTTPHeaders)
	}
}

func TestEffectiveAuthFallbackServersUsesServerSpecificAuthConfig(t *testing.T) {
	t.Parallel()

	cfg := Config{
		Auth: AuthConfig{
			FallbackServers: []string{"global-fallback.corp.example/outside"},
		},
		Servers: map[string]ServerConfig{
			"vpn-gw2.corp.example/outside": {
				Auth: &AuthConfig{
					FallbackServers: []string{
						"vpn-gw3.corp.example/outside",
						"vpn-gw4.corp.example/outside",
					},
				},
			},
		},
	}

	got := cfg.EffectiveAuthFallbackServers("vpn-gw2.corp.example/outside")
	want := []string{"vpn-gw3.corp.example/outside", "vpn-gw4.corp.example/outside"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("EffectiveAuthFallbackServers() = %#v, want %#v", got, want)
	}

	got[0] = "mutated"
	again := cfg.EffectiveAuthFallbackServers("vpn-gw2.corp.example/outside")
	if again[0] != "vpn-gw3.corp.example/outside" {
		t.Fatalf("EffectiveAuthFallbackServers returned aliased data: %#v", again)
	}

	if got := cfg.EffectiveAuthFallbackServers("vpn-gw5.corp.example/outside"); got != nil {
		t.Fatalf("unknown server fallback servers = %#v, want nil", got)
	}
}

func TestInitWritesFullModeScaffold(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "openconnect.json")
	cfg, resolved, err := Init(path, SetupOptions{
		ServerURL: "vpn.example.com/engineering",
		Profile:   "Corp VPN",
		Auth: AuthConfig{
			UsernameKeychainAccount: "vpn-example-com-engineering/username",
			PasswordKeychainAccount: "vpn-example-com-engineering/password",
			SecondFactor: &SecondFactorConfig{
				Mode:                SecondFactorModeTOTPAuto,
				TOTPKeychainAccount: "vpn-example-com-engineering/totp_secret",
			},
		},
	})
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	if got, want := resolved, path; got != want {
		t.Fatalf("resolved = %q, want %q", got, want)
	}
	selection := cfg.DefaultSelection()
	if got, want := selection.ServerURL, "vpn.example.com/engineering"; got != want {
		t.Fatalf("selection.ServerURL = %q, want %q", got, want)
	}
	if got, want := selection.Profile, "Corp VPN"; got != want {
		t.Fatalf("selection.Profile = %q, want %q", got, want)
	}
	if got, want := cfg.EffectiveMode(selection.ServerURL, selection.Profile), "full"; got != want {
		t.Fatalf("EffectiveMode() = %q, want %q", got, want)
	}
	serverCfg, ok := cfg.Servers[selection.ServerURL]
	if !ok {
		t.Fatalf("cfg.Servers missing %q", selection.ServerURL)
	}
	if !reflect.DeepEqual(cfg.Auth, AuthConfig{}) {
		t.Fatalf("cfg.Auth = %#v, want empty legacy fallback for new scaffold", cfg.Auth)
	}
	if serverCfg.Auth == nil {
		t.Fatal("serverCfg.Auth = nil, want populated auth")
	}
	if got, want := serverCfg.Auth.UsernameKeychainAccount, "vpn-example-com-engineering/username"; got != want {
		t.Fatalf("serverCfg.Auth.UsernameKeychainAccount = %q, want %q", got, want)
	}
	if got, want := serverCfg.Auth.PasswordKeychainAccount, "vpn-example-com-engineering/password"; got != want {
		t.Fatalf("serverCfg.Auth.PasswordKeychainAccount = %q, want %q", got, want)
	}
	if serverCfg.Auth.SecondFactor == nil {
		t.Fatal("serverCfg.Auth.SecondFactor = nil, want populated second factor")
	}
	if got, want := serverCfg.Auth.SecondFactor.Mode, SecondFactorModeTOTPAuto; got != want {
		t.Fatalf("serverCfg.Auth.SecondFactor.Mode = %q, want %q", got, want)
	}
	if got, want := serverCfg.Auth.SecondFactor.TOTPKeychainAccount, "vpn-example-com-engineering/totp_secret"; got != want {
		t.Fatalf("serverCfg.Auth.SecondFactor.TOTPKeychainAccount = %q, want %q", got, want)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("Stat(path) error = %v", err)
	}
}
