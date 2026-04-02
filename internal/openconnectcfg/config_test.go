package openconnectcfg

import (
	"os"
	"path/filepath"
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

func TestInitWritesFullModeScaffold(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "openconnect.json")
	cfg, resolved, err := Init(path, SetupOptions{
		ServerURL: "vpn.example.com/engineering",
		Profile:   "Corp VPN",
		Auth: AuthConfig{
			UsernameKeychainAccount: "vpn-example-com-engineering/username",
			PasswordKeychainAccount: "vpn-example-com-engineering/password",
			TOTPKeychainAccount:     "vpn-example-com-engineering/totp_secret",
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
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("Stat(path) error = %v", err)
	}
}
