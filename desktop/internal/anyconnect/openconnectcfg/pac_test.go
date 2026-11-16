package openconnectcfg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Claim: the most specific "pac" object wins as a whole, in the same order as
// split_include (top level < server < server profile < top-level profile entry),
// and an empty object at a more specific level disables PAC.
func TestEffectivePACPrecedence(t *testing.T) {
	cfg := Config{
		PAC: &PACConfig{URL: "http://pac.corp.example/top.pac"},
		Servers: map[string]ServerConfig{
			"corp": {
				ServerURL: "https://vpn.corp.example",
				PAC:       &PACConfig{File: "/etc/corp/server.pac"},
				Profiles: map[string]ProfileConfig{
					"outside": {Name: "Outside", PAC: &PACConfig{Script: "function FindProxyForURL(u, h) { return \"DIRECT\"; }"}},
					"plain":   {Name: "Plain"},
					"off":     {Name: "Off", PAC: &PACConfig{}},
				},
			},
		},
		Profiles: map[string]VPNConfig{
			"Pinned": {PAC: &PACConfig{URL: "http://pac.corp.example/pinned.pac"}},
		},
	}

	cases := []struct {
		name    string
		server  string
		profile string
		want    PACConfig
	}{
		{name: "top level only", server: "https://other.example", profile: "", want: PACConfig{URL: "http://pac.corp.example/top.pac"}},
		{name: "server overrides top", server: "corp", profile: "plain", want: PACConfig{File: "/etc/corp/server.pac"}},
		{name: "server profile overrides server", server: "corp", profile: "outside", want: PACConfig{Script: "function FindProxyForURL(u, h) { return \"DIRECT\"; }"}},
		{name: "empty profile object disables", server: "corp", profile: "off", want: PACConfig{}},
		{name: "top-level profile entry wins last", server: "corp", profile: "Pinned", want: PACConfig{URL: "http://pac.corp.example/pinned.pac"}},
	}
	for _, tc := range cases {
		got := cfg.EffectivePAC(tc.server, tc.profile)
		if got != tc.want {
			t.Fatalf("%s: EffectivePAC(%q, %q) = %+v, want %+v", tc.name, tc.server, tc.profile, got, tc.want)
		}
	}
	if cfg.EffectivePAC("corp", "off").Enabled() {
		t.Fatal("an empty pac object must report Enabled() == false")
	}
}

// Claim: with no "pac" key anywhere the effective PAC is empty and disabled,
// so openconnect-tun leaves the system proxy alone.
func TestEffectivePACAbsentIsDisabled(t *testing.T) {
	cfg := Config{Servers: map[string]ServerConfig{"corp": {ServerURL: "https://vpn.corp.example"}}}
	got := cfg.EffectivePAC("corp", "")
	if got.Enabled() || got != (PACConfig{}) {
		t.Fatalf("EffectivePAC without config = %+v, want empty and disabled", got)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("empty PAC must validate, got %v", err)
	}
}

// Claim: Validate accepts exactly one http(s) URL, absolute file or inline
// script, and rejects ambiguous selections, non-http schemes, relative
// (unresolved) files and URLs with control characters.
func TestPACConfigValidate(t *testing.T) {
	valid := []PACConfig{
		{URL: "http://pac.corp.example/proxy.pac"},
		{URL: "https://pac.corp.example/proxy.pac"},
		{File: "/etc/corp/proxy.pac"},
		{Script: "function FindProxyForURL(u, h) { return \"DIRECT\"; }"},
	}
	for _, cfg := range valid {
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate(%+v) = %v, want nil", cfg, err)
		}
		if !cfg.Enabled() {
			t.Fatalf("Enabled(%+v) = false, want true", cfg)
		}
	}

	invalid := []struct {
		cfg  PACConfig
		want string
	}{
		{cfg: PACConfig{URL: "http://pac.corp.example/a.pac", File: "/etc/a.pac"}, want: "only one"},
		{cfg: PACConfig{File: "/etc/a.pac", Script: "x"}, want: "only one"},
		{cfg: PACConfig{URL: "ftp://pac.corp.example/a.pac"}, want: "http or https"},
		{cfg: PACConfig{URL: "file:///etc/a.pac"}, want: "http or https"},
		{cfg: PACConfig{URL: "pac.corp.example/a.pac"}, want: "http or https"},
		{cfg: PACConfig{URL: "http://pac.corp.example/a.pac\nx"}, want: "http or https"},
		{cfg: PACConfig{File: "relative.pac"}, want: "not absolute"},
	}
	for _, tc := range invalid {
		err := tc.cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("Validate(%+v) = %v, want error containing %q", tc.cfg, err, tc.want)
		}
	}
}

// Claim: LoadOptional resolves a relative pac.file against the config file's
// directory at every level and leaves absolute paths, URLs and scripts as they are.
func TestLoadOptionalResolvesRelativePACFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	raw := `{
  "pac": {"file": "top.pac"},
  "profiles": {"Pinned": {"pac": {"file": "pinned.pac"}}},
  "servers": {
    "corp": {
      "server_url": "https://vpn.corp.example",
      "pac": {"file": "/abs/server.pac"},
      "profiles": {
        "outside": {"name": "Outside", "pac": {"file": "pacs/outside.pac"}},
        "remote": {"name": "Remote", "pac": {"url": "http://pac.corp.example/remote.pac"}}
      }
    }
  }
}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := LoadOptional(path)
	if err != nil {
		t.Fatalf("LoadOptional: %v", err)
	}
	checks := map[string]string{
		"top":     cfg.PAC.File,
		"pinned":  cfg.Profiles["Pinned"].PAC.File,
		"server":  cfg.Servers["corp"].PAC.File,
		"outside": cfg.Servers["corp"].Profiles["outside"].PAC.File,
	}
	want := map[string]string{
		"top":     filepath.Join(dir, "top.pac"),
		"pinned":  filepath.Join(dir, "pinned.pac"),
		"server":  "/abs/server.pac",
		"outside": filepath.Join(dir, "pacs", "outside.pac"),
	}
	for key, got := range checks {
		if got != want[key] {
			t.Fatalf("%s pac.file = %q, want %q", key, got, want[key])
		}
	}
	if got := cfg.Servers["corp"].Profiles["remote"].PAC.URL; got != "http://pac.corp.example/remote.pac" {
		t.Fatalf("remote pac.url changed to %q", got)
	}
	if err := cfg.EffectivePAC("corp", "outside").Validate(); err != nil {
		t.Fatalf("resolved relative file must validate: %v", err)
	}
}

// Claim: rewriting the config (set-current) keeps a relative pac.file relative;
// resolution happens only in memory for runtime use.
func TestSetCurrentKeepsRelativePACFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	raw := `{"servers": {"corp": {"server_url": "https://vpn.corp.example", "profiles": {"outside": {"name": "Outside", "pac": {"file": "outside.pac"}}}}}}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := SetCurrent(path, SelectionOptions{ServerURL: "corp", Profile: "outside"}); err != nil {
		t.Fatalf("SetCurrent: %v", err)
	}
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var back Config
	if err := json.Unmarshal(written, &back); err != nil {
		t.Fatal(err)
	}
	if got := back.Servers["corp"].Profiles["outside"].PAC.File; got != "outside.pac" {
		t.Fatalf("rewritten pac.file = %q, want the original relative %q", got, "outside.pac")
	}
}
