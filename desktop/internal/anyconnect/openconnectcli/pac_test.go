package openconnectcli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"multi-tun/desktop/internal/anyconnect/openconnectcfg"
)

// Claim: resolvePAC passes a URL through, loads a file or inline script as
// the PAC body, and returns nothing when PAC is not configured.
func TestResolvePACSources(t *testing.T) {
	body := "function FindProxyForURL(url, host) { return \"DIRECT\"; }"
	file := filepath.Join(t.TempDir(), "proxy.pac")
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name       string
		cfg        openconnectcfg.PACConfig
		wantURL    string
		wantScript string
	}{
		{name: "none", cfg: openconnectcfg.PACConfig{}},
		{name: "url", cfg: openconnectcfg.PACConfig{URL: " http://pac.corp.example/proxy.pac "}, wantURL: "http://pac.corp.example/proxy.pac"},
		{name: "file", cfg: openconnectcfg.PACConfig{File: file}, wantScript: body},
		{name: "script", cfg: openconnectcfg.PACConfig{Script: body}, wantScript: body},
	}
	for _, tc := range cases {
		url, script, err := resolvePAC(tc.cfg)
		if err != nil || url != tc.wantURL || script != tc.wantScript {
			t.Fatalf("%s: resolvePAC = (%q, %q, %v), want (%q, %q, nil)", tc.name, url, script, err, tc.wantURL, tc.wantScript)
		}
	}
}

// Claim: a configured PAC that cannot be used stops the start with a clear
// error instead of silently connecting without it.
func TestResolvePACRejectsUnusableConfig(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.pac")
	if err := os.WriteFile(empty, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	large := filepath.Join(dir, "large.pac")
	if err := os.WriteFile(large, []byte(strings.Repeat("x", pacScriptFileLimit+1)), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := map[string]openconnectcfg.PACConfig{
		"two sources":  {URL: "http://pac.corp.example/a.pac", Script: "x"},
		"bad scheme":   {URL: "file:///etc/proxy.pac"},
		"missing file": {File: filepath.Join(dir, "absent.pac")},
		"directory":    {File: dir},
		"empty file":   {File: empty},
		"large file":   {File: large},
		"large script": {Script: strings.Repeat("x", pacScriptFileLimit+1)},
	}
	for name, cfg := range cases {
		if url, script, err := resolvePAC(cfg); err == nil {
			t.Fatalf("%s: resolvePAC = (%q, %d bytes, nil), want error", name, url, len(script))
		}
	}
}
