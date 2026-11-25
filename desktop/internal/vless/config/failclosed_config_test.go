package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func parseFailClosed(t *testing.T, raw string) ProjectConfig {
	t.Helper()
	cfg := Default()
	cfg.Network.Mode = RenderModeTun
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &cfg.FailClosed); err != nil {
			t.Fatalf("unmarshal %s: %v", raw, err)
		}
	}
	return cfg
}

// Claim: an absent fail_closed section validates and resolves to the enabled codex-only default with
// the tunnel interface taken from network.tun.interface_name.
func TestFailClosedAbsentIsCodexOnlyDefault(t *testing.T) {
	cfg := parseFailClosed(t, "")
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	p, err := cfg.FailClosedPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if !p.Enabled || len(p.Services) != 1 || p.Services[0].Name != "codex" || p.TunnelInterface != cfg.TunInterfaceName() {
		t.Fatalf("policy = %+v", p)
	}
}

// Claim: services accept catalog names and full objects in one list, and the section round-trips
// through JSON unchanged in meaning.
func TestFailClosedMixedEntriesRoundTrip(t *testing.T) {
	cfg := parseFailClosed(t, `{"enabled":true,"services":["codex","claude",{"name":"internal-llm","domains":["llm.example.net"]}]}`)
	p, err := cfg.FailClosedPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Services) != 3 || p.Services[2].Name != "internal-llm" {
		t.Fatalf("services = %+v", p.Services)
	}
	out, err := json.Marshal(cfg.FailClosed)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"enabled":true,"services":["codex","claude",{"name":"internal-llm","domains":["llm.example.net"]}]}`
	if string(out) != want {
		t.Fatalf("marshal = %s, want %s", out, want)
	}
}

// Claim: enabled=false disables, and an explicit empty list enables nothing (it does not fall back to
// the default), so the owner can turn the list off either way.
func TestFailClosedDisabledAndEmpty(t *testing.T) {
	p, err := parseFailClosed(t, `{"enabled":false}`).FailClosedPolicy()
	if err != nil || p.Enabled {
		t.Fatalf("disabled = %+v, %v", p, err)
	}
	p, err = parseFailClosed(t, `{"services":[]}`).FailClosedPolicy()
	if err != nil || len(p.Services) != 0 {
		t.Fatalf("empty list = %+v, %v", p, err)
	}
}

// Claim: Validate refuses an unknown catalog name and a bad tunnel interface, and JSON decoding refuses
// an object entry with an unknown field instead of silently dropping it.
func TestFailClosedRefusals(t *testing.T) {
	for raw, want := range map[string]string{
		`{"services":["gemini"]}`:                            "not a catalog service",
		`{"tunnel_interface":"en0"}`:                         "utun interface",
		`{"services":[{"name":"x","cidrs":["10.0.0.0/8"]}]}`: "private",
	} {
		err := parseFailClosed(t, raw).Validate()
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: Validate() = %v, want %q", raw, err, want)
		}
	}
	var fc FailClosedConfig
	if err := json.Unmarshal([]byte(`{"services":[{"name":"x","domain":["a.com"]}]}`), &fc); err == nil {
		t.Error("object with unknown field 'domain' was accepted")
	}
}
