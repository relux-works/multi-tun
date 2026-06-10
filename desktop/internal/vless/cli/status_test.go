package cli

import (
	"os"
	"path/filepath"
	"testing"

	"multi-tun/desktop/internal/vless/config"
	"multi-tun/desktop/internal/vless/session"
)

func TestDeriveConnectionStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		sessionAlive     bool
		interfacePresent bool
		want             string
	}{
		{name: "tun down", sessionAlive: false, interfacePresent: false, want: "down"},
		{name: "tun degraded with session", sessionAlive: true, interfacePresent: false, want: "degraded"},
		{name: "tun degraded with interface", sessionAlive: false, interfacePresent: true, want: "degraded"},
		{name: "tun up", sessionAlive: true, interfacePresent: true, want: "up"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := deriveConnectionStatus(test.sessionAlive, test.interfacePresent)
			if got != test.want {
				t.Fatalf("deriveConnectionStatus(%t, %t) = %q, want %q", test.sessionAlive, test.interfacePresent, got, test.want)
			}
		})
	}
}

func TestActiveStatusSelectionPrefersSingleActiveServer(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	danceCache := filepath.Join(t.TempDir(), "dance-cache")
	freedomCache := filepath.Join(t.TempDir(), "freedom-cache")
	if err := os.WriteFile(configPath, []byte(`{
  "current": {"server": "dance", "profile": "default"},
  "servers": {
    "dance": {
      "source": {"mode": "direct", "url": "vless://dance@example.com:443?type=tcp&security=reality&pbk=abc&fp=chrome&sni=example.com&sid=1#dance"},
      "cache_dir": "`+danceCache+`",
      "artifacts": {"singbox_config_path": "`+filepath.Join(t.TempDir(), "dance.json")+`"},
      "engine": {"type": "sing-box"},
      "profiles": {"default": {"selector": "dance"}}
    },
    "freedom": {
      "source": {"mode": "direct", "url": "vless://freedom@example.com:443?type=tcp&security=reality&pbk=abc&fp=chrome&sni=example.com&sid=1#freedom"},
      "cache_dir": "`+freedomCache+`",
      "artifacts": {
        "singbox_config_path": "`+filepath.Join(t.TempDir(), "freedom.json")+`",
        "xray_config_path": "`+filepath.Join(t.TempDir(), "xray_freedom.json")+`"
      },
      "engine": {"type": "xray"},
      "profiles": {"default": {"selector": "freedom"}}
    }
  },
  "network": {"mode": "tun", "tun": {"interface_name": "utun233", "addresses": ["172.19.0.1/30"]}},
  "dns": {"proxy_resolver": {"address": "1.1.1.1", "port": 853, "tls_server_name": "cloudflare-dns.com"}}
}`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	previous := currentSessionStateStatus
	currentSessionStateStatus = func(cacheDir string, launch config.PrivilegedLaunchConfig) (*session.CurrentSession, string, bool, error) {
		if cacheDir == freedomCache {
			return &session.CurrentSession{ID: "freedom-active", PID: 21972}, "active", true, nil
		}
		return nil, "none", false, nil
	}
	t.Cleanup(func() {
		currentSessionStateStatus = previous
	})

	got, ok, err := activeStatusSelection(configPath)
	if err != nil {
		t.Fatalf("activeStatusSelection() error = %v", err)
	}
	if !ok {
		t.Fatal("activeStatusSelection() ok = false, want true")
	}
	if got != "freedom" {
		t.Fatalf("activeStatusSelection() = %q, want freedom", got)
	}
}

func TestActiveStatusSelectionKeepsCurrentWhenMultipleSessionsActive(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	danceCache := filepath.Join(t.TempDir(), "dance-cache")
	freedomCache := filepath.Join(t.TempDir(), "freedom-cache")
	if err := os.WriteFile(configPath, []byte(`{
  "current": {"server": "dance", "profile": "default"},
  "servers": {
    "dance": {
      "source": {"mode": "direct", "url": "vless://dance@example.com:443?type=tcp&security=reality&pbk=abc&fp=chrome&sni=example.com&sid=1#dance"},
      "cache_dir": "`+danceCache+`",
      "artifacts": {"singbox_config_path": "`+filepath.Join(t.TempDir(), "dance.json")+`"},
      "engine": {"type": "sing-box"},
      "profiles": {"default": {"selector": "dance"}}
    },
    "freedom": {
      "source": {"mode": "direct", "url": "vless://freedom@example.com:443?type=tcp&security=reality&pbk=abc&fp=chrome&sni=example.com&sid=1#freedom"},
      "cache_dir": "`+freedomCache+`",
      "artifacts": {
        "singbox_config_path": "`+filepath.Join(t.TempDir(), "freedom.json")+`",
        "xray_config_path": "`+filepath.Join(t.TempDir(), "xray_freedom.json")+`"
      },
      "engine": {"type": "xray"},
      "profiles": {"default": {"selector": "freedom"}}
    }
  },
  "network": {"mode": "tun", "tun": {"interface_name": "utun233", "addresses": ["172.19.0.1/30"]}},
  "dns": {"proxy_resolver": {"address": "1.1.1.1", "port": 853, "tls_server_name": "cloudflare-dns.com"}}
}`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	previous := currentSessionStateStatus
	currentSessionStateStatus = func(cacheDir string, launch config.PrivilegedLaunchConfig) (*session.CurrentSession, string, bool, error) {
		return &session.CurrentSession{ID: "active", PID: 21972}, "active", true, nil
	}
	t.Cleanup(func() {
		currentSessionStateStatus = previous
	})

	got, ok, err := activeStatusSelection(configPath)
	if err != nil {
		t.Fatalf("activeStatusSelection() error = %v", err)
	}
	if ok {
		t.Fatalf("activeStatusSelection() ok = true, got %q, want false for ambiguous active sessions", got)
	}
}

func TestStatusSelectionExplicit(t *testing.T) {
	if !statusSelectionExplicit("freedom", "", "", nil) {
		t.Fatal("server flag should make status selection explicit")
	}
	if !statusSelectionExplicit("", "", "", []string{"freedom"}) {
		t.Fatal("positional server should make status selection explicit")
	}
	if statusSelectionExplicit("", "", "", nil) {
		t.Fatal("empty selection should not be explicit")
	}
}
