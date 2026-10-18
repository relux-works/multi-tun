package cli

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"multi-tun/desktop/internal/vless/config"
	"multi-tun/desktop/internal/vless/session"
	"multi-tun/desktop/internal/vless/subscription"
)

func writeProbeSelectionConfig(t *testing.T) (string, string, string, []string) {
	t.Helper()
	root := t.TempDir()
	cacheDir := filepath.Join(root, "cache")
	otherCacheDir := filepath.Join(root, "other-cache")
	configPath := filepath.Join(root, "config.json")
	uris := []string{
		"vless://00000000-0000-0000-0000-000000000001@203.0.113.1:443?type=tcp&security=reality&pbk=abc&fp=chrome&sni=one.example&sid=1#%F0%9F%87%BA%F0%9F%87%B8%20first",
		"vless://00000000-0000-0000-0000-000000000002@203.0.113.2:443?type=tcp&security=reality&pbk=abc&fp=chrome&sni=two.example&sid=1#%F0%9F%87%BA%F0%9F%87%B8%20second",
	}
	profiles, err := subscription.ParseProfiles(strings.Join(uris, "\n"))
	if err != nil {
		t.Fatalf("ParseProfiles() error = %v", err)
	}
	if err := subscription.SaveCache(cacheDir, subscription.CacheSnapshot{FetchedAt: time.Now(), Profiles: profiles, Raw: strings.Join(uris, "\n")}); err != nil {
		t.Fatalf("SaveCache() error = %v", err)
	}
	data := `{
  "current": {"server": "provider", "profile": "us"},
  "servers": {
    "provider": {
      "source": {"mode": "direct", "url": "` + uris[0] + `"},
      "cache_dir": "` + cacheDir + `",
      "artifacts": {"singbox_config_path": "` + filepath.Join(root, "sing-box.json") + `"},
      "engine": {"type": "sing-box"},
      "profiles": {"us": {"match": {"country": "US"}, "pick": "probe"}}
    },
    "other": {
      "source": {"mode": "direct", "url": "` + uris[0] + `"},
      "cache_dir": "` + otherCacheDir + `",
      "artifacts": {"singbox_config_path": "` + filepath.Join(root, "other-sing-box.json") + `"},
      "engine": {"type": "sing-box"},
      "profiles": {"default": {"selector": "first"}}
    }
  },
  "network": {"mode": "tun", "tun": {"interface_name": "utun233", "addresses": ["172.19.0.1/30"]}},
  "dns": {"proxy_resolver": {"address": "1.1.1.1", "port": 853, "tls_server_name": "cloudflare-dns.com"}}
}`
	if err := os.WriteFile(configPath, []byte(data), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return configPath, cacheDir, otherCacheDir, []string{profiles[0].ID, profiles[1].ID}
}

func prepareProbeSelection(t *testing.T, configPath string) preparedStart {
	t.Helper()
	cfg, selection, err := loadEffectiveConfig(configPath, config.SelectionOptions{})
	if err != nil {
		t.Fatalf("loadEffectiveConfig() error = %v", err)
	}
	prepared, err := New(ioDiscard{}, ioDiscard{}).prepareStart(cfg, startOptions{
		configPath: configPath,
		refresh:    false,
		refreshSet: true,
	}.withEffectiveSelection(selection))
	if err != nil {
		t.Fatalf("prepareStart() error = %v", err)
	}
	return prepared
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }

func installProbeSelectionSeams(t *testing.T, running *session.CurrentSession, alive bool) *atomic.Int32 {
	t.Helper()
	previousState := currentSessionStateForSelection
	previousDial := profileProbeDialContext
	var dials atomic.Int32
	currentSessionStateForSelection = func(string, config.PrivilegedLaunchConfig) (*session.CurrentSession, string, bool, error) {
		return running, "active", alive, nil
	}
	profileProbeDialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		if strings.HasPrefix(address, "203.0.113.1:") {
			return nil, context.DeadlineExceeded
		}
		client, server := net.Pipe()
		_ = server.Close()
		return client, nil
	}
	t.Cleanup(func() {
		currentSessionStateForSelection = previousState
		profileProbeDialContext = previousDial
	})
	return &dials
}

// A running tunnel suppresses every probe dial and keeps its persisted alias entry when that entry remains a fresh match.
func TestPrepareStartProbeUsesStickyRunningResolutionWithoutDials(t *testing.T) {
	configPath, _, _, ids := writeProbeSelectionConfig(t)
	dials := installProbeSelectionSeams(t, &session.CurrentSession{ResolvedServer: "provider", ResolvedAlias: "us", ResolvedProfileID: ids[1]}, true)

	prepared := prepareProbeSelection(t, configPath)
	if prepared.profile.ID != ids[1] || dials.Load() != 0 {
		t.Fatalf("profile=%s dials=%d, want sticky %s and zero dials", prepared.profile.ID, dials.Load(), ids[1])
	}
	if !strings.Contains(prepared.resolution.Reason, "pick reason: sticky, tunnel up") {
		t.Fatalf("reason = %q, want sticky tunnel-up reason", prepared.resolution.Reason)
	}
}

// A running tunnel with a missing persisted entry suppresses probes and falls back to the first fresh match.
func TestPrepareStartProbeUsesFirstWhenStickyResolutionIsMissing(t *testing.T) {
	configPath, _, _, ids := writeProbeSelectionConfig(t)
	dials := installProbeSelectionSeams(t, &session.CurrentSession{ResolvedServer: "provider", ResolvedAlias: "us", ResolvedProfileID: "removed"}, true)

	prepared := prepareProbeSelection(t, configPath)
	if prepared.profile.ID != ids[0] || dials.Load() != 0 {
		t.Fatalf("profile=%s dials=%d, want first %s and zero dials", prepared.profile.ID, dials.Load(), ids[0])
	}
	if !strings.Contains(prepared.resolution.Reason, "pick reason: first, probe skipped while a tunnel is up") {
		t.Fatalf("reason = %q, want first tunnel-up reason", prepared.resolution.Reason)
	}
}

// With no running tunnel, pick=probe calls the injected dialer and selects the reachable candidate.
func TestPrepareStartProbeRunsWhenNoSessionIsActive(t *testing.T) {
	configPath, _, _, ids := writeProbeSelectionConfig(t)
	dials := installProbeSelectionSeams(t, nil, false)

	prepared := prepareProbeSelection(t, configPath)
	if prepared.profile.ID != ids[1] || dials.Load() != 2 {
		t.Fatalf("profile=%s dials=%d, want reachable %s and two dials", prepared.profile.ID, dials.Load(), ids[1])
	}
}

// A session running only in another configured server cache still suppresses probes for the selected server.
func TestPrepareStartProbeChecksEveryConfiguredServerCache(t *testing.T) {
	configPath, _, otherCacheDir, ids := writeProbeSelectionConfig(t)
	previousState := currentSessionStateForSelection
	previousDial := profileProbeDialContext
	var dials atomic.Int32
	currentSessionStateForSelection = func(cacheDir string, _ config.PrivilegedLaunchConfig) (*session.CurrentSession, string, bool, error) {
		if cacheDir == otherCacheDir {
			return &session.CurrentSession{ResolvedServer: "other", ResolvedAlias: "default", ResolvedProfileID: "other-id"}, "active", true, nil
		}
		return nil, "none", false, nil
	}
	profileProbeDialContext = func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, context.DeadlineExceeded
	}
	t.Cleanup(func() {
		currentSessionStateForSelection = previousState
		profileProbeDialContext = previousDial
	})

	prepared := prepareProbeSelection(t, configPath)
	if prepared.profile.ID != ids[0] || dials.Load() != 0 {
		t.Fatalf("profile=%s dials=%d, want first %s and zero dials", prepared.profile.ID, dials.Load(), ids[0])
	}
}
