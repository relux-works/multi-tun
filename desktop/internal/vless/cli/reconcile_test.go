package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"multi-tun/desktop/internal/core/vpncore"
	"multi-tun/desktop/internal/vless/config"
	"multi-tun/desktop/internal/vless/model"
	"multi-tun/desktop/internal/vless/session"
	"multi-tun/desktop/internal/vless/singbox"
	"multi-tun/desktop/internal/vless/subscription"
)

func installReconcileState(t *testing.T, current *session.CurrentSession, desired *singbox.OverlayDNS) {
	t.Helper()
	previousState, previousOptions := currentSessionStateForSelection, resolveRenderOptionsCLI
	currentSessionStateForSelection = func(string, config.PrivilegedLaunchConfig) (*session.CurrentSession, string, bool, error) {
		return current, "active", current != nil, nil
	}
	resolveRenderOptionsCLI = func(mode string) singbox.RenderOptions {
		if mode != config.RenderModeTun {
			t.Fatalf("render mode = %s", mode)
		}
		return singbox.RenderOptions{OverlayDNS: desired}
	}
	t.Cleanup(func() { currentSessionStateForSelection, resolveRenderOptionsCLI = previousState, previousOptions })
}

func TestReconcileNoActiveSession(t *testing.T) {
	for _, stale := range []bool{false, true} {
		t.Run("stale="+strconv.FormatBool(stale), func(t *testing.T) {
			path, _ := writeReconnectConfig(t, "us-east")
			installReconcileState(t, nil, nil)
			if stale {
				currentSessionStateForSelection = func(string, config.PrivilegedLaunchConfig) (*session.CurrentSession, string, bool, error) {
					return &session.CurrentSession{ID: "stopped"}, "stale", false, nil
				}
			}
			resolveRenderOptionsCLI = func(string) singbox.RenderOptions {
				t.Fatal("no session should not resolve host overlay")
				return singbox.RenderOptions{}
			}
			var stdout, stderr bytes.Buffer
			if code := New(&stdout, &stderr).Run([]string{"reconcile", "--config", path, "--force"}); code != 0 || stdout.String() != "reconcile: no active session\n" || stderr.Len() != 0 {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
		})
	}
}

func TestReconcileAlreadyConverged(t *testing.T) {
	for _, overlay := range []bool{false, true} {
		t.Run(strconv.FormatBool(overlay), func(t *testing.T) {
			path, _ := writeReconnectConfig(t, "us-east")
			current := &session.CurrentSession{OverlayDNSActive: overlay}
			var desired *singbox.OverlayDNS
			if overlay {
				current.OverlayDNSDomains = []string{" MTS.RU ", "mtsit.local", "mts.ru", ""}
				desired = &singbox.OverlayDNS{Domains: []string{"mtsit.local", "mts.ru"}, Nameservers: []string{"10.73.16.4"}}
			}
			installReconcileState(t, current, desired)
			h := installReconnectHarness(t)
			var stdout, stderr bytes.Buffer
			if code := New(&stdout, &stderr).Run([]string{"reconcile", "--config", path}); code != 0 || len(h.events) != 0 || !strings.Contains(stdout.String(), "reconcile: already converged (overlay_active="+strconv.FormatBool(overlay)+")") {
				t.Fatalf("code=%d events=%v stdout=%q stderr=%q", code, h.events, stdout.String(), stderr.String())
			}
		})
	}
}

// This exercises real reconnect preparation, the AWG renderer, cached catalog
// selection and start options. Credentials, process state and start/stop are
// fake; no tunnel, Keychain item or remote catalog is accessed.
func TestReconcilePreservesCachedAmneziaUSAcrossOverlayTransitions(t *testing.T) {
	for _, tc := range []struct {
		name                            string
		wasActive, desiredActive, force bool
		oldDomains                      []string
	}{
		{"openconnect-start", false, true, false, nil},
		{"openconnect-stop", true, false, false, []string{"mts.ru", "mtsit.local"}},
		{"force-standalone", false, false, true, nil},
		{"force-composed", true, true, true, []string{"mts.ru", "mtsit.local"}},
		{"domains-changed", true, true, false, []string{"old.example"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := installAmneziaFake(t)
			path, cfg := setupAmneziaConfig(t)
			f.items["tun-wave/amnezia/key"] = cliAWGExport(t, syntheticAWGKey(1))
			snapshot, err := refreshAmneziaSource(cfg)
			if err != nil {
				t.Fatal(err)
			}
			profile := snapshot.Profiles[0]
			// The configured default is deliberately a different server. Reconcile
			// must find the running amnezia cache and retain its alias and endpoint.
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var document map[string]any
			if err := json.Unmarshal(data, &document); err != nil {
				t.Fatal(err)
			}
			otherCache := filepath.Join(t.TempDir(), "other-cache")
			document["servers"].(map[string]any)["other"] = map[string]any{
				"source":    map[string]any{"mode": "direct", "url": "vless://00000000-0000-0000-0000-000000000000@203.0.113.2:443#other"},
				"engine":    map[string]any{"type": "sing-box"},
				"cache_dir": otherCache,
				"profiles":  map[string]any{"other": map[string]any{"selector": "other"}},
			}
			document["current"] = map[string]any{"server": "other", "profile": "other"}
			data, err = json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			current := &session.CurrentSession{ID: "running", ProfileID: profile.ID, ResolvedProfileID: profile.ID, ResolvedServer: "amnezia", ResolvedAlias: "us", OverlayDNSActive: tc.wasActive, OverlayDNSDomains: tc.oldDomains}
			var desired *singbox.OverlayDNS
			if tc.desiredActive {
				desired = &singbox.OverlayDNS{Domains: []string{"mts.ru", "mtsit.local"}, BypassDomains: []string{"vpn-ra2.mts.ru"}, Nameservers: []string{"10.73.16.4"}}
			}
			installReconcileState(t, current, desired)
			currentSessionStateForSelection = func(cache string, _ config.PrivilegedLaunchConfig) (*session.CurrentSession, string, bool, error) {
				if cache == cfg.CacheDir {
					return current, "active", true, nil
				}
				if cache != otherCache {
					t.Fatalf("unexpected cache %s", cache)
				}
				return nil, "none", false, nil
			}
			oldRefresh := refreshSourceFunc
			refreshSourceFunc = func(config.ProjectConfig) (subscription.CacheSnapshot, error) {
				t.Fatal("reconcile must pass --refresh=false")
				return subscription.CacheSnapshot{}, errors.New("unexpected refresh")
			}
			t.Cleanup(func() { refreshSourceFunc = oldRefresh })
			h := installReconnectHarness(t)
			stopCurrentSessionFunc = func(cache string, _ config.PrivilegedLaunchConfig, _ bool, _ time.Duration) (*session.CurrentSession, string, error) {
				if cache != cfg.CacheDir {
					return nil, "none", nil
				}
				h.events = append(h.events, "stop")
				return current, "stopped", nil
			}
			startSessionFunc = func(cache, configPath string, selected model.Profile, opts session.StartOptions) (session.CurrentSession, error) {
				if cache != cfg.CacheDir || configPath != cfg.SingboxConfigPath() || selected.ID != profile.ID || selected.Host != profile.Host {
					t.Fatal("reconcile changed active target or endpoint")
				}
				h.events = append(h.events, "start")
				h.startOptions = append(h.startOptions, opts)
				return session.CurrentSession{ID: "replacement"}, nil
			}
			args := []string{"reconcile", "--config", path, "--reason", tc.name}
			if tc.force {
				args = append(args, "--force")
			}
			var stdout, stderr bytes.Buffer
			if code := New(&stdout, &stderr).Run(args); code != 0 || strings.Join(h.events, ",") != "stop,start" || len(h.startOptions) != 1 {
				t.Fatalf("code=%d events=%v stdout=%q stderr=%q", code, h.events, stdout.String(), stderr.String())
			}
			opts := h.startOptions[0]
			if opts.ResolvedServer != "amnezia" || opts.ResolvedAlias != "us" || opts.ResolvedID != profile.ID || opts.Engine != config.EngineAWG || opts.OverlayDNSActive != tc.desiredActive {
				t.Fatalf("start options = %+v", opts)
			}
			if tc.desiredActive && !slices.Equal(opts.OverlayDNSDomains, desired.Domains) || !tc.desiredActive && len(opts.OverlayDNSDomains) != 0 {
				t.Fatalf("overlay domains = %v", opts.OverlayDNSDomains)
			}
			rendered, err := os.ReadFile(cfg.SingboxConfigPath())
			if err != nil {
				t.Fatal(err)
			}
			if err := vpncore.ValidateSingBoxConfig(rendered); err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(rendered, []byte("dns-overlay")) != tc.desiredActive || bytes.Contains(rendered, []byte("mts.ru")) != tc.desiredActive || !bytes.Contains(rendered, []byte("openconnect")) {
				t.Fatal("rendered overlay/process state mismatch")
			}
			if !strings.Contains(stdout.String(), "reason="+`"`+tc.name+`"`) {
				t.Fatalf("missing reason: %s", stdout.String())
			}
		})
	}
}

func TestReconcileRefusesAmbiguousOrUnreadableSession(t *testing.T) {
	for _, tc := range []string{"multiple", "unreadable", "missing-record"} {
		t.Run(tc, func(t *testing.T) {
			path, _, _, _ := writeProbeSelectionConfig(t)
			installReconcileState(t, nil, nil)
			currentSessionStateForSelection = func(string, config.PrivilegedLaunchConfig) (*session.CurrentSession, string, bool, error) {
				switch tc {
				case "unreadable":
					return nil, "unknown", false, errors.New("record unavailable")
				case "missing-record":
					return nil, "active", true, nil
				default:
					return &session.CurrentSession{ProfileID: "test"}, "active", true, nil
				}
			}
			h := installReconnectHarness(t)
			var stdout, stderr bytes.Buffer
			if code := New(&stdout, &stderr).Run([]string{"reconcile", "--config", path, "--force"}); code != 1 || len(h.events) != 0 || !strings.Contains(stderr.String(), "reconcile failed:") {
				t.Fatalf("code=%d events=%v stderr=%q", code, h.events, stderr.String())
			}
		})
	}
}

func TestReconcileRejectsInvalidArgumentsAndMissingConfig(t *testing.T) {
	for _, args := range [][]string{{"--unknown"}, {"unexpected"}, {"--force=invalid"}, {"--config"}} {
		var stdout, stderr bytes.Buffer
		if code := New(&stdout, &stderr).runReconcile(args); code != 2 {
			t.Fatalf("args=%v code=%d stderr=%q", args, code, stderr.String())
		}
	}
	var stdout, stderr bytes.Buffer
	if code := New(&stdout, &stderr).runReconcile([]string{"--config", filepath.Join(t.TempDir(), "missing")}); code != 1 || !strings.Contains(stderr.String(), "does not exist") {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
}

func TestReconcileRetainsProfileSelectorWithoutAlias(t *testing.T) {
	for _, tc := range []string{"server-only", "selector-only", "default-config"} {
		t.Run(tc, func(t *testing.T) {
			path, cache := writeReconnectConfig(t, "us-east")
			seedReconnectCache(t, cache)
			snapshot, err := subscription.LoadCache(cache)
			if err != nil {
				t.Fatal(err)
			}
			current := &session.CurrentSession{ProfileID: snapshot.Profiles[0].ID}
			if tc == "server-only" {
				current.ResolvedServer = "phantom"
			}
			installReconcileState(t, current, nil)
			h := installReconnectHarness(t)
			start := startSessionFunc
			startSessionFunc = func(cacheDir, configPath string, profile model.Profile, opts session.StartOptions) (session.CurrentSession, error) {
				if cacheDir != cache || profile.ID != current.ProfileID {
					t.Fatal("reconcile changed the cached session profile")
				}
				return start(cacheDir, configPath, profile, opts)
			}
			oldRefresh := refreshSourceFunc
			refreshSourceFunc = func(config.ProjectConfig) (subscription.CacheSnapshot, error) {
				t.Fatal("unexpected catalog refresh")
				return subscription.CacheSnapshot{}, errors.New("unexpected refresh")
			}
			t.Cleanup(func() { refreshSourceFunc = oldRefresh })
			args := []string{"reconcile", "--force", "--config", path}
			if tc == "default-config" {
				t.Setenv("TUN_WAVE_CONFIG", path)
				args = []string{"reconcile", "--force"}
			}
			var stdout, stderr bytes.Buffer
			if code := New(&stdout, &stderr).Run(args); code != 0 || strings.Join(h.events, ",") != "stop,start" || len(h.startOptions) != 1 {
				t.Fatalf("code=%d events=%v stderr=%q", code, h.events, stderr.String())
			}
		})
	}
}

func TestReconcileMissingProfileLeavesRunningSessionUntouched(t *testing.T) {
	for _, selector := range []string{"", "removed-profile"} {
		t.Run("selector="+selector, func(t *testing.T) {
			path, cache := writeReconnectConfig(t, "us-east")
			seedReconnectCache(t, cache)
			installReconcileState(t, &session.CurrentSession{ResolvedServer: "phantom", ProfileID: selector}, nil)
			h := installReconnectHarness(t)
			var stdout, stderr bytes.Buffer
			if code := New(&stdout, &stderr).Run([]string{"reconcile", "--force", "--config", path}); code != 1 || len(h.events) != 0 {
				t.Fatalf("code=%d events=%v stderr=%q", code, h.events, stderr.String())
			}
		})
	}
}
