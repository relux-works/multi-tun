package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"multi-tun/desktop/internal/vless/config"
	"multi-tun/desktop/internal/vless/model"
	"multi-tun/desktop/internal/vless/session"
	"multi-tun/desktop/internal/vless/subscription"
)

type reconnectHarness struct {
	events  []string
	started int
}

// installReconnectHarness replaces the session stop/start seams with recorders
// so reconnect ordering can be observed without touching a real tunnel.
func installReconnectHarness(t *testing.T) *reconnectHarness {
	t.Helper()
	h := &reconnectHarness{}
	previousStop := stopCurrentSessionFunc
	previousStart := startSessionFunc
	previousLookPath := lookPathFunc
	lookPathFunc = func(file string) (string, error) {
		return "/usr/local/bin/" + file, nil
	}
	stopCurrentSessionFunc = func(cacheDir string, launch config.PrivilegedLaunchConfig, force bool, timeout time.Duration) (*session.CurrentSession, string, error) {
		h.events = append(h.events, "stop")
		return &session.CurrentSession{ID: "previous", PID: 4242}, "stopped", nil
	}
	startSessionFunc = func(cacheDir, configPath string, profile model.Profile, options session.StartOptions) (session.CurrentSession, error) {
		h.events = append(h.events, "start")
		h.started++
		return session.CurrentSession{ID: "replacement", PID: 4343}, nil
	}
	t.Cleanup(func() {
		stopCurrentSessionFunc = previousStop
		startSessionFunc = previousStart
		lookPathFunc = previousLookPath
	})
	return h
}

func installRefreshFailure(t *testing.T, err error) {
	t.Helper()
	previous := refreshSourceFunc
	refreshSourceFunc = func(cfg config.ProjectConfig) (subscription.CacheSnapshot, error) {
		return subscription.CacheSnapshot{}, err
	}
	t.Cleanup(func() {
		refreshSourceFunc = previous
	})
}

func transientFetchError(message string) error {
	return &subscription.TransientFetchError{Err: errors.New(message)}
}

func writeReconnectConfig(t *testing.T, selector string) (string, string) {
	t.Helper()
	root := t.TempDir()
	cacheDir := filepath.Join(root, "cache")
	path := filepath.Join(root, "config.json")
	if err := os.WriteFile(path, []byte(`{
  "current": {"server": "phantom", "profile": "us"},
  "servers": {
    "phantom": {
      "source": {"mode": "direct", "url": "vless://00000000-0000-0000-0000-000000000003@us.example.com:443?type=tcp&security=reality&pbk=abc&fp=chrome&sni=us.example.com&sid=1#us-east"},
      "cache_dir": "`+cacheDir+`",
      "artifacts": {"singbox_config_path": "`+filepath.Join(root, "phantom.json")+`"},
      "engine": {"type": "sing-box"},
      "profiles": {"us": {"selector": "`+selector+`"}}
    }
  },
  "network": {"mode": "tun", "tun": {"interface_name": "utun233", "addresses": ["172.19.0.1/30"]}},
  "dns": {"proxy_resolver": {"address": "1.1.1.1", "port": 853, "tls_server_name": "cloudflare-dns.com"}}
}`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path, cacheDir
}

func seedReconnectCache(t *testing.T, cacheDir string) {
	t.Helper()
	cfgSnapshot, err := subscription.Refresh(t.Context(), "direct", "vless://00000000-0000-0000-0000-000000000003@us.example.com:443?type=tcp&security=reality&pbk=abc&fp=chrome&sni=us.example.com&sid=1#us-east", cacheDir)
	if err != nil {
		t.Fatalf("seed cache: %v", err)
	}
	if len(cfgSnapshot.Profiles) != 1 {
		t.Fatalf("seed cache profiles = %d, want 1", len(cfgSnapshot.Profiles))
	}
}

// Regression for BUG-261018-owa947: when the refreshed subscription no longer
// contains the configured profile, reconnect fails without stopping the
// running session and says so.
func TestReconnectLeavesRunningSessionWhenProfileNoLongerMatches(t *testing.T) {
	path, _ := writeReconnectConfig(t, "rotated-away-id")
	h := installReconnectHarness(t)

	var stdout, stderr bytes.Buffer
	exitCode := New(&stdout, &stderr).Run([]string{"reconnect", "--config", path})

	if exitCode != 1 {
		t.Fatalf("exitCode = %d, want 1", exitCode)
	}
	if len(h.events) != 0 {
		t.Fatalf("session events = %v, want none (running session must be kept)", h.events)
	}
	if !strings.Contains(stderr.String(), "did not match any refreshed subscription profile") {
		t.Fatalf("stderr = %q, want refreshed-profile mismatch", stderr.String())
	}
	if !strings.Contains(stderr.String(), "running sessions were left untouched") {
		t.Fatalf("stderr = %q, want explicit untouched notice", stderr.String())
	}
}

// Positive control for the regression above: with a matching profile,
// reconnect stops the old session and only then starts the replacement.
func TestReconnectStopsThenStartsWhenPrepareSucceeds(t *testing.T) {
	path, _ := writeReconnectConfig(t, "us-east")
	h := installReconnectHarness(t)

	var stdout, stderr bytes.Buffer
	exitCode := New(&stdout, &stderr).Run([]string{"reconnect", "--config", path})

	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0; stderr=%q", exitCode, stderr.String())
	}
	if strings.Join(h.events, ",") != "stop,start" {
		t.Fatalf("session events = %v, want [stop start]", h.events)
	}
	if !strings.Contains(stdout.String(), "reconnected vless-tun session replacement") {
		t.Fatalf("stdout = %q, want replacement session id", stdout.String())
	}
}

// A failed refresh with a usable cache reconnects from the cache and warns;
// the warning must carry the cause but not echo the subscription URL.
func TestReconnectFallsBackToCachedSnapshotWhenRefreshFails(t *testing.T) {
	path, cacheDir := writeReconnectConfig(t, "us-east")
	seedReconnectCache(t, cacheDir)
	installRefreshFailure(t, transientFetchError("subscription request failed: net/http: TLS handshake timeout"))
	h := installReconnectHarness(t)

	var stdout, stderr bytes.Buffer
	exitCode := New(&stdout, &stderr).Run([]string{"reconnect", "--config", path})

	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0; stderr=%q", exitCode, stderr.String())
	}
	if strings.Join(h.events, ",") != "stop,start" {
		t.Fatalf("session events = %v, want [stop start]", h.events)
	}
	if !strings.Contains(stderr.String(), "warning: subscription refresh failed") || !strings.Contains(stderr.String(), "using cached snapshot") {
		t.Fatalf("stderr = %q, want cache fallback warning", stderr.String())
	}
}

// Without a cache to fall back to, a failed refresh is a hard failure and the
// running session is not stopped.
func TestReconnectFailsWithoutStoppingWhenRefreshFailsAndNoCache(t *testing.T) {
	path, _ := writeReconnectConfig(t, "us-east")
	installRefreshFailure(t, transientFetchError("subscription request failed: net/http: TLS handshake timeout"))
	h := installReconnectHarness(t)

	var stdout, stderr bytes.Buffer
	exitCode := New(&stdout, &stderr).Run([]string{"reconnect", "--config", path})

	if exitCode != 1 {
		t.Fatalf("exitCode = %d, want 1", exitCode)
	}
	if len(h.events) != 0 {
		t.Fatalf("session events = %v, want none", h.events)
	}
	if !strings.Contains(stderr.String(), "TLS handshake timeout") {
		t.Fatalf("stderr = %q, want original refresh cause", stderr.String())
	}
}

// A selection failure against a cached fallback snapshot is labelled as
// cached, not refreshed, so the operator knows the data may be stale.
func TestReconnectLabelsCachedSnapshotInSelectionError(t *testing.T) {
	path, cacheDir := writeReconnectConfig(t, "rotated-away-id")
	seedReconnectCache(t, cacheDir)
	installRefreshFailure(t, transientFetchError("subscription request failed: i/o timeout"))
	h := installReconnectHarness(t)

	var stdout, stderr bytes.Buffer
	exitCode := New(&stdout, &stderr).Run([]string{"reconnect", "--config", path})

	if exitCode != 1 || len(h.events) != 0 {
		t.Fatalf("exitCode = %d events = %v, want 1 and none", exitCode, h.events)
	}
	if !strings.Contains(stderr.String(), "did not match any cached subscription profile") {
		t.Fatalf("stderr = %q, want cached-profile mismatch", stderr.String())
	}
}

// connect/disconnect are accepted as aliases (as in openconnect-tun) instead of
// failing as unknown commands; an unknown verb still fails with exit 2.
func TestConnectAndDisconnectAliasesAreAccepted(t *testing.T) {
	path, _ := writeReconnectConfig(t, "us-east")
	h := installReconnectHarness(t)

	var stdout, stderr bytes.Buffer
	app := New(&stdout, &stderr)
	if code := app.Run([]string{"connect", "--config", path}); code != 0 {
		t.Fatalf("connect exitCode = %d, want 0; stderr=%q", code, stderr.String())
	}
	if code := app.Run([]string{"disconnect", "--config", path}); code != 0 {
		t.Fatalf("disconnect exitCode = %d, want 0; stderr=%q", code, stderr.String())
	}
	if h.started != 1 || !strings.Contains(strings.Join(h.events, ","), "stop") {
		t.Fatalf("session events = %v started=%d, want one start and a stop", h.events, h.started)
	}
	if code := app.Run([]string{"konnect"}); code != 2 {
		t.Fatalf("unknown command exitCode = %d, want 2", code)
	}
}

// A refused (4xx) or unparsable subscription is not transient: reconnect must
// not fall back to possibly revoked cached credentials, and must not stop the
// running session either.
func TestReconnectDoesNotFallBackOnNonTransientRefreshErrors(t *testing.T) {
	for _, cause := range []error{
		errors.New("subscription request failed with status 403 Forbidden"),
		errors.New("parse vless profile: missing uuid"),
	} {
		t.Run(cause.Error(), func(t *testing.T) {
			path, cacheDir := writeReconnectConfig(t, "us-east")
			seedReconnectCache(t, cacheDir)
			installRefreshFailure(t, cause)
			h := installReconnectHarness(t)

			var stdout, stderr bytes.Buffer
			exitCode := New(&stdout, &stderr).Run([]string{"reconnect", "--config", path})

			if exitCode != 1 || len(h.events) != 0 {
				t.Fatalf("exitCode = %d events = %v, want 1 and none", exitCode, h.events)
			}
			if strings.Contains(stderr.String(), "using cached snapshot") {
				t.Fatalf("stderr = %q, must not fall back to the cache", stderr.String())
			}
			if !strings.Contains(stderr.String(), cause.Error()) {
				t.Fatalf("stderr = %q, want cause %q", stderr.String(), cause.Error())
			}
		})
	}
}

// A replacement whose engine executable is missing is caught before anything
// is stopped.
func TestReconnectPreflightMissingExecutableLeavesSessions(t *testing.T) {
	path, _ := writeReconnectConfig(t, "us-east")
	h := installReconnectHarness(t)
	lookPathFunc = func(file string) (string, error) {
		return "", errors.New("executable file not found in $PATH")
	}

	var stdout, stderr bytes.Buffer
	exitCode := New(&stdout, &stderr).Run([]string{"reconnect", "--config", path})

	if exitCode != 1 || len(h.events) != 0 {
		t.Fatalf("exitCode = %d events = %v, want 1 and none", exitCode, h.events)
	}
	if !strings.Contains(stderr.String(), "sing-box executable not found") || !strings.Contains(stderr.String(), "left untouched") {
		t.Fatalf("stderr = %q, want preflight failure and untouched notice", stderr.String())
	}
}

// With --refresh=false and no cache the loader fetches fresh, so a selection
// error must be labelled "refreshed", not "cached".
func TestReconnectNoRefreshWithoutCacheLabelsFreshSnapshot(t *testing.T) {
	path, _ := writeReconnectConfig(t, "rotated-away-id")
	h := installReconnectHarness(t)

	var stdout, stderr bytes.Buffer
	exitCode := New(&stdout, &stderr).Run([]string{"reconnect", "--config", path, "--refresh=false"})

	if exitCode != 1 || len(h.events) != 0 {
		t.Fatalf("exitCode = %d events = %v, want 1 and none", exitCode, h.events)
	}
	if !strings.Contains(stderr.String(), "did not match any refreshed subscription profile") {
		t.Fatalf("stderr = %q, want refreshed label", stderr.String())
	}
}
