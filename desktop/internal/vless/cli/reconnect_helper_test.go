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

type helperReconnect struct {
	events      []string
	starts      []string // config path per start
	startErrs   []error  // per start call, in order
	prevEngine  string
	prevSidecar bool
}

// setupHelperReconnect builds a reconnect fixture whose running session was started from the
// configured sing-box path with known bytes, and returns that path.
func setupHelperReconnect(t *testing.T, h *helperReconnect, launchMode string, validator func([]byte) error) (cfgPath, target string) {
	t.Helper()
	path, cacheDir := writeStableAliasReconnectConfig(t, "vless://00000000-0000-0000-0000-000000000003@203.0.113.10:443?type=tcp&security=reality&pbk=abc&fp=chrome&sni=example.com&sid=1#%F0%9F%87%BA%F0%9F%87%B8%20USA")
	if _, err := subscription.Refresh(t.Context(), "direct", "vless://00000000-0000-0000-0000-000000000004@203.0.113.99:8443?type=tcp&security=reality&pbk=abc&fp=chrome&sni=example.com&sid=1#%F0%9F%87%BA%F0%9F%87%B8%20USA", cacheDir); err != nil {
		t.Fatalf("seed cache: %v", err)
	}
	installRefreshFailure(t, transientFetchError("temporary timeout"))
	installReconnectHarness(t)
	target = filepath.Join(filepath.Dir(path), "phantombot.json")
	if err := os.WriteFile(target, []byte(`{"previous":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	prevResolve, prevValidate, prevStop, prevStart := resolveLaunchModeCLI, validateHelperConfigCLI, stopCurrentSessionFunc, startSessionFunc
	resolveLaunchModeCLI = func(string, config.PrivilegedLaunchConfig) (string, error) { return launchMode, nil }
	validateHelperConfigCLI = validator
	engine := h.prevEngine
	if engine == "" {
		engine = config.EngineSingbox
	}
	stopCurrentSessionFunc = func(string, config.PrivilegedLaunchConfig, bool, time.Duration) (*session.CurrentSession, string, error) {
		h.events = append(h.events, "stop")
		prev := &session.CurrentSession{ID: "previous", PID: 4242, Engine: engine, ConfigPath: target, ProfileID: "old-id", ProfileName: "old", ProfileEndpoint: "203.0.113.10:443"}
		if h.prevSidecar {
			prev.Sidecars = []session.SidecarSession{{Name: "xray"}}
		}
		return prev, "stopped", nil
	}
	startSessionFunc = func(cacheDir, configPath string, profile model.Profile, options session.StartOptions) (session.CurrentSession, error) {
		h.events = append(h.events, "start")
		n := len(h.starts)
		h.starts = append(h.starts, configPath)
		if n < len(h.startErrs) && h.startErrs[n] != nil {
			return session.CurrentSession{}, h.startErrs[n]
		}
		return session.CurrentSession{ID: "s" + string(rune('1'+n)), PID: 5000 + n, ProfileName: profile.Name}, nil
	}
	t.Cleanup(func() {
		resolveLaunchModeCLI, validateHelperConfigCLI, stopCurrentSessionFunc, startSessionFunc = prevResolve, prevValidate, prevStop, prevStart
	})
	return path, target
}

var refuseStack = func([]byte) error { return errors.New("sing-box key $.inbounds[0].stack is not allowed") }

// Regression witness for the 2026-11-25 outage: in helper mode a config the helper schema refuses is
// refused before anything is stopped, and the running session's config file is put back unchanged.
func TestReconnectRefusesHelperRejectedConfigBeforeStop(t *testing.T) {
	h := &helperReconnect{}
	path, target := setupHelperReconnect(t, h, config.LaunchModeHelper, refuseStack)
	var out, errb bytes.Buffer
	code := New(&out, &errb).Run([]string{"reconnect", "--config", path})
	if code != 1 || len(h.events) != 0 {
		t.Fatalf("exit %d events %v, want 1 and nothing stopped", code, h.events)
	}
	for _, want := range []string{"vpn-core helper would refuse", "stack is not allowed", "running sessions were left untouched"} {
		if !strings.Contains(errb.String(), want) {
			t.Fatalf("stderr %q lacks %q", errb.String(), want)
		}
	}
	if data, _ := os.ReadFile(target); string(data) != `{"previous":true}` {
		t.Fatalf("running session config not restored: %s", data)
	}
}

// Positive control: outside helper mode the helper schema is not consulted (a sudo-launched sing-box
// is not bound by it), so the same refusing validator does not block the reconnect.
func TestReconnectSkipsHelperSchemaOutsideHelperMode(t *testing.T) {
	h := &helperReconnect{}
	path, _ := setupHelperReconnect(t, h, config.LaunchModeSudo, refuseStack)
	var out, errb bytes.Buffer
	if code := New(&out, &errb).Run([]string{"reconnect", "--config", path}); code != 0 || strings.Join(h.events, ",") != "stop,start" {
		t.Fatalf("exit %d events %v stderr %q", code, h.events, errb.String())
	}
}

// Claim: a config the helper accepts reconnects normally in helper mode (one stop, one start).
func TestReconnectHelperAcceptedConfig(t *testing.T) {
	h := &helperReconnect{}
	path, _ := setupHelperReconnect(t, h, config.LaunchModeHelper, func([]byte) error { return nil })
	var out, errb bytes.Buffer
	if code := New(&out, &errb).Run([]string{"reconnect", "--config", path}); code != 0 || strings.Join(h.events, ",") != "stop,start" {
		t.Fatalf("exit %d events %v stderr %q", code, h.events, errb.String())
	}
}

// Claim: when the replacement start is refused after the stop (for example a client/daemon schema
// skew the preflight cannot see), the previous config is written back and the previous session is
// started again from it; the command still fails and says the previous session was restored.
func TestReconnectRestoresPreviousSessionAfterRefusedStart(t *testing.T) {
	h := &helperReconnect{startErrs: []error{errors.New("vpn core singbox.start: refused")}}
	path, target := setupHelperReconnect(t, h, config.LaunchModeHelper, func([]byte) error { return nil })
	var out, errb bytes.Buffer
	code := New(&out, &errb).Run([]string{"reconnect", "--config", path})
	if code != 1 || strings.Join(h.events, ",") != "stop,start,start" {
		t.Fatalf("exit %d events %v stderr %q", code, h.events, errb.String())
	}
	if h.starts[1] != target || !strings.Contains(errb.String(), "previous session restored as s2") {
		t.Fatalf("restore start %v stderr %q", h.starts, errb.String())
	}
	if data, _ := os.ReadFile(target); string(data) != `{"previous":true}` {
		t.Fatalf("previous config not written back: %s", data)
	}
}

// Claim: a previous session that cannot be restored automatically (xray sidecar) is not restarted
// with a guessed config; the user is told to start it, and only one start was attempted.
func TestReconnectDoesNotGuessRestoreForSidecarSession(t *testing.T) {
	h := &helperReconnect{startErrs: []error{errors.New("refused")}, prevSidecar: true}
	path, _ := setupHelperReconnect(t, h, config.LaunchModeHelper, func([]byte) error { return nil })
	var out, errb bytes.Buffer
	code := New(&out, &errb).Run([]string{"reconnect", "--config", path})
	if code != 1 || strings.Join(h.events, ",") != "stop,start" || !strings.Contains(errb.String(), "could not be restored automatically") {
		t.Fatalf("exit %d events %v stderr %q", code, h.events, errb.String())
	}
}

// Claim: when the restore start fails too, both failures are reported and no third start happens.
func TestReconnectReportsFailedRestore(t *testing.T) {
	h := &helperReconnect{startErrs: []error{errors.New("refused"), errors.New("still refused")}}
	path, _ := setupHelperReconnect(t, h, config.LaunchModeHelper, func([]byte) error { return nil })
	var out, errb bytes.Buffer
	code := New(&out, &errb).Run([]string{"reconnect", "--config", path})
	if code != 1 || strings.Join(h.events, ",") != "stop,start,start" || !strings.Contains(errb.String(), "restore of the previous session failed") {
		t.Fatalf("exit %d events %v stderr %q", code, h.events, errb.String())
	}
}
