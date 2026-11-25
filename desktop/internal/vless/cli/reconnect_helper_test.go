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
	startDirs   []string // cache dir per start
	startOpts   []session.StartOptions
	startErrs   []error // per start call, in order
	prevEngine  string
	prevSidecar bool
	prevRecord  *session.CurrentSession // overrides the default stopped record when set
	resolves    int
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
	resolveLaunchModeCLI = func(string, config.PrivilegedLaunchConfig) (string, error) { h.resolves++; return launchMode, nil }
	validateHelperConfigCLI = validator
	engine := h.prevEngine
	if engine == "" {
		engine = config.EngineSingbox
	}
	stopCurrentSessionFunc = func(string, config.PrivilegedLaunchConfig, bool, time.Duration) (*session.CurrentSession, string, error) {
		h.events = append(h.events, "stop")
		prev := &session.CurrentSession{ID: "previous", PID: 4242, Engine: engine, ConfigPath: target, ProfileID: "old-id", ProfileName: "old", ProfileEndpoint: "203.0.113.10:443"}
		if h.prevRecord != nil {
			copyRec := *h.prevRecord
			copyRec.ConfigPath = target
			prev = &copyRec
		}
		if h.prevSidecar {
			prev.Sidecars = []session.SidecarSession{{Name: "xray"}}
		}
		return prev, "stopped", nil
	}
	startSessionFunc = func(cacheDir, configPath string, profile model.Profile, options session.StartOptions) (session.CurrentSession, error) {
		h.events = append(h.events, "start")
		n := len(h.starts)
		h.starts = append(h.starts, configPath)
		h.startDirs = append(h.startDirs, cacheDir)
		h.startOpts = append(h.startOpts, options)
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

// Claim: with the Xray engine in helper mode the sing-box TUN frontend the helper launches is checked
// too; a refused frontend stops nothing.
func TestReconnectXrayHelperRejectedNoStop(t *testing.T) {
	h := &helperReconnect{}
	path, _ := setupHelperReconnect(t, h, config.LaunchModeHelper, refuseStack)
	data, _ := os.ReadFile(path)
	xrayCfg := strings.Replace(string(data), `"engine": {"type": "sing-box"}`, `"engine": {"type": "xray", "xray": {"socks_listen": "127.0.0.1", "socks_port": 21808}}`, 1)
	if xrayCfg == string(data) {
		t.Fatal("fixture engine not found")
	}
	os.WriteFile(path, []byte(xrayCfg), 0o600)
	var out, errb bytes.Buffer
	code := New(&out, &errb).Run([]string{"reconnect", "--config", path})
	if code != 1 || len(h.events) != 0 || !strings.Contains(errb.String(), "vpn-core helper would refuse") {
		t.Fatalf("exit %d events %v stderr %q", code, h.events, errb.String())
	}
}

// Claim: the launch mode is resolved once and pinned into the start, so a helper that disappears
// between the preflight and the start cannot change the mode the config was checked for.
func TestReconnectPinsLaunchModeAcrossStop(t *testing.T) {
	h := &helperReconnect{}
	path, _ := setupHelperReconnect(t, h, config.LaunchModeHelper, func([]byte) error { return nil })
	// From the second resolution on the helper looks unavailable.
	prev := resolveLaunchModeCLI
	resolveLaunchModeCLI = func(m string, l config.PrivilegedLaunchConfig) (string, error) {
		mode, err := prev(m, l)
		if h.resolves > 1 {
			return config.LaunchModeSudo, nil
		}
		return mode, err
	}
	var out, errb bytes.Buffer
	if code := New(&out, &errb).Run([]string{"reconnect", "--config", path}); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if h.resolves != 1 || len(h.startOpts) != 1 || h.startOpts[0].PrivilegedLaunch.Mode != config.LaunchModeHelper {
		t.Fatalf("resolves=%d start launch=%+v", h.resolves, h.startOpts)
	}
}

// Claim: the restore restarts the previous session in its own cache dir with its own recorded mode,
// launch mode, interface, bypass list, log limit and resolution, not the replacement's.
func TestReconnectRestoreUsesStoppedSessionContext(t *testing.T) {
	h := &helperReconnect{startErrs: []error{errors.New("refused")}, prevRecord: &session.CurrentSession{
		ID: "previous", PID: 4242, Engine: config.EngineSingbox, ProfileID: "old-id", ProfileName: "old", ProfileEndpoint: "203.0.113.10:443",
		Mode: "tun", LaunchMode: config.LaunchModeSudo, InterfaceName: "utun9", BypassSuffixes: []string{"a.example"},
		LogMaxLines: 7, ResolvedProfileID: "old-resolved", ResolvedProfileName: "Old",
	}}
	path, _ := setupHelperReconnect(t, h, config.LaunchModeHelper, func([]byte) error { return nil })
	var out, errb bytes.Buffer
	if code := New(&out, &errb).Run([]string{"reconnect", "--config", path}); code != 1 || len(h.startOpts) != 2 {
		t.Fatalf("exit %d starts %d: %s", code, len(h.startOpts), errb.String())
	}
	got := h.startOpts[1]
	if got.PrivilegedLaunch.Mode != config.LaunchModeSudo || got.InterfaceName != "utun9" || got.Mode != "tun" ||
		strings.Join(got.BypassSuffixes, ",") != "a.example" || got.LogMaxLines != 7 || got.ResolvedID != "old-resolved" || got.ResolvedName != "Old" {
		t.Fatalf("restore options = %+v", got)
	}
	if h.startDirs[1] == "" || h.startDirs[1] != h.startDirs[0] {
		t.Fatalf("restore cache dir %q, want the stopped target's %q", h.startDirs[1], h.startDirs[0])
	}
}

// Claim: when the preflight refuses and putting the previous config back fails, the failure is
// reported (not hidden behind "left untouched") and nothing is stopped.
func TestReconnectReportsFailedConfigRollback(t *testing.T) {
	h := &helperReconnect{}
	path, _ := setupHelperReconnect(t, h, config.LaunchModeHelper, refuseStack)
	prevWrite := writeRestoredConfigCLI
	writeRestoredConfigCLI = func(string, []byte) error { return errors.New("disk full") }
	t.Cleanup(func() { writeRestoredConfigCLI = prevWrite })
	var out, errb bytes.Buffer
	code := New(&out, &errb).Run([]string{"reconnect", "--config", path})
	if code != 1 || len(h.events) != 0 || !strings.Contains(errb.String(), "previous content failed: disk full") {
		t.Fatalf("exit %d events %v stderr %q", code, h.events, errb.String())
	}
}

// Claim: an unreadable current config (other than absent) refuses the reconnect before anything is
// rendered or stopped, so the running config file keeps its bytes.
func TestReconnectRefusesUnreadablePreviousConfig(t *testing.T) {
	h := &helperReconnect{}
	path, target := setupHelperReconnect(t, h, config.LaunchModeHelper, func([]byte) error { return nil })
	prevRead := readFileCLI
	readFileCLI = func(p string) ([]byte, error) {
		if p == target {
			return nil, os.ErrPermission
		}
		return prevRead(p)
	}
	t.Cleanup(func() { readFileCLI = prevRead })
	var out, errb bytes.Buffer
	code := New(&out, &errb).Run([]string{"reconnect", "--config", path})
	if code != 1 || len(h.events) != 0 || !strings.Contains(errb.String(), "cannot read the current config") {
		t.Fatalf("exit %d events %v stderr %q", code, h.events, errb.String())
	}
	if data, _ := os.ReadFile(target); string(data) != `{"previous":true}` {
		t.Fatalf("running config changed: %s", data)
	}
}

// Claim: when no config file existed before, a refused replacement leaves no rendered file behind.
func TestReconnectRemovesRenderedConfigWhenNoneExisted(t *testing.T) {
	h := &helperReconnect{}
	path, target := setupHelperReconnect(t, h, config.LaunchModeHelper, refuseStack)
	os.Remove(target)
	var out, errb bytes.Buffer
	if code := New(&out, &errb).Run([]string{"reconnect", "--config", path}); code != 1 || len(h.events) != 0 {
		t.Fatalf("exit %d events %v", code, h.events)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rendered file left behind: %v", err)
	}
}

// Claim: with more than one stopped session the restore is refused with a manual-start message and
// no start is attempted.
func TestRestorePreviousSessionRefusesMultipleSessions(t *testing.T) {
	starts := 0
	prevStart := startSessionFunc
	startSessionFunc = func(string, string, model.Profile, session.StartOptions) (session.CurrentSession, error) {
		starts++
		return session.CurrentSession{}, nil
	}
	t.Cleanup(func() { startSessionFunc = prevStart })
	rec := &session.CurrentSession{Engine: config.EngineSingbox, ConfigPath: "/x"}
	var out, errb bytes.Buffer
	a := New(&out, &errb)
	a.restorePreviousSession(config.Default(), session.StartOptions{}, []stopSessionResult{{stopped: rec}, {stopped: rec}}, "/x", []byte("{}"), true)
	if starts != 0 || !strings.Contains(errb.String(), "could not be restored automatically") {
		t.Fatalf("starts %d stderr %q", starts, errb.String())
	}
}
