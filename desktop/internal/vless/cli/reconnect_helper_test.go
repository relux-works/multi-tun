package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"multi-tun/desktop/internal/core/vpncore"
	"multi-tun/desktop/internal/vless/config"
	"multi-tun/desktop/internal/vless/model"
	"multi-tun/desktop/internal/vless/session"
	"multi-tun/desktop/internal/vless/subscription"
)

// refusedStart marks a fixture start error as one that proves nothing was left running, the way
// session.Start marks a helper refusal; its message is the wrapped error's.
type refusedStart struct{ error }

func (e refusedStart) Unwrap() error        { return e.error }
func (e refusedStart) Is(target error) bool { return target == session.ErrNothingStarted }

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
		prev := &session.CurrentSession{ID: "previous", PID: 4242, Engine: engine, ConfigPath: target, ProfileID: "old-id", ProfileName: "old", ProfileEndpoint: "203.0.113.10:443", StartOptionsRecorded: true}
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
			// A fixture start error is a refusal that left nothing running (session.ErrNothingStarted).
			return session.CurrentSession{}, refusedStart{h.startErrs[n]}
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

// Claim: the restore restarts the previous session with its own recorded start options (mode, launch
// mode, interface, bypass list, TUN addresses, overlay and system DNS, log limit, resolution), which
// differ here from the replacement's, so values taken from the replacement would fail the test.
func TestReconnectRestoreUsesStoppedSessionContext(t *testing.T) {
	h := &helperReconnect{startErrs: []error{errors.New("refused")}, prevRecord: &session.CurrentSession{
		ID: "previous", PID: 4242, Engine: config.EngineSingbox, ProfileID: "old-id", ProfileName: "old", ProfileEndpoint: "203.0.113.10:443",
		Mode: "tun", LaunchMode: config.LaunchModeSudo, InterfaceName: "utun9", BypassSuffixes: []string{"a.example"},
		LogMaxLines: 7, ResolvedProfileID: "old-resolved", ResolvedProfileName: "Old",
		StartOptionsRecorded: true, TunAddresses: []string{"172.20.9.1/30"}, OverlayDNSActive: true,
		OverlayDNSDomains: []string{"corp.example"}, SystemDNSServers: []string{"9.9.9.9"},
	}}
	path, _ := setupHelperReconnect(t, h, config.LaunchModeHelper, func([]byte) error { return nil })
	var out, errb bytes.Buffer
	if code := New(&out, &errb).Run([]string{"reconnect", "--config", path}); code != 1 || len(h.startOpts) != 2 {
		t.Fatalf("exit %d starts %d: %s", code, len(h.startOpts), errb.String())
	}
	replacement, got := h.startOpts[0], h.startOpts[1]
	// The replacement's overlay DNS is pinned empty by the package guard's render-options seam, so the
	// flag and the domains differ from the stopped record's.
	if strings.Join(replacement.TunAddresses, ",") == "172.20.9.1/30" || strings.Join(replacement.SystemDNSServers, ",") == "9.9.9.9" ||
		replacement.OverlayDNSActive || len(replacement.OverlayDNSDomains) != 0 {
		t.Fatalf("fixture: replacement must differ from the stopped record: %+v", replacement)
	}
	if got.PrivilegedLaunch.Mode != config.LaunchModeSudo || got.InterfaceName != "utun9" || got.Mode != "tun" ||
		strings.Join(got.BypassSuffixes, ",") != "a.example" || got.LogMaxLines != 7 || got.ResolvedID != "old-resolved" || got.ResolvedName != "Old" ||
		strings.Join(got.TunAddresses, ",") != "172.20.9.1/30" || !got.OverlayDNSActive ||
		strings.Join(got.OverlayDNSDomains, ",") != "corp.example" || strings.Join(got.SystemDNSServers, ",") != "9.9.9.9" {
		t.Fatalf("restore options = %+v", got)
	}
}

// Claim: the restore starts in the stopped target's cache dir, not the current config's (the two differ
// here).
func TestRestorePreviousSessionUsesStoppedTargetCacheDir(t *testing.T) {
	var dirs []string
	prevStart, prevWrite := startSessionFunc, writeRestoredConfigCLI
	startSessionFunc = func(dir, _ string, _ model.Profile, _ session.StartOptions) (session.CurrentSession, error) {
		dirs = append(dirs, dir)
		return session.CurrentSession{ID: "r"}, nil
	}
	writeRestoredConfigCLI = func(string, []byte) error { return nil }
	t.Cleanup(func() { startSessionFunc, writeRestoredConfigCLI = prevStart, prevWrite })
	cfg := config.Default()
	cfg.CacheDir = "/replacement/cache"
	rec := &session.CurrentSession{Engine: config.EngineSingbox, ConfigPath: "/x", StartOptionsRecorded: true}
	var out, errb bytes.Buffer
	New(&out, &errb).restorePreviousSession(cfg, []stopSessionResult{{target: sessionTarget{cacheDir: "/stopped/cache"}, stopped: rec}}, "/x", []byte("{}"), true)
	if len(dirs) != 1 || dirs[0] != "/stopped/cache" {
		t.Fatalf("restore cache dirs = %v: %s", dirs, errb.String())
	}
}

// Claim: a stopped record written without recorded start options (an older build) is not restored
// with guessed DNS or TUN settings; the user is told to start it and no start is attempted.
func TestRestorePreviousSessionRefusesRecordWithoutStartOptions(t *testing.T) {
	starts := 0
	prevStart := startSessionFunc
	startSessionFunc = func(string, string, model.Profile, session.StartOptions) (session.CurrentSession, error) {
		starts++
		return session.CurrentSession{}, nil
	}
	t.Cleanup(func() { startSessionFunc = prevStart })
	rec := &session.CurrentSession{Engine: config.EngineSingbox, ConfigPath: "/x"}
	var out, errb bytes.Buffer
	New(&out, &errb).restorePreviousSession(config.Default(), []stopSessionResult{{stopped: rec}}, "/x", []byte("{}"), true)
	if starts != 0 || !strings.Contains(errb.String(), "could not be restored automatically") {
		t.Fatalf("starts %d stderr %q", starts, errb.String())
	}
}

// Claim: when the launch mode cannot be resolved, reconnect refuses before stopping anything.
func TestReconnectRefusesWhenLaunchModeUnresolved(t *testing.T) {
	h := &helperReconnect{}
	path, _ := setupHelperReconnect(t, h, config.LaunchModeHelper, func([]byte) error { return nil })
	resolveLaunchModeCLI = func(string, config.PrivilegedLaunchConfig) (string, error) { return "", errors.New("probe failed") }
	var out, errb bytes.Buffer
	code := New(&out, &errb).Run([]string{"reconnect", "--config", path})
	if code != 1 || len(h.events) != 0 || !strings.Contains(errb.String(), "cannot resolve the launch mode") {
		t.Fatalf("exit %d events %v stderr %q", code, h.events, errb.String())
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
	if code != 1 || len(h.events) != 0 || !strings.Contains(errb.String(), "restoring the previous config files failed") || !strings.Contains(errb.String(), "disk full") {
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
	rec.StartOptionsRecorded = true
	a.restorePreviousSession(config.Default(), []stopSessionResult{{stopped: rec}, {stopped: rec}}, "/x", []byte("{}"), true)
	if starts != 0 || !strings.Contains(errb.String(), "could not be restored automatically") {
		t.Fatalf("starts %d stderr %q", starts, errb.String())
	}
}

// Claim: every pre-stop refusal (a missing engine executable, or the helper refusing the config)
// puts both config files a render may touch, the sing-box config and the Xray config, back to their
// exact previous bytes, and stops nothing.
func TestReconnectPreStopRefusalRestoresBothConfigFiles(t *testing.T) {
	for name, tc := range map[string]struct {
		validator func([]byte) error
		lookFails bool
	}{
		"engine missing": {validator: func([]byte) error { return nil }, lookFails: true},
		"helper refuses": {validator: refuseStack},
	} {
		h := &helperReconnect{}
		path, target := setupHelperReconnect(t, h, config.LaunchModeHelper, tc.validator)
		data, _ := os.ReadFile(path)
		os.WriteFile(path, []byte(strings.Replace(string(data), `"engine": {"type": "sing-box"}`, `"engine": {"type": "xray", "xray": {"socks_listen": "127.0.0.1", "socks_port": 21808}}`, 1)), 0o600)
		cfg, _, err := loadEffectiveConfig(path, config.SelectionOptions{})
		if err != nil {
			t.Fatal(err)
		}
		xrayPath := cfg.XrayConfigPath()
		if xrayPath == "" || xrayPath == target {
			t.Fatalf("%s: fixture xray path %q", name, xrayPath)
		}
		os.WriteFile(xrayPath, []byte(`{"previous-xray":true}`), 0o600)
		if tc.lookFails {
			prev := lookPathFunc
			lookPathFunc = func(file string) (string, error) { return "", errors.New("not found: " + file) }
			t.Cleanup(func() { lookPathFunc = prev })
		}
		var out, errb bytes.Buffer
		code := New(&out, &errb).Run([]string{"reconnect", "--config", path})
		if tc.lookFails {
			lookPathFunc = func(file string) (string, error) { return "/usr/local/bin/" + file, nil }
		}
		if code != 1 || len(h.events) != 0 {
			t.Fatalf("%s: exit %d events %v stderr %q", name, code, h.events, errb.String())
		}
		if got, _ := os.ReadFile(target); string(got) != `{"previous":true}` {
			t.Fatalf("%s: sing-box config not restored: %s", name, got)
		}
		if got, _ := os.ReadFile(xrayPath); string(got) != `{"previous-xray":true}` {
			t.Fatalf("%s: xray config not restored: %s", name, got)
		}
	}
}

// Claim: when the Xray config did not exist before a refused reconnect, the refusal removes the
// Xray file the render wrote and keeps the sing-box config's previous bytes; when that removal fails,
// the failure is reported with the Xray path. Nothing is stopped in either case. Positive control:
// the same fixture with removal working leaves no Xray file and reports no rollback failure.
func TestReconnectRefusalRemovesPreviouslyAbsentXrayConfig(t *testing.T) {
	for _, removalFails := range []bool{false, true} {
		h := &helperReconnect{}
		path, target := setupHelperReconnect(t, h, config.LaunchModeHelper, refuseStack)
		data, _ := os.ReadFile(path)
		os.WriteFile(path, []byte(strings.Replace(string(data), `"engine": {"type": "sing-box"}`, `"engine": {"type": "xray", "xray": {"socks_listen": "127.0.0.1", "socks_port": 21808}}`, 1)), 0o600)
		cfg, _, err := loadEffectiveConfig(path, config.SelectionOptions{})
		if err != nil {
			t.Fatal(err)
		}
		xrayPath := cfg.XrayConfigPath()
		if xrayPath == "" || xrayPath == target {
			t.Fatalf("fixture xray path %q", xrayPath)
		}
		os.Remove(xrayPath)
		var removed []string
		prevRemove := removeRenderedConfigCLI
		removeRenderedConfigCLI = func(p string) error {
			removed = append(removed, p)
			if removalFails && p == xrayPath {
				return errors.New("read-only file system")
			}
			return prevRemove(p)
		}
		var out, errb bytes.Buffer
		code := New(&out, &errb).Run([]string{"reconnect", "--config", path})
		removeRenderedConfigCLI = prevRemove
		if code != 1 || len(h.events) != 0 || strings.Join(removed, ",") != xrayPath {
			t.Fatalf("removalFails=%v: exit %d events %v removed %v stderr %q", removalFails, code, h.events, removed, errb.String())
		}
		if got, _ := os.ReadFile(target); string(got) != `{"previous":true}` {
			t.Fatalf("removalFails=%v: sing-box config not restored: %s", removalFails, got)
		}
		_, statErr := os.Stat(xrayPath)
		reported := strings.Contains(errb.String(), "restoring the previous config files failed") && strings.Contains(errb.String(), xrayPath)
		if !removalFails && (!errors.Is(statErr, os.ErrNotExist) || reported) {
			t.Fatalf("xray file left behind (%v) or failure reported: %q", statErr, errb.String())
		}
		if removalFails && !reported {
			t.Fatalf("failed removal not reported: %q", errb.String())
		}
	}
}

// Claim: when the replacement start is refused and the previous session is restored, the restored
// start is preceded by the fail-closed apply just like the replacement start, and followed by a
// refresh: the order is apply, start (refused), apply, start (restored), apply. Limit: the helper,
// the pf calls and name resolution are fakes.
func TestFailClosedAppliedBeforeRestoredStart(t *testing.T) {
	h := &helperReconnect{startErrs: []error{errors.New("refused")}}
	f := &fcFakes{}
	withFailClosedFakes(t, f, upIfs, map[string][]string{"chatgpt.com": {"104.18.32.47"}})
	path, _ := setupHelperReconnect(t, h, config.LaunchModeHelper, func([]byte) error { return nil })
	var order []string
	prevApply, prevReady, fixtureStart := failClosedApplyCLI, failClosedHelperReadyCLI, startSessionFunc
	failClosedApplyCLI = func(c vpncore.ServiceConfig, i, tb []string) error {
		order = append(order, "apply")
		return prevApply(c, i, tb)
	}
	failClosedHelperReadyCLI = func() bool { return true }
	startSessionFunc = func(cacheDir, configPath string, profile model.Profile, options session.StartOptions) (session.CurrentSession, error) {
		order = append(order, "start")
		s, err := fixtureStart(cacheDir, configPath, profile, options)
		if err == nil {
			s.LaunchMode = config.LaunchModeHelper
		}
		return s, err
	}
	t.Cleanup(func() {
		failClosedApplyCLI, failClosedHelperReadyCLI, startSessionFunc = prevApply, prevReady, fixtureStart
	})
	var out, errb bytes.Buffer
	code := New(&out, &errb).Run([]string{"reconnect", "--config", path})
	if code != 1 || !strings.Contains(errb.String(), "previous session restored") || strings.Join(order, ",") != "apply,start,apply,start,apply" {
		t.Fatalf("exit %d order %v stderr %q", code, order, errb.String())
	}
}

// Claim: after the replacement start fails, reconnect starts the previous session again only when
// nothing of the replacement can still run: the start error carries session.ErrNothingStarted, or
// the replacement it returned (main process and sidecars) is confirmed gone, at once or after a stop
// through its own record or its own handle. A start with no session and no marker (a lost helper
// reply), a replacement still running or of unknown state after the stop, and a current record of
// another session all block the restore; another session's record is never stopped or written.
// A replacement that cannot be stopped is recorded only when no record exists, and the operator is
// pointed to `vless-tun stop`. Limit: every session operation is a fake here; the session package
// tests cover the real marker, SessionStopped, StopIfCurrent, StopReturned and SaveCurrentIfAbsent.
func TestReconnectReconcilesUncertainStartBeforeRestore(t *testing.T) {
	replacement := session.CurrentSession{ID: "replacement", PID: 9999, Handle: "own-handle", LaunchMode: config.LaunchModeHelper}
	lostReply := errors.New("vpn core singbox.start: unexpected EOF")
	type outcome struct {
		stopped bool
		err     error
	}
	gone, running, unknown := outcome{true, nil}, outcome{false, nil}, outcome{false, errors.New("lookup denied")}
	noRecord := func(string) (session.CurrentSession, error) { return session.CurrentSession{}, os.ErrNotExist }
	ownRecord := func(string) (session.CurrentSession, error) { return replacement, nil }
	otherRecord := func(string) (session.CurrentSession, error) {
		sameIDOtherProcess := func(string) (session.CurrentSession, error) {
			return session.CurrentSession{ID: replacement.ID, PID: 7777, Handle: "other-handle", LaunchMode: config.LaunchModeHelper}, nil
		}
		return session.CurrentSession{ID: "other", PID: 7777}, nil
	}
	cases := []struct {
		name       string
		returned   session.CurrentSession
		startErr   error
		checks     []outcome // SessionStopped results, in order
		record     func(string) (session.CurrentSession, error)
		stopErr    error // from the record stop or the handle stop
		saveErr    error
		wantEvents string
		wantSaves  int
		wantErr    string
	}{
		{name: "nothing started (helper refusal)", startErr: refusedStart{errors.New("refused")}, wantEvents: "stop,start,start"},
		{name: "B1 no session, no marker (lost helper reply)", startErr: lostReply,
			wantEvents: "stop,start", wantErr: "unknown"},
		{name: "returned replacement already gone", returned: replacement, startErr: errors.New("exited"), checks: []outcome{gone},
			wantEvents: "stop,start,start"},
		{name: "own record stopped, then gone", returned: replacement, startErr: errors.New("liveness unknown"), checks: []outcome{unknown, gone},
			record: ownRecord, wantEvents: "stop,start,stop-record,start"},
		{name: "B2 sidecar still alive after the stop", returned: replacement, startErr: errors.New("exited"), checks: []outcome{running, running},
			record: noRecord, wantEvents: "stop,start,stop-handle", wantErr: "still running after the stop"},
		{name: "B2 state unknown after the stop", returned: replacement, startErr: errors.New("exited"), checks: []outcome{running, unknown},
			record: noRecord, wantEvents: "stop,start,stop-handle", wantErr: "is unknown"},
		{name: "B3 another session's record is left alone", returned: replacement, startErr: errors.New("exited"), checks: []outcome{running},
			record: otherRecord, wantEvents: "stop,start", wantErr: "left alone"},
		{name: "same ID, other process: its record is left alone", returned: replacement, startErr: errors.New("exited"), checks: []outcome{running},
			record: sameIDOtherProcess, wantEvents: "stop,start", wantErr: "left alone"},
		{name: "B4 no record, stopped through its own handle", returned: replacement, startErr: errors.New("exited"), checks: []outcome{running, gone},
			record: noRecord, wantEvents: "stop,start,stop-handle,start"},
		{name: "B4 handle stop fails, recorded for vless-tun stop", returned: replacement, startErr: errors.New("exited"), checks: []outcome{running},
			record: noRecord, stopErr: errors.New("helper refused the signal"), wantSaves: 1,
			wantEvents: "stop,start,stop-handle", wantErr: "it is now recorded, stop it with `vless-tun stop`"},
		{name: "B4 handle stop and record write fail", returned: replacement, startErr: errors.New("exited"), checks: []outcome{running},
			record: noRecord, stopErr: errors.New("helper refused the signal"), saveErr: errors.New("disk full"), wantSaves: 1,
			wantEvents: "stop,start,stop-handle", wantErr: "could not be stopped (helper refused the signal)"},
		{name: "own record, its stop fails", returned: replacement, startErr: errors.New("liveness unknown"), checks: []outcome{unknown},
			record: ownRecord, stopErr: errors.New("timeout"), wantEvents: "stop,start,stop-record", wantErr: "it is recorded, stop it with `vless-tun stop`"},
	}
	guards := []any{sessionStoppedFunc, loadCurrentFunc, stopCurrentIfFunc, stopReturnedFunc, saveCurrentIfAbsentFunc}
	t.Cleanup(func() {
		sessionStoppedFunc = guards[0].(func(session.CurrentSession) (bool, error))
		loadCurrentFunc = guards[1].(func(string) (session.CurrentSession, error))
		stopCurrentIfFunc = guards[2].(func(string, session.CurrentSession, config.PrivilegedLaunchConfig, bool, time.Duration) (session.CurrentSession, string, error))
		stopReturnedFunc = guards[3].(func(session.CurrentSession) error)
		saveCurrentIfAbsentFunc = guards[4].(func(string, session.CurrentSession) error)
	})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &helperReconnect{}
			path, _ := setupHelperReconnect(t, h, config.LaunchModeHelper, func([]byte) error { return nil })
			fixtureStart := startSessionFunc
			starts := 0
			startSessionFunc = func(cacheDir, configPath string, profile model.Profile, options session.StartOptions) (session.CurrentSession, error) {
				starts++
				if starts == 1 {
					h.events = append(h.events, "start")
					return tc.returned, tc.startErr
				}
				return fixtureStart(cacheDir, configPath, profile, options)
			}
			checks := 0
			sessionStoppedFunc = func(c session.CurrentSession) (bool, error) {
				if c.ID != replacement.ID || checks >= len(tc.checks) {
					t.Fatalf("unexpected stopped check %d of %+v", checks+1, c)
				}
				checks++
				return tc.checks[checks-1].stopped, tc.checks[checks-1].err
			}
			loadCurrentFunc = func(dir string) (session.CurrentSession, error) {
				if tc.record == nil {
					t.Fatal("unexpected record read")
				}
				return tc.record(dir)
			}
			stopCurrentIfFunc = func(_ string, expected session.CurrentSession, _ config.PrivilegedLaunchConfig, _ bool, _ time.Duration) (session.CurrentSession, string, error) {
				if !session.SameSession(expected, replacement) {
					t.Fatalf("record stop for %+v", expected)
				}
				h.events = append(h.events, "stop-record")
				return replacement, "stopped", tc.stopErr
			}
			stopReturnedFunc = func(c session.CurrentSession) error {
				if c.ID != replacement.ID || c.Handle != replacement.Handle {
					t.Fatalf("handle stop of %+v", c)
				}
				h.events = append(h.events, "stop-handle")
				return tc.stopErr
			}
			var saved []session.CurrentSession
			saveCurrentIfAbsentFunc = func(_ string, c session.CurrentSession) error {
				saved = append(saved, c)
				return tc.saveErr
			}
			var out, errb bytes.Buffer
			code := New(&out, &errb).Run([]string{"reconnect", "--config", path})
			startSessionFunc = fixtureStart
			if code != 1 || strings.Join(h.events, ",") != tc.wantEvents {
				t.Fatalf("exit %d events %v stderr %q", code, h.events, errb.String())
			}
			if checks != len(tc.checks) || len(saved) != tc.wantSaves || (tc.wantSaves > 0 && saved[0].ID != replacement.ID) {
				t.Fatalf("stopped checks %d/%d, record writes %v", checks, len(tc.checks), saved)
			}
			restored := 0
			for _, e := range strings.Split(tc.wantEvents, ",") {
				if e == "start" {
					restored++
				}
			}
			restored-- // the replacement's own start
			if blocked := strings.Contains(errb.String(), "previous session was not restored"); blocked == (restored == 1) {
				t.Fatalf("restores=%d but stderr %q", restored, errb.String())
			}
			if tc.wantErr != "" && !strings.Contains(errb.String(), tc.wantErr) {
				t.Fatalf("stderr %q lacks %q", errb.String(), tc.wantErr)
			}
		})
	}
}

// Claim: when the replacement cannot be stopped and is recorded for the operator, the public
// `vless-tun stop` then finds exactly that replacement's record, and an existing record of another
// session written meanwhile is never overwritten (the reconcile leaves it and reports the failure).
// Limit: the stop itself is a fake that reads the real record file; the helper is not involved.
func TestReconnectRecordedReplacementIsStoppableAndNeverOverwrites(t *testing.T) {
	replacement := session.CurrentSession{ID: "replacement", PID: 9999, Handle: "own-handle", LaunchMode: config.LaunchModeHelper}
	for _, race := range []bool{false, true} {
		name := "recorded, then vless-tun stop finds it"
		if race {
			name = "another record appears before the write"
		}
		t.Run(name, func(t *testing.T) {
			h := &helperReconnect{}
			path, _ := setupHelperReconnect(t, h, config.LaunchModeHelper, func([]byte) error { return nil })
			fixtureStart, fixtureStop := startSessionFunc, stopCurrentSessionFunc
			guardStopped, guardLoad, guardReturned, guardSave := sessionStoppedFunc, loadCurrentFunc, stopReturnedFunc, saveCurrentIfAbsentFunc
			t.Cleanup(func() {
				sessionStoppedFunc, loadCurrentFunc, stopReturnedFunc, saveCurrentIfAbsentFunc = guardStopped, guardLoad, guardReturned, guardSave
			})
			startSessionFunc = func(string, string, model.Profile, session.StartOptions) (session.CurrentSession, error) {
				return replacement, errors.New("exited")
			}
			sessionStoppedFunc = func(session.CurrentSession) (bool, error) { return false, nil }
			loadCurrentFunc = session.LoadCurrent
			saveCurrentIfAbsentFunc = session.SaveCurrentIfAbsent
			var cache string
			var before []byte
			stopReturnedFunc = func(session.CurrentSession) error {
				if race {
					// Another session starts and records itself between the record read and the write.
					if err := session.SaveCurrent(cache, session.CurrentSession{ID: "other", PID: 7777}); err != nil {
						t.Fatal(err)
					}
					before, _ = os.ReadFile(session.CurrentPath(cache))
				}
				return errors.New("helper refused the signal")
			}
			stopCurrentSessionFunc = func(dir string, l config.PrivilegedLaunchConfig, f bool, d time.Duration) (*session.CurrentSession, string, error) {
				if cache == "" {
					cache = dir // the first stop is reconnect's own stop of the running session
					return fixtureStop(dir, l, f, d)
				}
				rec, err := session.LoadCurrent(dir)
				if err != nil {
					return nil, "", err
				}
				return &rec, "stopped", nil
			}
			var out, errb bytes.Buffer
			if code := New(&out, &errb).Run([]string{"reconnect", "--config", path}); code != 1 || !strings.Contains(errb.String(), "previous session was not restored") {
				t.Fatalf("reconnect exit %d stderr %q", code, errb.String())
			}
			startSessionFunc = fixtureStart
			if race {
				if after, _ := os.ReadFile(session.CurrentPath(cache)); !bytes.Equal(before, after) || strings.Contains(errb.String(), "now recorded") {
					t.Fatalf("another session's record changed or claimed recorded: %s / %q", after, errb.String())
				}
				return
			}
			if !strings.Contains(errb.String(), "vless-tun stop") {
				t.Fatalf("no operator step in %q", errb.String())
			}
			out.Reset()
			if code := New(&out, &errb).Run([]string{"stop", "--config", path}); code != 0 || !strings.Contains(out.String(), "replacement") {
				t.Fatalf("vless-tun stop exit %d out %q err %q", code, out.String(), errb.String())
			}
		})
	}
}
