package openconnect

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"multi-tun/desktop/internal/core/vpncore"
)

// Even pre-existing Connect/Stop tests cannot discover or invoke a real tunnel
// reconciler. Individual command tests install only their harmless fixture.
func init() {
	reconcileLookPathOpenConnect = func(string) (string, error) { return "", exec.ErrNotFound }
}

func captureReconcile(t *testing.T) *[]string {
	t.Helper()
	previous := reconcileTunWaveOpenConnect
	var reasons []string
	reconcileTunWaveOpenConnect = func(_ context.Context, reason string) error {
		reasons = append(reasons, reason)
		return errors.New("optional reconciliation unavailable")
	}
	t.Cleanup(func() { reconcileTunWaveOpenConnect = previous })
	return &reasons
}

func TestReconcileConnectStopAndDryRunHooks(t *testing.T) {
	withIdentitySeams(t, "openconnect", time.Now().Add(-time.Minute), nil)
	withConnectIdentitySeams(t)
	withStopCleanupSeams(t)
	reasons := captureReconcile(t)
	cache := t.TempDir()
	options := ConnectOptions{Server: "127.0.0.1", CacheDir: cache, PrivilegedMode: PrivilegedModeDirect}
	options.DryRun = true
	if _, err := Connect(options); err != nil {
		t.Fatal(err)
	}
	if len(*reasons) != 0 {
		t.Fatal("dry run reconciled")
	}
	options.DryRun = false
	if _, err := Connect(options); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*reasons, []string{"openconnect-start"}) {
		t.Fatalf("start reasons=%v", *reasons)
	}
	stopped := false
	processAliveOpenConnect = func(int) (bool, error) { return !stopped, nil }
	signalSessionOpenConnect = func(int, string, string, string) error { stopped = true; return nil }
	if _, status, err := Disconnect(cache, time.Second); err != nil || status != "stopped" {
		t.Fatalf("disconnect status=%s error=%v", status, err)
	}
	if !reflect.DeepEqual(*reasons, []string{"openconnect-start", "openconnect-stop"}) {
		t.Fatalf("reasons=%v", *reasons)
	}
}

func TestReconcileDoesNotRunOnFailedConnectOrStop(t *testing.T) {
	withIdentitySeams(t, "openconnect", time.Now(), nil)
	withConnectIdentitySeams(t)
	reasons := captureReconcile(t)
	authenticateOpenConnect = func(string, ConnectOptions, string, io.Writer, io.Writer) (*authResult, error) {
		return nil, errors.New("authentication refused")
	}
	cache := t.TempDir()
	if _, err := Connect(ConnectOptions{Server: "127.0.0.1", CacheDir: cache, PrivilegedMode: PrivilegedModeDirect}); err == nil {
		t.Fatal("failed authentication succeeded")
	}
	if err := SaveCurrent(cache, CurrentSession{ID: "test", PID: 4242}); err != nil {
		t.Fatal(err)
	}
	processAliveOpenConnect = func(int) (bool, error) { return false, errors.New("process inspection refused") }
	if _, _, err := Stop(cache, time.Millisecond); err == nil {
		t.Fatal("failed stop succeeded")
	}
	if len(*reasons) != 0 {
		t.Fatalf("failed operations reconciled: %v", *reasons)
	}
}

func TestDefaultReconcileMissingBinaryIsOptional(t *testing.T) {
	previousLookup, previousCommand := reconcileLookPathOpenConnect, reconcileCommandOpenConnect
	reconcileLookPathOpenConnect = func(string) (string, error) { return "", exec.ErrNotFound }
	reconcileCommandOpenConnect = func(context.Context, string, ...string) *exec.Cmd {
		t.Fatal("missing binary started a command")
		return nil
	}
	t.Cleanup(func() { reconcileLookPathOpenConnect, reconcileCommandOpenConnect = previousLookup, previousCommand })
	if err := defaultReconcileTunWave(context.Background(), "openconnect-start"); err != nil {
		t.Fatal(err)
	}
}

func TestDefaultReconcileResolutionAndDeadline(t *testing.T) {
	for _, target := range []string{"tun-wave", "vless-tun", "/offline/bin/tun-wave", "/offline/vless-tun/vless-tun"} {
		t.Run(target, func(t *testing.T) {
			previousLookup, previousExe, previousCommand := reconcileLookPathOpenConnect, reconcileExecutableOpenConnect, reconcileCommandOpenConnect
			reconcileExecutableOpenConnect = func() (string, error) { return "/offline/bin/openconnect-tun", nil }
			reconcileLookPathOpenConnect = func(name string) (string, error) {
				if name == target {
					return "/offline/reconciler", nil
				}
				return "", exec.ErrNotFound
			}
			calls := 0
			reconcileCommandOpenConnect = func(ctx context.Context, name string, args ...string) *exec.Cmd {
				calls++
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 30*time.Second || time.Until(deadline) < 29*time.Second {
					t.Fatal("missing bounded reconcile deadline")
				}
				if name != "/offline/reconciler" || !reflect.DeepEqual(args, []string{"reconcile", "--reason", "openconnect-stop"}) {
					t.Fatal("unexpected reconcile command")
				}
				return exec.CommandContext(ctx, "/usr/bin/true")
			}
			t.Cleanup(func() {
				reconcileLookPathOpenConnect, reconcileExecutableOpenConnect, reconcileCommandOpenConnect = previousLookup, previousExe, previousCommand
			})
			if err := defaultReconcileTunWave(context.Background(), "openconnect-stop"); err != nil || calls != 1 {
				t.Fatalf("calls=%d error=%v", calls, err)
			}
		})
	}
}

func TestDefaultReconcileHonorsCancellation(t *testing.T) {
	previousLookup, previousCommand := reconcileLookPathOpenConnect, reconcileCommandOpenConnect
	reconcileLookPathOpenConnect = func(string) (string, error) { return "/offline/reconciler", nil }
	reconcileCommandOpenConnect = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/usr/bin/true")
	}
	t.Cleanup(func() { reconcileLookPathOpenConnect, reconcileCommandOpenConnect = previousLookup, previousCommand })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := defaultReconcileTunWave(ctx, "openconnect-start"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}

func TestTypedHelperConnectPersistsHandleAndStopsByHandle(t *testing.T) {
	withIdentitySeams(t, "openconnect", time.Now().Add(-time.Minute), nil)
	withConnectIdentitySeams(t)
	withStopCleanupSeams(t)
	captureReconcile(t)
	oldResolve, oldStart, oldSignal := resolvePrivilegedModeOpenConnect, vpnCoreStartOpenConnect, vpnCoreSignalHandleOpenConnect
	resolvePrivilegedModeOpenConnect = func(string) (string, PrivilegedHelperConfig, error) {
		return PrivilegedModeHelper, PrivilegedHelperConfig{SocketPath: "/offline/helper.sock"}, nil
	}
	connectWithCookieOpenConnect = connectWithCookieTyped
	authenticateOpenConnect = func(string, ConnectOptions, string, io.Writer, io.Writer) (*authResult, error) {
		return &authResult{ConnectURL: "https://vpn.example.test/outside", Cookie: "COOKIE_TEST_SECRET", Resolve: "vpn.example.test:192.0.2.1"}, nil
	}
	var request vpncore.OpenConnectStartRequest
	vpnCoreStartOpenConnect = func(cfg vpncore.ServiceConfig, req vpncore.OpenConnectStartRequest, logPath string) (int, string, error) {
		if cfg.SocketPath != "/offline/helper.sock" || logPath == "" {
			t.Fatal("typed helper config or log lost")
		}
		request = req
		return 4242, "issued-handle", nil
	}
	stopped := false
	var signals []string
	vpnCoreSignalHandleOpenConnect = func(cfg vpncore.ServiceConfig, handle, signal string) (string, error) {
		if cfg.SocketPath != "/offline/helper.sock" || handle != "issued-handle" {
			t.Fatal("wrong stop authority")
		}
		signals = append(signals, signal)
		stopped = true
		return "", nil
	}
	t.Cleanup(func() {
		resolvePrivilegedModeOpenConnect, vpnCoreStartOpenConnect, vpnCoreSignalHandleOpenConnect = oldResolve, oldStart, oldSignal
	})
	cache := t.TempDir()
	result, err := Connect(ConnectOptions{Server: "vpn.example.test/outside", CacheDir: cache, PrivilegedMode: PrivilegedModeHelper, ClientMimicry: ClientMimicry{UserAgent: "Offline Client", OS: "mac-intel", Version: "1.2", LocalHostname: "offline-host"}})
	if err != nil {
		t.Fatal(err)
	}
	current, err := LoadCurrent(cache)
	if err != nil || current.Handle != "issued-handle" || current.PID != 4242 || result.PrivilegedMode != PrivilegedModeHelper || !reflect.DeepEqual(current.GatewayIPs, []string{"192.0.2.1"}) {
		t.Fatalf("managed session fields lost: %v", err)
	}
	if request.Cookie != "COOKIE_TEST_SECRET" || request.ServerURL != "https://vpn.example.test/outside" || request.Protocol != "anyconnect" || request.ScriptPath == "" || request.PIDFilePath == "" || request.UserAgent != "Offline Client" || request.LocalHostname != "offline-host" {
		t.Fatal("typed request lost launch inputs")
	}
	for _, arg := range current.Command {
		if arg == "--background" || strings.Contains(arg, request.Cookie) {
			t.Fatal("unsafe helper preview")
		}
	}
	raw, err := os.ReadFile(current.LogPath)
	if err != nil || strings.Contains(string(raw), request.Cookie) {
		t.Fatal("cookie leaked to log")
	}
	raw, err = os.ReadFile(current.MetadataPath)
	if err != nil || strings.Contains(string(raw), request.Cookie) || !strings.Contains(string(raw), "issued-handle") {
		t.Fatal("metadata lost handle or exposed cookie")
	}
	processAliveOpenConnect = func(int) (bool, error) { return !stopped, nil }
	if _, _, err := Stop(cache, time.Second); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(signals, []string{"-TERM"}) {
		t.Fatalf("signals=%v", signals)
	}
}

func TestHelperSignalForceUsesHandle(t *testing.T) {
	old := vpnCoreSignalHandleOpenConnect
	defer func() { vpnCoreSignalHandleOpenConnect = old }()
	called := false
	vpnCoreSignalHandleOpenConnect = func(_ vpncore.ServiceConfig, handle, signal string) (string, error) {
		called = handle == "issued" && signal == "-KILL"
		return "", nil
	}
	if err := signalCurrentOpenConnectSession(CurrentSession{PrivilegedMode: PrivilegedModeHelper, Handle: "issued"}, "-KILL", PrivilegedModeHelper); err != nil || !called {
		t.Fatalf("force handle signal missing: %v", err)
	}
}

func TestActiveOverlayDNSBypassAndGatewayExcludes(t *testing.T) {
	withIdentitySeams(t, "openconnect", time.Now(), nil)
	cache := t.TempDir()
	logPath := filepath.Join(cache, "observed.log")
	if err := os.WriteFile(logPath, []byte("vpnc_wrapper_vpngateway_route: 192.0.2.8 -> 192.0.2.254 (en0)\nvpnc_wrapper_vpngateway_route: invalid -> ignored\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	current := CurrentSession{ID: "offline", PID: 4242, Server: "https://[2001:db8::1]/outside", Mode: ConnectModeSplitInclude, VPNDomains: []string{"corp.example.test"}, BypassSuffixes: []string{"vpn.corp.example.test", "login.corp.example.test"}, VPNNameservers: []string{"192.0.2.53"}, GatewayIPs: []string{"192.0.2.9"}, LogPath: logPath}
	if err := SaveCurrent(cache, current); err != nil {
		t.Fatal(err)
	}
	dns, err := ActiveOverlayDNS(cache)
	if err != nil || dns == nil {
		t.Fatalf("overlay lookup failed: %v", err)
	}
	if !reflect.DeepEqual(dns.BypassDomains, current.BypassSuffixes) {
		t.Fatalf("bypass domains lost: %v", dns.BypassDomains)
	}
	for _, expected := range []string{"192.0.2.53/32", "192.0.2.8/32", "192.0.2.9/32", "2001:db8::1/128"} {
		found := false
		for _, route := range dns.RouteExcludes {
			if route == expected {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing route exclusion %s", expected)
		}
	}
	current.Mode, current.Server = ConnectModeFull, "vpn.corp.example/outside"
	if err := SaveCurrent(cache, current); err != nil {
		t.Fatal(err)
	}
	dns, err = ActiveOverlayDNS(cache)
	if err != nil || dns == nil || !reflect.DeepEqual(dns.BypassDomains, current.BypassSuffixes) {
		t.Fatalf("full-mode overlay lost bypass domains: %v", err)
	}

}

func TestAutomaticHelperFallbackOnlyOnUnsupportedAction(t *testing.T) {
	for _, test := range []struct {
		name, mode string
		err        error
		fallback   bool
	}{
		{"old helper auto", PrivilegedModeAuto, errors.New("unsupported vpn core action openconnect.start"), true},
		{"old helper default", "", errors.New("unsupported vpn core action openconnect.start"), true},
		{"old helper explicit", PrivilegedModeHelper, errors.New("unsupported vpn core action openconnect.start"), false},
		{"transport timeout", PrivilegedModeAuto, context.DeadlineExceeded, false},
		{"typed refusal", PrivilegedModeAuto, errors.New("openconnect script refused"), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			withIdentitySeams(t, "openconnect", time.Now().Add(-time.Minute), nil)
			withConnectIdentitySeams(t)
			captureReconcile(t)
			oldResolve := resolvePrivilegedModeOpenConnect
			resolvePrivilegedModeOpenConnect = func(string) (string, PrivilegedHelperConfig, error) {
				return PrivilegedModeHelper, PrivilegedHelperConfig{}, nil
			}
			t.Cleanup(func() { resolvePrivilegedModeOpenConnect = oldResolve })
			var modes []string
			connectWithCookieOpenConnect = func(_ *authResult, _, _, _ string, _ io.Writer, mode string, _ PrivilegedHelperConfig, _ ClientMimicry) (int, string, error) {
				modes = append(modes, mode)
				if mode == PrivilegedModeHelper {
					return 0, "", test.err
				}
				return 4242, "utun-test", nil
			}
			result, err := Connect(ConnectOptions{Server: "127.0.0.1", CacheDir: t.TempDir(), PrivilegedMode: test.mode})
			if test.fallback {
				if err != nil || result.PrivilegedMode != PrivilegedModeSudo || !reflect.DeepEqual(modes, []string{PrivilegedModeHelper, PrivilegedModeSudo}) {
					t.Fatalf("fallback modes=%v err=%v", modes, err)
				}
			} else if !errors.Is(err, test.err) || !reflect.DeepEqual(modes, []string{PrivilegedModeHelper}) {
				t.Fatalf("unsafe retry or refusal lost: modes=%v err=%v", modes, err)
			}
		})
	}
}

func TestFailedHelperStartCleanupUsesIssuedHandle(t *testing.T) {
	withIdentitySeams(t, "openconnect", time.Now(), nil)
	withFailedStartIdentitySeams(t)
	oldSignal := vpnCoreSignalHandleOpenConnect
	stopped := false
	failedStartProcessAliveOpenConnect = func(int) (bool, error) { return !stopped, nil }
	vpnCoreSignalHandleOpenConnect = func(_ vpncore.ServiceConfig, handle, signal string) (string, error) {
		if handle != "issued-handle" || signal != "-TERM" {
			t.Fatal("failed-start cleanup used wrong authority or signal")
		}
		stopped = true
		return "", nil
	}
	t.Cleanup(func() { vpnCoreSignalHandleOpenConnect = oldSignal })
	if err := cleanupFailedOpenConnectStart(CurrentSession{PID: 4242, PrivilegedMode: PrivilegedModeHelper, Handle: "issued-handle"}); err != nil || !stopped {
		t.Fatalf("cleanup failed: %v", err)
	}
}
