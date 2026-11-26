package session

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"multi-tun/desktop/internal/vless/config"
	"multi-tun/desktop/internal/vless/model"
)

// The session log header records the stable alias mapping, provider identity, reason, and snapshot timestamp.
func TestWriteLogHeaderIncludesProfileResolution(t *testing.T) {
	fetchedAt := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	current := CurrentSession{
		ID:                  "session",
		StartedAt:           fetchedAt,
		ResolvedServer:      "phantombot",
		ResolvedAlias:       "us",
		ResolvedProfileName: "🇺🇸 США",
		ResolvedProfileID:   "abc123def456",
		ResolutionReason:    "match country=US; pick=probe fastest reachable",
		SnapshotFetchedAt:   &fetchedAt,
	}
	profile := model.Profile{ID: "abc123def456", Name: "🇺🇸 США", Host: "203.0.113.1", Port: 443}
	var output bytes.Buffer

	writeLogHeader(&output, current, profile)

	for _, want := range []string{
		"resolved: phantombot/us -> 🇺🇸 США (abc123def456) via match country=US; pick=probe fastest reachable",
		"snapshot_fetched_at: 2026-10-18T12:00:00Z",
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("header = %q, want %q", output.String(), want)
		}
	}
}

func TestStartWithVPNCorePropagatesTimeoutSnapshotWithoutPayload(t *testing.T) {
	// This proves helper startup sends rendered bytes, not a root-readable user path, while preserving redacted timeout context.
	previous := vpnCoreStartSingBoxSession
	timeoutErr := errors.New("vpn core rpc singbox.start timed out after 5s; helper snapshot: state=reachable daemon_pid=42 active_requests=singbox.start(age=5000ms)")
	var capturedConfig []byte
	vpnCoreStartSingBoxSession = func(configJSON []byte, _ string, _ int, _ bool) (int, string, error) {
		capturedConfig = append([]byte(nil), configJSON...)
		return 0, "", timeoutErr
	}
	t.Cleanup(func() {
		vpnCoreStartSingBoxSession = previous
	})

	secretConfigPath := filepath.Join(t.TempDir(), "credential-secret-vless.json")
	if err := os.WriteFile(secretConfigPath, []byte(`{"log":{"level":"info"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := startWithVPNCore(CurrentSession{
		ConfigPath:  secretConfigPath,
		LogPath:     "/tmp/credential-secret-vless.log",
		LogMaxLines: 100,
	})
	if !errors.Is(err, timeoutErr) {
		t.Fatalf("startWithVPNCore() error = %v, want wrapped timeout", err)
	}
	if !strings.Contains(err.Error(), "vpn core singbox.start: vpn core rpc singbox.start timed out") || !strings.Contains(err.Error(), "helper snapshot: state=reachable") {
		t.Fatalf("startWithVPNCore() error missing helper snapshot: %v", err)
	}
	if strings.Contains(err.Error(), secretConfigPath) || strings.Contains(err.Error(), "credential-secret") {
		t.Fatalf("startWithVPNCore() error leaked payload: %v", err)
	}
	if string(capturedConfig) != `{"log":{"level":"info"}}` {
		t.Fatalf("captured config = %q", capturedConfig)
	}
}

// This proves VLESS current-session persistence retains the exact interface name used for ownership attribution.
func TestSaveAndLoadCurrent(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	want := CurrentSession{
		ID:            "20260324T120000Z",
		PID:           12345,
		StartedAt:     time.Date(2026, 3, 24, 12, 0, 0, 0, time.UTC),
		Engine:        config.EngineXray,
		InterfaceName: "utun233",
		LogPath:       filepath.Join(cacheDir, "sessions", "sing-box-session-20260324T120000Z.log"),
		LaunchMode:    config.LaunchModeDirect,
		Sidecars: []SidecarSession{
			{
				Name:    "xray",
				PID:     22222,
				Command: []string{"/opt/homebrew/bin/xray", "run", "-c", "/tmp/xray.json"},
				LogPath: filepath.Join(cacheDir, "sessions", "xray-session-20260324T120000Z.log"),
			},
		},
	}

	if err := SaveCurrent(cacheDir, want); err != nil {
		t.Fatalf("SaveCurrent returned error: %v", err)
	}

	got, err := LoadCurrent(cacheDir)
	if err != nil {
		t.Fatalf("LoadCurrent returned error: %v", err)
	}
	if got.ID != want.ID || got.PID != want.PID || got.Engine != want.Engine || got.InterfaceName != want.InterfaceName || got.LogPath != want.LogPath {
		t.Fatalf("loaded session = %#v, want %#v", got, want)
	}
	if len(got.Sidecars) != 1 || got.Sidecars[0].Name != "xray" || got.Sidecars[0].PID != 22222 {
		t.Fatalf("loaded sidecars = %#v, want %#v", got.Sidecars, want.Sidecars)
	}
}

func TestLegacyHelperStopRefusesPIDFallbackWithoutHandle(t *testing.T) {
	// This proves legacy helper metadata cannot turn a stored PID into a privileged signal target when no safe direct fallback exists.
	err := stopHelperSession(CurrentSession{PID: 4242}, true, time.Second)
	if err == nil || !strings.Contains(err.Error(), "no safe direct fallback") {
		t.Fatalf("stopHelperSession() error = %v", err)
	}
}

func TestClearCurrent(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	if err := SaveCurrent(cacheDir, CurrentSession{ID: "abc", PID: 1}); err != nil {
		t.Fatalf("SaveCurrent returned error: %v", err)
	}

	if err := ClearCurrent(cacheDir); err != nil {
		t.Fatalf("ClearCurrent returned error: %v", err)
	}
	if _, err := os.Stat(CurrentPath(cacheDir)); !os.IsNotExist(err) {
		t.Fatalf("current session file still exists: %v", err)
	}
}

func TestProcessAliveCurrentProcess(t *testing.T) {
	t.Parallel()

	alive, err := ProcessAlive(os.Getpid())
	if err != nil {
		t.Fatalf("ProcessAlive returned error: %v", err)
	}
	if !alive {
		t.Fatal("expected current process to be alive")
	}
}

// Claim: a process found at start by a sidecar's executable and config path is never signalled:
// cleanupOrphanSidecars returns errOrphanSidecarRunning naming exactly the matching PID (not a process
// with another config path, not an unrelated command that mentions the path) and states only what one
// ps row observed: PID, config, command and the start time from that same row; that the process may
// be another vless-tun session's sidecar or another program; a ps check bound to that start time, with
// a reused PID left alone; stop through the owner; how to confirm the original is gone. The start time
// is never looked up again by PID, so a same-name process that reused the PID cannot lend its start
// time. A row without a start time gives no check or stop step. No owner, no stop or kill command, no
// PID or group signal in any case. Positive control: no matching process gives no error. Limit: the
// process list and signals are fakes.
func TestCleanupOrphanSidecarsReportsWithoutSignal(t *testing.T) {
	prevList, prevAlive, prevIdentity := sidecarProcessListSession, sidecarProcessAliveSession, processIdentitySession
	prevSignalPID, prevSignalGroup := sidecarSignalPIDSession, sidecarSignalGroupSession
	t.Cleanup(func() {
		sidecarProcessListSession, sidecarProcessAliveSession, processIdentitySession = prevList, prevAlive, prevIdentity
		sidecarSignalPIDSession, sidecarSignalGroupSession = prevSignalPID, prevSignalGroup
	})
	var signals []int
	sidecarSignalPIDSession = func(pid int, _ syscall.Signal) error { signals = append(signals, pid); return nil }
	sidecarSignalGroupSession = func(pid int, _ syscall.Signal) error { signals = append(signals, -pid); return nil }
	sidecarProcessAliveSession = func(int) (bool, error) { return true, nil }
	// A later lookup by PID would see a same-name process that reused the PID (another start time).
	reused := time.Date(2026, 11, 26, 7, 45, 0, 0, time.UTC)
	identityLookups := 0
	processIdentitySession = func(int) (string, time.Time, error) { identityLookups++; return "xray", reused, nil }
	options := []SidecarOptions{{Name: "xray", Executable: "/opt/homebrew/opt/xray/libexec/xray", Args: []string{"run", "-c", "/tmp/xray_freedom.json"}}}
	const cmd = "/opt/homebrew/Cellar/xray/26.3.27/libexec/xray run -c /tmp/xray_freedom.json"
	row := func(pid, pgid string, start time.Time) string {
		return " " + pid + "   1 " + pgid + " " + start.UTC().Format(psStartLayout) + " " + cmd
	}
	listed := time.Date(2026, 11, 26, 5, 0, 7, 0, time.UTC)
	later := time.Date(2026, 11, 6, 6, 30, 7, 0, time.UTC) // single-digit day: lstart pads it with a space
	for _, tc := range []struct {
		name    string
		listing []string
		pid     string    // the matching PID, or "" for no error
		start   time.Time // the start in that PID's row; zero when the row has none
	}{
		{"matching leftover", []string{
			row("111", "111", listed),
			" 222   1 222 " + listed.Format(psStartLayout) + " /opt/homebrew/Cellar/xray/26.3.27/libexec/xray run -c /tmp/xray_other.json",
			" 333   1 333 " + listed.Format(psStartLayout) + " /opt/homebrew/bin/rg xray /tmp/xray_freedom.json",
		}, "111", listed},
		{"process group differs, another start", []string{row("444", "999", later)}, "444", later},
		{"same-name process reuses the PID after the listing", []string{row("666", "666", listed)}, "666", listed},
		{"row without a start time", []string{" 555   1 555 " + cmd}, "555", time.Time{}},
		{"no matching process", []string{
			" 222   1 222 " + listed.Format(psStartLayout) + " /opt/homebrew/Cellar/xray/26.3.27/libexec/xray run -c /tmp/xray_other.json",
		}, "", time.Time{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signals, identityLookups = nil, 0
			sidecarProcessListSession = func() ([]byte, error) { return []byte(strings.Join(tc.listing, "\n")), nil }
			logPath := filepath.Join(t.TempDir(), "session.log")
			logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
			if err != nil {
				t.Fatal(err)
			}
			err = cleanupOrphanSidecars(options, logFile, time.Millisecond)
			_ = logFile.Close()
			if len(signals) != 0 || identityLookups != 0 {
				t.Fatalf("signals sent %v, identity lookups %d", signals, identityLookups)
			}
			if tc.pid == "" {
				if err != nil {
					t.Fatalf("no matching process: err %v", err)
				}
				return
			}
			msg := ""
			if err != nil {
				msg = err.Error()
			}
			if !errors.Is(err, errOrphanSidecarRunning) || strings.Contains(msg, "pid 222") || strings.Contains(msg, "pid 333") {
				t.Fatalf("err = %v, want errOrphanSidecarRunning naming only pid %s", err, tc.pid)
			}
			want := []string{
				"leftover xray sidecar process: pid " + tc.pid + ", config /tmp/xray_freedom.json, command " + cmd,
				"it may belong to another vless-tun session that uses the same Xray config, or to another program",
				"then start again",
			}
			if tc.start.IsZero() {
				want = append(want, "leave pid "+tc.pid+" alone unless whoever owns it can confirm it is this process")
				for _, absent := range []string{"started:", "check it:", "stop it:"} {
					if strings.Contains(msg, absent) {
						t.Fatalf("%q given without a start time:\n%s", absent, msg)
					}
				}
			} else {
				shown := tc.start.UTC().Format(psStartLayout)
				want = append(want,
					"started:   "+shown+" UTC ("+tc.start.UTC().Format(time.RFC3339)+")",
					"check it:  LC_ALL=C TZ=UTC0 ps -o pid,lstart,command -p "+tc.pid,
					"a start time other than "+shown+" means the original is gone and pid "+tc.pid+" was reused: leave that process alone",
					"stop it:   through the session or program that owns it",
					"confirm:   the original is gone once `ps` shows no process "+tc.pid+" or one with another start time",
				)
				if strings.Contains(msg, reused.Format(psStartLayout)) {
					t.Fatalf("the reusing process's start time was printed:\n%s", msg)
				}
			}
			for _, line := range want {
				if !strings.Contains(msg, line) {
					t.Fatalf("refusal lacks %q:\n%s", line, msg)
				}
			}
			// Negative: no stop or kill command and no ownership claim.
			for _, forbidden := range []string{"vless-tun stop", "kill ", "no vless-tun session record"} {
				if strings.Contains(msg, forbidden) {
					t.Fatalf("refusal contains %q:\n%s", forbidden, msg)
				}
			}
			body, _ := os.ReadFile(logPath)
			if !strings.Contains(string(body), "orphan_sidecar_found name=xray pid="+tc.pid) {
				t.Fatalf("session log:\n%s", body)
			}
		})
	}
}

// Claim: the process list reads each process's start time from the same row as its command, in the
// pinned C locale and UTC, including a space-padded single-digit day; a row without a start time
// still parses with a zero start. Limit: fixed rows, no live ps.
func TestParseSidecarProcessesReadsStartFromTheSameRow(t *testing.T) {
	got := parseSidecarProcesses([]byte(strings.Join([]string{
		" 111   1 111 Thu Nov 26 05:00:07 2026 /opt/bin/xray run -c /tmp/a.json",
		" 222   1 222 Fri Nov  6 06:30:07 2026 /opt/bin/xray run -c /tmp/b.json",
		" 333   1 333 /opt/bin/xray run -c /tmp/c.json",
	}, "\n")))
	want := []sidecarProcess{
		{PID: 111, PPID: 1, PGID: 111, Started: time.Date(2026, 11, 26, 5, 0, 7, 0, time.UTC), Command: "/opt/bin/xray run -c /tmp/a.json"},
		{PID: 222, PPID: 1, PGID: 222, Started: time.Date(2026, 11, 6, 6, 30, 7, 0, time.UTC), Command: "/opt/bin/xray run -c /tmp/b.json"},
		{PID: 333, PPID: 1, PGID: 333, Command: "/opt/bin/xray run -c /tmp/c.json"},
	}
	if len(got) != len(want) {
		t.Fatalf("parsed %d rows: %+v", len(got), got)
	}
	for i := range want {
		if got[i].PID != want[i].PID || got[i].Command != want[i].Command || !got[i].Started.Equal(want[i].Started) {
			t.Fatalf("row %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestCleanupOrphanSidecarsSkipsOptionsWithoutConfigPath(t *testing.T) {
	prevList := sidecarProcessListSession
	t.Cleanup(func() {
		sidecarProcessListSession = prevList
	})

	called := false
	sidecarProcessListSession = func() ([]byte, error) {
		called = true
		return nil, nil
	}

	logFile, err := os.Create(filepath.Join(t.TempDir(), "session.log"))
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	defer logFile.Close()

	err = cleanupOrphanSidecars([]SidecarOptions{
		{
			Name:       "xray",
			Executable: "xray",
			Args:       []string{"run"},
		},
	}, logFile, time.Millisecond)
	if err != nil {
		t.Fatalf("cleanupOrphanSidecars() error = %v", err)
	}
	if called {
		t.Fatal("sidecarProcessListSession was called for sidecar without config path")
	}
}

// A discovered fork replaces the starter PID and records its observed identity.
func TestWaitForSidecarStartDiscoversForkedSidecar(t *testing.T) {
	previousIdentity := processIdentitySession
	t.Cleanup(func() { processIdentitySession = previousIdentity })
	started := time.Now().Add(-time.Minute)
	var identityPIDs []int
	processIdentitySession = func(pid int) (string, time.Time, error) {
		identityPIDs = append(identityPIDs, pid)
		if pid != 777 {
			t.Fatalf("identity PID=%d, want discovered PID 777", pid)
		}
		return "xray", started, nil
	}
	prevList := sidecarProcessListSession
	prevAlive := sidecarProcessAliveSession
	t.Cleanup(func() {
		sidecarProcessListSession = prevList
		sidecarProcessAliveSession = prevAlive
	})

	sidecarProcessAliveSession = func(pid int) (bool, error) {
		if pid != 111 {
			t.Fatalf("ProcessAlive pid = %d, want initial pid 111", pid)
		}
		return false, nil
	}
	sidecarProcessListSession = func() ([]byte, error) {
		return []byte(" 777   1 777 /opt/homebrew/Cellar/xray/26.3.27/libexec/xray run -c /tmp/xray_freedom.json\n"), nil
	}

	got, err := waitForSidecarStart(SidecarSession{
		Name:        "xray",
		PID:         111,
		Command:     []string{"sudo", "-n", "/opt/bin/xray", "run"},
		ProcessComm: "sudo", ProcessStart: started.Add(-time.Hour),
		LogPath: filepath.Join(t.TempDir(), "xray.log"),
	}, SidecarOptions{
		Name:       "xray",
		Executable: "xray",
		Args:       []string{"run", "-c", "/tmp/xray_freedom.json"},
	}, time.Millisecond)
	if err != nil {
		t.Fatalf("waitForSidecarStart() error = %v", err)
	}
	if got.PID != 777 || got.ProcessComm != "xray" || !got.ProcessStart.Equal(started) || len(identityPIDs) != 1 || identityPIDs[0] != 777 {
		t.Fatalf("result=%+v identity PIDs=%v", got, identityPIDs)
	}
	if strings.Join(got.Command, " ") != "sudo -n /opt/bin/xray run" {
		t.Fatalf("original command changed: %v", got.Command)
	}
}

func TestLastRelevantLogLine(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "session.log")
	content := "=== vless-tun session start ===\n" +
		"session_id: abc\n" +
		"--- sing-box output follows ---\n" +
		"\x1b[31mFATAL\x1b[0m[0000] start service: something broke\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	got := LastRelevantLogLine(path)
	want := "FATAL[0000] start service: something broke"
	if got != want {
		t.Fatalf("LastRelevantLogLine() = %q, want %q", got, want)
	}
}

func TestResolveLaunchMode(t *testing.T) {
	prevVPNCoreAvailable := vpnCoreAvailableSession
	vpnCoreAvailableSession = func() bool { return false }
	t.Cleanup(func() {
		vpnCoreAvailableSession = prevVPNCoreAvailable
	})

	tests := []struct {
		name       string
		renderMode string
		launchMode string
		want       string
	}{
		{name: "tun explicit launchd maps to helper", renderMode: config.RenderModeTun, launchMode: config.LaunchModeLaunchd, want: config.LaunchModeHelper},
		{name: "tun explicit sudo", renderMode: config.RenderModeTun, launchMode: config.LaunchModeSudo, want: config.LaunchModeSudo},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := resolveLaunchMode(test.renderMode, config.PrivilegedLaunchConfig{Mode: test.launchMode})
			if err != nil {
				t.Fatalf("resolveLaunchMode() returned error: %v", err)
			}
			if got != test.want {
				t.Fatalf("resolveLaunchMode() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestResolveLaunchModeRejectsUnsupportedRenderMode(t *testing.T) {
	t.Parallel()

	if _, err := resolveLaunchMode("system_proxy", config.PrivilegedLaunchConfig{Mode: config.LaunchModeAuto}); err == nil {
		t.Fatal("resolveLaunchMode() error = nil, want non-nil")
	}
}

func TestResolveLaunchModeAutoPrefersVPNCore(t *testing.T) {
	prevVPNCoreAvailable := vpnCoreAvailableSession
	vpnCoreAvailableSession = func() bool { return true }
	t.Cleanup(func() {
		vpnCoreAvailableSession = prevVPNCoreAvailable
	})

	got, err := resolveLaunchMode(config.RenderModeTun, config.PrivilegedLaunchConfig{Mode: config.LaunchModeAuto})
	if err != nil {
		t.Fatalf("resolveLaunchMode() returned error: %v", err)
	}
	if got != config.LaunchModeHelper {
		t.Fatalf("resolveLaunchMode() = %q, want %q", got, config.LaunchModeHelper)
	}
}

func TestGuardNestedTunnelStartupBlocksVPNRoute(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("nested tunnel guard is only enabled on darwin")
	}

	prevRouteGetHost := routeGetHostSession
	prevNetworkConnections := networkConnectionListSession
	routeGetHostSession = func(host string) ([]byte, error) {
		if host != "203.0.113.77" {
			t.Fatalf("routeGetHostSession host = %q, want %q", host, "203.0.113.77")
		}
		return []byte("   route to: 203.0.113.77\n  interface: utun11\n"), nil
	}
	networkConnectionListSession = func() ([]byte, error) {
		return []byte(strings.Join([]string{
			`* (Connected)      1 VPN (...) "v2RayTun" [VPN:foo]`,
			`* (Connected)      2 VPN (...) "corp outside" [VPN:bar]`,
		}, "\n")), nil
	}
	t.Cleanup(func() {
		routeGetHostSession = prevRouteGetHost
		networkConnectionListSession = prevNetworkConnections
	})

	err := guardNestedTunnelStartup(model.Profile{Host: "203.0.113.77", Port: 8443}, config.RenderModeTun)
	if err == nil {
		t.Fatal("guardNestedTunnelStartup() error = nil, want non-nil")
	}
	for _, want := range []string{"203.0.113.77:8443", "utun11", "v2RayTun", "corp outside"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("guardNestedTunnelStartup() error = %q, want substring %q", err.Error(), want)
		}
	}
}

func TestGuardNestedTunnelStartupAllowsPhysicalRoute(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("nested tunnel guard is only enabled on darwin")
	}

	prevRouteGetHost := routeGetHostSession
	routeGetHostSession = func(host string) ([]byte, error) {
		return []byte("   route to: 203.0.113.77\n  interface: en0\n"), nil
	}
	t.Cleanup(func() {
		routeGetHostSession = prevRouteGetHost
	})

	if err := guardNestedTunnelStartup(model.Profile{Host: "203.0.113.77", Port: 8443}, config.RenderModeTun); err != nil {
		t.Fatalf("guardNestedTunnelStartup() error = %v, want nil", err)
	}
}

func TestStopLegacyLaunchdSessionUsesLaunchdPath(t *testing.T) {
	cacheDir := t.TempDir()
	current := CurrentSession{
		ID:          "20260328T101711Z",
		PID:         31004,
		LaunchMode:  config.LaunchModeLaunchd,
		LaunchLabel: "works.relux.vless-tun",
	}
	if err := SaveCurrent(cacheDir, current); err != nil {
		t.Fatalf("SaveCurrent() error = %v", err)
	}

	prevLaunchdPID := launchdPIDSession
	prevStopLaunchd := stopLaunchdSessionFunc
	launchdPIDSession = func(label string) (int, error) {
		if label != current.LaunchLabel {
			t.Fatalf("launchdPIDSession label = %q, want %q", label, current.LaunchLabel)
		}
		return current.PID, nil
	}
	stopCalled := false
	stopLaunchdSessionFunc = func(got CurrentSession, timeout time.Duration) error {
		stopCalled = true
		if got.LaunchLabel != current.LaunchLabel {
			t.Fatalf("stopLaunchdSessionFunc label = %q, want %q", got.LaunchLabel, current.LaunchLabel)
		}
		if got.PID != current.PID {
			t.Fatalf("stopLaunchdSessionFunc pid = %d, want %d", got.PID, current.PID)
		}
		if timeout != 2*time.Second {
			t.Fatalf("stopLaunchdSessionFunc timeout = %s, want %s", timeout, 2*time.Second)
		}
		return nil
	}
	t.Cleanup(func() {
		launchdPIDSession = prevLaunchdPID
		stopLaunchdSessionFunc = prevStopLaunchd
	})

	got, state, err := Stop(cacheDir, config.PrivilegedLaunchConfig{
		Label: current.LaunchLabel,
	}, false, 2*time.Second)
	if err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if !stopCalled {
		t.Fatal("Stop() did not use legacy launchd stop path")
	}
	if state != "stopped" {
		t.Fatalf("Stop() state = %q, want %q", state, "stopped")
	}
	if got.LaunchMode != config.LaunchModeLaunchd {
		t.Fatalf("Stop() launch_mode = %q, want %q", got.LaunchMode, config.LaunchModeLaunchd)
	}
	if _, err := os.Stat(CurrentPath(cacheDir)); !os.IsNotExist(err) {
		t.Fatalf("current session file still exists: %v", err)
	}
}

func TestResolveCurrentFallsBackToLegacyLaunchdMetadata(t *testing.T) {
	cacheDir := t.TempDir()
	current := CurrentSession{
		ID:              "20260328T101711Z",
		PID:             31004,
		StartedAt:       time.Date(2026, 3, 28, 10, 17, 11, 0, time.UTC),
		LogPath:         filepath.Join(cacheDir, "sessions", "sing-box-session-20260328T101711Z.log"),
		LaunchMode:      config.LaunchModeLaunchd,
		LaunchLabel:     "works.relux.vless-tun",
		LaunchPlistPath: "/Library/LaunchDaemons/works.relux.vless-tun.plist",
	}
	if err := os.MkdirAll(SessionsDir(cacheDir), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := saveJSON(filepath.Join(SessionsDir(cacheDir), "session-20260328T101711Z.json"), current); err != nil {
		t.Fatalf("saveJSON() error = %v", err)
	}

	prevLaunchdPID := launchdPIDSession
	launchdPIDSession = func(label string) (int, error) {
		if label != current.LaunchLabel {
			t.Fatalf("launchdPIDSession label = %q, want %q", label, current.LaunchLabel)
		}
		return 570, nil
	}
	t.Cleanup(func() {
		launchdPIDSession = prevLaunchdPID
	})

	got, err := ResolveCurrent(cacheDir, config.PrivilegedLaunchConfig{
		Label:     current.LaunchLabel,
		PlistPath: current.LaunchPlistPath,
	})
	if err != nil {
		t.Fatalf("ResolveCurrent() error = %v", err)
	}
	if got.ID != current.ID {
		t.Fatalf("ResolveCurrent() id = %q, want %q", got.ID, current.ID)
	}
	if got.PID != 570 {
		t.Fatalf("ResolveCurrent() pid = %d, want %d", got.PID, 570)
	}
	if got.LogPath != current.LogPath {
		t.Fatalf("ResolveCurrent() log_path = %q, want %q", got.LogPath, current.LogPath)
	}
	if got.LaunchMode != config.LaunchModeLaunchd {
		t.Fatalf("ResolveCurrent() launch_mode = %q, want %q", got.LaunchMode, config.LaunchModeLaunchd)
	}
}

func TestStopLegacyLaunchdSessionWithoutCurrentFileUsesFallback(t *testing.T) {
	cacheDir := t.TempDir()
	launchCfg := config.PrivilegedLaunchConfig{
		Label:     "works.relux.vless-tun",
		PlistPath: "/Library/LaunchDaemons/works.relux.vless-tun.plist",
	}

	prevLaunchdPID := launchdPIDSession
	prevStopLaunchd := stopLaunchdSessionFunc
	launchdPIDSession = func(label string) (int, error) {
		if label != launchCfg.Label {
			t.Fatalf("launchdPIDSession label = %q, want %q", label, launchCfg.Label)
		}
		return 570, nil
	}
	stopCalled := false
	stopLaunchdSessionFunc = func(got CurrentSession, timeout time.Duration) error {
		stopCalled = true
		if got.LaunchLabel != launchCfg.Label {
			t.Fatalf("stopLaunchdSessionFunc label = %q, want %q", got.LaunchLabel, launchCfg.Label)
		}
		if got.PID != 570 {
			t.Fatalf("stopLaunchdSessionFunc pid = %d, want %d", got.PID, 570)
		}
		return nil
	}
	t.Cleanup(func() {
		launchdPIDSession = prevLaunchdPID
		stopLaunchdSessionFunc = prevStopLaunchd
	})

	got, state, err := Stop(cacheDir, launchCfg, false, 2*time.Second)
	if err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if !stopCalled {
		t.Fatal("Stop() did not use legacy launchd fallback")
	}
	if state != "stopped" {
		t.Fatalf("Stop() state = %q, want %q", state, "stopped")
	}
	if got.LaunchMode != config.LaunchModeLaunchd {
		t.Fatalf("Stop() launch_mode = %q, want %q", got.LaunchMode, config.LaunchModeLaunchd)
	}
	if got.LaunchLabel != launchCfg.Label {
		t.Fatalf("Stop() launch_label = %q, want %q", got.LaunchLabel, launchCfg.Label)
	}
}

func TestScutilDNSHandoffVisibleRequiresMatchingResolverBlock(t *testing.T) {
	t.Parallel()

	current := CurrentSession{
		DNSHandoffMode:      dnsHandoffModeScutil,
		DNSHandoffInterface: "utun233",
		DNSHandoffServers:   []string{"1.1.1.1"},
	}

	visibleOutput := strings.Join([]string{
		"DNS configuration",
		"",
		"resolver #1",
		"  nameserver[0] : 192.168.1.1",
		"  if_index : 17 (en0)",
		"",
		"resolver #2",
		"  nameserver[0] : 1.1.1.1",
		"  if_index : 32 (utun233)",
	}, "\n")
	if !scutilDNSHandoffVisible(visibleOutput, current) {
		t.Fatal("scutilDNSHandoffVisible() = false, want true")
	}

	mismatchedOutput := strings.Join([]string{
		"DNS configuration",
		"",
		"resolver #1",
		"  nameserver[0] : 1.1.1.1",
		"  if_index : 17 (en0)",
		"",
		"resolver #2",
		"  nameserver[0] : 192.168.1.1",
		"  if_index : 32 (utun233)",
	}, "\n")
	if scutilDNSHandoffVisible(mismatchedOutput, current) {
		t.Fatal("scutilDNSHandoffVisible() = true, want false for mismatched resolver block")
	}
}

func TestWaitForStartupDNSReadinessRequiresConsecutiveSuccesses(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-specific startup readiness")
	}

	prevAlive := startupSessionAlive
	prevResolve := startupResolveHost
	prevScutil := startupScutilDNSDump
	t.Cleanup(func() {
		startupSessionAlive = prevAlive
		startupResolveHost = prevResolve
		startupScutilDNSDump = prevScutil
	})

	startupSessionAlive = func(current CurrentSession) (bool, int, error) {
		return true, 4242, nil
	}
	startupScutilDNSDump = func() ([]byte, error) {
		return []byte(strings.Join([]string{
			"DNS configuration",
			"",
			"resolver #1",
			"  nameserver[0] : 1.1.1.1",
			"  if_index : 32 (utun233)",
		}, "\n")), nil
	}

	call := 0
	startupResolveHost = func(ctx context.Context, host string) ([]string, error) {
		call++
		if call == 2 {
			return nil, context.DeadlineExceeded
		}
		return []string{"1.1.1.1"}, nil
	}

	logPath := filepath.Join(t.TempDir(), "session.log")
	current := CurrentSession{
		ID:                  "20260331T120000Z",
		LogPath:             logPath,
		Mode:                config.RenderModeTun,
		DNSHandoffMode:      dnsHandoffModeScutil,
		DNSHandoffInterface: "utun233",
		DNSHandoffServers:   []string{"1.1.1.1"},
	}
	options := StartOptions{
		Mode:             config.RenderModeTun,
		OverlayDNSActive: true,
	}

	if err := waitForStartupDNSReadiness(current, options, 100*time.Millisecond, 0); err != nil {
		t.Fatalf("waitForStartupDNSReadiness() error = %v", err)
	}
	if call != 6 {
		t.Fatalf("startupResolveHost call count = %d, want %d", call, 6)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	body := string(data)
	for _, needle := range []string{
		"startup_readiness_begin hosts=github.com,yandex.ru",
		"startup_readiness_pending reason=resolve yandex.ru: context deadline exceeded",
		"startup_readiness_ok hosts=github.com,yandex.ru checks=2",
	} {
		if !strings.Contains(body, needle) {
			t.Fatalf("session log missing %q:\n%s", needle, body)
		}
	}
}

func TestWaitForStartupDNSReadinessTimeoutIncludesLastIssue(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-specific startup readiness")
	}

	prevAlive := startupSessionAlive
	prevResolve := startupResolveHost
	prevScutil := startupScutilDNSDump
	t.Cleanup(func() {
		startupSessionAlive = prevAlive
		startupResolveHost = prevResolve
		startupScutilDNSDump = prevScutil
	})

	startupSessionAlive = func(current CurrentSession) (bool, int, error) {
		return true, 4242, nil
	}
	startupScutilDNSDump = func() ([]byte, error) {
		return []byte(strings.Join([]string{
			"DNS configuration",
			"",
			"resolver #1",
			"  nameserver[0] : 1.1.1.1",
			"  if_index : 32 (utun233)",
		}, "\n")), nil
	}
	startupResolveHost = func(ctx context.Context, host string) ([]string, error) {
		return nil, context.DeadlineExceeded
	}

	current := CurrentSession{
		ID:                  "20260331T120500Z",
		LogPath:             filepath.Join(t.TempDir(), "session.log"),
		Mode:                config.RenderModeTun,
		DNSHandoffMode:      dnsHandoffModeScutil,
		DNSHandoffInterface: "utun233",
		DNSHandoffServers:   []string{"1.1.1.1"},
	}
	options := StartOptions{
		Mode:             config.RenderModeTun,
		OverlayDNSActive: true,
	}

	err := waitForStartupDNSReadiness(current, options, 5*time.Millisecond, 0)
	if err == nil {
		t.Fatal("waitForStartupDNSReadiness() error = nil, want timeout")
	}
	if !strings.Contains(err.Error(), "timed out waiting for public DNS readiness") || !strings.Contains(err.Error(), "resolve github.com: context deadline exceeded") {
		t.Fatalf("waitForStartupDNSReadiness() error = %v, want timeout with last issue", err)
	}
}

// Claim: in a French locale and a non-UTC zone, the real process list still yields this test
// process's start time, and the shown check command prints exactly the printed start time; the same
// ps without the pinned LC_ALL=C TZ=UTC0 does not (negative control: the environment really differs).
// Limit: darwin only (BSD ps); the process is this test binary, read-only.
func TestOrphanGuidanceCheckMatchesPsInAnyLocale(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("BSD ps lstart is checked on darwin")
	}
	t.Setenv("LANG", "fr_FR.UTF-8")
	t.Setenv("LC_ALL", "fr_FR.UTF-8")
	t.Setenv("TZ", "Pacific/Auckland")
	out, err := sidecarProcessListSession()
	if err != nil {
		t.Fatal(err)
	}
	var self sidecarProcess
	for _, p := range parseSidecarProcesses(out) {
		if p.PID == os.Getpid() {
			self = p
		}
	}
	if self.PID == 0 || self.Started.IsZero() {
		t.Fatalf("own row %+v: no start time from the process list", self)
	}
	text := orphanSidecarGuidance(orphanSidecarTarget{Name: "xray", ConfigPath: "/tmp/x.json"}, self)
	line := func(prefix string) string {
		for _, l := range strings.Split(text, "\n") {
			if i := strings.Index(l, prefix); i >= 0 {
				return strings.TrimSpace(l[i+len(prefix):])
			}
		}
		t.Fatalf("no %q line in:\n%s", prefix, text)
		return ""
	}
	shown := strings.TrimSuffix(strings.SplitN(line("started:"), " (", 2)[0], " UTC")
	check := line("check it:")
	run := func(command string) string {
		out, err := exec.Command("/bin/sh", "-c", command).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", command, err, out)
		}
		return string(out)
	}
	if out := run(check); !strings.Contains(out, shown) {
		t.Fatalf("shown check %q printed\n%s\nwithout the printed start %q", check, out, shown)
	}
	unpinned := strings.TrimPrefix(check, "LC_ALL=C TZ=UTC0 ")
	if out := run(unpinned); strings.Contains(out, shown) {
		t.Fatalf("control: %q under fr_FR/Auckland also printed %q; the test environment does not differ", unpinned, shown)
	}
}
