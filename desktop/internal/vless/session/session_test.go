package session

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"multi-tun/desktop/internal/vless/config"
	"multi-tun/desktop/internal/vless/model"
)

func TestSaveAndLoadCurrent(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	want := CurrentSession{
		ID:         "20260324T120000Z",
		PID:        12345,
		StartedAt:  time.Date(2026, 3, 24, 12, 0, 0, 0, time.UTC),
		Engine:     config.EngineXray,
		LogPath:    filepath.Join(cacheDir, "sessions", "sing-box-session-20260324T120000Z.log"),
		LaunchMode: config.LaunchModeDirect,
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
	if got.ID != want.ID || got.PID != want.PID || got.Engine != want.Engine || got.LogPath != want.LogPath {
		t.Fatalf("loaded session = %#v, want %#v", got, want)
	}
	if len(got.Sidecars) != 1 || got.Sidecars[0].Name != "xray" || got.Sidecars[0].PID != 22222 {
		t.Fatalf("loaded sidecars = %#v, want %#v", got.Sidecars, want.Sidecars)
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

func TestCleanupOrphanSidecarsKillsOnlyMatchingConfigProcess(t *testing.T) {
	prevList := sidecarProcessListSession
	prevAlive := sidecarProcessAliveSession
	prevSignalPID := sidecarSignalPIDSession
	prevSignalGroup := sidecarSignalGroupSession
	t.Cleanup(func() {
		sidecarProcessListSession = prevList
		sidecarProcessAliveSession = prevAlive
		sidecarSignalPIDSession = prevSignalPID
		sidecarSignalGroupSession = prevSignalGroup
	})

	sidecarProcessListSession = func() ([]byte, error) {
		return []byte(strings.Join([]string{
			" 111   1 111 /opt/homebrew/Cellar/xray/26.3.27/libexec/xray run -c /tmp/xray_freedom.json",
			" 222   1 222 /opt/homebrew/Cellar/xray/26.3.27/libexec/xray run -c /tmp/xray_other.json",
			" 333   1 333 /opt/homebrew/bin/rg xray /tmp/xray_freedom.json",
		}, "\n")), nil
	}
	sidecarProcessAliveSession = func(pid int) (bool, error) {
		return false, nil
	}

	var pidSignals []int
	var groupSignals []int
	sidecarSignalPIDSession = func(pid int, signal syscall.Signal) error {
		if signal != syscall.SIGTERM {
			t.Fatalf("sidecarSignalPIDSession signal = %v, want SIGTERM", signal)
		}
		pidSignals = append(pidSignals, pid)
		return nil
	}
	sidecarSignalGroupSession = func(pid int, signal syscall.Signal) error {
		if signal != syscall.SIGTERM {
			t.Fatalf("sidecarSignalGroupSession signal = %v, want SIGTERM", signal)
		}
		groupSignals = append(groupSignals, pid)
		return nil
	}

	logPath := filepath.Join(t.TempDir(), "session.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatalf("OpenFile() error = %v", err)
	}

	err = cleanupOrphanSidecars([]SidecarOptions{
		{
			Name:       "xray",
			Executable: "/opt/homebrew/opt/xray/libexec/xray",
			Args:       []string{"run", "-c", "/tmp/xray_freedom.json"},
		},
	}, logFile, time.Millisecond)
	if closeErr := logFile.Close(); closeErr != nil {
		t.Fatalf("Close() error = %v", closeErr)
	}
	if err != nil {
		t.Fatalf("cleanupOrphanSidecars() error = %v", err)
	}

	if len(pidSignals) != 0 {
		t.Fatalf("pid signals = %#v, want none", pidSignals)
	}
	if len(groupSignals) != 1 || groupSignals[0] != 111 {
		t.Fatalf("group signals = %#v, want [111]", groupSignals)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	body := string(data)
	for _, want := range []string{
		"orphan_sidecar_cleanup_begin targets=xray:/tmp/xray_freedom.json",
		"orphan_sidecar_cleanup_kill name=xray pid=111",
		"orphan_sidecar_cleanup_done killed=1",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("session log missing %q:\n%s", want, body)
		}
	}
}

func TestCleanupOrphanSidecarsUsesPIDWhenProcessGroupDiffers(t *testing.T) {
	prevList := sidecarProcessListSession
	prevAlive := sidecarProcessAliveSession
	prevSignalPID := sidecarSignalPIDSession
	prevSignalGroup := sidecarSignalGroupSession
	t.Cleanup(func() {
		sidecarProcessListSession = prevList
		sidecarProcessAliveSession = prevAlive
		sidecarSignalPIDSession = prevSignalPID
		sidecarSignalGroupSession = prevSignalGroup
	})

	sidecarProcessListSession = func() ([]byte, error) {
		return []byte(" 444   1 999 /opt/homebrew/Cellar/xray/26.3.27/libexec/xray run -c=/tmp/xray_freedom.json\n"), nil
	}
	sidecarProcessAliveSession = func(pid int) (bool, error) {
		return false, nil
	}

	var pidSignals []int
	var groupSignals []int
	sidecarSignalPIDSession = func(pid int, signal syscall.Signal) error {
		pidSignals = append(pidSignals, pid)
		return nil
	}
	sidecarSignalGroupSession = func(pid int, signal syscall.Signal) error {
		groupSignals = append(groupSignals, pid)
		return nil
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
			Args:       []string{"run", "-c=/tmp/xray_freedom.json"},
		},
	}, logFile, time.Millisecond)
	if err != nil {
		t.Fatalf("cleanupOrphanSidecars() error = %v", err)
	}

	if len(groupSignals) != 0 {
		t.Fatalf("group signals = %#v, want none", groupSignals)
	}
	if len(pidSignals) != 1 || pidSignals[0] != 444 {
		t.Fatalf("pid signals = %#v, want [444]", pidSignals)
	}
}

func TestCleanupOrphanSidecarsFallsBackToPIDWhenGroupSignalDenied(t *testing.T) {
	prevList := sidecarProcessListSession
	prevAlive := sidecarProcessAliveSession
	prevSignalPID := sidecarSignalPIDSession
	prevSignalGroup := sidecarSignalGroupSession
	t.Cleanup(func() {
		sidecarProcessListSession = prevList
		sidecarProcessAliveSession = prevAlive
		sidecarSignalPIDSession = prevSignalPID
		sidecarSignalGroupSession = prevSignalGroup
	})

	sidecarProcessListSession = func() ([]byte, error) {
		return []byte(" 555   1 555 /opt/homebrew/Cellar/xray/26.3.27/libexec/xray run -c /tmp/xray_freedom.json\n"), nil
	}
	sidecarProcessAliveSession = func(pid int) (bool, error) {
		return false, nil
	}

	var pidSignals []int
	var groupSignals []int
	sidecarSignalGroupSession = func(pid int, signal syscall.Signal) error {
		groupSignals = append(groupSignals, pid)
		return syscall.EPERM
	}
	sidecarSignalPIDSession = func(pid int, signal syscall.Signal) error {
		pidSignals = append(pidSignals, pid)
		return nil
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
			Args:       []string{"run", "-c", "/tmp/xray_freedom.json"},
		},
	}, logFile, time.Millisecond)
	if err != nil {
		t.Fatalf("cleanupOrphanSidecars() error = %v", err)
	}
	if len(groupSignals) != 1 || groupSignals[0] != 555 {
		t.Fatalf("group signals = %#v, want [555]", groupSignals)
	}
	if len(pidSignals) != 1 || pidSignals[0] != 555 {
		t.Fatalf("pid signals = %#v, want [555]", pidSignals)
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

func TestWaitForSidecarStartDiscoversForkedSidecar(t *testing.T) {
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
		Name:    "xray",
		PID:     111,
		LogPath: filepath.Join(t.TempDir(), "xray.log"),
	}, SidecarOptions{
		Name:       "xray",
		Executable: "xray",
		Args:       []string{"run", "-c", "/tmp/xray_freedom.json"},
	}, time.Millisecond)
	if err != nil {
		t.Fatalf("waitForSidecarStart() error = %v", err)
	}
	if got.PID != 777 {
		t.Fatalf("waitForSidecarStart() pid = %d, want discovered pid 777", got.PID)
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
		if host != "144.31.90.46" {
			t.Fatalf("routeGetHostSession host = %q, want %q", host, "144.31.90.46")
		}
		return []byte("   route to: 144.31.90.46\n  interface: utun11\n"), nil
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

	err := guardNestedTunnelStartup(model.Profile{Host: "144.31.90.46", Port: 8443}, config.RenderModeTun)
	if err == nil {
		t.Fatal("guardNestedTunnelStartup() error = nil, want non-nil")
	}
	for _, want := range []string{"144.31.90.46:8443", "utun11", "v2RayTun", "corp outside"} {
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
		return []byte("   route to: 144.31.90.46\n  interface: en0\n"), nil
	}
	t.Cleanup(func() {
		routeGetHostSession = prevRouteGetHost
	})

	if err := guardNestedTunnelStartup(model.Profile{Host: "144.31.90.46", Port: 8443}, config.RenderModeTun); err != nil {
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
