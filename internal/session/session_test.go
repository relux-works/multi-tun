package session

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"multi-tun/internal/config"
)

func TestSaveAndLoadCurrent(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	want := CurrentSession{
		ID:         "20260324T120000Z",
		PID:        12345,
		StartedAt:  time.Date(2026, 3, 24, 12, 0, 0, 0, time.UTC),
		LogPath:    filepath.Join(cacheDir, "sessions", "sing-box-session-20260324T120000Z.log"),
		LaunchMode: config.LaunchModeDirect,
	}

	if err := SaveCurrent(cacheDir, want); err != nil {
		t.Fatalf("SaveCurrent returned error: %v", err)
	}

	got, err := LoadCurrent(cacheDir)
	if err != nil {
		t.Fatalf("LoadCurrent returned error: %v", err)
	}
	if got.ID != want.ID || got.PID != want.PID || got.LogPath != want.LogPath {
		t.Fatalf("loaded session = %#v, want %#v", got, want)
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
		{name: "system proxy defaults direct", renderMode: config.RenderModeSystemProxy, launchMode: config.LaunchModeAuto, want: config.LaunchModeDirect},
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

	got, state, err := Stop(cacheDir, false, 2*time.Second)
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
