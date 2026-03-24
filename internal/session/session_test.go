package session

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"vpn-config/internal/config"
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
	t.Parallel()

	tests := []struct {
		name       string
		renderMode string
		launchMode string
		want       string
	}{
		{name: "system proxy defaults direct", renderMode: config.RenderModeSystemProxy, launchMode: config.LaunchModeAuto, want: config.LaunchModeDirect},
		{name: "tun explicit launchd", renderMode: config.RenderModeTun, launchMode: config.LaunchModeLaunchd, want: config.LaunchModeLaunchd},
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
