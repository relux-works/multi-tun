package session

import (
	"path/filepath"
	"testing"
	"time"
)

func TestSaveLoadAndRemove(t *testing.T) {
	t.Parallel()

	cacheDir := filepath.Join(t.TempDir(), "cache")
	want := CurrentSession{
		ID:            "20260713T210000Z",
		PID:           4242,
		Server:        "dedicated",
		Host:          "dedicated.example",
		ListenAddress: "127.0.0.1",
		SocksPort:     1080,
		StartedAt:     time.Date(2026, 7, 13, 21, 0, 0, 0, time.UTC),
		LogPath:       filepath.Join(cacheDir, "sessions", "ssh-proxy-session-20260713T210000Z.log"),
	}
	if err := Save(cacheDir, want); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	got, err := Load(cacheDir)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.ID != want.ID || got.PID != want.PID || got.Host != want.Host || got.SocksPort != want.SocksPort {
		t.Fatalf("Load() = %#v, want %#v", got, want)
	}
	if err := Remove(cacheDir); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	if _, err := Load(cacheDir); err == nil {
		t.Fatal("Load() error = nil after Remove()")
	}
}

func TestAliveRejectsInvalidPID(t *testing.T) {
	t.Parallel()

	if Alive(0) {
		t.Fatal("Alive(0) = true, want false")
	}
}

func TestLogPathUsesSSHProxyPrefix(t *testing.T) {
	t.Parallel()

	cacheDir := filepath.Join(t.TempDir(), "cache")
	if got, want := LogPath(cacheDir, "session-id"), filepath.Join(cacheDir, "sessions", "ssh-proxy-session-session-id.log"); got != want {
		t.Fatalf("LogPath() = %q, want %q", got, want)
	}
}
