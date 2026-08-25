package session

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

type CurrentSession struct {
	ID            string    `json:"id"`
	PID           int       `json:"pid"`
	Server        string    `json:"server"`
	Host          string    `json:"host"`
	ListenAddress string    `json:"listen_address"`
	SocksPort     int       `json:"socks_port"`
	StartedAt     time.Time `json:"started_at"`
	LogPath       string    `json:"log_path"`
}

func RuntimeDir(cacheDir string) string {
	return filepath.Join(cacheDir, "runtime")
}

func CurrentPath(cacheDir string) string {
	return filepath.Join(RuntimeDir(cacheDir), "current-session.json")
}

func LogPath(cacheDir string, id string) string {
	return filepath.Join(cacheDir, "sessions", "ssh-proxy-session-"+id+".log")
}

func Load(cacheDir string) (*CurrentSession, error) {
	raw, err := os.ReadFile(CurrentPath(cacheDir))
	if err != nil {
		return nil, err
	}
	var current CurrentSession
	if err := json.Unmarshal(raw, &current); err != nil {
		return nil, err
	}
	return &current, nil
}

func Save(cacheDir string, current CurrentSession) error {
	if err := os.MkdirAll(RuntimeDir(cacheDir), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(current, "", "  ")
	if err != nil {
		return err
	}
	path := CurrentPath(cacheDir)
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func Remove(cacheDir string) error {
	err := os.Remove(CurrentPath(cacheDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func Alive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
