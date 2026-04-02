package ciscodump

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const (
	sessionTimestampFormat = "20060102T150405Z"
	logFilePrefix          = "cisco-dump-session-"
	metadataFilePrefix     = "session-"
	runtimeFileName        = "current-session.json"
)

type CurrentSession struct {
	ID                        string     `json:"id"`
	PID                       int        `json:"pid"`
	StartedAt                 time.Time  `json:"started_at"`
	StoppedAt                 *time.Time `json:"stopped_at,omitempty"`
	LogPath                   string     `json:"log_path"`
	MetadataPath              string     `json:"metadata_path"`
	ArtifactDir               string     `json:"artifact_dir"`
	PcapPath                  string     `json:"pcap_path,omitempty"`
	OCSCPcapPath              string     `json:"ocsc_pcap_path,omitempty"`
	Interface                 string     `json:"interface"`
	Filter                    string     `json:"filter"`
	TcpdumpEnabled            bool       `json:"tcpdump_enabled"`
	TcpdumpBackend            string     `json:"tcpdump_backend,omitempty"`
	TcpdumpPID                int        `json:"tcpdump_pid,omitempty"`
	OCSCTcpdumpPID            int        `json:"ocsc_tcpdump_pid,omitempty"`
	ProbeHosts                []string   `json:"probe_hosts,omitempty"`
	ProbeNameservers          []string   `json:"probe_nameservers,omitempty"`
	SnapshotCount             int        `json:"snapshot_count,omitempty"`
	OCSCFrameCount            int        `json:"ocsc_frame_count,omitempty"`
	OCSCInterestingFrameCount int        `json:"ocsc_interesting_frame_count,omitempty"`
	OCSCTimelinePath          string     `json:"ocsc_timeline_path,omitempty"`
	OCSCSummaryPath           string     `json:"ocsc_summary_path,omitempty"`
}

func DefaultCacheDir() string {
	if dir := os.Getenv("XDG_CACHE_HOME"); dir != "" {
		return filepath.Join(dir, "cisco-dump")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".cache", "cisco-dump")
	}
	return filepath.Join(".cache", "cisco-dump")
}

func ResolveCacheDir(cacheDir string) string {
	cacheDir = strings.TrimSpace(cacheDir)
	if cacheDir == "" {
		return DefaultCacheDir()
	}
	return cacheDir
}

func SessionsDir(cacheDir string) string {
	return filepath.Join(cacheDir, "sessions")
}

func RuntimeDir(cacheDir string) string {
	return filepath.Join(cacheDir, "runtime")
}

func SessionArtifactDir(cacheDir, sessionID string) string {
	return filepath.Join(SessionsDir(cacheDir), logFilePrefix+sessionID)
}

func CurrentPath(cacheDir string) string {
	return filepath.Join(RuntimeDir(cacheDir), runtimeFileName)
}

func LoadCurrent(cacheDir string) (CurrentSession, error) {
	return loadSessionJSON(CurrentPath(cacheDir))
}

func LoadMetadata(path string) (CurrentSession, error) {
	return loadSessionJSON(path)
}

func loadSessionJSON(path string) (CurrentSession, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return CurrentSession{}, err
	}

	var current CurrentSession
	if err := json.Unmarshal(raw, &current); err != nil {
		return CurrentSession{}, err
	}
	return current, nil
}

func SaveCurrent(cacheDir string, current CurrentSession) error {
	if err := os.MkdirAll(RuntimeDir(cacheDir), 0o755); err != nil {
		return err
	}
	return saveJSON(CurrentPath(cacheDir), current)
}

func ClearCurrent(cacheDir string) error {
	err := os.Remove(CurrentPath(cacheDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func SaveMetadata(current CurrentSession) error {
	if current.MetadataPath == "" {
		return errors.New("metadata path is required")
	}
	return saveJSON(current.MetadataPath, current)
}

func ProcessAlive(pid int) (bool, error) {
	if pid <= 0 {
		return false, nil
	}
	err := syscall.Kill(pid, 0)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, syscall.ESRCH) {
		return false, nil
	}
	if errors.Is(err, syscall.EPERM) {
		return true, nil
	}
	return false, err
}

func SessionAlive(current CurrentSession) (bool, int, error) {
	alive, err := ProcessAlive(current.PID)
	if err != nil {
		return false, current.PID, err
	}
	return alive, current.PID, nil
}

func writeLogHeader(file *os.File, current CurrentSession) {
	_, _ = fmt.Fprintf(file, "=== dump session start ===\n")
	_, _ = fmt.Fprintf(file, "session_id: %s\n", current.ID)
	_, _ = fmt.Fprintf(file, "started_at: %s\n", current.StartedAt.Format(time.RFC3339))
	_, _ = fmt.Fprintf(file, "interface: %s\n", current.Interface)
	_, _ = fmt.Fprintf(file, "filter: %s\n", current.Filter)
	_, _ = fmt.Fprintf(file, "artifact_dir: %s\n", current.ArtifactDir)
	if current.PcapPath != "" {
		_, _ = fmt.Fprintf(file, "pcap_file: %s\n", current.PcapPath)
	}
	if current.OCSCPcapPath != "" {
		_, _ = fmt.Fprintf(file, "ocsc_pcap_file: %s\n", current.OCSCPcapPath)
	}
	_, _ = fmt.Fprintf(file, "tcpdump_enabled: %t\n", current.TcpdumpEnabled)
	if current.TcpdumpBackend != "" {
		_, _ = fmt.Fprintf(file, "tcpdump_backend: %s\n", current.TcpdumpBackend)
	}
	if len(current.ProbeHosts) > 0 {
		_, _ = fmt.Fprintf(file, "probe_hosts: %s\n", strings.Join(current.ProbeHosts, ", "))
	}
	if len(current.ProbeNameservers) > 0 {
		_, _ = fmt.Fprintf(file, "probe_nameservers: %s\n", strings.Join(current.ProbeNameservers, ", "))
	}
	_, _ = fmt.Fprintf(file, "--- dump output follows ---\n")
}

func saveJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

var ansiRegexp = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func LastRelevantLogLine(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(ansiRegexp.ReplaceAllString(lines[i], ""))
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "==="),
			strings.HasPrefix(line, "session_id:"),
			strings.HasPrefix(line, "started_at:"),
			strings.HasPrefix(line, "interface:"),
			strings.HasPrefix(line, "filter:"),
			strings.HasPrefix(line, "artifact_dir:"),
			strings.HasPrefix(line, "pcap_file:"),
			strings.HasPrefix(line, "ocsc_pcap_file:"),
			strings.HasPrefix(line, "tcpdump_enabled:"),
			strings.HasPrefix(line, "tcpdump_backend:"),
			strings.HasPrefix(line, "probe_hosts:"),
			strings.HasPrefix(line, "probe_nameservers:"),
			strings.HasPrefix(line, "---"):
			continue
		}
		return line
	}
	return ""
}
