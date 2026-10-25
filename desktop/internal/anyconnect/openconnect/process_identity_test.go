package openconnect

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func withIdentitySeams(t *testing.T, comm string, started time.Time, lookupErr error) *[]string {
	t.Helper()
	previousAlive, previousIdentity, previousSignal, previousCleanup := processAliveOpenConnect, processIdentityOpenConnect, signalSessionOpenConnect, cleanupOrphanedResolverStateOpenConnect
	processAliveOpenConnect = func(int) (bool, error) { return true, nil }
	processIdentityOpenConnect = func(int) (string, time.Time, error) { return comm, started, lookupErr }
	cleanupOrphanedResolverStateOpenConnect = func(string) (bool, error) { return false, nil }
	var signals []string
	signalSessionOpenConnect = func(_ int, signal, _, _ string) error { signals = append(signals, signal); return nil }
	t.Cleanup(func() {
		processAliveOpenConnect, processIdentityOpenConnect, signalSessionOpenConnect, cleanupOrphanedResolverStateOpenConnect = previousAlive, previousIdentity, previousSignal, previousCleanup
	})
	return &signals
}

// Exact identities are alive; changed start times/commands are stale, and lookup errors preserve the record without interrupting.
func TestSessionIdentityLivenessAndStop(t *testing.T) {
	started := time.Date(2026, 10, 19, 1, 0, 0, 0, time.UTC)
	failure := errors.New("sysctl permission denied")
	for _, tt := range []struct {
		name, comm    string
		start         time.Time
		err           error
		legacy, alive bool
	}{
		{"match", "openconnect", started, nil, false, true},
		{"reused start", "openconnect", started.Add(time.Hour), nil, false, false},
		{"reused command", "zsh", started, nil, false, false},
		{"identity error", "", time.Time{}, failure, false, false},
		{"legacy match", "openconnect", started.Add(time.Hour), nil, true, true},
		{"legacy mismatch", "zsh", started, nil, true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			signals := withIdentitySeams(t, tt.comm, tt.start, tt.err)
			current := CurrentSession{ID: "test", PID: 4242, ProcessComm: "openconnect", ProcessStart: started, Command: []string{"sudo", "openconnect"}}
			if tt.legacy {
				current.ProcessComm, current.ProcessStart = "", time.Time{}
			}
			alive, pid, err := SessionAlive(current)
			if alive != tt.alive || pid != current.PID || !errors.Is(err, tt.err) {
				t.Fatalf("alive=%v pid=%d err=%v", alive, pid, err)
			}
			if tt.alive {
				if err := signalMatchingSession(current, "-INT", PrivilegedModeDirect); err != nil || len(*signals) != 1 || (*signals)[0] != "-INT" {
					t.Fatalf("err=%v signals=%v", err, *signals)
				}
				return
			}
			cache := t.TempDir()
			if err := SaveCurrent(cache, current); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(CurrentPath(cache))
			_, status, err := Stop(cache, 0)
			if !errors.Is(err, tt.err) || len(*signals) != 0 {
				t.Fatalf("Stop err=%v signals=%v", err, *signals)
			}
			after, readErr := os.ReadFile(CurrentPath(cache))
			if tt.err != nil {
				if readErr != nil || !bytes.Equal(before, after) {
					t.Fatalf("unknown identity lost record: %v", readErr)
				}
			} else if status != "stale" || !errors.Is(readErr, os.ErrNotExist) {
				t.Fatalf("status=%q readErr=%v", status, readErr)
			}
		})
	}
}

// Interrupt, terminate, and kill each recheck identity and reject reuse or lookup errors before their signal seam.
func TestEveryStopSignalRechecksIdentity(t *testing.T) {
	started := time.Now().Add(-time.Hour)
	failure := errors.New("sysctl failed")
	for _, signal := range []string{"-INT", "-TERM", "-KILL"} {
		t.Run(signal, func(t *testing.T) {
			signals := withIdentitySeams(t, "openconnect", started, nil)
			current := CurrentSession{PID: 4242, ProcessComm: "openconnect", ProcessStart: started}
			if alive, _, err := SessionAlive(current); !alive || err != nil {
				t.Fatalf("positive control: alive=%v err=%v", alive, err)
			}
			processIdentityOpenConnect = func(int) (string, time.Time, error) { return "openconnect", started.Add(time.Hour), nil }
			if err := signalMatchingSession(current, signal, PrivilegedModeDirect); err != nil || len(*signals) != 0 {
				t.Fatalf("reuse err=%v signals=%v", err, *signals)
			}
			processIdentityOpenConnect = func(int) (string, time.Time, error) { return "", time.Time{}, failure }
			if err := signalMatchingSession(current, signal, PrivilegedModeDirect); !errors.Is(err, failure) || len(*signals) != 0 {
				t.Fatalf("lookup err=%v signals=%v", err, *signals)
			}
		})
	}
}

// Legacy JSON omitting identity fields loads and matches only the openconnect name, independent of a sudo command prefix.
func TestLegacyOpenConnectJSON(t *testing.T) {
	cache := t.TempDir()
	if err := os.MkdirAll(RuntimeDir(cache), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(CurrentPath(cache), []byte(`{"id":"old","pid":4242,"command":["sudo","openconnect"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	current, err := LoadCurrent(cache)
	if err != nil || current.ProcessComm != "" || !current.ProcessStart.IsZero() {
		t.Fatalf("current=%+v err=%v", current, err)
	}
	withIdentitySeams(t, "openconnect", time.Now(), nil)
	if alive, _, err := SessionAlive(current); !alive || err != nil {
		t.Fatalf("legacy match alive=%v err=%v", alive, err)
	}
	processIdentityOpenConnect = func(int) (string, time.Time, error) { return "sudo", time.Now(), nil }
	if alive, _, err := SessionAlive(current); alive || err != nil {
		t.Fatalf("legacy mismatch alive=%v err=%v", alive, err)
	}
}

func withConnectIdentitySeams(t *testing.T) {
	t.Helper()
	previousLookPath, previousList, previousAuth, previousConnect, previousExec := execLookPathOpenConnect, listOpenConnectProcessesOpenConnect, authenticateOpenConnect, connectWithCookieOpenConnect, execCommandOpenConnect
	execLookPathOpenConnect = func(string) (string, error) { return "/opt/bin/openconnect", nil }
	listOpenConnectProcessesOpenConnect = func() ([]openConnectProcess, error) { return nil, nil }
	authenticateOpenConnect = func(string, ConnectOptions, string, io.Writer, io.Writer) (*authResult, error) {
		return &authResult{ConnectURL: "https://127.0.0.1"}, nil
	}
	connectWithCookieOpenConnect = func(_ *authResult, _, _, pidFile string, _ io.Writer, _ string, _ PrivilegedHelperConfig, _ ClientMimicry) (int, string, error) {
		if err := os.WriteFile(pidFile, []byte("4242\n"), 0o600); err != nil {
			return 0, "", err
		}
		return 4242, "utun-test", nil
	}
	execCommandOpenConnect = func(string, ...string) *exec.Cmd { return exec.Command("/usr/bin/true") }
	t.Cleanup(func() {
		execLookPathOpenConnect, listOpenConnectProcessesOpenConnect, authenticateOpenConnect, connectWithCookieOpenConnect, execCommandOpenConnect = previousLookPath, previousList, previousAuth, previousConnect, previousExec
	})
}

// A successful seam-driven Connect records the returned daemon PID's identity in both current and historical JSON.
func TestConnectRecordsProcessIdentity(t *testing.T) {
	started := time.Now().Add(-time.Minute)
	withIdentitySeams(t, "openconnect", started, nil)
	withConnectIdentitySeams(t)
	lookedUp := 0
	processIdentityOpenConnect = func(pid int) (string, time.Time, error) {
		if pid != 4242 {
			t.Fatalf("identity PID=%d, want connected PID 4242", pid)
		}
		lookedUp++
		return "openconnect", started, nil
	}
	cache := t.TempDir()
	result, err := Connect(ConnectOptions{Server: "127.0.0.1", CacheDir: cache, PrivilegedMode: PrivilegedModeDirect})
	if err != nil {
		t.Fatal(err)
	}
	current, err := LoadCurrent(cache)
	if err != nil || lookedUp == 0 || result.PID != 4242 || current.ProcessComm != "openconnect" || !current.ProcessStart.Equal(started) {
		t.Fatalf("current=%+v lookups=%d err=%v", current, lookedUp, err)
	}
	data, err := os.ReadFile(current.MetadataPath)
	if err != nil {
		t.Fatal(err)
	}
	var historical CurrentSession
	if err := json.Unmarshal(data, &historical); err != nil || historical.ProcessComm != current.ProcessComm || !historical.ProcessStart.Equal(started) {
		t.Fatalf("historical=%+v err=%v", historical, err)
	}
}

// Connect preserves current and historical records and sends no signal when the newly known PID's identity cannot be recorded.
func TestConnectIdentityLookupFailureDoesNotSignal(t *testing.T) {
	failure := errors.New("sysctl denied")
	signals := withIdentitySeams(t, "", time.Time{}, failure)
	withConnectIdentitySeams(t)
	previousDelay := identityRetryDelayOpenConnect
	identityRetryDelayOpenConnect = 0
	t.Cleanup(func() { identityRetryDelayOpenConnect = previousDelay })
	cache := t.TempDir()
	if _, err := Connect(ConnectOptions{Server: "127.0.0.1", CacheDir: cache, PrivilegedMode: PrivilegedModeDirect}); !errors.Is(err, failure) {
		t.Fatalf("Connect err=%v", err)
	}
	if len(*signals) != 0 {
		t.Fatalf("signals=%v", *signals)
	}
	paths, err := filepath.Glob(filepath.Join(SessionsDir(cache), metadataFilePrefix+"*.json"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("metadata=%v err=%v", paths, err)
	}
	data, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	var current CurrentSession
	if err := json.Unmarshal(data, &current); err != nil || current.PID != 4242 {
		t.Fatalf("metadata=%+v err=%v", current, err)
	}
	saved, err := LoadCurrent(cache)
	if err != nil || saved.PID != 4242 || saved.ProcessComm != "" || !saved.ProcessStart.IsZero() || saved.MetadataPath != current.MetadataPath {
		t.Fatalf("missing current recovery: %+v err=%v", saved, err)
	}
}

// Identity recording retries one transient failure and never reports persistent lookup failure as success.
func TestRecordProcessIdentityRetries(t *testing.T) {
	failure := errors.New("transient sysctl failure")
	withIdentitySeams(t, "", time.Time{}, failure)
	previousDelay := identityRetryDelayOpenConnect
	identityRetryDelayOpenConnect = 0
	t.Cleanup(func() { identityRetryDelayOpenConnect = previousDelay })
	calls := 0
	started := time.Now()
	processIdentityOpenConnect = func(int) (string, time.Time, error) {
		calls++
		if calls == 1 {
			return "", time.Time{}, failure
		}
		return "openconnect", started, nil
	}
	current := CurrentSession{PID: 4242}
	if err := recordProcessIdentity(&current); err != nil || calls != 2 || current.ProcessComm != "openconnect" || !current.ProcessStart.Equal(started) {
		t.Fatalf("current=%+v calls=%d err=%v", current, calls, err)
	}
	processIdentityOpenConnect = func(int) (string, time.Time, error) { return "", time.Time{}, failure }
	empty := CurrentSession{PID: 4242}
	if err := recordProcessIdentity(&empty); !errors.Is(err, failure) || empty.ProcessComm != "" {
		t.Fatalf("current=%+v err=%v", empty, err)
	}
}
