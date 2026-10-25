package openconnect

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func withFailedStartIdentitySeams(t *testing.T) {
	t.Helper()
	previousAlive, previousSignal := failedStartProcessAliveOpenConnect, failedStartSignalOpenConnect
	previousTimeout, previousPoll := failedStartCleanupTimeoutOpenConnect, failedStartCleanupPollOpenConnect
	failedStartProcessAliveOpenConnect = func(pid int) (bool, error) { return processAliveOpenConnect(pid) }
	failedStartSignalOpenConnect = func(pid int, signal, mode, socket string) error {
		return signalSessionOpenConnect(pid, signal, mode, socket)
	}
	failedStartCleanupTimeoutOpenConnect, failedStartCleanupPollOpenConnect = 0, 0
	t.Cleanup(func() {
		failedStartProcessAliveOpenConnect, failedStartSignalOpenConnect = previousAlive, previousSignal
		failedStartCleanupTimeoutOpenConnect, failedStartCleanupPollOpenConnect = previousTimeout, previousPoll
	})
}

func withStopCleanupSeams(t *testing.T) *int {
	t.Helper()
	previousSnapshot, previousCleanup := appendPreStopSnapshotOpenConnect, waitForSessionCleanupOpenConnect
	appendPreStopSnapshotOpenConnect = func(string, CurrentSession) error { return nil }
	calls := 0
	waitForSessionCleanupOpenConnect = func(string, CurrentSession, time.Duration) error { calls++; return nil }
	t.Cleanup(func() {
		appendPreStopSnapshotOpenConnect, waitForSessionCleanupOpenConnect = previousSnapshot, previousCleanup
	})
	return &calls
}

// After recording the daemon, Connect never signals a reused/unreadable PID and retains both recovery records and the PID file.
func TestConnectStableStartIdentityFailurePreservesRecovery(t *testing.T) {
	started := time.Now().Add(-time.Minute)
	failure := errors.New("startup identity denied")
	for _, tt := range []struct {
		name string
		err  error
	}{{"mismatch", nil}, {"lookup failure", failure}} {
		t.Run(tt.name, func(t *testing.T) {
			signals := withIdentitySeams(t, "openconnect", started, nil)
			withConnectIdentitySeams(t)
			withFailedStartIdentitySeams(t)
			lookups := 0
			processIdentityOpenConnect = func(pid int) (string, time.Time, error) {
				if pid != 4242 {
					t.Fatalf("identity PID=%d, want daemon PID 4242", pid)
				}
				lookups++
				if lookups == 1 {
					return "openconnect", started, nil
				}
				return "openconnect", started.Add(time.Hour), tt.err
			}
			cache := t.TempDir()
			_, err := Connect(ConnectOptions{Server: "127.0.0.1", CacheDir: cache, PrivilegedMode: PrivilegedModeDirect})
			if err == nil || (tt.err != nil && !errors.Is(err, tt.err)) || len(*signals) != 0 {
				t.Fatalf("Connect err=%v signals=%v", err, *signals)
			}
			current, err := LoadCurrent(cache)
			if err != nil || current.PID != 4242 || current.ProcessComm != "openconnect" || !current.ProcessStart.Equal(started) || lookups < 3 {
				t.Fatalf("recovery=%+v lookups=%d err=%v", current, lookups, err)
			}
			if _, err := os.Stat(current.PIDFilePath); err != nil {
				t.Fatalf("PID file not retained: %v", err)
			}
			data, err := os.ReadFile(current.MetadataPath)
			if err != nil || !bytes.Contains(data, []byte(`"process_comm": "openconnect"`)) {
				t.Fatalf("historical recovery missing: %q, %v", data, err)
			}
		})
	}
}

// Cleanup rechecks even after a matching poll, immediately before each signal; a change or lookup error prevents that signal and all later ones.
func TestFailedStartCleanupRechecksEverySignal(t *testing.T) {
	started := time.Now().Add(-time.Hour)
	failure := errors.New("cleanup identity denied")
	for _, signal := range []string{"-INT", "-TERM", "-KILL"} {
		for _, lookupErr := range []error{nil, failure} {
			t.Run(signal+"/"+fmtErrorName(lookupErr), func(t *testing.T) {
				signals := withIdentitySeams(t, "openconnect", started, nil)
				withFailedStartIdentitySeams(t)
				wantBefore := map[string]int{"-INT": 0, "-TERM": 1, "-KILL": 2}[signal]
				// With zero waits each successful signal has exactly one subsequent identity poll.
				lookups := 0
				processIdentityOpenConnect = func(int) (string, time.Time, error) {
					lookups++
					if lookups == 2*wantBefore+1 {
						return "openconnect", started.Add(time.Hour), lookupErr
					}
					return "openconnect", started, nil
				}
				err := cleanupFailedOpenConnectStart(CurrentSession{PID: 4242, ProcessComm: "openconnect", ProcessStart: started})
				if err == nil || (lookupErr != nil && !errors.Is(err, lookupErr)) || len(*signals) != wantBefore {
					t.Fatalf("err=%v signals=%v, want %d signals before %s", err, *signals, wantBefore, signal)
				}
			})
		}
	}
}

func fmtErrorName(err error) string {
	if err == nil {
		return "mismatch"
	}
	return "lookup failure"
}

// Signal failures at INT, TERM and KILL permit cleanup only on confirmed exit/reuse; matching or uncertain PIDs retain the exact record and errors.
func TestStopSignalErrorRechecksLiveness(t *testing.T) {
	started := time.Now().Add(-time.Hour)
	identityErr, aliveErr := errors.New("post-signal identity denied"), errors.New("post-signal liveness denied")
	for _, signal := range []string{"-INT", "-TERM", "-KILL"} {
		for _, outcome := range []string{"gone", "reused", "matching", "identity error", "liveness error"} {
			t.Run(signal+"/"+outcome, func(t *testing.T) {
				withIdentitySeams(t, "openconnect", started, nil)
				cleanupCalls := withStopCleanupSeams(t)
				current := CurrentSession{ID: "signal-race", PID: 4242, ProcessComm: "openconnect", ProcessStart: started, PrivilegedMode: PrivilegedModeDirect}
				cache := t.TempDir()
				if err := SaveCurrent(cache, current); err != nil {
					t.Fatal(err)
				}
				before, err := os.ReadFile(CurrentPath(cache))
				if err != nil {
					t.Fatal(err)
				}
				failed := false
				var signals []string
				signalErr := error(syscall.ESRCH)
				if outcome == "matching" {
					signalErr = syscall.EPERM
				}
				signalSessionOpenConnect = func(pid int, sig, mode, _ string) error {
					if pid != 4242 || mode != PrivilegedModeDirect {
						t.Fatalf("signal PID=%d mode=%s", pid, mode)
					}
					signals = append(signals, sig)
					if sig == signal {
						failed = true
						return signalErr
					}
					return nil
				}
				processAliveOpenConnect = func(int) (bool, error) {
					if failed && outcome == "gone" {
						return false, nil
					}
					if failed && outcome == "liveness error" {
						return false, aliveErr
					}
					return true, nil
				}
				processIdentityOpenConnect = func(int) (string, time.Time, error) {
					if failed && outcome == "reused" {
						return "openconnect", started.Add(time.Hour), nil
					}
					if failed && outcome == "identity error" {
						return "", time.Time{}, identityErr
					}
					return "openconnect", started, nil
				}
				timeout := time.Second
				if signal == "-TERM" {
					timeout = 600 * time.Millisecond
				} else if signal == "-KILL" {
					timeout = 0
				}
				_, status, stopErr := Stop(cache, timeout)
				if !failed || len(signals) == 0 || signals[len(signals)-1] != signal {
					t.Fatalf("target signal was not last: signals=%v err=%v", signals, stopErr)
				}
				after, readErr := os.ReadFile(CurrentPath(cache))
				if outcome == "gone" || outcome == "reused" {
					if stopErr != nil || !strings.HasPrefix(status, "stopped") || !errors.Is(readErr, os.ErrNotExist) || *cleanupCalls != 1 {
						t.Fatalf("status=%s err=%v record=%v cleanup=%d", status, stopErr, readErr, *cleanupCalls)
					}
				} else {
					if !errors.Is(stopErr, signalErr) || readErr != nil || !bytes.Equal(before, after) || *cleanupCalls != 0 {
						t.Fatalf("err=%v record=%v cleanup=%d", stopErr, readErr, *cleanupCalls)
					}
					if outcome == "identity error" && !errors.Is(stopErr, identityErr) {
						t.Fatalf("lost identity error: %v", stopErr)
					}
					if outcome == "liveness error" && !errors.Is(stopErr, aliveErr) {
						t.Fatalf("lost liveness error: %v", stopErr)
					}
				}
			})
		}
	}
}

// An initial identity error leaves a discoverable current record with privilege/helper and resolver context; Stop later verifies its legacy name.
func TestConnectIdentityFailureRecoveryContext(t *testing.T) {
	for _, mode := range []string{PrivilegedModeDirect, PrivilegedModeSudo, PrivilegedModeHelper} {
		for _, liveName := range []string{"openconnect", "zsh"} {
			t.Run(mode+"/"+liveName, func(t *testing.T) {
				failure := errors.New("record identity denied")
				signals := withIdentitySeams(t, "", time.Time{}, failure)
				withConnectIdentitySeams(t)
				withFailedStartIdentitySeams(t)
				cleanupCalls := withStopCleanupSeams(t)
				previousResolve, previousDelay := resolvePrivilegedModeOpenConnect, identityRetryDelayOpenConnect
				identityRetryDelayOpenConnect = 0
				socket := filepath.Join(t.TempDir(), "helper.sock")
				// Exercise persisted compatibility fields without contacting a helper or resolving real privilege.
				resolvePrivilegedModeOpenConnect = func(string) (string, PrivilegedHelperConfig, error) {
					return mode, PrivilegedHelperConfig{SocketPath: socket}, nil
				}
				t.Cleanup(func() {
					resolvePrivilegedModeOpenConnect, identityRetryDelayOpenConnect = previousResolve, previousDelay
				})
				cache := t.TempDir()
				options := ConnectOptions{Server: "127.0.0.1", CacheDir: cache, PrivilegedMode: mode, Mode: ConnectModeFull,
					IncludeRoutes: []string{"192.0.2.0/24"}, VPNDomains: []string{"corp.example.test"}, BypassSuffixes: []string{"public.example.test"}, VPNNameservers: []string{"192.0.2.53"}}
				if _, err := Connect(options); !errors.Is(err, failure) || len(*signals) != 0 {
					t.Fatalf("Connect err=%v signals=%v", err, *signals)
				}
				current, err := LoadCurrent(cache)
				if err != nil || current.PID != 4242 || current.PrivilegedMode != mode || current.ProcessComm != "" || !current.ProcessStart.IsZero() || current.Interface != "utun-test" {
					t.Fatalf("recovery=%+v err=%v", current, err)
				}
				if (mode == PrivilegedModeHelper && current.HelperSocketPath != socket) ||
					current.Mode != options.Mode || !reflect.DeepEqual(current.IncludeRoutes, options.IncludeRoutes) || !reflect.DeepEqual(current.VPNDomains, options.VPNDomains) ||
					!reflect.DeepEqual(current.BypassSuffixes, options.BypassSuffixes) || !reflect.DeepEqual(current.VPNNameservers, options.VPNNameservers) || current.Script == "" || current.PIDFilePath == "" {
					t.Fatalf("lost cleanup context: %+v", current)
				}
				// A later read succeeds, with a different start time: this must take the name-only legacy path.
				processIdentityOpenConnect = func(pid int) (string, time.Time, error) {
					if pid != 4242 {
						t.Fatalf("Stop identity PID=%d, want recorded PID", pid)
					}
					return liveName, time.Now().Add(time.Hour), nil
				}
				signalSessionOpenConnect = func(pid int, signal, actualMode, actualSocket string) error {
					*signals = append(*signals, signal)
					if pid != 4242 || actualMode != mode || actualSocket != current.HelperSocketPath {
						t.Fatalf("wrong stop context PID=%d mode=%s socket=%s", pid, actualMode, actualSocket)
					}
					processAliveOpenConnect = func(int) (bool, error) { return false, nil }
					return nil
				}
				_, status, err := Stop(cache, time.Second)
				wantSignals, wantCleanup, wantStatus := 0, 0, "stale"
				if liveName == "openconnect" {
					wantSignals, wantCleanup, wantStatus = 1, 1, "stopped"
				}
				if err != nil || status != wantStatus || len(*signals) != wantSignals || *cleanupCalls != wantCleanup {
					t.Fatalf("Stop status=%s err=%v signals=%v cleanup=%d", status, err, *signals, *cleanupCalls)
				}
				if _, err := LoadCurrent(cache); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("record not cleared: %v", err)
				}
			})
		}
	}
}
