package session

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"multi-tun/desktop/internal/vless/config"
	"multi-tun/desktop/internal/vless/model"
)

func withLaunchdLiveness(t *testing.T, output string, printErr error) {
	t.Helper()
	previousExec, previousAlive := execCombinedOutput, processAliveSession
	execCombinedOutput = func(string, ...string) ([]byte, error) { return []byte(output), printErr }
	processAliveSession = func(int) (bool, error) { return false, nil }
	t.Cleanup(func() { execCombinedOutput, processAliveSession = previousExec, previousAlive })
}

// Only an explicit missing-service diagnostic is absence; healthy prints return the service PID.
func TestLaunchdLivenessClassification(t *testing.T) {
	failure := errors.New("permission denied")
	for _, tt := range []struct {
		name, output string
		err          error
		alive        bool
		pid          int
	}{
		{"missing output", "Could not find service works.relux.test", failure, false, 0},
		{"missing error", "", errors.New("Could not find service"), false, 0},
		{"healthy", "state = running\npid = 4321\n", nil, true, 4321},
	} {
		t.Run(tt.name, func(t *testing.T) {
			withLaunchdLiveness(t, tt.output, tt.err)
			current := CurrentSession{LaunchMode: config.LaunchModeLaunchd, LaunchLabel: "works.relux.test"}
			alive, pid, err := SessionAlive(current)
			if err != nil || alive != tt.alive || pid != tt.pid {
				t.Fatalf("alive=%v pid=%d err=%v", alive, pid, err)
			}
			status, err := InspectLaunchd(current.LaunchLabel)
			if err != nil || status.Found != tt.alive || status.PID != tt.pid {
				t.Fatalf("status=%+v err=%v", status, err)
			}
		})
	}
}

// Print permission, authentication, and timeout errors preserve the record without sidecar, DNS, or service actions.
func TestLaunchdLookupErrorPreservesSession(t *testing.T) {
	for _, message := range []string{"permission denied", "sudo: a password is required", "print timed out"} {
		t.Run(message, func(t *testing.T) {
			failure := errors.New(message)
			withLaunchdLiveness(t, "", failure)
			previousSignal, previousDNS, previousStop := sidecarSignalGroupSession, setDNSServersPrivilegedSession, stopLaunchdSessionFunc
			previousSidecarAlive := sidecarProcessAliveSession
			calls := 0
			sidecarSignalGroupSession = func(int, syscall.Signal) error { calls++; return nil }
			sidecarProcessAliveSession = func(int) (bool, error) { return calls == 0, nil }
			setDNSServersPrivilegedSession = func(string, string, int, string, []string) error { calls++; return nil }
			stopLaunchdSessionFunc = func(CurrentSession, time.Duration) error { calls++; return nil }
			t.Cleanup(func() {
				sidecarSignalGroupSession, setDNSServersPrivilegedSession, stopLaunchdSessionFunc = previousSignal, previousDNS, previousStop
				sidecarProcessAliveSession = previousSidecarAlive
			})
			withProcessIdentity(t, "xray", time.Now(), nil)
			cache := t.TempDir()
			current := CurrentSession{ID: "keep", LaunchMode: config.LaunchModeLaunchd, LaunchLabel: "works.relux.test",
				Sidecars:          []SidecarSession{{Name: "xray", PID: 1234, Command: []string{"/opt/bin/xray"}}},
				DNSHandoffService: "Wi-Fi", DNSHandoffServers: []string{"127.0.0.1"}}
			if err := SaveCurrent(cache, current); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(CurrentPath(cache))
			if err != nil {
				t.Fatal(err)
			}
			if alive, _, err := SessionAlive(current); alive || !errors.Is(err, failure) {
				t.Fatalf("alive=%v err=%v", alive, err)
			}
			if _, err := InspectLaunchd(current.LaunchLabel); !errors.Is(err, failure) {
				t.Fatalf("InspectLaunchd err=%v", err)
			}
			if _, _, err := Stop(cache, config.PrivilegedLaunchConfig{}, true, time.Millisecond); !errors.Is(err, failure) {
				t.Fatalf("Stop err=%v", err)
			}
			after, err := os.ReadFile(CurrentPath(cache))
			if err != nil || !bytes.Equal(before, after) || calls != 0 {
				t.Fatalf("record changed or actions taken: err=%v calls=%d", err, calls)
			}
		})
	}
}

// Launchd lookup errors leave saved metadata intact in legacy resolution and startup/stop polls, with no action after the failed poll.
func TestLaunchdLookupErrorPropagatesThroughWaits(t *testing.T) {
	failure := errors.New("print timed out")
	withLaunchdLiveness(t, "", failure)
	cache := t.TempDir()
	current := CurrentSession{ID: "keep", LaunchMode: config.LaunchModeLaunchd, LaunchLabel: "works.relux.test"}
	if err := SaveCurrent(cache, current); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(CurrentPath(cache))
	if _, _, err := resolveLegacyLaunchdCurrent(cache, config.PrivilegedLaunchConfig{Label: current.LaunchLabel}); !errors.Is(err, failure) {
		t.Fatalf("resolve err=%v", err)
	}
	if _, err := waitForStableStart(current, time.Millisecond); !errors.Is(err, failure) || !errors.Is(err, errSessionLivenessUnknown) {
		t.Fatalf("start poll err=%v", err)
	}
	previousSudo, previousExec := ensureSudoLaunchd, execCombinedOutput
	ensureSudoLaunchd = func() error { return nil }
	bootouts := 0
	execCombinedOutput = func(name string, args ...string) ([]byte, error) {
		for _, arg := range args {
			if arg == "bootout" {
				bootouts++
				return nil, nil
			}
		}
		return nil, failure
	}
	t.Cleanup(func() { ensureSudoLaunchd, execCombinedOutput = previousSudo, previousExec })
	if err := stopLaunchdSession(current, time.Second); !errors.Is(err, failure) {
		t.Fatalf("stop poll err=%v", err)
	}
	after, err := os.ReadFile(CurrentPath(cache))
	if bootouts != 1 || err != nil || !bytes.Equal(before, after) {
		t.Fatalf("bootouts=%d record err=%v", bootouts, err)
	}
}

func withSidecarSeams(t *testing.T, identity func(int) (string, time.Time, error)) *[]syscall.Signal {
	t.Helper()
	previousAlive, previousSignal, previousIdentity := sidecarProcessAliveSession, sidecarSignalGroupSession, processIdentitySession
	sidecarProcessAliveSession = func(int) (bool, error) { return true, nil }
	processIdentitySession = identity
	var signals []syscall.Signal
	sidecarSignalGroupSession = func(_ int, signal syscall.Signal) error { signals = append(signals, signal); return nil }
	t.Cleanup(func() {
		sidecarProcessAliveSession, sidecarSignalGroupSession, processIdentitySession = previousAlive, previousSignal, previousIdentity
	})
	return &signals
}

// Sidecar identity matches allow signals; reused PIDs, unreadable identities, and legacy name mismatches never do.
func TestStopSidecarIdentity(t *testing.T) {
	started := time.Date(2026, 10, 19, 1, 0, 0, 0, time.UTC)
	failure := errors.New("identity denied")
	for _, tt := range []struct {
		name, comm string
		start      time.Time
		lookupErr  error
		legacy     bool
		count      int
	}{
		{"match", "xray", started, nil, false, 2},
		{"reused start", "xray", started.Add(time.Hour), nil, false, 0},
		{"reused command", "zsh", started, nil, false, 0},
		{"unreadable", "", time.Time{}, failure, false, 0},
		{"legacy match", "xray", started, nil, true, 2},
		{"legacy mismatch", "zsh", started, nil, true, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			signals := withSidecarSeams(t, func(int) (string, time.Time, error) { return tt.comm, tt.start, tt.lookupErr })
			sidecar := SidecarSession{Name: "xray", PID: 1234, Command: []string{"/opt/bin/xray"}, ProcessComm: "xray", ProcessStart: started}
			if tt.legacy {
				sidecar.ProcessComm, sidecar.ProcessStart = "", time.Time{}
			}
			err := stopSidecar(sidecar, true, 0)
			if !errors.Is(err, tt.lookupErr) || len(*signals) != tt.count {
				t.Fatalf("err=%v signals=%v", err, *signals)
			}
			if tt.count == 2 && ((*signals)[0] != syscall.SIGTERM || (*signals)[1] != syscall.SIGKILL) {
				t.Fatalf("signals=%v", *signals)
			}
		})
	}
}

// PID reuse or a lookup failure after SIGTERM prevents SIGKILL; lookup errors preserve the failure verdict.
func TestStopSidecarRechecksBeforeKill(t *testing.T) {
	started := time.Now().Add(-time.Hour)
	failure := errors.New("sysctl unavailable")
	for _, tt := range []struct {
		name string
		err  error
	}{{"reused", nil}, {"unknown", failure}} {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			signals := withSidecarSeams(t, func(int) (string, time.Time, error) {
				calls++
				if calls == 1 {
					return "xray", started, nil
				}
				return "xray", started.Add(time.Hour), tt.err
			})
			err := stopSidecar(SidecarSession{PID: 1234, ProcessComm: "xray", ProcessStart: started}, true, 0)
			if !errors.Is(err, tt.err) || len(*signals) != 1 || (*signals)[0] != syscall.SIGTERM {
				t.Fatalf("err=%v signals=%v", err, *signals)
			}
		})
	}
}

// A sidecar identity read error preserves the parent's current record and prevents DNS restoration and signals.
func TestStopPreservesRecordOnSidecarIdentityError(t *testing.T) {
	failure := errors.New("sysctl denied")
	signals := withSidecarSeams(t, func(int) (string, time.Time, error) { return "", time.Time{}, failure })
	previousAlive, previousDNS := processAliveSession, setDNSServersPrivilegedSession
	processAliveSession = func(int) (bool, error) { return false, nil }
	dnsCalls := 0
	setDNSServersPrivilegedSession = func(string, string, int, string, []string) error { dnsCalls++; return nil }
	t.Cleanup(func() { processAliveSession, setDNSServersPrivilegedSession = previousAlive, previousDNS })
	cache := t.TempDir()
	current := CurrentSession{ID: "keep", Sidecars: []SidecarSession{{PID: 1234, Command: []string{"xray"}}}, DNSHandoffService: "Wi-Fi", DNSHandoffServers: []string{"127.0.0.1"}}
	if err := SaveCurrent(cache, current); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(CurrentPath(cache))
	if _, _, err := Stop(cache, config.PrivilegedLaunchConfig{}, true, 0); !errors.Is(err, failure) {
		t.Fatalf("Stop err=%v", err)
	}
	after, err := os.ReadFile(CurrentPath(cache))
	if err != nil || !bytes.Equal(before, after) || dnsCalls != 0 || len(*signals) != 0 {
		t.Fatalf("record err=%v dns=%d signals=%v", err, dnsCalls, *signals)
	}
}

// Old sidecar JSON loads without identity fields and uses the recorded executable's base name.
func TestLegacySidecarJSON(t *testing.T) {
	cache := t.TempDir()
	if err := os.MkdirAll(RuntimeDir(cache), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(CurrentPath(cache), []byte(`{"sidecars":[{"name":"xray","pid":1234,"command":["/opt/bin/xray"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	current, err := LoadCurrent(cache)
	if err != nil || len(current.Sidecars) != 1 {
		t.Fatalf("load=%+v err=%v", current, err)
	}
	sidecar := current.Sidecars[0]
	if sidecar.ProcessComm != "" || !sidecar.ProcessStart.IsZero() {
		t.Fatalf("identity=%+v", sidecar)
	}
	signals := withSidecarSeams(t, func(int) (string, time.Time, error) { return "xray", time.Now(), nil })
	if err := stopSidecar(sidecar, true, 0); err != nil || len(*signals) != 2 {
		t.Fatalf("err=%v signals=%v", err, *signals)
	}
	processIdentitySession = func(int) (string, time.Time, error) { return "zsh", time.Now(), nil }
	*signals = nil
	if err := stopSidecar(sidecar, true, 0); err != nil || len(*signals) != 0 {
		t.Fatalf("err=%v signals=%v", err, *signals)
	}
}

// Recording a sidecar identity persists command/start time; persistent lookup failure refuses a weaker new record.
func TestRecordSidecarIdentity(t *testing.T) {
	started := time.Now().Add(-time.Minute)
	withProcessIdentity(t, "xray", started, nil)
	previousDelay := identityRetryDelay
	identityRetryDelay = 0
	t.Cleanup(func() { identityRetryDelay = previousDelay })
	sidecar := SidecarSession{PID: 1234}
	if err := recordSidecarIdentity(&sidecar); err != nil || sidecar.ProcessComm != "xray" || !sidecar.ProcessStart.Equal(started) {
		t.Fatalf("identity=%+v err=%v", sidecar, err)
	}
	cache := t.TempDir()
	if err := SaveCurrent(cache, CurrentSession{Sidecars: []SidecarSession{sidecar}}); err != nil {
		t.Fatal(err)
	}
	saved, err := LoadCurrent(cache)
	if err != nil || saved.Sidecars[0].ProcessComm != "xray" || !saved.Sidecars[0].ProcessStart.Equal(started) {
		t.Fatalf("saved=%+v err=%v", saved, err)
	}
	failure := errors.New("sysctl denied")
	processIdentitySession = func(int) (string, time.Time, error) { return "", time.Time{}, failure }
	empty := SidecarSession{PID: 5678}
	if err := recordSidecarIdentity(&empty); !errors.Is(err, failure) || empty.ProcessComm != "" {
		t.Fatalf("identity=%+v err=%v", empty, err)
	}
}

// A fork discovered during startup replaces the original PID identity before the sidecar is returned.
func TestForkedSidecarRecordsIdentity(t *testing.T) {
	previousAlive, previousList := sidecarProcessAliveSession, sidecarProcessListSession
	sidecarProcessAliveSession = func(int) (bool, error) { return false, nil }
	sidecarProcessListSession = func() ([]byte, error) { return []byte(" 777 1 777 /opt/bin/xray run -c /tmp/test-xray.json\n"), nil }
	t.Cleanup(func() { sidecarProcessAliveSession, sidecarProcessListSession = previousAlive, previousList })
	started := time.Now()
	previousIdentity := processIdentitySession
	t.Cleanup(func() { processIdentitySession = previousIdentity })
	var identityPIDs []int
	processIdentitySession = func(pid int) (string, time.Time, error) {
		identityPIDs = append(identityPIDs, pid)
		if pid != 777 {
			t.Fatalf("identity PID=%d, want discovered PID 777", pid)
		}
		return "xray", started, nil
	}
	result, err := waitForSidecarStart(SidecarSession{PID: 111, LogPath: filepath.Join(t.TempDir(), "sidecar.log")}, SidecarOptions{Executable: "xray", Args: []string{"run", "-c", "/tmp/test-xray.json"}}, 0)
	if err != nil || result.PID != 777 || result.ProcessComm != "xray" || !result.ProcessStart.Equal(started) || len(identityPIDs) != 1 || identityPIDs[0] != 777 {
		t.Fatalf("result=%+v identity PIDs=%v err=%v", result, identityPIDs, err)
	}
	cache := t.TempDir()
	if err := SaveCurrent(cache, CurrentSession{Sidecars: []SidecarSession{result}}); err != nil {
		t.Fatal(err)
	}
	saved, err := LoadCurrent(cache)
	if err != nil || len(saved.Sidecars) != 1 || saved.Sidecars[0].PID != 777 || saved.Sidecars[0].ProcessComm != "xray" || !saved.Sidecars[0].ProcessStart.Equal(started) {
		t.Fatalf("saved=%+v err=%v", saved, err)
	}
}

// Startup liveness uncertainty retains the recoverable record without signals; confirmed exit still cleans up its own helper handle.
func TestStartPreservesRecordWhenLivenessIsUnknown(t *testing.T) {
	failure := errors.New("liveness lookup denied")
	for _, tt := range []struct {
		name    string
		err     error
		signals int
	}{{"unknown", failure, 0}, {"confirmed exit", nil, 1}} {
		t.Run(tt.name, func(t *testing.T) {
			previousStart, previousSignal, previousAlive := vpnCoreStartSingBoxSession, vpnCoreSignalSession, processAliveSession
			vpnCoreStartSingBoxSession = func([]byte, string, int, bool) (int, string, error) { return 4242, "own-child-handle", nil }
			calls := 0
			vpnCoreSignalSession = func(handle, signal string) error {
				calls++
				if handle != "own-child-handle" || signal != "-KILL" {
					t.Fatalf("handle=%s signal=%s", handle, signal)
				}
				return nil
			}
			processAliveSession = func(int) (bool, error) { return false, tt.err }
			t.Cleanup(func() {
				vpnCoreStartSingBoxSession, vpnCoreSignalSession, processAliveSession = previousStart, previousSignal, previousAlive
			})
			withProcessIdentity(t, "sing-box", time.Now(), nil)
			cache := t.TempDir()
			path := filepath.Join(cache, "config.json")
			if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Start(cache, path, model.Profile{}, StartOptions{Mode: config.RenderModeTun, PrivilegedLaunch: config.PrivilegedLaunchConfig{Mode: config.LaunchModeHelper}})
			if err == nil || calls != tt.signals {
				t.Fatalf("err=%v signals=%d", err, calls)
			}
			current, loadErr := LoadCurrent(cache)
			if tt.err != nil {
				if !errors.Is(err, failure) || loadErr != nil || current.PID != 4242 || current.ProcessComm != "sing-box" {
					t.Fatalf("current=%+v loadErr=%v err=%v", current, loadErr, err)
				}
			} else if !errors.Is(loadErr, os.ErrNotExist) {
				t.Fatalf("confirmed exit retained record: %v", loadErr)
			}
		})
	}
}

// A failed launchd startup PID lookup preserves its record and issues no further service actions.
func TestLaunchdStartLookupErrorPreservesRecord(t *testing.T) {
	failure := errors.New("print permission denied")
	previousSudo, previousExec := ensureSudoLaunchd, execCombinedOutput
	ensureSudoLaunchd = func() error { return nil }
	failed, commandsAfterFailure := false, 0
	execCombinedOutput = func(name string, args ...string) ([]byte, error) {
		isPrint := false
		for _, arg := range args {
			if arg == "print" {
				isPrint = true
			}
		}
		if isPrint {
			failed = true
			return nil, failure
		}
		if failed {
			commandsAfterFailure++
		}
		return nil, nil
	}
	t.Cleanup(func() { ensureSudoLaunchd, execCombinedOutput = previousSudo, previousExec })
	cache := t.TempDir()
	current := CurrentSession{ID: "keep", LaunchMode: config.LaunchModeLaunchd, LaunchLabel: "works.relux.test", LaunchPlistPath: filepath.Join(cache, "test.plist"), LogPath: filepath.Join(cache, "test.log")}
	if err := SaveCurrent(cache, current); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(CurrentPath(cache))
	if _, err := startWithLaunchd(current, "/opt/bin/sing-box"); !errors.Is(err, failure) {
		t.Fatalf("start err=%v", err)
	}
	after, err := os.ReadFile(CurrentPath(cache))
	if err != nil || !bytes.Equal(before, after) || commandsAfterFailure != 0 {
		t.Fatalf("record err=%v commands after failure=%d", err, commandsAfterFailure)
	}
}

// Legacy sidecars without a recorded executable cannot claim a sing-box PID and return a specific error without signals.
func TestLegacySidecarWithoutCommandFailsClosed(t *testing.T) {
	for _, command := range [][]string{nil, {""}, {" "}} {
		signals := withSidecarSeams(t, func(int) (string, time.Time, error) { return "sing-box", time.Now(), nil })
		err := stopSidecar(SidecarSession{PID: 1234, Command: command}, true, 0)
		if err == nil || !strings.Contains(err.Error(), "missing recorded command") || len(*signals) != 0 {
			t.Fatalf("err=%v signals=%v", err, *signals)
		}
	}
}

// Known legacy wrappers accept supervisor and payload names with either force setting; a known unrelated PID is gone without signals.
func TestStopLegacyWrappedSidecar(t *testing.T) {
	for _, tt := range []struct {
		name    string
		command []string
	}{
		{"sudo", []string{"/usr/bin/sudo", "-n", "/opt/bin/xray", "run"}},
		{"env", []string{"env", "XRAY_MODE=test", "/opt/bin/xray", "run"}},
		{"nice", []string{"nice", "-n", "5", "/opt/bin/xray", "run"}},
		{"nohup", []string{"nohup", "--", "/opt/bin/xray", "run"}},
		{"caffeinate", []string{"caffeinate", "-dimsu", "-t", "30", "/opt/bin/xray", "run"}},
		{"nested", []string{"sudo", "-n", "-u", "root", "env", "-i", "XRAY_MODE=test", "nice", "-n", "5", "nohup", "caffeinate", "-i", "/opt/bin/xray", "run"}},
	} {
		for _, liveName := range []string{"xray", "unrelated", filepath.Base(tt.command[0])} {
			for _, force := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/force=%t", tt.name, liveName, force), func(t *testing.T) {
					signals := withSidecarSeams(t, func(pid int) (string, time.Time, error) {
						if pid != 1234 {
							t.Fatalf("identity PID=%d, want sidecar PID 1234", pid)
						}
						return liveName, time.Now(), nil
					})
					sidecarProcessAliveSession = func(int) (bool, error) { return len(*signals) == 0, nil }
					err := stopSidecar(SidecarSession{Name: "xray", PID: 1234, Command: tt.command}, force, time.Second)
					wantSignals := 1
					if liveName == "unrelated" {
						wantSignals = 0
					}
					if err != nil || len(*signals) != wantSignals || (wantSignals > 0 && (*signals)[0] != syscall.SIGTERM) {
						t.Fatalf("err=%v signals=%v want=%d TERM", err, *signals, wantSignals)
					}
				})
			}
		}
	}
}

// The stale-primary Stop branch used by CLI restart cleanup terminates a live legacy supervisor, restores DNS and clears its record.
func TestStopStaleSessionWithLegacyWrapperSupervisor(t *testing.T) {
	for _, wrapper := range []string{"sudo", "caffeinate"} {
		t.Run(wrapper, func(t *testing.T) {
			signals := withSidecarSeams(t, func(int) (string, time.Time, error) { return wrapper, time.Now(), nil })
			sidecarProcessAliveSession = func(int) (bool, error) { return len(*signals) == 0, nil }
			previousAlive, previousDNS := processAliveSession, setDNSServersPrivilegedSession
			processAliveSession = func(int) (bool, error) { return false, nil }
			dnsCalls := 0
			setDNSServersPrivilegedSession = func(string, string, int, string, []string) error { dnsCalls++; return nil }
			t.Cleanup(func() { processAliveSession, setDNSServersPrivilegedSession = previousAlive, previousDNS })
			cache := t.TempDir()
			current := CurrentSession{ID: "stale-wrapper", PID: 4321,
				Sidecars:          []SidecarSession{{Name: "xray", PID: 1234, Command: []string{wrapper, "/opt/bin/xray", "run"}}},
				DNSHandoffService: "Wi-Fi", DNSHandoffServers: []string{"127.0.0.1"}}
			if err := SaveCurrent(cache, current); err != nil {
				t.Fatal(err)
			}
			stopped, state, err := Stop(cache, config.PrivilegedLaunchConfig{}, true, 1500*time.Millisecond)
			_, readErr := LoadCurrent(cache)
			if err != nil || state != "stale" || stopped.ID != current.ID || len(*signals) != 1 || (*signals)[0] != syscall.SIGTERM || !errors.Is(readErr, os.ErrNotExist) || dnsCalls != 1 {
				t.Fatalf("state=%s err=%v signals=%v record=%v DNS=%d", state, err, *signals, readErr, dnsCalls)
			}
		})
	}
}

// Unsupported flags or missing payloads reject other live names with actionable context; the wrapper's own name still authorizes Stop.
func TestLegacySidecarAmbiguousWrapperFailsClosed(t *testing.T) {
	for _, command := range [][]string{
		{"sudo"}, {"sudo", "-u"}, {"sudo", "--unknown", "xray"},
		{"env", "-S", "xray run"}, {"nice", "--unknown", "xray"},
		{"nohup", "--unknown", "xray"}, {"caffeinate", "-t"}, {"sudo", "-n", ""},
	} {
		for _, liveName := range []string{"xray", filepath.Base(command[0])} {
			t.Run(strings.Join(command, " ")+"/"+liveName, func(t *testing.T) {
				signals := withSidecarSeams(t, func(int) (string, time.Time, error) { return liveName, time.Now(), nil })
				sidecarProcessAliveSession = func(int) (bool, error) { return len(*signals) == 0, nil }
				previousAlive, previousDNS := processAliveSession, setDNSServersPrivilegedSession
				processAliveSession = func(int) (bool, error) { return false, nil }
				dnsCalls := 0
				setDNSServersPrivilegedSession = func(string, string, int, string, []string) error { dnsCalls++; return nil }
				t.Cleanup(func() { processAliveSession, setDNSServersPrivilegedSession = previousAlive, previousDNS })
				cache := t.TempDir()
				current := CurrentSession{ID: "ambiguous-wrapper",
					Sidecars:          []SidecarSession{{Name: "legacy-worker", PID: 1234, Command: command}},
					DNSHandoffService: "Wi-Fi", DNSHandoffServers: []string{"127.0.0.1"}}
				if err := SaveCurrent(cache, current); err != nil {
					t.Fatal(err)
				}
				before, readErr := os.ReadFile(CurrentPath(cache))
				if readErr != nil {
					t.Fatal(readErr)
				}
				_, _, err := Stop(cache, config.PrivilegedLaunchConfig{}, true, time.Second)
				after, readErr := os.ReadFile(CurrentPath(cache))
				if liveName == "xray" {
					if err == nil || len(*signals) != 0 || readErr != nil || !bytes.Equal(before, after) || dnsCalls != 0 {
						t.Fatalf("err=%v signals=%v record=%v DNS=%d", err, *signals, readErr, dnsCalls)
					}
					for _, context := range []string{"cannot verify legacy wrapped sidecar", `"legacy-worker"`, "pid 1234", `live process "xray"`} {
						if !strings.Contains(err.Error(), context) {
							t.Errorf("error %q missing %q", err, context)
						}
					}
				} else if err != nil || len(*signals) != 1 || (*signals)[0] != syscall.SIGTERM || !errors.Is(readErr, os.ErrNotExist) || dnsCalls != 1 {
					t.Fatalf("wrapper err=%v signals=%v record=%v DNS=%d", err, *signals, readErr, dnsCalls)
				}
			})
		}
	}
}

// A wrapper's identity lookup failure never authorizes a signal, even with force.
func TestLegacyWrapperIdentityLookupErrorNeverSignals(t *testing.T) {
	failure := errors.New("identity denied")
	signals := withSidecarSeams(t, func(int) (string, time.Time, error) { return "", time.Time{}, failure })
	err := stopSidecar(SidecarSession{Name: "xray", PID: 1234, Command: []string{"sudo", "xray"}}, true, 0)
	if !errors.Is(err, failure) || len(*signals) != 0 {
		t.Fatalf("err=%v signals=%v", err, *signals)
	}
}

// Recorded identities bypass legacy command parsing, including unsupported wrappers and absent commands; only their identity controls signals.
func TestSidecarRecordedIdentityIgnoresWrapperCommand(t *testing.T) {
	started := time.Now().Add(-time.Hour)
	for _, command := range [][]string{nil, {"sudo", "--unknown", "xray"}, {"env", "-S", "xray run"}} {
		for _, comm := range []string{"xray", "unrelated"} {
			t.Run(strings.Join(command, " ")+"/"+comm, func(t *testing.T) {
				signals := withSidecarSeams(t, func(int) (string, time.Time, error) { return comm, started, nil })
				err := stopSidecar(SidecarSession{PID: 1234, Command: command, ProcessComm: "xray", ProcessStart: started}, true, 0)
				want := 0
				if comm == "xray" {
					want = 2
				}
				if err != nil || len(*signals) != want {
					t.Fatalf("err=%v signals=%v want=%d", err, *signals, want)
				}
			})
		}
	}
}
