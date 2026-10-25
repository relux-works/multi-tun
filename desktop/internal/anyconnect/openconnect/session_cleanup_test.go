package openconnect

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"multi-tun/desktop/internal/core/vpncore"
)

func holdStartupFlockForTest(t *testing.T, cache string) {
	t.Helper()
	if err := os.MkdirAll(RuntimeDir(cache), 0o755); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(filepath.Join(RuntimeDir(cache), startupLockFileName), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
}

func TestStopCleanupStartupLock(t *testing.T) {
	// Proves held/error locks preserve each cleanup branch's record and artifacts; free locks retain statuses and are held through cleanup, then released.
	for _, branch := range []struct {
		name, status string
		current      *CurrentSession
		clear        bool
	}{
		{"missing_session", "cleaned_orphaned", nil, false},
		{"no_session", "cleaned_orphaned", &CurrentSession{}, false},
		{"starting_record", "cleared_starting_cleaned", &CurrentSession{ID: "starting"}, true},
		{"stale_session", "stale_cleaned", &CurrentSession{ID: "stale", PID: 4242}, true},
	} {
		for _, lockState := range []string{"held", "free", "open_error"} {
			t.Run(branch.name+"/"+lockState, func(t *testing.T) {
				cache := t.TempDir()
				if branch.current != nil {
					if err := SaveCurrent(cache, *branch.current); err != nil {
						t.Fatal(err)
					}
				}
				before, beforeErr := os.ReadFile(CurrentPath(cache))
				if beforeErr != nil && !errors.Is(beforeErr, os.ErrNotExist) {
					t.Fatal(beforeErr)
				}
				artifact := filepath.Join(cache, "resolver-fixture")
				if err := os.WriteFile(artifact, []byte("owned resolver\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				previousAlive, previousExec := processAliveOpenConnect, execCommandOpenConnect
				previousCleanup := cleanupOrphanedResolverStateOpenConnect
				t.Cleanup(func() {
					processAliveOpenConnect, execCommandOpenConnect = previousAlive, previousExec
					cleanupOrphanedResolverStateOpenConnect = previousCleanup
				})
				processAliveOpenConnect = func(int) (bool, error) { return false, nil }
				execCommandOpenConnect = func(name string, args ...string) *exec.Cmd {
					if branch.current != nil || name != "pgrep" || strings.Join(args, " ") != "-x openconnect" {
						t.Fatalf("unexpected command: %s %q", name, args)
					}
					return exec.Command("/usr/bin/false")
				}
				cleanupCalls := 0
				cleanupOrphanedResolverStateOpenConnect = func(gotCache string) (bool, error) {
					cleanupCalls++
					if gotCache != cache {
						t.Fatalf("cleanup cache=%q, want %q", gotCache, cache)
					}
					lock, err := acquireOpenConnectStartupLock(cache)
					if err == nil {
						_ = lock.Close()
						t.Fatal("cleanup ran without holding startup lock")
					}
					if !errors.Is(err, errOpenConnectStartupInProgress) {
						t.Fatalf("cleanup lock error=%v", err)
					}
					return true, os.Remove(artifact)
				}
				switch lockState {
				case "held":
					holdStartupFlockForTest(t, cache)
				case "open_error":
					if err := os.MkdirAll(filepath.Join(RuntimeDir(cache), startupLockFileName), 0o700); err != nil {
						t.Fatal(err)
					}
				}
				_, status, stopErr := Stop(cache, time.Second)
				after, afterErr := os.ReadFile(CurrentPath(cache))
				if lockState != "free" {
					if stopErr == nil || status != "" || cleanupCalls != 0 {
						t.Fatalf("err=%v status=%q cleanup=%d", stopErr, status, cleanupCalls)
					}
					if lockState == "held" {
						if !strings.Contains(stopErr.Error(), "openconnect startup is already in progress for this cache") || !strings.Contains(stopErr.Error(), "retry stop after it finishes") {
							t.Fatalf("missing startup/retry explanation: %v", stopErr)
						}
					} else if !strings.Contains(stopErr.Error(), "open openconnect startup lock") || errors.Is(stopErr, errOpenConnectStartupInProgress) {
						t.Fatalf("wrong lock error: %v", stopErr)
					}
					if !bytes.Equal(before, after) || errors.Is(beforeErr, os.ErrNotExist) != errors.Is(afterErr, os.ErrNotExist) || (afterErr != nil && !errors.Is(afterErr, os.ErrNotExist)) {
						t.Fatalf("record changed: before=%q (%v), after=%q (%v)", before, beforeErr, after, afterErr)
					}
					if raw, err := os.ReadFile(artifact); err != nil || string(raw) != "owned resolver\n" {
						t.Fatalf("artifact changed: %q (%v)", raw, err)
					}
					return
				}
				if stopErr != nil || status != branch.status || cleanupCalls != 1 {
					t.Fatalf("err=%v status=%q cleanup=%d; want %q/1", stopErr, status, cleanupCalls, branch.status)
				}
				if branch.clear || branch.current == nil {
					if !errors.Is(afterErr, os.ErrNotExist) {
						t.Fatalf("record still present: %v", afterErr)
					}
				} else if afterErr != nil || !bytes.Equal(before, after) {
					t.Fatalf("empty record changed: %q (%v)", after, afterErr)
				}
				if _, err := os.Stat(artifact); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("artifact not removed: %v", err)
				}
				lock, err := acquireOpenConnectStartupLock(cache)
				if err != nil {
					t.Fatalf("Stop leaked lock: %v", err)
				}
				_ = lock.Close()
			})
		}
	}
}

func TestStopLiveSessionIgnoresStartupLock(t *testing.T) {
	// Proves a held startup lock does not block verified live Stop's interrupt, cleanup wait, or record removal, using only seams.
	started := time.Now().Add(-time.Hour)
	signals := withIdentitySeams(t, "openconnect", started, nil)
	cleanupCalls := withStopCleanupSeams(t)
	cache := t.TempDir()
	current := CurrentSession{ID: "live", PID: 4242, ProcessComm: "openconnect", ProcessStart: started}
	if err := SaveCurrent(cache, current); err != nil {
		t.Fatal(err)
	}
	holdStartupFlockForTest(t, cache)
	processAliveOpenConnect = func(int) (bool, error) { return len(*signals) == 0, nil }
	cleanupOrphanedResolverStateOpenConnect = func(string) (bool, error) {
		t.Fatal("live Stop invoked orphan cleanup")
		return false, nil
	}
	_, status, err := Stop(cache, time.Second)
	if err != nil || status != "stopped" || !reflect.DeepEqual(*signals, []string{"-INT"}) || *cleanupCalls != 1 {
		t.Fatalf("err=%v status=%q signals=%v cleanup=%d", err, status, *signals, *cleanupCalls)
	}
	if _, err := os.ReadFile(CurrentPath(cache)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("live record not cleared: %v", err)
	}
}

func TestStopCleanupRevalidatesSession(t *testing.T) {
	// Proves publication before lock acquisition preserves a newly verified live session and its marked resolver, refusing Stop without signals or cleanup.
	// Non-live replacements select their new cleanup status under lock; malformed records and identity errors preserve all state without cleanup.
	started := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	identityErr := errors.New("fixture identity unavailable")
	for _, initial := range []struct {
		name    string
		current *CurrentSession
	}{
		{"missing_session", nil},
		{"no_session", &CurrentSession{}},
		{"starting_record", &CurrentSession{ID: "old-starting"}},
		{"stale_session", &CurrentSession{ID: "old-stale", PID: 4242}},
	} {
		for _, next := range []struct {
			name, status string
			current      CurrentSession
			preserve     bool
		}{
			{"live", "", CurrentSession{ID: "new-live", PID: 4244, ProcessComm: "openconnect", ProcessStart: started}, true},
			{"starting", "cleared_starting_cleaned", CurrentSession{ID: "new-starting"}, false},
			{"stale", "stale_cleaned", CurrentSession{ID: "new-stale", PID: 4243}, false},
			{"reused_pid", "stale_cleaned", CurrentSession{ID: "new-reused", PID: 4244, ProcessComm: "openconnect", ProcessStart: started.Add(-time.Hour)}, false},
			{"missing", "cleaned_orphaned", CurrentSession{}, false},
			{"empty", "cleaned_orphaned", CurrentSession{}, false},
			{"identity_error", "", CurrentSession{ID: "new-uncertain", PID: 4245}, true},
			{"malformed", "", CurrentSession{}, true},
		} {
			t.Run(initial.name+"/"+next.name, func(t *testing.T) {
				cache, resolverDir := resolverHistoryForTest(t, "new.test")
				if initial.current != nil {
					if err := SaveCurrent(cache, *initial.current); err != nil {
						t.Fatal(err)
					}
				}
				signals := withIdentitySeams(t, "openconnect", started, nil)
				processAliveOpenConnect = func(pid int) (bool, error) { return pid == 4244 || pid == 4245, nil }
				identityCalls := 0
				processIdentityOpenConnect = func(pid int) (string, time.Time, error) {
					identityCalls++
					if pid == 4245 {
						return "", time.Time{}, identityErr
					}
					return "openconnect", started, nil
				}
				previousLock, previousExec := acquireStopCleanupLockOpenConnect, execCommandOpenConnect
				t.Cleanup(func() {
					acquireStopCleanupLockOpenConnect, execCommandOpenConnect = previousLock, previousExec
				})
				execCommandOpenConnect = func(name string, args ...string) *exec.Cmd {
					if name != "pgrep" || strings.Join(args, " ") != "-x openconnect" {
						t.Fatalf("unexpected command: %s %q", name, args)
					}
					return exec.Command("/usr/bin/false")
				}
				artifact := filepath.Join(resolverDir, "new.test")
				const resolver = "# Added by openconnect-tun DNS shim\nnameserver 192.0.2.53\n"
				var published []byte
				lockCalls := 0
				acquireStopCleanupLockOpenConnect = func(gotCache string) (*openConnectStartupLock, error) {
					lockCalls++
					// Model Connect's complete publication after Stop's read and before its lock.
					lock, err := acquireOpenConnectStartupLock(gotCache)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = lock.Close() })
					if err := SaveCurrent(cache, next.current); err != nil {
						t.Fatal(err)
					}
					if next.name == "missing" {
						if err := ClearCurrent(cache); err != nil {
							t.Fatal(err)
						}
					} else {
						if next.name == "malformed" {
							if err := os.WriteFile(CurrentPath(cache), []byte("{broken"), 0o600); err != nil {
								t.Fatal(err)
							}
						}
						published, err = os.ReadFile(CurrentPath(cache))
						if err != nil {
							t.Fatal(err)
						}
					}
					if err := os.WriteFile(artifact, []byte(resolver), 0o600); err != nil {
						t.Fatal(err)
					}
					if err := lock.Close(); err != nil {
						t.Fatal(err)
					}
					return acquireOpenConnectStopCleanupLock(gotCache)
				}
				cleanupCalls := 0
				cleanupOrphanedResolverStateOpenConnect = func(string) (bool, error) {
					cleanupCalls++
					lock, err := acquireOpenConnectStartupLock(cache)
					if err == nil {
						_ = lock.Close()
						t.Fatal("cleanup ran without startup lock")
					}
					if !errors.Is(err, errOpenConnectStartupInProgress) {
						t.Fatalf("unexpected lock error: %v", err)
					}
					return true, os.Remove(artifact)
				}
				got, status, stopErr := Stop(cache, time.Second)
				if lockCalls != 1 || len(*signals) != 0 {
					t.Fatalf("lock calls=%d signals=%v", lockCalls, *signals)
				}
				if next.preserve {
					after, err := os.ReadFile(CurrentPath(cache))
					if err != nil || !bytes.Equal(after, published) {
						t.Errorf("published record changed: %q (%v)", after, err)
					}
					if raw, err := os.ReadFile(artifact); err != nil || string(raw) != resolver {
						t.Errorf("published resolver changed: %q (%v)", raw, err)
					}
					if cleanupCalls != 0 || stopErr == nil || status != "" {
						t.Errorf("cleanup=%d err=%v status=%q", cleanupCalls, stopErr, status)
					}
					switch next.name {
					case "live":
						if stopErr == nil || !strings.Contains(stopErr.Error(), "session started while stop was running") || !strings.Contains(stopErr.Error(), "retry stop") || !reflect.DeepEqual(got, next.current) || identityCalls != 1 {
							t.Errorf("wrong live refusal: current=%+v err=%v identity calls=%d", got, stopErr, identityCalls)
						}
					case "identity_error":
						if !errors.Is(stopErr, identityErr) {
							t.Errorf("wrong identity error: %v", stopErr)
						}
					case "malformed":
						var syntaxErr *json.SyntaxError
						if !errors.As(stopErr, &syntaxErr) {
							t.Errorf("wrong record error: %v", stopErr)
						}
					}
				} else {
					if stopErr != nil || status != next.status || cleanupCalls != 1 || !reflect.DeepEqual(got, next.current) {
						t.Errorf("current=%+v err=%v status=%q cleanup=%d; want %+v/%q/1", got, stopErr, status, cleanupCalls, next.current, next.status)
					}
					after, err := os.ReadFile(CurrentPath(cache))
					if next.name == "empty" {
						if err != nil || !bytes.Equal(after, published) {
							t.Errorf("empty record changed: %q (%v)", after, err)
						}
					} else if !errors.Is(err, os.ErrNotExist) {
						t.Errorf("non-live record remains: %q (%v)", after, err)
					}
					if _, err := os.Stat(artifact); !errors.Is(err, os.ErrNotExist) {
						t.Errorf("orphan resolver remains: %v", err)
					}
				}
				lock, err := acquireOpenConnectStartupLock(cache)
				if err != nil {
					t.Fatalf("Stop leaked lock: %v", err)
				}
				_ = lock.Close()
			})
		}
	}
}

func TestPreStopCommandBoundsInheritedPipesOnDeadline(t *testing.T) {
	// Proves the real runner records timeout and returns before self-expiring children close inherited output pipes, without signals or PID probes.
	previousTimeout := preStopCommandTimeoutOpenConnect
	t.Cleanup(func() { preStopCommandTimeoutOpenConnect = previousTimeout })
	const timeout = 100 * time.Millisecond
	preStopCommandTimeoutOpenConnect = timeout
	start := time.Now()
	out := commandCombinedOutput("/bin/sh", "-c", "sleep 2 & echo ready; sleep 2")
	elapsed := time.Since(start)
	if out != "/bin/sh: timed out after 100ms" {
		t.Errorf("timeout output=%q", out)
	}
	if elapsed > timeout+900*time.Millisecond {
		t.Errorf("runner exceeded timeout plus scheduling margin: %s", elapsed)
	}
	t.Logf("runner returned in %s with deadline %s", elapsed, timeout)
}

func TestPreStopCommandNormalCompletion(t *testing.T) {
	// Proves a successful command created by the seam returns healthy output unchanged, with exact arguments and one invocation.
	previousCommand, previousTimeout := newPreStopCommandOpenConnect, preStopCommandTimeoutOpenConnect
	t.Cleanup(func() {
		newPreStopCommandOpenConnect, preStopCommandTimeoutOpenConnect = previousCommand, previousTimeout
	})
	preStopCommandTimeoutOpenConnect = time.Second
	const output = "healthy diagnostic output"
	calls := 0
	newPreStopCommandOpenConnect = func(name string, args ...string) *exec.Cmd {
		calls++
		if name != "scutil" || !reflect.DeepEqual(args, []string{"--dns"}) {
			t.Fatalf("unexpected command: %s %q", name, args)
		}
		return exec.Command("/bin/sh", "-c", `printf '%s' "$1"`, "sh", output)
	}
	if got := commandCombinedOutput("scutil", "--dns"); got != output || strings.Contains(got, "timed out") {
		t.Fatalf("normal output=%q, want %q without timeout", got, output)
	}
	if calls != 1 {
		t.Fatalf("command calls=%d, want 1", calls)
	}
}

func TestPreStopCommandDiscardsLateOutput(t *testing.T) {
	// Proves timeout discards early and late child output; the file gate forces late writes after return and keeps them exercised under -race.
	previousCommand, previousTimeout := newPreStopCommandOpenConnect, preStopCommandTimeoutOpenConnect
	t.Cleanup(func() {
		newPreStopCommandOpenConnect, preStopCommandTimeoutOpenConnect = previousCommand, previousTimeout
	})
	preStopCommandTimeoutOpenConnect = 100 * time.Millisecond
	dir := t.TempDir()
	release, finished := filepath.Join(dir, "release"), filepath.Join(dir, "finished")
	newPreStopCommandOpenConnect = func(string, ...string) *exec.Cmd {
		return exec.Command("/bin/sh", "-c", `printf 'early diagnostic output'; i=0; while [ ! -f "$1" ] && [ "$i" -lt 200 ]; do sleep 0.01; i=$((i+1)); done; printf 'late diagnostic output'; printf done > "$2"`, "sh", release, finished)
	}
	// Release even if an assertion fails, so this fixture cannot leave a waiting child.
	t.Cleanup(func() { _ = os.WriteFile(release, nil, 0o600) })
	got := commandCombinedOutput("scutil", "--dns")
	if err := os.WriteFile(release, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if content, err := os.ReadFile(finished); err == nil && string(content) == "done" {
			break
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("slow command did not finish its late output naturally")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got != "scutil: timed out after 100ms" || strings.Contains(got, "diagnostic output") {
		t.Fatalf("timeout leaked child output: %q", got)
	}
}

func TestPreStopCommandCompletionResults(t *testing.T) {
	// Proves combined stdout/stderr and whitespace trimming survive nonzero exit; empty failure and start failure stay empty.
	previousCommand := newPreStopCommandOpenConnect
	t.Cleanup(func() { newPreStopCommandOpenConnect = previousCommand })
	for _, tc := range []struct{ name, script, want string }{
		{"combined_nonzero", "printf '  stdout'; printf ' stderr  ' >&2; exit 1", "stdout stderr"},
		{"empty_nonzero", "exit 1", ""},
		{"start_failure", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			newPreStopCommandOpenConnect = func(string, ...string) *exec.Cmd {
				if tc.name == "start_failure" {
					return exec.Command(filepath.Join(t.TempDir(), "missing-command"))
				}
				return exec.Command("/bin/sh", "-c", tc.script)
			}
			if got := commandCombinedOutput("diagnostic"); got != tc.want {
				t.Fatalf("output=%q, want %q", got, tc.want)
			}
		})
	}
}

func resolverHistoryForTest(t *testing.T, domains ...string) (string, string) {
	t.Helper()
	cache, dir := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(SessionsDir(cache), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := SaveMetadata(CurrentSession{
		ID: "fixture", MetadataPath: filepath.Join(SessionsDir(cache), metadataFilePrefix+"fixture.json"),
		Server: "vpn.example.test/outside", Mode: ConnectModeSplitInclude,
		VPNDomains: domains, VPNNameservers: []string{"192.0.2.53"},
	}); err != nil {
		t.Fatal(err)
	}
	previous := resolverDirOpenConnect
	resolverDirOpenConnect = dir
	t.Cleanup(func() { resolverDirOpenConnect = previous })
	return cache, dir
}

func TestOrphanedResolverPresenceRequiresMarkedRegularFile(t *testing.T) {
	// Proves both first-line marker families count; foreign, later-line markers, missing files, symlinks, directories and FIFOs do not.
	for _, tc := range []struct {
		name, contents string
		want           bool
	}{
		{"dns", "# Added by openconnect-tun DNS shim (fixture)\nnameserver 192.0.2.53\n", true},
		{"bypass", "# Added by openconnect-tun public bypass\n", true},
		{"no_newline", "# Added by openconnect-tun DNS shim", true},
		{"foreign", "# Added by another VPN\nnameserver 192.0.2.53\n", false},
		{"second_line", "# foreign\n# Added by openconnect-tun DNS shim\n", false},
		{"missing", "", false},
		{"symlink", "", false},
		{"directory", "", false},
		{"fifo", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache, dir := resolverHistoryForTest(t, "example.test")
			path := filepath.Join(dir, "example.test")
			var err error
			switch tc.name {
			case "missing":
			case "symlink":
				target := filepath.Join(t.TempDir(), "marked")
				if err := os.WriteFile(target, []byte("# Added by openconnect-tun DNS shim\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				err = os.Symlink(target, path)
			case "directory":
				err = os.Mkdir(path, 0o700)
			case "fifo":
				err = syscall.Mkfifo(path, 0o600)
			default:
				err = os.WriteFile(path, []byte(tc.contents), 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := orphanedResolverArtifactsPresent(cache); got != tc.want {
				t.Fatalf("present=%t, want %t", got, tc.want)
			}
		})
	}
}

func TestStopPreservesForeignHistoricalResolver(t *testing.T) {
	// Proves a foreign historical resolver neither triggers cleanup alone nor fails the post-cleanup check when another owned file is removed.
	for _, marked := range []bool{false, true} {
		t.Run(fmt.Sprintf("marked=%t", marked), func(t *testing.T) {
			cache, dir := resolverHistoryForTest(t, "foreign.test", "owned.test")
			foreign := filepath.Join(dir, "foreign.test")
			const content = "# Managed by another VPN\nnameserver 192.0.2.53\n"
			if err := os.WriteFile(foreign, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			owned := filepath.Join(dir, "owned.test")
			if marked {
				if err := os.WriteFile(owned, []byte("# Added by openconnect-tun DNS shim\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := SaveCurrent(cache, CurrentSession{ID: "starting"}); err != nil {
				t.Fatal(err)
			}
			previousState, previousAvailable := detectStateOpenConnect, vpnCoreAvailableOpenConnect
			previousCleanup, previousExec := vpnCoreCleanupResolversOpenConnect, execCommandOpenConnect
			t.Cleanup(func() {
				detectStateOpenConnect, vpnCoreAvailableOpenConnect = previousState, previousAvailable
				vpnCoreCleanupResolversOpenConnect, execCommandOpenConnect = previousCleanup, previousExec
			})
			stateCalls, cleanupCalls := 0, 0
			detectStateOpenConnect = func() (State, string, error) { stateCalls++; return StateDisconnected, "", nil }
			vpnCoreAvailableOpenConnect = func(vpncore.ServiceConfig) bool { return true }
			vpnCoreCleanupResolversOpenConnect = func(vpncore.ServiceConfig) error { cleanupCalls++; return os.Remove(owned) }
			execCommandOpenConnect = func(name string, args ...string) *exec.Cmd {
				t.Fatalf("unexpected real command: %s %q", name, args)
				return nil
			}
			_, status, err := Stop(cache, time.Second)
			wantStatus, wantCalls := "cleared_starting", 0
			if marked {
				wantStatus, wantCalls = "cleared_starting_cleaned", 1
			}
			if err != nil || status != wantStatus || stateCalls != wantCalls || cleanupCalls != wantCalls {
				t.Fatalf("err=%v status=%q state=%d cleanup=%d", err, status, stateCalls, cleanupCalls)
			}
			if raw, err := os.ReadFile(foreign); err != nil || string(raw) != content {
				t.Fatalf("foreign resolver changed: %q (%v)", raw, err)
			}
		})
	}
}

func TestPreStopSnapshotDiagnosticCommandDeadlines(t *testing.T) {
	// Proves each slow DNS/route command times out independently while the snapshot completes and healthy output survives.
	for _, hang := range []string{"scutil", "netstat", "both", "neither"} {
		t.Run(hang, func(t *testing.T) {
			current := installPreStopSnapshotTestSeams(t)
			detectStateOpenConnect = func() (State, string, error) { return StateNotInstalled, "", nil }
			getConnectionInfoOpenConnect = func() (*ConnectionInfo, string, error) { return nil, "", nil }
			previousTimeout := preStopCommandTimeoutOpenConnect
			t.Cleanup(func() { preStopCommandTimeoutOpenConnect = previousTimeout })
			const timeout = 20 * time.Millisecond
			preStopCommandTimeoutOpenConnect = timeout
			var calls []string
			newPreStopCommandOpenConnect = func(name string, args ...string) *exec.Cmd {
				calls = append(calls, name+" "+strings.Join(args, " "))
				if hang == name || hang == "both" {
					return exec.Command("/bin/sh", "-c", "sleep 0.2; printf 'late output'")
				}
				return exec.Command("/bin/sh", "-c", `printf 'healthy %s\n' "$1"`, "sh", name)
			}
			start := time.Now()
			got := appendPreStopSnapshotForTest(t, current)
			if elapsed := time.Since(start); elapsed >= 2*timeout+300*time.Millisecond {
				t.Fatalf("snapshot took %s", elapsed)
			}
			if !reflect.DeepEqual(calls, []string{"scutil --dns", "netstat -rn -f inet"}) {
				t.Fatalf("commands=%v", calls)
			}
			for _, name := range []string{"scutil", "netstat"} {
				want := "healthy " + name
				if hang == name || hang == "both" {
					want = name + ": timed out after 20ms"
				}
				if !strings.Contains(got, want) {
					t.Fatalf("snapshot missing %q: %s", want, got)
				}
			}
			if !strings.Contains(got, "=== end pre-stop snapshot ===") {
				t.Fatal("snapshot did not finish")
			}
		})
	}
}

func TestOrphanedResolverCleanupScriptSkipsSymlinks(t *testing.T) {
	// Proves generated shell cleanup checks symlinks before reading, removes both marker families, and preserves foreign files, links and their targets in a temp dir.
	dir := filepath.Join(t.TempDir(), "resolver's dir")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	previous := resolverDirOpenConnect
	resolverDirOpenConnect = dir
	t.Cleanup(func() { resolverDirOpenConnect = previous })
	contents := map[string]string{
		"dns":     "# Added by openconnect-tun DNS shim (fixture)\nnameserver 192.0.2.53\n",
		"bypass":  "# Added by openconnect-tun public bypass\n",
		"foreign": "# foreign\n# Added by openconnect-tun DNS shim\n",
	}
	for name, content := range contents {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(t.TempDir(), "marked-target")
	const targetContent = "# Added by openconnect-tun public bypass\n"
	if err := os.WriteFile(target, []byte(targetContent), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "directory"), 0o700); err != nil {
		t.Fatal(err)
	}
	script := orphanedResolverCleanupScript()
	guard, read := strings.Index(script, `[ -L "$f" ] && continue`), strings.Index(script, "first_line=")
	if guard < 0 || read < 0 || guard > read || strings.Contains(script, "/etc/resolver") || !strings.Contains(script, shellQuote(dir)) {
		t.Fatalf("unsafe generated script: %s", script)
	}
	if out, err := exec.Command("/bin/sh", "-c", script).CombinedOutput(); err != nil {
		t.Fatalf("temp-only script: %v: %s", err, out)
	}
	for _, name := range []string{"dns", "bypass"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("owned %s not removed: %v", name, err)
		}
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "foreign")); err != nil || string(raw) != contents["foreign"] {
		t.Fatalf("foreign changed: %q (%v)", raw, err)
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink removed: %v", err)
	}
	if raw, err := os.ReadFile(target); err != nil || string(raw) != targetContent {
		t.Fatalf("target changed: %q (%v)", raw, err)
	}
	if info, err := os.Stat(filepath.Join(dir, "directory")); err != nil || !info.IsDir() {
		t.Fatalf("directory removed: %v", err)
	}
}
