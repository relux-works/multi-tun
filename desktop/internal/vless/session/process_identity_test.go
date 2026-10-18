package session

import (
	"errors"
	"os"
	"runtime"
	"testing"
	"time"

	"multi-tun/desktop/internal/vless/config"
)

func withProcessIdentity(t *testing.T, comm string, started time.Time, err error) {
	t.Helper()
	previous := processIdentitySession
	processIdentitySession = func(int) (string, time.Time, error) { return comm, started, err }
	t.Cleanup(func() { processIdentitySession = previous })
}

// Stale metadata whose PID now belongs to an unrelated live process (the test
// binary itself, through the real kern.proc lookup) is not a running session.
func TestSessionAliveRejectsLivePIDOfAnotherProgram(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("process identity is darwin-only")
	}
	current := CurrentSession{PID: os.Getpid(), Command: []string{"/opt/homebrew/bin/sing-box", "run"}, StartedAt: time.Now()}
	alive, _, err := SessionAlive(current)
	if err != nil || alive {
		t.Fatalf("SessionAlive(live unrelated pid) = (%v, %v), want (false, nil)", alive, err)
	}
}

// A record carrying the observed identity matches only the same name and the
// same start time (within kern.proc granularity); a PID reused by a later
// process or by another program is not the session.
func TestSessionAliveComparesRecordedIdentityExactly(t *testing.T) {
	recorded := time.Now().Add(-6 * time.Hour)
	current := CurrentSession{PID: os.Getpid(), ProcessComm: "sing-box", ProcessStart: recorded}

	withProcessIdentity(t, "sing-box", recorded.Add(300*time.Millisecond), nil)
	if alive, _, err := SessionAlive(current); err != nil || !alive {
		t.Fatalf("matching identity = (%v, %v), want (true, nil)", alive, err)
	}
	withProcessIdentity(t, "sing-box", recorded.Add(3*time.Hour), nil)
	if alive, _, _ := SessionAlive(current); alive {
		t.Fatal("same name, later start: want not alive (reused pid)")
	}
	withProcessIdentity(t, "zsh", recorded, nil)
	if alive, _, _ := SessionAlive(current); alive {
		t.Fatal("same start, other program: want not alive")
	}
}

// When the identity cannot be read, SessionAlive reports an error instead of
// guessing, so callers neither signal the PID nor drop the record.
func TestSessionAliveFailsClosedWhenIdentityIsUnreadable(t *testing.T) {
	current := CurrentSession{PID: os.Getpid(), ProcessComm: "sing-box", ProcessStart: time.Now()}
	withProcessIdentity(t, "", time.Time{}, errors.New("sysctl: operation not permitted"))
	alive, _, err := SessionAlive(current)
	if err == nil || alive {
		t.Fatalf("SessionAlive(unreadable identity) = (%v, %v), want (false, error)", alive, err)
	}
}

// A launchd-managed session whose recorded PID was reused is looked up through
// launchd instead of being declared gone, so the genuine service stays managed.
func TestSessionAliveFallsBackToLaunchdWhenRecordedPIDIsReused(t *testing.T) {
	current := CurrentSession{PID: os.Getpid(), ProcessComm: "sing-box", ProcessStart: time.Now().Add(-time.Hour), LaunchMode: config.LaunchModeLaunchd, LaunchLabel: "works.relux.test"}
	withProcessIdentity(t, "zsh", time.Now(), nil)
	previous := launchdPIDSession
	launchdPIDSession = func(string) (int, error) { return 4242, nil }
	t.Cleanup(func() { launchdPIDSession = previous })

	alive, pid, err := SessionAlive(current)
	if err != nil || !alive || pid != 4242 {
		t.Fatalf("SessionAlive(reused pid, launchd) = (%v, %d, %v), want (true, 4242, nil)", alive, pid, err)
	}
}

// recordProcessIdentity stores what the live process reports, retries a
// transient failure once, and returns an error (leaving the record empty)
// when the identity still cannot be read, so a fresh session is never saved
// as a weaker legacy record.
func TestRecordProcessIdentityStoresOrFails(t *testing.T) {
	previousDelay := identityRetryDelay
	identityRetryDelay = 0
	t.Cleanup(func() { identityRetryDelay = previousDelay })

	started := time.Now().Add(-time.Minute)
	session := CurrentSession{PID: 4242}
	withProcessIdentity(t, "sudo", started, nil)
	if err := recordProcessIdentity(&session); err != nil || session.ProcessComm != "sudo" || !session.ProcessStart.Equal(started) {
		t.Fatalf("recorded = (%q, %v, %v), want (sudo, %v, nil)", session.ProcessComm, session.ProcessStart, err, started)
	}

	calls := 0
	previous := processIdentitySession
	processIdentitySession = func(int) (string, time.Time, error) {
		calls++
		if calls == 1 {
			return "", time.Time{}, errors.New("transient")
		}
		return "sing-box", started, nil
	}
	retried := CurrentSession{PID: 4243}
	if err := recordProcessIdentity(&retried); err != nil || retried.ProcessComm != "sing-box" || calls != 2 {
		t.Fatalf("retry = (%q, %v, calls=%d), want (sing-box, nil, 2)", retried.ProcessComm, err, calls)
	}
	processIdentitySession = previous

	withProcessIdentity(t, "", time.Time{}, errors.New("gone"))
	failed := CurrentSession{PID: 4244}
	if err := recordProcessIdentity(&failed); err == nil || failed.ProcessComm != "" {
		t.Fatalf("persistent failure = (%q, %v), want (empty, error)", failed.ProcessComm, err)
	}
}

// The launchd stop poll keeps the recorded identity: a reused PID held by a
// different sing-box (later start) is not the stopped service, and with
// launchd reporting no PID the session counts as stopped.
func TestLaunchdStopPollKeepsRecordedIdentity(t *testing.T) {
	recorded := time.Now().Add(-time.Hour)
	current := CurrentSession{PID: os.Getpid(), ProcessComm: "sing-box", ProcessStart: recorded, LaunchMode: config.LaunchModeLaunchd, LaunchLabel: "works.relux.test", ID: "x", LogPath: "/tmp/x"}
	poll := launchdStopPollRecord(current)
	if poll.ProcessComm != "sing-box" || !poll.ProcessStart.Equal(recorded) {
		t.Fatalf("poll record dropped identity: %+v", poll)
	}
	withProcessIdentity(t, "sing-box", recorded.Add(30*time.Minute), nil)
	previous := launchdPIDSession
	launchdPIDSession = func(string) (int, error) { return 0, nil }
	t.Cleanup(func() { launchdPIDSession = previous })
	if alive, _, err := SessionAlive(poll); err != nil || alive {
		t.Fatalf("SessionAlive(poll, reused same-name pid, launchd gone) = (%v, %v), want (false, nil)", alive, err)
	}
}

// Legacy records without a recorded identity are checked by name only.
func TestSessionAliveLegacyRecordChecksNameOnly(t *testing.T) {
	current := CurrentSession{PID: os.Getpid(), Command: []string{"/usr/local/bin/sing-box"}}
	withProcessIdentity(t, "sing-box", time.Now(), nil)
	if alive, _, _ := SessionAlive(current); !alive {
		t.Fatal("legacy record with matching name: want alive")
	}
	withProcessIdentity(t, "zsh", time.Now(), nil)
	if alive, _, _ := SessionAlive(current); alive {
		t.Fatal("legacy record with another program's name: want not alive")
	}
}

// A helper-mode startup kill goes only through the opaque vpn-core handle: a
// legacy record without a handle is refused with no signal sent, and a record
// with a handle sends exactly one -KILL to that handle (positive control), even
// when the recorded PID now belongs to another program.
func TestKillHelperSessionSignalsOnlyByHandle(t *testing.T) {
	recorded := time.Now().Add(-time.Minute)
	type sent struct{ handle, signal string }
	var signalled []sent
	previous := vpnCoreSignalSession
	vpnCoreSignalSession = func(handle, signal string) error {
		signalled = append(signalled, sent{handle, signal})
		return nil
	}
	t.Cleanup(func() { vpnCoreSignalSession = previous })

	legacy := CurrentSession{PID: 4242, ProcessComm: "sing-box", ProcessStart: recorded, LaunchMode: config.LaunchModeHelper}
	withProcessIdentity(t, "sing-box", recorded, nil)
	if err := killHelperSession(legacy); err == nil {
		t.Fatal("killHelperSession(no handle) error = nil, want refusal")
	}
	if len(signalled) != 0 {
		t.Fatalf("signals sent despite refusal: %v", signalled)
	}

	withHandle := legacy
	withHandle.Handle = "h-test-1"
	withProcessIdentity(t, "zsh", time.Now(), nil)
	if err := killHelperSession(withHandle); err != nil {
		t.Fatalf("killHelperSession(handle) = %v, want nil", err)
	}
	if len(signalled) != 1 || signalled[0] != (sent{"h-test-1", "-KILL"}) {
		t.Fatalf("signals = %v, want exactly one -KILL to h-test-1", signalled)
	}
}
