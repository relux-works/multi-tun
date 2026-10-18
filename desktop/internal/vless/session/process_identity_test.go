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

// recordProcessIdentity stores what the live process reports, and clears the
// fields when the lookup fails rather than keeping stale values.
func TestRecordProcessIdentityStoresObservedValues(t *testing.T) {
	started := time.Now().Add(-time.Minute)
	session := CurrentSession{PID: 4242}
	withProcessIdentity(t, "sudo", started, nil)
	recordProcessIdentity(&session)
	if session.ProcessComm != "sudo" || !session.ProcessStart.Equal(started) {
		t.Fatalf("recorded = (%q, %v), want (sudo, %v)", session.ProcessComm, session.ProcessStart, started)
	}
	withProcessIdentity(t, "", time.Time{}, errors.New("gone"))
	recordProcessIdentity(&session)
	if session.ProcessComm != "" || !session.ProcessStart.IsZero() {
		t.Fatalf("after failed lookup = (%q, %v), want cleared", session.ProcessComm, session.ProcessStart)
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
