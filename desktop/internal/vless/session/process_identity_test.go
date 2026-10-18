package session

import (
	"os"
	"runtime"
	"testing"
	"time"
)

func withProcessIdentity(t *testing.T, comm string, started time.Time) {
	t.Helper()
	previous := processIdentitySession
	processIdentitySession = func(int) (string, time.Time, error) { return comm, started, nil }
	t.Cleanup(func() { processIdentitySession = previous })
}

// Stale metadata whose PID now belongs to an unrelated live process (here the
// test binary itself, read through the real kern.proc lookup) is not a
// running session, so nothing trusts or signals that PID.
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

// Positive control and the reuse-by-a-later-process case: the same command
// name started near the recorded start is alive; one that started hours later
// is a reused PID.
func TestSessionAliveMatchesCommandAndStartTime(t *testing.T) {
	recorded := time.Now().Add(-6 * time.Hour)
	current := CurrentSession{PID: os.Getpid(), Command: []string{"/opt/homebrew/bin/sing-box", "run"}, StartedAt: recorded}

	withProcessIdentity(t, "sing-box", recorded.Add(2*time.Second))
	if alive, _, err := SessionAlive(current); err != nil || !alive {
		t.Fatalf("SessionAlive(matching process) = (%v, %v), want (true, nil)", alive, err)
	}

	withProcessIdentity(t, "sing-box", recorded.Add(3*time.Hour))
	if alive, _, _ := SessionAlive(current); alive {
		t.Fatal("SessionAlive(sing-box started hours after the record) = true, want false (reused pid)")
	}
}

// Legacy metadata without a recorded start is checked by command name only.
func TestSessionAliveLegacyRecordChecksNameOnly(t *testing.T) {
	current := CurrentSession{PID: os.Getpid(), Command: []string{"/usr/local/bin/sing-box"}}
	withProcessIdentity(t, "sing-box", time.Now())
	if alive, _, _ := SessionAlive(current); !alive {
		t.Fatal("legacy record with matching name: want alive")
	}
	withProcessIdentity(t, "zsh", time.Now())
	if alive, _, _ := SessionAlive(current); alive {
		t.Fatal("legacy record with another program's name: want not alive")
	}
}
