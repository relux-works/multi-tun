package cli

import (
	"errors"
	"testing"
	"time"

	"multi-tun/desktop/internal/vless/config"
	"multi-tun/desktop/internal/vless/model"
	"multi-tun/desktop/internal/vless/session"
)

// errUnsanctionedSessionCall marks a test that reached a real session operation without its own
// fake: start, stop, the failed-start checks, or a read or write of the current-session record. The
// real ones would probe the live vpn-core helper, launch a TUN process, stop the owner's running
// tunnel, probe an unrelated process by PID or touch a real record. Package init installs failing
// guards before any test runs; tests that exercise these install their own fakes and restore the
// guards afterwards.
var errUnsanctionedSessionCall = errors.New("test reached the real session start or stop")

func init() {
	startSessionFunc = func(string, string, model.Profile, session.StartOptions) (session.CurrentSession, error) {
		return session.CurrentSession{}, errUnsanctionedSessionCall
	}
	stopCurrentSessionFunc = func(string, config.PrivilegedLaunchConfig, bool, time.Duration) (*session.CurrentSession, string, error) {
		return nil, "", errUnsanctionedSessionCall
	}
	sessionStoppedFunc = func(session.CurrentSession) (bool, error) { return false, errUnsanctionedSessionCall }
	loadCurrentFunc = func(string) (session.CurrentSession, error) {
		return session.CurrentSession{}, errUnsanctionedSessionCall
	}
	stopCurrentIfFunc = func(string, session.CurrentSession, config.PrivilegedLaunchConfig, bool, time.Duration) (session.CurrentSession, string, error) {
		return session.CurrentSession{}, "", errUnsanctionedSessionCall
	}
	stopReturnedFunc = func(session.CurrentSession) error { return errUnsanctionedSessionCall }
	saveCurrentIfAbsentFunc = func(string, session.CurrentSession) error { return errUnsanctionedSessionCall }
}

// Claim: in this test binary the default start, stop and every failed-start reconcile seam fail
// with the guard error and touch nothing, so an unsanctioned call cannot reach the real helper or tunnel (negative control: a
// direct call through each seam returns the guard error).
func TestSessionSeamsAreGuardedInTests(t *testing.T) {
	if _, err := startSessionFunc("", "", model.Profile{}, session.StartOptions{}); !errors.Is(err, errUnsanctionedSessionCall) {
		t.Fatalf("start seam = %v, want the guard", err)
	}
	if _, _, err := stopCurrentSessionFunc("", config.PrivilegedLaunchConfig{}, false, 0); !errors.Is(err, errUnsanctionedSessionCall) {
		t.Fatalf("stop seam = %v, want the guard", err)
	}
	if _, err := sessionStoppedFunc(session.CurrentSession{PID: 1}); !errors.Is(err, errUnsanctionedSessionCall) {
		t.Fatalf("stopped-check seam = %v, want the guard", err)
	}
	if _, err := loadCurrentFunc(t.TempDir()); !errors.Is(err, errUnsanctionedSessionCall) {
		t.Fatalf("record-read seam = %v, want the guard", err)
	}
	if _, _, err := stopCurrentIfFunc(t.TempDir(), session.CurrentSession{ID: "x"}, config.PrivilegedLaunchConfig{}, false, 0); !errors.Is(err, errUnsanctionedSessionCall) {
		t.Fatalf("record-stop seam = %v, want the guard", err)
	}
	if err := stopReturnedFunc(session.CurrentSession{PID: 1}); !errors.Is(err, errUnsanctionedSessionCall) {
		t.Fatalf("handle-stop seam = %v, want the guard", err)
	}
	if err := saveCurrentIfAbsentFunc(t.TempDir(), session.CurrentSession{}); !errors.Is(err, errUnsanctionedSessionCall) {
		t.Fatalf("record-write seam = %v, want the guard", err)
	}
}
