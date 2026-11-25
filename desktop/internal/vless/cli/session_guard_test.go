package cli

import (
	"errors"
	"testing"
	"time"

	"multi-tun/desktop/internal/vless/config"
	"multi-tun/desktop/internal/vless/model"
	"multi-tun/desktop/internal/vless/session"
)

// errUnsanctionedSessionCall marks a test that reached the real session start, stop or liveness
// check or record write without its own fake. The real ones would probe the live vpn-core helper, launch a TUN
// process, stop the owner's running tunnel or probe an unrelated process by PID. Package init installs failing guards before any test runs; tests that
// exercise start or stop install their own fakes and restore these guards afterwards.
var errUnsanctionedSessionCall = errors.New("test reached the real session start or stop")

func init() {
	startSessionFunc = func(string, string, model.Profile, session.StartOptions) (session.CurrentSession, error) {
		return session.CurrentSession{}, errUnsanctionedSessionCall
	}
	stopCurrentSessionFunc = func(string, config.PrivilegedLaunchConfig, bool, time.Duration) (*session.CurrentSession, string, error) {
		return nil, "", errUnsanctionedSessionCall
	}
	sessionAliveFunc = func(session.CurrentSession) (bool, int, error) {
		return false, 0, errUnsanctionedSessionCall
	}
	saveCurrentFunc = func(string, session.CurrentSession) error {
		return errUnsanctionedSessionCall
	}
}

// Claim: in this test binary the default start, stop, liveness and record seams fail with the guard error and touch
// nothing, so an unsanctioned call cannot reach the real helper or tunnel (negative control: a
// direct call through each seam returns the guard error).
func TestSessionSeamsAreGuardedInTests(t *testing.T) {
	if _, err := startSessionFunc("", "", model.Profile{}, session.StartOptions{}); !errors.Is(err, errUnsanctionedSessionCall) {
		t.Fatalf("start seam = %v, want the guard", err)
	}
	if _, _, err := stopCurrentSessionFunc("", config.PrivilegedLaunchConfig{}, false, 0); !errors.Is(err, errUnsanctionedSessionCall) {
		t.Fatalf("stop seam = %v, want the guard", err)
	}
	if _, _, err := sessionAliveFunc(session.CurrentSession{PID: 1}); !errors.Is(err, errUnsanctionedSessionCall) {
		t.Fatalf("liveness seam = %v, want the guard", err)
	}
	if err := saveCurrentFunc(t.TempDir(), session.CurrentSession{}); !errors.Is(err, errUnsanctionedSessionCall) {
		t.Fatalf("record seam = %v, want the guard", err)
	}
}
