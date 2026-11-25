package vpncore

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// errTestReachedRealPFCTL marks a test that reached the production pfctl runner. Package init below
// installs it before any test runs, so every daemon built by any fixture (newServiceDaemon ->
// newFailClosedManager) gets a temp state path and a pfctl that fails instead of running /sbin/pfctl.
var errTestReachedRealPFCTL = errors.New("test reached the production pfctl runner")

const productionFailClosedStatePath = "/Library/Application Support/works.relux.vpn-core/failclosed.json"

func init() {
	dir, err := os.MkdirTemp("", "vpncore-failclosed-test-")
	if err != nil {
		panic(err)
	}
	failClosedStatePathVPNCore = filepath.Join(dir, "failclosed.json")
	pfctlVPNCore = func([]string, string) ([]byte, error) { return nil, errTestReachedRealPFCTL }
	// Any test that reaches the privileged runner or sudo without its own seam fails instead of
	// running sudo, launchctl, pfctl or rm as root on the host.
	runPrivilegedCommandVPNCore = func(string, ...string) ([]byte, error) { return nil, errTestReachedRealPrivileged }
	ensureSudoCredentialsVPNCore = func() error { return errTestReachedRealPrivileged }
	// Host-state commands never run from tests: they are replaced by /usr/bin/false, which fails
	// without side effects. Other commands (test fixtures, ls for ACL checks) run unchanged.
	realCommand, realCommandContext := execCommandVPNCore, execCommandContextVPNCore
	execCommandVPNCore = func(name string, args ...string) *exec.Cmd {
		if deniedTestCommand(name) {
			return realCommand("/usr/bin/false")
		}
		return realCommand(name, args...)
	}
	execCommandContextVPNCore = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if deniedTestCommand(name) {
			return realCommandContext(ctx, "/usr/bin/false")
		}
		return realCommandContext(ctx, name, args...)
	}
}

// deniedTestCommand names commands that change or probe host network, service or privilege state.
func deniedTestCommand(name string) bool {
	switch filepath.Base(name) {
	case "pfctl", "scutil", "networksetup", "route", "launchctl", "sudo", "sing-box", "tcpdump", "colima", "docker", "ifconfig", "dscacheutil", "killall":
		return true
	}
	return false
}

var errTestReachedRealPrivileged = errors.New("test reached the production privileged runner")

// Claim: in this test binary a daemon built the way every serving fixture builds it carries a temp
// state path (never the production one) and a pfctl that cannot run /sbin/pfctl. Negative control: an
// enabled state seeded at that temp path makes the start-time re-apply hit the guard, so a fixture that
// reaches pf fails loudly instead of touching the host.
func TestDaemonFixturesCannotReachRealPF(t *testing.T) {
	d := newServiceDaemon(ServiceConfig{}, 501, 20)
	if d.failClosed == nil {
		t.Fatal("daemon has no fail-closed manager")
	}
	if d.failClosed.statePath == productionFailClosedStatePath || !strings.HasPrefix(d.failClosed.statePath, os.TempDir()) {
		t.Fatalf("fixture state path %q is not a temp path", d.failClosed.statePath)
	}
	if _, err := d.failClosed.pfctl([]string{"-s", "info"}, ""); !errors.Is(err, errTestReachedRealPFCTL) {
		t.Fatalf("fixture pfctl = %v, want the guard", err)
	}
	if err := os.WriteFile(d.failClosed.statePath, []byte(`{"enabled":true,"interfaces":["en0"],"table":["1.1.1.1/32"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(d.failClosed.statePath) })
	if err := d.failClosed.ReapplyAtStart(); !errors.Is(err, errTestReachedRealPFCTL) {
		t.Fatalf("re-apply with an enabled state = %v, want the guard error", err)
	}
}

// Claim: denied host commands are neutralised in this test binary (a guarded scutil call fails and
// the real binary is never started), while an ordinary command still runs.
func TestHostCommandsNeutralisedInTests(t *testing.T) {
	if out, err := execCommandVPNCore("/usr/sbin/scutil", "--dns").Output(); err == nil || len(out) != 0 {
		t.Fatalf("scutil ran in a test: err=%v out=%d bytes", err, len(out))
	}
	if out, err := execCommandVPNCore("/bin/echo", "ok").Output(); err != nil || strings.TrimSpace(string(out)) != "ok" {
		t.Fatalf("ordinary command blocked: %v %q", err, out)
	}
}
