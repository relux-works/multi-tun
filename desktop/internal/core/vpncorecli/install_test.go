package vpncorecli

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"multi-tun/desktop/internal/core/vpncore"
)

func TestInstallRequiresExpectedDigestAndNoPositionalArguments(t *testing.T) {
	// This proves missing, malformed, uppercase, and stray install inputs are refused before the install API is called.
	previous := installServiceVPNCoreCLI
	called := false
	installServiceVPNCoreCLI = func(vpncore.ServiceConfig, string, int, int, string) error {
		called = true
		return nil
	}
	t.Cleanup(func() { installServiceVPNCoreCLI = previous })

	cases := [][]string{
		{"install"},
		{"install", "--expect-sha256", "abc"},
		{"install", "--expect-sha256", strings.Repeat("A", 64)},
		{"install", "--expect-sha256", strings.Repeat("a", 64), "stray"},
	}
	for _, args := range cases {
		var stdout, stderr bytes.Buffer
		if code := New(&stdout, &stderr).Run(args); code != 2 {
			t.Fatalf("Run(%v) code = %d, want 2; stderr=%q", args, code, stderr.String())
		}
	}
	if called {
		t.Fatal("invalid install arguments reached InstallService")
	}
}

func TestInstallDigestPrintsComputedDigest(t *testing.T) {
	// This proves install-digest emits one lowercase digest and rejects positional ambiguity.
	previous := installDigestVPNCoreCLI
	installDigestVPNCoreCLI = func(string) (string, error) { return strings.Repeat("b", 64), nil }
	t.Cleanup(func() { installDigestVPNCoreCLI = previous })
	var stdout, stderr bytes.Buffer
	if code := New(&stdout, &stderr).Run([]string{"install-digest"}); code != 0 {
		t.Fatalf("install-digest code = %d, stderr=%q", code, stderr.String())
	}
	if got := strings.Split(strings.TrimSpace(stdout.String()), "\n")[0]; got != strings.Repeat("b", 64) {
		t.Fatalf("install-digest first line = %q", got)
	}
	stdout.Reset()
	stderr.Reset()
	if code := New(&stdout, &stderr).Run([]string{"install-digest", "stray"}); code != 2 {
		t.Fatalf("install-digest stray code = %d", code)
	}
}

func TestInstallDigestFailureIsReported(t *testing.T) {
	// This proves digest computation failures cannot fall through to installation.
	previous := installDigestVPNCoreCLI
	installDigestVPNCoreCLI = func(string) (string, error) { return "", errors.New("hash failed") }
	t.Cleanup(func() { installDigestVPNCoreCLI = previous })
	var stdout, stderr bytes.Buffer
	if code := New(&stdout, &stderr).Run([]string{"install-digest"}); code != 1 {
		t.Fatalf("install-digest code = %d, want 1", code)
	}
}

func TestInstallRefusesSuccessWhenDaemonRemainsUnreachable(t *testing.T) {
	// This proves a completed bootstrap is not reported as success when bounded status polling never reaches the daemon, and diagnostics identify its socket and launchd tail.
	previousInstall := installServiceVPNCoreCLI
	previousInspect := inspectServiceVPNCoreCLI
	previousNow := installNowVPNCoreCLI
	previousSleep := installSleepVPNCoreCLI
	previousPrint := launchctlPrintVPNCoreCLI
	installServiceVPNCoreCLI = func(vpncore.ServiceConfig, string, int, int, string) error { return nil }
	inspectServiceVPNCoreCLI = func(cfg vpncore.ServiceConfig) (vpncore.ServiceStatus, error) {
		return vpncore.ServiceStatus{Label: cfg.Label, SocketPath: cfg.SocketPath, PlistPath: cfg.PlistPath}, nil
	}
	base := time.Unix(1, 0)
	calls := 0
	installNowVPNCoreCLI = func() time.Time {
		calls++
		if calls == 1 {
			return base
		}
		return base.Add(installReachabilityTimeoutVPNCoreCLI)
	}
	installSleepVPNCoreCLI = func(time.Duration) {}
	launchctlPrintVPNCoreCLI = func(string) ([]byte, error) { return []byte("line one\nself-verification failed\n"), nil }
	t.Cleanup(func() {
		installServiceVPNCoreCLI = previousInstall
		inspectServiceVPNCoreCLI = previousInspect
		installNowVPNCoreCLI = previousNow
		installSleepVPNCoreCLI = previousSleep
		launchctlPrintVPNCoreCLI = previousPrint
	})

	var stdout, stderr bytes.Buffer
	code := New(&stdout, &stderr).Run([]string{"install", "--expect-sha256", strings.Repeat("a", 64)})
	if code != 1 {
		t.Fatalf("install code = %d, want 1", code)
	}
	if strings.Contains(stdout.String(), "installed vpn core") {
		t.Fatalf("false success output = %q", stdout.String())
	}
	for _, want := range []string{"did not become reachable", vpncore.DefaultServiceConfig().SocketPath, "self-verification failed"} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("stderr = %q, want %q", stderr.String(), want)
		}
	}
}

func TestInstallPrintsSuccessAfterReachableStatus(t *testing.T) {
	// This positive control proves install still succeeds once bounded polling observes the hardened daemon as reachable.
	previousInstall := installServiceVPNCoreCLI
	previousInspect := inspectServiceVPNCoreCLI
	installServiceVPNCoreCLI = func(vpncore.ServiceConfig, string, int, int, string) error { return nil }
	inspectServiceVPNCoreCLI = func(cfg vpncore.ServiceConfig) (vpncore.ServiceStatus, error) {
		return vpncore.ServiceStatus{Label: cfg.Label, SocketPath: cfg.SocketPath, PlistPath: cfg.PlistPath, Reachable: true}, nil
	}
	t.Cleanup(func() {
		installServiceVPNCoreCLI = previousInstall
		inspectServiceVPNCoreCLI = previousInspect
	})
	var stdout, stderr bytes.Buffer
	if code := New(&stdout, &stderr).Run([]string{"install", "--expect-sha256", strings.Repeat("a", 64)}); code != 0 {
		t.Fatalf("install code = %d, stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "installed vpn core") {
		t.Fatalf("success output = %q", stdout.String())
	}
}
