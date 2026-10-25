package vpncorecli

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"multi-tun/desktop/internal/core/vpncore"
)

type fakeInstallPlan struct {
	digest    string
	tools     []vpncore.PinnedTool
	install   func(vpncore.ServiceConfig, int, int, string) error
	closeCall bool
	options   []vpncore.MaintenanceOptions
}

func (p *fakeInstallPlan) Digest() string { return p.digest }
func (p *fakeInstallPlan) PinnedTools() []vpncore.PinnedTool {
	return append([]vpncore.PinnedTool(nil), p.tools...)
}
func (p *fakeInstallPlan) Install(cfg vpncore.ServiceConfig, uid, gid int, digest string, options ...vpncore.MaintenanceOptions) error {
	p.options = append([]vpncore.MaintenanceOptions(nil), options...)
	if p.install == nil {
		return nil
	}
	return p.install(cfg, uid, gid, digest)
}
func (p *fakeInstallPlan) Close() error { p.closeCall = true; return nil }

func TestInstallRequiresExpectedDigestAndNoPositionalArguments(t *testing.T) {
	// This proves missing, malformed, uppercase, and stray install inputs are refused before an immutable install plan is prepared.
	previous := prepareInstallPlanVPNCoreCLI
	called := false
	prepareInstallPlanVPNCoreCLI = func(string) (installPlanVPNCoreCLI, error) {
		called = true
		return &fakeInstallPlan{}, nil
	}
	t.Cleanup(func() { prepareInstallPlanVPNCoreCLI = previous })

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
		t.Fatal("invalid install arguments prepared an install plan")
	}
}

func TestInstallDigestPrintsComputedDigest(t *testing.T) {
	// This proves install-digest emits digest and metadata from one plan, closes it, and rejects positional ambiguity.
	previous := prepareInstallPlanVPNCoreCLI
	plan := &fakeInstallPlan{digest: strings.Repeat("b", 64), tools: []vpncore.PinnedTool{{Name: "sing-box", Size: 4242, SHA256: strings.Repeat("c", 64), SourcePath: "/path/sing-box"}}}
	prepareInstallPlanVPNCoreCLI = func(string) (installPlanVPNCoreCLI, error) { return plan, nil }
	t.Cleanup(func() { prepareInstallPlanVPNCoreCLI = previous })
	var stdout, stderr bytes.Buffer
	if code := New(&stdout, &stderr).Run([]string{"install-digest"}); code != 0 {
		t.Fatalf("install-digest code = %d, stderr=%q", code, stderr.String())
	}
	if got := strings.Split(strings.TrimSpace(stdout.String()), "\n")[0]; got != strings.Repeat("b", 64) {
		t.Fatalf("install-digest first line = %q", got)
	}
	if !strings.Contains(stderr.String(), "size=4242") || !plan.closeCall {
		t.Fatalf("install-digest metadata=%q close=%t", stderr.String(), plan.closeCall)
	}
	stdout.Reset()
	stderr.Reset()
	if code := New(&stdout, &stderr).Run([]string{"install-digest", "stray"}); code != 2 {
		t.Fatalf("install-digest stray code = %d", code)
	}
}

func TestInstallDigestFailureIsReported(t *testing.T) {
	// This proves install-plan preparation failures cannot fall through to output or installation.
	previous := prepareInstallPlanVPNCoreCLI
	prepareInstallPlanVPNCoreCLI = func(string) (installPlanVPNCoreCLI, error) { return nil, errors.New("hash failed") }
	t.Cleanup(func() { prepareInstallPlanVPNCoreCLI = previous })
	var stdout, stderr bytes.Buffer
	if code := New(&stdout, &stderr).Run([]string{"install-digest"}); code != 1 {
		t.Fatalf("install-digest code = %d, want 1", code)
	}
}

func TestInstallRefusesSuccessWhenDaemonRemainsUnreachable(t *testing.T) {
	// This proves a completed bootstrap is not reported as success when bounded status polling never reaches the daemon, and diagnostics identify its socket and launchd tail.
	previousPlan := prepareInstallPlanVPNCoreCLI
	previousInspect := inspectServiceVPNCoreCLI
	previousNow := installNowVPNCoreCLI
	previousSleep := installSleepVPNCoreCLI
	previousPrint := launchctlPrintVPNCoreCLI
	prepareInstallPlanVPNCoreCLI = func(string) (installPlanVPNCoreCLI, error) { return &fakeInstallPlan{}, nil }
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
		prepareInstallPlanVPNCoreCLI = previousPlan
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
	// This positive control proves install and its success metadata use the same plan once bounded polling observes the hardened daemon as reachable.
	previousPlan := prepareInstallPlanVPNCoreCLI
	previousInspect := inspectServiceVPNCoreCLI
	installed := false
	plan := &fakeInstallPlan{
		tools: []vpncore.PinnedTool{{Name: "sing-box", Size: 777, SHA256: strings.Repeat("d", 64), SourcePath: "/same/plan"}},
		install: func(_ vpncore.ServiceConfig, _, _ int, digest string) error {
			installed = digest == strings.Repeat("a", 64)
			return nil
		},
	}
	prepareInstallPlanVPNCoreCLI = func(string) (installPlanVPNCoreCLI, error) { return plan, nil }
	inspectServiceVPNCoreCLI = func(cfg vpncore.ServiceConfig) (vpncore.ServiceStatus, error) {
		return vpncore.ServiceStatus{Label: cfg.Label, SocketPath: cfg.SocketPath, PlistPath: cfg.PlistPath, Reachable: true}, nil
	}
	t.Cleanup(func() {
		prepareInstallPlanVPNCoreCLI = previousPlan
		inspectServiceVPNCoreCLI = previousInspect
	})
	var stdout, stderr bytes.Buffer
	if code := New(&stdout, &stderr).Run([]string{"install", "--expect-sha256", strings.Repeat("a", 64)}); code != 0 {
		t.Fatalf("install code = %d, stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "installed vpn core") || !strings.Contains(stdout.String(), "size=777") || !installed || !plan.closeCall {
		t.Fatalf("success output = %q", stdout.String())
	}
}

// A PATH-resolved source path carrying terminal control bytes is printed
// escaped, so install-digest output cannot clear or rewrite the operator's
// screen; the path itself stays identifiable.
func TestInstallDigestEscapesControlBytesInSourcePath(t *testing.T) {
	previous := prepareInstallPlanVPNCoreCLI
	plan := &fakeInstallPlan{digest: strings.Repeat("b", 64), tools: []vpncore.PinnedTool{{Name: "sing-box", Size: 1, SHA256: strings.Repeat("c", 64), SourcePath: "/tmp/evil\x1b[2J/sing-box"}}}
	prepareInstallPlanVPNCoreCLI = func(string) (installPlanVPNCoreCLI, error) { return plan, nil }
	t.Cleanup(func() { prepareInstallPlanVPNCoreCLI = previous })
	var stdout, stderr bytes.Buffer
	if code := New(&stdout, &stderr).Run([]string{"install-digest"}); code != 0 {
		t.Fatalf("install-digest code = %d, stderr=%q", code, stderr.String())
	}
	all := stdout.String() + stderr.String()
	if strings.ContainsRune(all, '\x1b') {
		t.Fatalf("output contains a raw ESC byte: %q", all)
	}
	if !strings.Contains(all, `evil\x1b[2J`) {
		t.Fatalf("output = %q, want the escaped source path", all)
	}
}
