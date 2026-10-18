package vpncorecli

import (
	"bytes"
	"strings"
	"testing"

	"multi-tun/desktop/internal/core/vpncore"
)

func TestStatusPrintsRedactedRequestSnapshot(t *testing.T) {
	previous := inspectServiceVPNCoreCLI
	previousDrift := toolDriftVPNCoreCLI
	toolDriftVPNCoreCLI = func(vpncore.ServiceConfig) ([]string, error) { return nil, nil }
	inspectServiceVPNCoreCLI = func(vpncore.ServiceConfig) (vpncore.ServiceStatus, error) {
		return vpncore.ServiceStatus{
			Label:      "works.relux.vpn-core",
			PlistPath:  "/Library/LaunchDaemons/works.relux.vpn-core.plist",
			SocketPath: "/var/run/works.relux.vpn-core.sock",
			Reachable:  true,
			DaemonPID:  42,
			HelperSnapshot: &vpncore.HelperSnapshot{
				ActiveRequests: []vpncore.RequestSnapshot{{Action: "singbox.start", AgeMillis: 6000}},
				QueuedRequests: []vpncore.RequestSnapshot{{Action: "pending", AgeMillis: 2000}},
				LastCompletedRequest: &vpncore.CompletedRequestSnapshot{
					Action:         "tcpdump.start",
					Outcome:        "ok",
					DurationMillis: 12,
					AgeMillis:      3,
				},
			},
		}, nil
	}
	t.Cleanup(func() {
		inspectServiceVPNCoreCLI = previous
		toolDriftVPNCoreCLI = previousDrift
	})

	var stdout, stderr bytes.Buffer
	exitCode := New(&stdout, &stderr).Run([]string{"status"})
	if exitCode != 0 {
		t.Fatalf("status exit code = %d, stderr = %q", exitCode, stderr.String())
	}
	for _, want := range []string{
		"active_requests: singbox.start(age=6000ms)",
		"queued_requests: pending(age=2000ms)",
		"last_completed_request: tcpdump.start(outcome=ok,duration=12ms,age=3ms)",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("status output missing %q:\n%s", want, stdout.String())
		}
	}
	for _, secret := range []string{"COOKIE_SECRET", "https://vpn.example.invalid", "--cookie-on-stdin"} {
		if strings.Contains(stdout.String(), secret) {
			t.Fatalf("status output leaked %q:\n%s", secret, stdout.String())
		}
	}
}

func TestStatusPrintsDriftOnlyWhenReported(t *testing.T) {
	// This proves the unprivileged status surface prints a pinned/PATH mismatch and emits no drift line for equality.
	previousInspect := inspectServiceVPNCoreCLI
	previousDrift := toolDriftVPNCoreCLI
	inspectServiceVPNCoreCLI = func(cfg vpncore.ServiceConfig) (vpncore.ServiceStatus, error) {
		return vpncore.ServiceStatus{Label: cfg.Label, PlistPath: cfg.PlistPath, SocketPath: cfg.SocketPath}, nil
	}
	t.Cleanup(func() { inspectServiceVPNCoreCLI = previousInspect; toolDriftVPNCoreCLI = previousDrift })

	for _, tc := range []struct {
		lines []string
		want  bool
	}{
		{nil, false},
		{[]string{"drift: sing-box pinned=aaaaaaaaaaaa path=bbbbbbbbbbbb"}, true},
	} {
		toolDriftVPNCoreCLI = func(vpncore.ServiceConfig) ([]string, error) { return tc.lines, nil }
		var stdout, stderr bytes.Buffer
		if code := New(&stdout, &stderr).Run([]string{"status"}); code != 0 {
			t.Fatalf("code=%d stderr=%q", code, stderr.String())
		}
		if got := strings.Contains(stdout.String(), "drift: sing-box"); got != tc.want {
			t.Fatalf("output=%q drift=%t want=%t", stdout.String(), got, tc.want)
		}
	}
}
