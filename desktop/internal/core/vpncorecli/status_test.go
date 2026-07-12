package vpncorecli

import (
	"bytes"
	"strings"
	"testing"

	"multi-tun/desktop/internal/core/vpncore"
)

func TestStatusPrintsRedactedRequestSnapshot(t *testing.T) {
	previous := inspectServiceVPNCoreCLI
	inspectServiceVPNCoreCLI = func(vpncore.ServiceConfig) (vpncore.ServiceStatus, error) {
		return vpncore.ServiceStatus{
			Label:      "works.relux.vpn-core",
			PlistPath:  "/Library/LaunchDaemons/works.relux.vpn-core.plist",
			SocketPath: "/var/run/works.relux.vpn-core.sock",
			Reachable:  true,
			DaemonPID:  42,
			HelperSnapshot: &vpncore.HelperSnapshot{
				ActiveRequests: []vpncore.RequestSnapshot{{Action: "run", AgeMillis: 6000}},
				QueuedRequests: []vpncore.RequestSnapshot{{Action: "pending", AgeMillis: 2000}},
				LastCompletedRequest: &vpncore.CompletedRequestSnapshot{
					Action:         "spawn",
					Outcome:        "ok",
					DurationMillis: 12,
					AgeMillis:      3,
				},
			},
		}, nil
	}
	t.Cleanup(func() {
		inspectServiceVPNCoreCLI = previous
	})

	var stdout, stderr bytes.Buffer
	exitCode := New(&stdout, &stderr).Run([]string{"status"})
	if exitCode != 0 {
		t.Fatalf("status exit code = %d, stderr = %q", exitCode, stderr.String())
	}
	for _, want := range []string{
		"active_requests: run(age=6000ms)",
		"queued_requests: pending(age=2000ms)",
		"last_completed_request: spawn(outcome=ok,duration=12ms,age=3ms)",
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
