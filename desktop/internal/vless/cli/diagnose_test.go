package cli

import (
	"bytes"
	"strings"
	"testing"

	"multi-tun/desktop/internal/core/vpncore"
	"multi-tun/desktop/internal/vless/config"
)

func TestVPNCoreDiagnosticsPrintRequestSnapshot(t *testing.T) {
	previous := inspectVPNCoreServiceCLI
	inspectVPNCoreServiceCLI = func(vpncore.ServiceConfig) (vpncore.ServiceStatus, error) {
		return vpncore.ServiceStatus{
			Label:      "works.relux.vpn-core",
			SocketPath: "/var/run/works.relux.vpn-core.sock",
			Reachable:  true,
			DaemonPID:  42,
			HelperSnapshot: &vpncore.HelperSnapshot{
				ActiveRequests: []vpncore.RequestSnapshot{{Action: "spawn", AgeMillis: 5001}},
				QueuedRequests: []vpncore.RequestSnapshot{{Action: "pending", AgeMillis: 11}},
				LastCompletedRequest: &vpncore.CompletedRequestSnapshot{
					Action:         "run",
					Outcome:        "error",
					DurationMillis: 20000,
					AgeMillis:      7,
				},
			},
		}, nil
	}
	t.Cleanup(func() {
		inspectVPNCoreServiceCLI = previous
	})

	var stdout, stderr bytes.Buffer
	exitCode := New(&stdout, &stderr).printVPNCoreDiagnostics(config.PrivilegedLaunchConfig{Mode: config.LaunchModeHelper})
	if exitCode != 0 {
		t.Fatalf("printVPNCoreDiagnostics() exit code = %d, stderr = %q", exitCode, stderr.String())
	}
	for _, want := range []string{
		"vpn_core_active_requests: spawn(age=5001ms)",
		"vpn_core_queued_requests: pending(age=11ms)",
		"vpn_core_last_completed_request: run(outcome=error,duration=20000ms,age=7ms)",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("vpn core diagnostics missing %q:\n%s", want, stdout.String())
		}
	}
}
