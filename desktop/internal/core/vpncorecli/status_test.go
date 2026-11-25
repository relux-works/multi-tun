package vpncorecli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"multi-tun/desktop/internal/core/vpncore"
)

func TestStatusMaintenanceCapability(t *testing.T) {
	// Status distinguishes advertised support, legacy omission and absence; RPC errors never produce a capability verdict.
	previousInspect, previousDrift := inspectServiceVPNCoreCLI, toolDriftVPNCoreCLI
	t.Cleanup(func() { inspectServiceVPNCoreCLI = previousInspect; toolDriftVPNCoreCLI = previousDrift })
	toolDriftVPNCoreCLI = func(vpncore.ServiceConfig) ([]string, error) { return nil, nil }
	for _, tc := range []struct {
		name   string
		status vpncore.ServiceStatus
		err    error
		want   string
	}{
		{"inactive", vpncore.ServiceStatus{Reachable: true, MaintenanceDrain: &vpncore.MaintenanceDrainState{}}, nil, "maintenance_drain: supported\nmaintenance_active: false\n"},
		{"active", vpncore.ServiceStatus{Reachable: true, MaintenanceDrain: &vpncore.MaintenanceDrainState{Active: true, ExpiresAt: "PRIVATE_EXPIRY"}}, nil, "maintenance_drain: supported\nmaintenance_active: true\n"},
		{"legacy", vpncore.ServiceStatus{Reachable: true}, nil, "maintenance_drain: unadvertised\n"},
		{"missing", vpncore.ServiceStatus{}, nil, "maintenance_drain: unknown\n"},
		{"refused", vpncore.ServiceStatus{Reachable: true}, errors.New("peer uid refused"), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inspectServiceVPNCoreCLI = func(vpncore.ServiceConfig) (vpncore.ServiceStatus, error) { return tc.status, tc.err }
			var stdout, stderr bytes.Buffer
			code := New(&stdout, &stderr).Run([]string{"status"})
			if tc.err != nil {
				if code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "peer uid refused") {
					t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
				}
				return
			}
			if code != 0 || !strings.Contains(stdout.String(), tc.want) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			if strings.Count(stdout.String(), "maintenance_drain:") != 1 || strings.Contains(stdout.String(), "PRIVATE_EXPIRY") || (tc.status.MaintenanceDrain == nil && strings.Contains(stdout.String(), "maintenance_active:")) {
				t.Fatalf("ambiguous or excess status: %q", stdout.String())
			}
		})
	}
}

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
