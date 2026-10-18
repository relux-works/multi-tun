package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"multi-tun/desktop/internal/core/vpncore"
	"multi-tun/desktop/internal/vless/config"
	"multi-tun/desktop/internal/vless/subscription"
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
				ActiveRequests: []vpncore.RequestSnapshot{{Action: "singbox.start", AgeMillis: 5001}},
				QueuedRequests: []vpncore.RequestSnapshot{{Action: "pending", AgeMillis: 11}},
				LastCompletedRequest: &vpncore.CompletedRequestSnapshot{
					Action:         "dns.scutil",
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
		"vpn_core_active_requests: singbox.start(age=5001ms)",
		"vpn_core_queued_requests: pending(age=11ms)",
		"vpn_core_last_completed_request: dns.scutil(outcome=error,duration=20000ms,age=7ms)",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("vpn core diagnostics missing %q:\n%s", want, stdout.String())
		}
	}
}

// Diagnose warns for an exact lowercase content-hash selector with a country match replacement, while a name selector is the positive no-warning control.
func TestDiagnoseConfigWarnsOnlyForHashLikeSelector(t *testing.T) {
	const source = "vless://00000000-0000-0000-0000-000000000003@us.example.com:443?type=tcp&security=reality&pbk=abc&fp=chrome&sni=us.example.com&sid=1#USA"
	profile, err := subscription.ParseVLESSURI(source)
	if err != nil {
		t.Fatalf("ParseVLESSURI() error = %v", err)
	}

	t.Run("hash selector", func(t *testing.T) {
		path, _ := writeReconnectConfig(t, profile.ID)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile() error = %v", err)
		}
		raw = []byte(strings.Replace(string(raw), "#us-east\"", "#USA\"", 1))
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
		var stdout, stderr bytes.Buffer
		exitCode := New(&stdout, &stderr).Run([]string{"diagnose", "config", "--config", path})
		if exitCode != 0 {
			t.Fatalf("exitCode = %d, stderr=%q", exitCode, stderr.String())
		}
		for _, want := range []string{"warning:", "content-hash id", `"country": "US"`} {
			if !strings.Contains(stdout.String(), want) {
				t.Fatalf("stdout = %q, want %q", stdout.String(), want)
			}
		}
	})

	t.Run("name selector", func(t *testing.T) {
		path, _ := writeReconnectConfig(t, "us-east")
		var stdout, stderr bytes.Buffer
		exitCode := New(&stdout, &stderr).Run([]string{"diagnose", "config", "--config", path})
		if exitCode != 0 {
			t.Fatalf("exitCode = %d, stderr=%q", exitCode, stderr.String())
		}
		if strings.Contains(stdout.String(), "content-hash id") {
			t.Fatalf("stdout = %q, want no hash warning", stdout.String())
		}
	})
}
