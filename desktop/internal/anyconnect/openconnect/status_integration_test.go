package openconnect_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"multi-tun/desktop/internal/anyconnect/openconnect"
	"multi-tun/desktop/internal/anyconnect/openconnectcli"
)

func TestStatusCancelsHangingCiscoStateProbeAndShowsLiveSession(t *testing.T) {
	// Proves status cancels a genuinely hanging vpn state command within one shortened timeout, skips later Cisco probes, and still shows the live OpenConnect session with exit 0.
	const timeout = 25 * time.Millisecond
	commandCalls := 0
	restore := openconnect.InstallCiscoTestSeams(openconnect.CiscoTestSeams{
		CommandTimeout:      timeout,
		VPNBinaryCandidates: []string{"/fake/cisco/vpn"},
		PathStat:            func(string) (os.FileInfo, error) { return nil, nil },
		RunCommand: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			commandCalls++
			if name != "/fake/cisco/vpn" || len(args) != 1 || args[0] != "state" {
				t.Fatalf("runCommand(%q, %q), want only vpn state", name, args)
			}
			<-ctx.Done()
			return nil, ctx.Err()
		},
	})
	t.Cleanup(restore)

	root := t.TempDir()
	configPath := filepath.Join(root, "openconnect.json")
	if err := os.WriteFile(configPath, []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(configPath) error = %v", err)
	}
	cacheDir := filepath.Join(root, "cache")
	var stdout, stderr bytes.Buffer
	app := openconnectcli.NewWithStatusDependencies(&stdout, &stderr, openconnectcli.StatusDependencies{
		DetectState:    openconnect.DetectState,
		ConnectionInfo: openconnect.GetConnectionInfo,
		CurrentRuntime: func() (*openconnect.RuntimeStatus, error) {
			return &openconnect.RuntimeStatus{PID: 4242, Interface: "utun8", Uptime: "00:36"}, nil
		},
		ListProfiles: openconnect.ListProfiles,
		CurrentSession: func(string) (*openconnect.CurrentSession, string, bool, error) {
			return &openconnect.CurrentSession{
				ID:        "20261020T080000Z",
				Mode:      openconnect.ConnectModeSplitInclude,
				Server:    "vpn.example.com/outside",
				StartedAt: time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC),
				Interface: "utun8",
			}, "active", true, nil
		},
	})

	startedAt := time.Now()
	exitCode := app.Run([]string{"status", "--config", configPath, "--cache-dir", cacheDir})
	elapsed := time.Since(startedAt)

	if exitCode != 0 {
		t.Fatalf("Run(status) exitCode = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	if elapsed >= timeout+200*time.Millisecond {
		t.Fatalf("Run(status) elapsed = %s, want < %s", elapsed, timeout+200*time.Millisecond)
	}
	if commandCalls != 1 {
		t.Fatalf("Cisco command calls = %d, want 1", commandCalls)
	}
	for _, want := range []string{
		"session: active\n",
		"session_id: 20261020T080000Z\n",
		fmt.Sprintf("cisco agent unavailable: vpn state timed out after %s\n", timeout),
		"state: connected\n",
		"state_source: openconnect_runtime\n",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("status output missing %q:\n%s", want, stdout.String())
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("Run(status) stderr = %q, want empty", stderr.String())
	}
}
