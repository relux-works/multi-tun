package cli

import (
	"bytes"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"multi-tun/desktop/internal/sshproxy/config"
)

func TestStatusAndStopReportNoCurrentSession(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.json")
	if _, _, err := config.Setup(path, config.SetupOptions{
		ServerName: "dedicated",
		Host:       "dedicated.example",
	}, false); err != nil {
		t.Fatalf("Setup() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := New(&stdout, &stderr)
	if exitCode := app.Run([]string{"status", "--config", path}); exitCode != 0 {
		t.Fatalf("Run(status) exitCode = %d, stderr = %q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "connection: down") {
		t.Fatalf("status stdout = %q, want down connection", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if exitCode := app.Run([]string{"stop", "--config", path}); exitCode != 0 {
		t.Fatalf("Run(stop) exitCode = %d, stderr = %q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "no current session file found") {
		t.Fatalf("stop stdout = %q, want no current session", stdout.String())
	}
}

func TestEnsurePortAvailableRejectsBoundEndpoint(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()
	if err := ensurePortAvailable(listener.Addr().String()); err == nil {
		t.Fatal("ensurePortAvailable() error = nil, want busy endpoint error")
	}
}

func TestUsageUsesSSHProxyName(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := New(&stdout, &stderr)
	if exitCode := app.Run([]string{"help"}); exitCode != 0 {
		t.Fatalf("Run(help) exitCode = %d, stderr = %q", exitCode, stderr.String())
	}
	legacyCommand := "ssh" + "-tun"
	if got := stdout.String(); !strings.Contains(got, "ssh-proxy manages") || strings.Contains(got, legacyCommand) {
		t.Fatalf("usage = %q, want ssh-proxy-only output", got)
	}
}
