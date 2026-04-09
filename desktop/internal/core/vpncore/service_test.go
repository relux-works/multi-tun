package vpncore

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRenderPlist(t *testing.T) {
	t.Parallel()

	cfg := ServiceConfig{
		Label:      "works.relux.test-vpn-core",
		PlistPath:  "/Library/LaunchDaemons/works.relux.test-vpn-core.plist",
		SocketPath: "/var/run/works.relux.test-vpn-core.sock",
	}
	plist := string(RenderServicePlist(cfg, "/tmp/vpn-core", 501, 20))
	for _, want := range []string{
		"<string>works.relux.test-vpn-core</string>",
		"<string>/tmp/vpn-core</string>",
		"<string>_daemon</string>",
		"<string>/var/run/works.relux.test-vpn-core.sock</string>",
		"<string>501</string>",
		"<string>20</string>",
	} {
		if !strings.Contains(plist, want) {
			t.Fatalf("plist missing %q", want)
		}
	}
}

func TestDaemonRunSpawnAndSignal(t *testing.T) {
	socketPath := filepath.Join(os.TempDir(), fmt.Sprintf("vpn-core-%d.sock", time.Now().UnixNano()))
	_ = os.Remove(socketPath)
	defer os.Remove(socketPath)

	cfg := ServiceConfig{
		Label:      "test",
		PlistPath:  "test",
		SocketPath: socketPath,
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- RunDaemon(cfg, os.Getuid(), os.Getgid())
	}()
	waitForSocket(t, cfg, errCh)

	dir := t.TempDir()
	runStdinPath := filepath.Join(dir, "run-stdin.txt")
	runLogPath := filepath.Join(dir, "run.log")
	runScriptPath := filepath.Join(dir, "run.sh")
	runScript := "#!/bin/sh\nset -eu\ncat >" + testShellQuote(runStdinPath) + "\necho vpn-core-run-ok\n"
	if err := os.WriteFile(runScriptPath, []byte(runScript), 0o755); err != nil {
		t.Fatalf("WriteFile(run script) error = %v", err)
	}

	if err := Run(cfg, []string{runScriptPath}, "RUN_STDIN\n", runLogPath); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	rawRunStdin, err := os.ReadFile(runStdinPath)
	if err != nil {
		t.Fatalf("ReadFile(run stdin) error = %v", err)
	}
	if got := strings.TrimSpace(string(rawRunStdin)); got != "RUN_STDIN" {
		t.Fatalf("run stdin = %q, want %q", got, "RUN_STDIN")
	}

	spawnLogPath := filepath.Join(dir, "spawn.log")
	spawnPidFile := filepath.Join(dir, "spawn.pid")
	spawnScriptPath := filepath.Join(dir, "spawn.sh")
	spawnScript := "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$$\" >" + testShellQuote(spawnPidFile) + "\nsleep 30\n"
	if err := os.WriteFile(spawnScriptPath, []byte(spawnScript), 0o755); err != nil {
		t.Fatalf("WriteFile(spawn script) error = %v", err)
	}

	pid, err := SpawnDetached(cfg, []string{spawnScriptPath}, "", spawnLogPath, true)
	if err != nil {
		t.Fatalf("SpawnDetached() error = %v", err)
	}
	if pid <= 0 {
		t.Fatalf("SpawnDetached() pid = %d", pid)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		rawPid, err := os.ReadFile(spawnPidFile)
		if err == nil && strings.TrimSpace(string(rawPid)) != "" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if err := Signal(cfg, pid, "-TERM", true); err != nil {
		t.Fatalf("Signal() error = %v", err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		err := syscallKill(pid, 0)
		if err != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("spawned pid %d is still alive after signal", pid)
}

func TestCompatibilityFallbackUsesLegacyService(t *testing.T) {
	primarySocketPath := filepath.Join(os.TempDir(), fmt.Sprintf("vpn-core-primary-%d.sock", time.Now().UnixNano()))
	legacySocketPath := filepath.Join(os.TempDir(), fmt.Sprintf("vpn-core-legacy-%d.sock", time.Now().UnixNano()))
	_ = os.Remove(primarySocketPath)
	_ = os.Remove(legacySocketPath)
	defer os.Remove(primarySocketPath)
	defer os.Remove(legacySocketPath)

	primaryCfg := ServiceConfig{
		Label:      "works.relux.primary-test",
		PlistPath:  "/Library/LaunchDaemons/works.relux.primary-test.plist",
		SocketPath: primarySocketPath,
	}
	legacyCfg := ServiceConfig{
		Label:      "works.relux.legacy-test",
		PlistPath:  "/Library/LaunchDaemons/works.relux.legacy-test.plist",
		SocketPath: legacySocketPath,
	}

	prevCompat := compatibilityServiceConfigsVPNCore
	compatibilityServiceConfigsVPNCore = func(cfg ServiceConfig) []compatibilityConfig {
		if !sameServiceConfig(cfg, primaryCfg) {
			return nil
		}
		return []compatibilityConfig{{
			ServiceConfig: legacyCfg,
			Compatibility: CompatibilityLegacyOpenConnectHelper,
		}}
	}
	t.Cleanup(func() {
		compatibilityServiceConfigsVPNCore = prevCompat
	})

	errCh := make(chan error, 1)
	go func() {
		errCh <- RunDaemon(legacyCfg, os.Getuid(), os.Getgid())
	}()
	waitForSocket(t, legacyCfg, errCh)

	status, err := InspectService(primaryCfg)
	if err != nil {
		t.Fatalf("InspectService() error = %v", err)
	}
	if !status.Reachable {
		t.Fatalf("InspectService() reachable = false")
	}
	if status.Label != legacyCfg.Label {
		t.Fatalf("InspectService() label = %q, want %q", status.Label, legacyCfg.Label)
	}
	if status.Compatibility != CompatibilityLegacyOpenConnectHelper {
		t.Fatalf("InspectService() compatibility = %q, want %q", status.Compatibility, CompatibilityLegacyOpenConnectHelper)
	}
	if !Available(primaryCfg) {
		t.Fatalf("Available() = false, want true")
	}

	dir := t.TempDir()
	runStdinPath := filepath.Join(dir, "legacy-stdin.txt")
	runLogPath := filepath.Join(dir, "legacy.log")
	runScriptPath := filepath.Join(dir, "legacy.sh")
	runScript := "#!/bin/sh\nset -eu\ncat >" + testShellQuote(runStdinPath) + "\necho compat-ok\n"
	if err := os.WriteFile(runScriptPath, []byte(runScript), 0o755); err != nil {
		t.Fatalf("WriteFile(legacy script) error = %v", err)
	}

	if err := Run(primaryCfg, []string{runScriptPath}, "LEGACY_STDIN\n", runLogPath); err != nil {
		t.Fatalf("Run() fallback error = %v", err)
	}
	rawStdin, err := os.ReadFile(runStdinPath)
	if err != nil {
		t.Fatalf("ReadFile(legacy stdin) error = %v", err)
	}
	if got := strings.TrimSpace(string(rawStdin)); got != "LEGACY_STDIN" {
		t.Fatalf("legacy stdin = %q, want %q", got, "LEGACY_STDIN")
	}
}

func waitForSocket(t *testing.T, cfg ServiceConfig, errCh <-chan error) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			t.Fatalf("vpn core daemon exited early: %v", err)
		default:
		}
		status, err := InspectService(cfg)
		if err == nil && status.Reachable {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("vpn core socket %s did not become reachable", cfg.SocketPath)
}

func testShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func syscallKill(pid int, signal int) error {
	cmd := exec.Command("kill", fmt.Sprintf("-%d", signal), fmt.Sprintf("%d", pid))
	return cmd.Run()
}
