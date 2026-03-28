package openconnect

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRenderPrivilegedHelperPlist(t *testing.T) {
	t.Parallel()

	cfg := PrivilegedHelperConfig{
		Label:      "works.relux.test-helper",
		PlistPath:  "/Library/LaunchDaemons/works.relux.test-helper.plist",
		SocketPath: "/var/run/works.relux.test-helper.sock",
	}
	plist := string(renderPrivilegedHelperPlist(cfg, "/tmp/openconnect-tun", 501, 20))
	for _, want := range []string{
		"<string>works.relux.test-helper</string>",
		"<string>/tmp/openconnect-tun</string>",
		"<string>_daemon</string>",
		"<string>/var/run/works.relux.test-helper.sock</string>",
		"<string>501</string>",
		"<string>20</string>",
	} {
		if !strings.Contains(plist, want) {
			t.Fatalf("plist missing %q", want)
		}
	}
}

func TestPrivilegedHelperDaemonConnectAndSignal(t *testing.T) {
	socketPath := filepath.Join(os.TempDir(), fmt.Sprintf("oc-helper-%d.sock", time.Now().UnixNano()))
	_ = os.Remove(socketPath)
	defer os.Remove(socketPath)
	errCh := make(chan error, 1)
	go func() {
		errCh <- RunPrivilegedHelperDaemon(socketPath, os.Getuid(), os.Getgid())
	}()
	waitForHelperSocket(t, socketPath, errCh)

	status, err := InspectPrivilegedHelper(PrivilegedHelperConfig{
		Label:      "test",
		PlistPath:  "test",
		SocketPath: socketPath,
	})
	if err != nil {
		t.Fatalf("InspectPrivilegedHelper() error = %v", err)
	}
	if !status.Reachable || status.DaemonPID <= 0 {
		t.Fatalf("helper status = %#v, want reachable daemon pid", status)
	}

	dir := t.TempDir()
	cookiePath := filepath.Join(dir, "cookie.txt")
	logPath := filepath.Join(dir, "openconnect.log")
	scriptPath := filepath.Join(dir, "fake-openconnect.sh")
	script := "#!/bin/sh\nset -eu\ncat >" + testShellQuote(cookiePath) + "\necho helper-connect-ok\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile(script) error = %v", err)
	}

	if err := helperConnect(defaultHelperConfigForSocket(socketPath), []string{scriptPath}, "COOKIE_VALUE", logPath); err != nil {
		t.Fatalf("helperConnect() error = %v", err)
	}
	rawCookie, err := os.ReadFile(cookiePath)
	if err != nil {
		t.Fatalf("ReadFile(cookie) error = %v", err)
	}
	if got := strings.TrimSpace(string(rawCookie)); got != "COOKIE_VALUE" {
		t.Fatalf("cookie = %q, want %q", got, "COOKIE_VALUE")
	}

	sleepCmd := exec.Command("sleep", "30")
	if err := sleepCmd.Start(); err != nil {
		t.Fatalf("sleep start error = %v", err)
	}
	if err := helperSignal(defaultHelperConfigForSocket(socketPath), sleepCmd.Process.Pid, "-TERM"); err != nil {
		t.Fatalf("helperSignal() error = %v", err)
	}
	_ = sleepCmd.Wait()
	alive, err := ProcessAlive(sleepCmd.Process.Pid)
	if err != nil {
		t.Fatalf("ProcessAlive() error = %v", err)
	}
	if alive {
		t.Fatalf("sleep pid %d is still alive after helper signal", sleepCmd.Process.Pid)
	}
}

func waitForHelperSocket(t *testing.T, socketPath string, errCh <-chan error) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			t.Fatalf("helper daemon exited early: %v", err)
		default:
		}
		status, err := InspectPrivilegedHelper(PrivilegedHelperConfig{
			Label:      "test",
			PlistPath:  "test",
			SocketPath: socketPath,
		})
		if err == nil && status.Reachable {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("helper socket %s did not become reachable", socketPath)
}

func testShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
