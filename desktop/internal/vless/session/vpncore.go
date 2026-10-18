package session

import (
	"fmt"
	"os"
	"time"
)

func startWithVPNCore(current CurrentSession) (int, string, error) {
	configJSON, err := os.ReadFile(current.ConfigPath)
	if err != nil {
		return 0, "", fmt.Errorf("read rendered sing-box config: %w", err)
	}
	pid, handle, err := vpnCoreStartSingBoxSession(configJSON, current.LogPath, current.LogMaxLines, true)
	if err != nil {
		return 0, "", fmt.Errorf("vpn core singbox.start: %w", err)
	}
	return pid, handle, nil
}

func stopHelperSession(current CurrentSession, force bool, timeout time.Duration) error {
	if current.Handle == "" {
		return fmt.Errorf("legacy helper session has no opaque handle; helper-mode stop is refused and this client has no safe direct fallback—stop the pre-PR-B session with the previous client before upgrading")
	}
	if err := vpnCoreSignalSession(current.Handle, "-TERM"); err != nil {
		return fmt.Errorf("vpn core signal: %w", err)
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		alive, _, err := SessionAlive(current)
		if err != nil {
			return err
		}
		if !alive {
			return nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	if !force {
		return fmt.Errorf("timeout waiting for sing-box pid %d to stop", current.PID)
	}
	if err := vpnCoreSignalSession(current.Handle, "-KILL"); err != nil {
		return fmt.Errorf("vpn core signal: %w", err)
	}
	deadline = time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		alive, _, err := SessionAlive(current)
		if err != nil {
			return err
		}
		if !alive {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for sing-box pid %d to stop", current.PID)
}

// killHelperSession force-stops a helper-mode sing-box after a failed start.
// It signals through the opaque handle the hardened vpn-core issued for the
// child it still holds, so a reused PID can never be hit. A legacy session
// without a handle is refused: there is no safe PID-based fallback.
func killHelperSession(current CurrentSession) error {
	if current.Handle == "" {
		return fmt.Errorf("legacy helper session has no opaque handle; refusing PID-based helper stop because no safe direct fallback exists")
	}
	if err := vpnCoreSignalSession(current.Handle, "-KILL"); err != nil {
		return fmt.Errorf("vpn core signal: %w", err)
	}
	return nil
}
