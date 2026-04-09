package session

import (
	"fmt"
	"time"
)

func startWithVPNCore(current CurrentSession, executable string) (int, error) {
	command := []string{executable, "run", "-c", current.ConfigPath}
	pid, err := vpnCoreSpawnDetachedSession(command, current.LogPath, true)
	if err != nil {
		return 0, fmt.Errorf("vpn core spawn: %w", err)
	}
	return pid, nil
}

func stopHelperSession(current CurrentSession, force bool, timeout time.Duration) error {
	if err := vpnCoreSignalSession(current.PID, "-TERM", true); err != nil {
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
	if err := vpnCoreSignalSession(current.PID, "-KILL", true); err != nil {
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

func killHelperSession(current CurrentSession) error {
	if err := vpnCoreSignalSession(current.PID, "-KILL", true); err != nil {
		return fmt.Errorf("vpn core signal: %w", err)
	}
	return nil
}
