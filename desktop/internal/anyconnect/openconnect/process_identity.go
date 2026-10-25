package openconnect

import (
	"errors"
	"fmt"
	"time"

	"multi-tun/desktop/internal/processidentity"
)

var (
	processIdentityOpenConnect    = processidentity.Read
	processAliveOpenConnect       = ProcessAlive
	signalSessionOpenConnect      = signalOpenConnectPID
	identityRetryDelayOpenConnect = 100 * time.Millisecond
)

func sessionProcessMatches(current CurrentSession) (bool, error) {
	comm, started, err := processIdentityOpenConnect(current.PID)
	if errors.Is(err, processidentity.ErrUnsupported) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("verify identity of openconnect pid %d: %w", current.PID, err)
	}
	return processidentity.Matches(comm, started, current.ProcessComm, current.ProcessStart, "openconnect"), nil
}

// recordProcessIdentity captures the daemon identity as soon as connect returns its PID.
func recordProcessIdentity(current *CurrentSession) error {
	comm, started, err := processIdentityOpenConnect(current.PID)
	if err != nil && !errors.Is(err, processidentity.ErrUnsupported) {
		time.Sleep(identityRetryDelayOpenConnect)
		comm, started, err = processIdentityOpenConnect(current.PID)
	}
	if errors.Is(err, processidentity.ErrUnsupported) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("record identity of openconnect pid %d: %w", current.PID, err)
	}
	current.ProcessComm, current.ProcessStart = comm, started
	return nil
}

// Recheck immediately before each interrupt or escalation, including after diagnostics.
func signalMatchingSession(current CurrentSession, signal, mode string) error {
	alive, _, err := SessionAlive(current)
	if err != nil || !alive {
		return err
	}
	if signalErr := signalSessionOpenConnect(current.PID, signal, mode, current.HelperSocketPath); signalErr != nil {
		// The daemon may have exited between verification and delivery of the signal.
		alive, _, lookupErr := SessionAlive(current)
		if lookupErr == nil && !alive {
			return nil
		}
		return errors.Join(signalErr, lookupErr)
	}
	return nil
}
