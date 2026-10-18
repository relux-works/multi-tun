//go:build darwin

package vpncore

import (
	"fmt"

	"golang.org/x/sys/unix"
)

var watchProcessExitVPNCore = watchProcessExit

func watchProcessExit(pid int, exited func()) error {
	kqueue, err := unix.Kqueue()
	if err != nil {
		return err
	}
	event := unix.Kevent_t{
		Ident:  uint64(pid),
		Filter: unix.EVFILT_PROC,
		Flags:  unix.EV_ADD | unix.EV_ONESHOT,
		Fflags: unix.NOTE_EXIT,
	}
	if _, err := unix.Kevent(kqueue, []unix.Kevent_t{event}, nil, nil); err != nil {
		_ = unix.Close(kqueue)
		return fmt.Errorf("register EVFILT_PROC NOTE_EXIT: %w", err)
	}
	go func() {
		defer unix.Close(kqueue)
		events := make([]unix.Kevent_t, 1)
		for {
			if _, err := unix.Kevent(kqueue, nil, events, nil); err == unix.EINTR {
				continue
			}
			exited()
			return
		}
	}()
	return nil
}
