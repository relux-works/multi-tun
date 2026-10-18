//go:build darwin

package vpncore

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func localPeerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var credential *unix.Xucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		credential, socketErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if socketErr != nil {
		return 0, socketErr
	}
	if credential == nil || credential.Version != 0 {
		return 0, fmt.Errorf("unexpected LOCAL_PEERCRED version")
	}
	return credential.Uid, nil
}
