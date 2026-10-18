//go:build !darwin

package vpncore

import (
	"errors"
	"net"
)

func localPeerUID(*net.UnixConn) (uint32, error) {
	return 0, errors.New("LOCAL_PEERCRED is unavailable; vpn-core only supports darwin")
}
