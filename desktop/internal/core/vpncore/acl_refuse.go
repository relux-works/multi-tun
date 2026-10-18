//go:build !darwin || !cgo

package vpncore

import "errors"

func checkWriteACL(string, int) error {
	return errors.New("ACL verification is unavailable; vpn-core refuses to start without darwin+cgo")
}
