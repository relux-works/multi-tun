//go:build !darwin

package vpncore

import "errors"

var watchProcessExitVPNCore = func(int, func()) error {
	return errors.New("process exit watching requires Darwin kqueue")
}
