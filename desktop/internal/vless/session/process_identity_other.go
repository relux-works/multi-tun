//go:build !darwin

package session

import (
	"errors"
	"time"
)

// processIdentity is only implemented on darwin, the platform vless-tun
// targets; elsewhere identity checks are skipped by the caller.
func processIdentity(int) (string, time.Time, error) {
	return "", time.Time{}, errProcessIdentityUnsupported
}

var errProcessIdentityUnsupported = errors.New("process identity is unsupported on this platform")
