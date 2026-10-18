//go:build !darwin

package session

import "time"

// processIdentity is only implemented on darwin, the platform vless-tun
// targets; elsewhere sessionProcessMatches keeps the plain liveness answer.
func processIdentity(int) (string, time.Time, error) {
	return "", time.Time{}, errProcessIdentityUnsupported
}
