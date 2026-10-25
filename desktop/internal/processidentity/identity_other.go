//go:build !darwin

package processidentity

import "time"

// Read is only implemented on darwin, the platform vless-tun
// targets; elsewhere callers can retain their platform fallback.
func Read(int) (string, time.Time, error) {
	return "", time.Time{}, ErrUnsupported
}
