// Package processidentity reads process identity without invoking privileged commands.
package processidentity

import (
	"errors"
	"time"
)

// ErrUnsupported indicates that the current platform has no identity lookup.
var ErrUnsupported = errors.New("process identity is unsupported on this platform")

// Matches retains the existing one-second kern.proc tolerance for recorded
// identities and the MAXCOMLEN-truncated name check for legacy records.
func Matches(comm string, started time.Time, recordedComm string, recordedStart time.Time, legacyName string) bool {
	if recordedComm != "" {
		delta := started.Sub(recordedStart)
		if delta < 0 {
			delta = -delta
		}
		return comm == recordedComm && delta <= time.Second
	}
	if len(legacyName) > 16 {
		legacyName = legacyName[:16]
	}
	return comm == legacyName
}
