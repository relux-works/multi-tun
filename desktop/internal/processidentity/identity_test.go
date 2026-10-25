package processidentity

import (
	"testing"
	"time"
)

// Recorded identities retain the existing ±1s tolerance; legacy names use Darwin's 16-byte truncation without accepting other commands.
func TestMatchesRecordedAndLegacyIdentity(t *testing.T) {
	started := time.Date(2026, 10, 19, 1, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		name, comm, recorded, legacy string
		delta                        time.Duration
		want                         bool
	}{
		{"recorded exact", "openconnect", "openconnect", "", 0, true},
		{"recorded tolerance", "openconnect", "openconnect", "", time.Second, true},
		{"recorded earlier tolerance", "openconnect", "openconnect", "", -time.Second, true},
		{"reused start", "openconnect", "openconnect", "", time.Second + time.Nanosecond, false},
		{"reused earlier start", "openconnect", "openconnect", "", -time.Second - time.Nanosecond, false},
		{"other command", "zsh", "openconnect", "", 0, false},
		{"legacy", "openconnect", "", "openconnect", time.Hour, true},
		{"legacy truncated", "1234567890123456", "", "12345678901234567", 0, true},
		{"legacy other command", "zsh", "", "openconnect", 0, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := Matches(tt.comm, started.Add(tt.delta), tt.recorded, started, tt.legacy); got != tt.want {
				t.Fatalf("Matches=%v want=%v", got, tt.want)
			}
		})
	}
}
