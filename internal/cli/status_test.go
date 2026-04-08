package cli

import (
	"testing"
)

func TestDeriveConnectionStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		sessionAlive     bool
		interfacePresent bool
		want             string
	}{
		{name: "tun down", sessionAlive: false, interfacePresent: false, want: "down"},
		{name: "tun degraded with session", sessionAlive: true, interfacePresent: false, want: "degraded"},
		{name: "tun degraded with interface", sessionAlive: false, interfacePresent: true, want: "degraded"},
		{name: "tun up", sessionAlive: true, interfacePresent: true, want: "up"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := deriveConnectionStatus(test.sessionAlive, test.interfacePresent)
			if got != test.want {
				t.Fatalf("deriveConnectionStatus(%t, %t) = %q, want %q", test.sessionAlive, test.interfacePresent, got, test.want)
			}
		})
	}
}
