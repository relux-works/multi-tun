package cli

import (
	"testing"

	"multi-tun/internal/config"
)

func TestDeriveConnectionStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		mode             string
		sessionAlive     bool
		interfacePresent bool
		want             string
	}{
		{name: "tun down", mode: config.RenderModeTun, sessionAlive: false, interfacePresent: false, want: "down"},
		{name: "tun degraded with session", mode: config.RenderModeTun, sessionAlive: true, interfacePresent: false, want: "degraded"},
		{name: "tun degraded with interface", mode: config.RenderModeTun, sessionAlive: false, interfacePresent: true, want: "degraded"},
		{name: "tun up", mode: config.RenderModeTun, sessionAlive: true, interfacePresent: true, want: "up"},
		{name: "system proxy down", mode: config.RenderModeSystemProxy, sessionAlive: false, interfacePresent: false, want: "down"},
		{name: "system proxy up", mode: config.RenderModeSystemProxy, sessionAlive: true, interfacePresent: false, want: "up"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := deriveConnectionStatus(test.mode, test.sessionAlive, test.interfacePresent)
			if got != test.want {
				t.Fatalf("deriveConnectionStatus(%q, %t, %t) = %q, want %q", test.mode, test.sessionAlive, test.interfacePresent, got, test.want)
			}
		})
	}
}
