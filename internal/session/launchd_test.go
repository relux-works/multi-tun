package session

import (
	"strings"
	"testing"
)

func TestRenderLaunchdPlist(t *testing.T) {
	t.Parallel()

	plist := string(renderLaunchdPlist(
		"com.example.vless-tun",
		"/opt/homebrew/bin/sing-box",
		"/tmp/test.json",
		"/tmp/test.log",
	))

	for _, want := range []string{
		"<string>com.example.vless-tun</string>",
		"<string>/opt/homebrew/bin/sing-box</string>",
		"<string>/tmp/test.json</string>",
		"<string>/tmp/test.log</string>",
	} {
		if !strings.Contains(plist, want) {
			t.Fatalf("plist missing %q", want)
		}
	}
}

func TestParseLaunchdPID(t *testing.T) {
	t.Parallel()

	output := `
system/com.example.vless-tun = {
	pid = 4242
	state = running
}`

	if got := parseLaunchdPID(output); got != 4242 {
		t.Fatalf("parseLaunchdPID() = %d, want 4242", got)
	}
}
