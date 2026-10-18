package vpncorecli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"multi-tun/desktop/internal/core/vpncore"
)

// Every line the CLI prints goes through the escaping writer: a preparation
// error that embeds a PATH-derived path with an ESC byte reaches the operator
// escaped, while newlines and ordinary UTF-8 text are untouched.
func TestCLIOutputEscapesControlBytesFromPreparationErrors(t *testing.T) {
	previous := prepareInstallPlanVPNCoreCLI
	prepareInstallPlanVPNCoreCLI = func(string) (installPlanVPNCoreCLI, error) {
		return nil, errors.New("stage sing-box: open /tmp/evil\x1b[2J\x9b1m\u009b31m/sing-box: permission denied")
	}
	t.Cleanup(func() { prepareInstallPlanVPNCoreCLI = previous })
	for _, args := range [][]string{{"install-digest"}, {"install", "--expect-sha256", strings.Repeat("a", 64)}} {
		var stdout, stderr bytes.Buffer
		_ = New(&stdout, &stderr).Run(args)
		all := stdout.String() + stderr.String()
		if strings.Contains(all, "\x1b") || strings.Contains(all, "\x9b") || strings.Contains(all, "\u009b") {
			t.Fatalf("%v output contains raw control characters: %q", args, all)
		}
		if !strings.Contains(all, `evil\x1b[2J`) || !strings.Contains(all, `\x9b1m`) || !strings.Contains(all, `\xc2\x9b31m`) {
			t.Fatalf("%v output = %q, want escaped control characters", args, all)
		}
	}
}

// The writer passes newline, tab and printable UTF-8 through unchanged and
// reports the full input length to callers.
func TestControlEscapingWriterKeepsPrintableText(t *testing.T) {
	var buf bytes.Buffer
	w := newControlEscapingWriter(&buf)
	in := "Нидерланды\tok\nline two\x07\xff\n"
	n, err := w.Write([]byte(in))
	if err != nil || n != len(in) {
		t.Fatalf("Write() = (%d, %v), want (%d, nil)", n, err, len(in))
	}
	if got, want := buf.String(), "Нидерланды\tok\nline two\\x07\\xff\n"; got != want {
		t.Fatalf("escaped = %q, want %q", got, want)
	}
	_ = vpncore.ServiceConfig{}
}
