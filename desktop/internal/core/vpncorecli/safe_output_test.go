package vpncorecli

import (
	"bytes"
	"errors"
	"io"
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

// A printable multi-byte rune split across Write calls arrives intact, and a
// trailing incomplete sequence is escaped on Flush rather than lost silently.
func TestControlEscapingWriterJoinsRunesAcrossWrites(t *testing.T) {
	var buf bytes.Buffer
	w := newControlEscapingWriter(&buf).(*controlEscapingWriter)
	euro := []byte("€")
	for _, part := range [][]byte{euro[:1], euro[1:2], euro[2:], []byte("\n")} {
		if n, err := w.Write(part); err != nil || n != len(part) {
			t.Fatalf("Write(%q) = (%d, %v)", part, n, err)
		}
	}
	if got := buf.String(); got != "€\n" {
		t.Fatalf("joined output = %q, want %q", got, "€\n")
	}
	buf.Reset()
	if _, err := w.Write(euro[:2]); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != `\xe2\x82` {
		t.Fatalf("flushed tail = %q, want escaped bytes", got)
	}
}

type shortWriter struct {
	limit int
	buf   bytes.Buffer
}

func (s *shortWriter) Write(p []byte) (int, error) {
	n := min(len(p), s.limit)
	s.buf.Write(p[:n])
	if n < len(p) {
		return n, io.ErrShortWrite
	}
	return n, nil
}

// On a short downstream write the reported count covers exactly the input
// bytes whose escaped form was fully written, so a retry from that offset
// neither duplicates nor drops input (io.Writer contract).
func TestControlEscapingWriterReportsShortWrites(t *testing.T) {
	for _, tc := range []struct {
		in    string
		limit int
		want  int
	}{
		{"ok", 1, 1},
		{"a\x1bb", 1, 1}, // the 4-byte escape for ESC does not fit
		{"a\x1bb", 5, 2}, // "a" + "\x1b" escape fully written
		{"ab", 0, 0},
	} {
		sw := &shortWriter{limit: tc.limit}
		n, err := newControlEscapingWriter(sw).Write([]byte(tc.in))
		if !errors.Is(err, io.ErrShortWrite) || n != tc.want {
			t.Fatalf("Write(%q) limit %d = (%d, %v), want (%d, ErrShortWrite)", tc.in, tc.limit, n, err, tc.want)
		}
	}
}
