package vpncorecli

import (
	"fmt"
	"io"
	"unicode/utf8"
)

// controlEscapingWriter escapes terminal control characters before they reach
// the operator. Much of what vpn-core prints (PATH-resolved paths, errors that
// embed them, launchctl diagnostics) is shaped by the unprivileged user, and
// the operator reads that output while deciding on a sudo digest. Newline and
// tab pass through; every other C0/C1 control, DEL and invalid UTF-8 byte is
// written as a \xNN escape.
type controlEscapingWriter struct {
	w io.Writer
}

func newControlEscapingWriter(w io.Writer) io.Writer {
	if w == nil {
		return nil
	}
	if _, ok := w.(controlEscapingWriter); ok {
		return w
	}
	return controlEscapingWriter{w: w}
}

func (c controlEscapingWriter) Write(p []byte) (int, error) {
	out := make([]byte, 0, len(p))
	for i := 0; i < len(p); {
		r, size := utf8.DecodeRune(p[i:])
		switch {
		case r == utf8.RuneError && size <= 1:
			out = fmt.Appendf(out, `\x%02x`, p[i])
		case r == '\n' || r == '\t':
			out = append(out, byte(r))
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
			for _, b := range p[i : i+size] {
				out = fmt.Appendf(out, `\x%02x`, b)
			}
		default:
			out = append(out, p[i:i+size]...)
		}
		i += size
	}
	if _, err := c.w.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}
