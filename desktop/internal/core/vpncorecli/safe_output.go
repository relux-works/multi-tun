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
//
// A rune split across Write calls is held back (at most utf8.UTFMax-1 bytes)
// until the next Write or Flush, so printable multi-byte text is never
// mangled. Flush escapes a trailing incomplete sequence.
type controlEscapingWriter struct {
	w       io.Writer
	pending []byte
}

func newControlEscapingWriter(w io.Writer) io.Writer {
	if w == nil {
		return nil
	}
	if _, ok := w.(*controlEscapingWriter); ok {
		return w
	}
	return &controlEscapingWriter{w: w}
}

// Write consumes p and reports how many of its bytes were handled. When the
// underlying writer fails or writes short, the count covers only the input
// bytes whose escaped form was written completely, so a caller that retries
// from the reported offset loses nothing.
func (c *controlEscapingWriter) Write(p []byte) (int, error) {
	data := append(c.pending, p...)
	c.pending = nil
	held := incompleteRuneSuffix(data)
	body := data[:len(data)-held]

	out, ends := escapeControls(body)
	written, err := c.w.Write(out)
	if err == nil && written < len(out) {
		err = io.ErrShortWrite
	}
	if err != nil {
		// ends[i] is the output offset after input byte i of body.
		doneBody := 0
		for doneBody < len(ends) && ends[doneBody] <= written {
			doneBody++
		}
		previouslyPending := len(data) - len(p)
		consumed := max(doneBody-previouslyPending, 0)
		// Held-back bytes from an earlier call that did not make it out are
		// dropped with the error; they were already reported as consumed.
		return consumed, err
	}
	c.pending = append([]byte(nil), data[len(body):]...)
	return len(p), nil
}

// Flush writes any held incomplete sequence, escaped.
func (c *controlEscapingWriter) Flush() error {
	if len(c.pending) == 0 {
		return nil
	}
	out := make([]byte, 0, 4*len(c.pending))
	for _, b := range c.pending {
		out = fmt.Appendf(out, `\x%02x`, b)
	}
	c.pending = nil
	_, err := c.w.Write(out)
	return err
}

// incompleteRuneSuffix returns how many trailing bytes form the start of a
// valid but unfinished UTF-8 sequence.
func incompleteRuneSuffix(data []byte) int {
	for n := 1; n < utf8.UTFMax && n <= len(data); n++ {
		start := len(data) - n
		if !utf8.RuneStart(data[start]) {
			continue
		}
		if utf8.FullRune(data[start:]) {
			return 0
		}
		return n
	}
	return 0
}

// escapeControls returns the escaped bytes and, for each input byte, the
// output length once that byte has been fully emitted.
func escapeControls(p []byte) ([]byte, []int) {
	out := make([]byte, 0, len(p))
	ends := make([]int, len(p))
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
		for j := i; j < i+size; j++ {
			ends[j] = len(out)
		}
		i += size
	}
	return out, ends
}
