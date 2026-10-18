package vpncore

import (
	"bytes"
	"os"
	"sync"
)

const maxBoundedLogBytes = 1 << 20

type passedLogWriter struct {
	file     *os.File
	maxLines int
	mu       sync.Mutex
	tail     []byte
	closed   bool
}

func newPassedLogWriter(file *os.File, maxLines int) *passedLogWriter {
	return &passedLogWriter{file: file, maxLines: maxLines}
}

func (w *passedLogWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, os.ErrClosed
	}
	if w.maxLines <= 0 {
		return w.file.Write(data)
	}
	w.tail = boundedLastLines(append(w.tail, data...), w.maxLines, maxBoundedLogBytes)
	if err := w.file.Truncate(0); err != nil {
		return 0, err
	}
	if _, err := w.file.Seek(0, 0); err != nil {
		return 0, err
	}
	if _, err := w.file.Write(w.tail); err != nil {
		return 0, err
	}
	return len(data), nil
}

func (w *passedLogWriter) Close() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true
	w.mu.Unlock()
	return w.file.Close()
}

func boundedLastLines(data []byte, maxLines, maxBytes int) []byte {
	if len(data) > maxBytes {
		data = data[len(data)-maxBytes:]
	}
	lines := bytes.SplitAfter(data, []byte{'\n'})
	if len(lines) > 0 && len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return bytes.Join(lines, nil)
}
