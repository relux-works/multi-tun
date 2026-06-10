package logtail

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

const defaultFlushInterval = 250 * time.Millisecond

type Options struct {
	MaxLines      int
	FlushInterval time.Duration
}

type writer struct {
	path          string
	maxLines      int
	flushInterval time.Duration

	mu      sync.Mutex
	pending []byte
	closed  bool

	done chan struct{}
	once sync.Once
	wg   sync.WaitGroup
}

func Open(path string, options Options) (io.WriteCloser, error) {
	if options.MaxLines <= 0 {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
		return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	}

	if err := Append(path, options.MaxLines, nil); err != nil {
		return nil, err
	}
	interval := options.FlushInterval
	if interval <= 0 {
		interval = defaultFlushInterval
	}
	w := &writer{
		path:          path,
		maxLines:      options.MaxLines,
		flushInterval: interval,
		done:          make(chan struct{}),
	}
	w.wg.Add(1)
	go w.flushLoop()
	return w, nil
}

func Append(path string, maxLines int, data []byte) error {
	if maxLines <= 0 {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return err
		}
		_, writeErr := file.Write(data)
		closeErr := file.Close()
		return errors.Join(writeErr, closeErr)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)

	existing, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	trimmed := lastLines(append(existing, data...), maxLines)

	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(trimmed); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func Trim(path string, maxLines int) error {
	return Append(path, maxLines, nil)
}

func (w *writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return 0, os.ErrClosed
	}
	w.pending = append(w.pending, p...)
	shouldFlush := len(w.pending) >= 256*1024
	w.mu.Unlock()

	if shouldFlush {
		if err := w.Flush(); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (w *writer) Close() error {
	w.once.Do(func() {
		close(w.done)
	})
	w.wg.Wait()

	w.mu.Lock()
	w.closed = true
	w.mu.Unlock()
	return w.Flush()
}

func (w *writer) Flush() error {
	w.mu.Lock()
	if len(w.pending) == 0 {
		w.mu.Unlock()
		return nil
	}
	pending := append([]byte(nil), w.pending...)
	w.pending = nil
	w.mu.Unlock()

	if err := Append(w.path, w.maxLines, pending); err != nil {
		w.mu.Lock()
		w.pending = append(pending, w.pending...)
		w.mu.Unlock()
		return err
	}
	return nil
}

func (w *writer) flushLoop() {
	defer w.wg.Done()
	ticker := time.NewTicker(w.flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			_ = w.Flush()
		case <-w.done:
			return
		}
	}
}

func lastLines(data []byte, maxLines int) []byte {
	if maxLines <= 0 || len(data) == 0 {
		return data
	}

	lines := 0
	if data[len(data)-1] != '\n' {
		lines = 1
	}
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] != '\n' {
			continue
		}
		lines++
		if lines > maxLines {
			return bytes.TrimLeft(data[i+1:], "\n")
		}
	}
	return data
}
