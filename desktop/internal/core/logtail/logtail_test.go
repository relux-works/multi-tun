package logtail

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppendKeepsLastLines(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "session.log")
	if err := Append(path, 3, []byte("one\ntwo\nthree\n")); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	if err := Append(path, 3, []byte("four\nfive\n")); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if got, want := string(raw), "three\nfour\nfive\n"; got != want {
		t.Fatalf("log = %q, want %q", got, want)
	}
}

func TestOpenWriterKeepsLastLines(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "session.log")
	writer, err := Open(path, Options{MaxLines: 4})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	for i := 1; i <= 8; i++ {
		if _, err := fmt.Fprintf(writer, "line-%d\n", i); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	body := strings.TrimSpace(string(raw))
	if got, want := body, "line-5\nline-6\nline-7\nline-8"; got != want {
		t.Fatalf("log = %q, want %q", got, want)
	}
}

func TestTrimKeepsExistingTail(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "session.log")
	if err := os.WriteFile(path, []byte("a\nb\nc\nd\n"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := Trim(path, 2); err != nil {
		t.Fatalf("Trim() error = %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if got, want := string(raw), "c\nd\n"; got != want {
		t.Fatalf("log = %q, want %q", got, want)
	}
}
