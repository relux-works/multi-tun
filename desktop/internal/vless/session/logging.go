package session

import (
	"fmt"
	"io"
	"strings"

	"multi-tun/desktop/internal/core/logtail"
)

func openSessionLog(path string, maxLines int) (io.WriteCloser, error) {
	return logtail.Open(path, logtail.Options{MaxLines: maxLines})
}

func writeSessionLog(out io.Writer, level, format string, args ...any) {
	_, _ = io.WriteString(out, formatSessionLogLine(level, format, args...))
}

func appendSessionLog(current CurrentSession, level, format string, args ...any) {
	appendSessionLogPath(current.LogPath, current.LogMaxLines, level, format, args...)
}

func appendSessionLogPath(path string, maxLines int, level, format string, args ...any) {
	if strings.TrimSpace(path) == "" {
		return
	}
	_ = logtail.Append(path, maxLines, []byte(formatSessionLogLine(level, format, args...)))
}

func formatSessionLogLine(level, format string, args ...any) string {
	message := fmt.Sprintf(format, args...)
	if !strings.HasSuffix(message, "\n") {
		message += "\n"
	}
	level = strings.TrimSpace(strings.ToLower(level))
	if level == "" {
		return message
	}
	return "[" + level + "] " + message
}
