package cli

import (
	"fmt"
	"strings"

	"multi-tun/desktop/internal/vless/config"
)

func runtimeLoggingPerformanceWarning(cfg config.ProjectConfig) string {
	if cfg.NetworkMode() != config.RenderModeTun {
		return ""
	}
	level := strings.ToLower(strings.TrimSpace(cfg.LogLevel()))
	switch level {
	case "trace", "debug", "info":
		if maxLines := cfg.LogMaxLines(); maxLines > 0 {
			return fmt.Sprintf("logging.level=%s is verbose for TUN sessions; logging.max_lines=%d bounds the file tail, but sing-box can still spend CPU logging every connection. Set logging.level=\"warn\" for normal runtime use.", level, maxLines)
		}
		return fmt.Sprintf("logging.level=%s is verbose for TUN sessions; sing-box can log every connection and burn CPU/disk. Set logging.level=\"warn\" and logging.max_lines=1000 for normal runtime use.", level)
	default:
		return ""
	}
}
