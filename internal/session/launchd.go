package session

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	execCombinedOutput    = func(name string, args ...string) ([]byte, error) { return exec.Command(name, args...).CombinedOutput() }
	launchctlPIDPattern   = regexp.MustCompile(`\bpid = ([0-9]+)\b`)
	launchctlStatePattern = regexp.MustCompile(`\bstate = ([A-Za-z0-9_-]+)\b`)
)

type LaunchdServiceStatus struct {
	Label string
	State string
	PID   int
	Found bool
}

func startWithLaunchd(current CurrentSession, executable string) (int, error) {
	if err := ensureSudo(); err != nil {
		return 0, fmt.Errorf("sudo authentication: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(current.LogPath), 0o755); err != nil {
		return 0, fmt.Errorf("create log dir: %w", err)
	}

	plistData := renderLaunchdPlist(current.LaunchLabel, executable, current.ConfigPath, current.LogPath)
	tmpFile, err := os.CreateTemp("", "vless-tun-*.plist")
	if err != nil {
		return 0, fmt.Errorf("create temp plist: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.Write(plistData); err != nil {
		_ = tmpFile.Close()
		return 0, fmt.Errorf("write temp plist: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return 0, fmt.Errorf("close temp plist: %w", err)
	}

	if _, err := runPrivilegedCommand("install", "-o", "root", "-g", "wheel", "-m", "0644", tmpPath, current.LaunchPlistPath); err != nil {
		return 0, fmt.Errorf("install launchd plist: %w", err)
	}

	_, _ = runPrivilegedCommand("launchctl", "bootout", launchctlTarget(current.LaunchLabel))
	if _, err := runPrivilegedCommand("launchctl", "bootstrap", "system", current.LaunchPlistPath); err != nil {
		return 0, fmt.Errorf("bootstrap launchd service: %w", err)
	}

	time.Sleep(1200 * time.Millisecond)
	pid, err := launchdPID(current.LaunchLabel)
	if err != nil {
		return 0, err
	}
	if pid <= 0 {
		return 0, fmt.Errorf("launchd service started without a running pid")
	}
	return pid, nil
}

func stopLaunchdSession(current CurrentSession, timeout time.Duration) error {
	if err := ensureSudo(); err != nil {
		return fmt.Errorf("sudo authentication: %w", err)
	}

	if _, err := runPrivilegedCommand("launchctl", "bootout", launchctlTarget(current.LaunchLabel)); err != nil {
		return fmt.Errorf("bootout launchd service: %w", err)
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		alive, _, err := SessionAlive(CurrentSession{
			PID:         current.PID,
			LaunchMode:  current.LaunchMode,
			LaunchLabel: current.LaunchLabel,
		})
		if err != nil {
			return err
		}
		if !alive {
			return nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for launchd service %s to stop", current.LaunchLabel)
}

func launchdPID(label string) (int, error) {
	if label == "" {
		return 0, nil
	}

	var (
		out []byte
		err error
	)
	if os.Geteuid() == 0 {
		out, err = execCombinedOutput("launchctl", "print", launchctlTarget(label))
	} else {
		out, err = execCombinedOutput("sudo", "-n", "launchctl", "print", launchctlTarget(label))
	}
	if err != nil {
		return 0, nil
	}
	return parseLaunchdPID(string(out)), nil
}

func InspectLaunchd(label string) (LaunchdServiceStatus, error) {
	status := LaunchdServiceStatus{Label: label}
	if label == "" {
		return status, nil
	}

	out, err := runPrivilegedCommand("launchctl", "print", launchctlTarget(label))
	if err != nil {
		if strings.Contains(err.Error(), "Could not find service") {
			return status, nil
		}
		return status, err
	}

	status.Found = true
	status.PID = parseLaunchdPID(string(out))
	status.State = parseLaunchdState(string(out))
	return status, nil
}

func renderLaunchdPlist(label, executable, configPath, logPath string) []byte {
	var buf bytes.Buffer
	buf.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	buf.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	buf.WriteString(`<plist version="1.0">` + "\n")
	buf.WriteString(`<dict>` + "\n")
	buf.WriteString(`  <key>Label</key>` + "\n")
	buf.WriteString(`  <string>` + xmlEscape(label) + `</string>` + "\n")
	buf.WriteString(`  <key>ProgramArguments</key>` + "\n")
	buf.WriteString(`  <array>` + "\n")
	buf.WriteString(`    <string>` + xmlEscape(executable) + `</string>` + "\n")
	buf.WriteString(`    <string>run</string>` + "\n")
	buf.WriteString(`    <string>-c</string>` + "\n")
	buf.WriteString(`    <string>` + xmlEscape(configPath) + `</string>` + "\n")
	buf.WriteString(`  </array>` + "\n")
	buf.WriteString(`  <key>RunAtLoad</key>` + "\n")
	buf.WriteString(`  <true/>` + "\n")
	buf.WriteString(`  <key>StandardOutPath</key>` + "\n")
	buf.WriteString(`  <string>` + xmlEscape(logPath) + `</string>` + "\n")
	buf.WriteString(`  <key>StandardErrorPath</key>` + "\n")
	buf.WriteString(`  <string>` + xmlEscape(logPath) + `</string>` + "\n")
	buf.WriteString(`</dict>` + "\n")
	buf.WriteString(`</plist>` + "\n")
	return buf.Bytes()
}

func parseLaunchdPID(output string) int {
	match := launchctlPIDPattern.FindStringSubmatch(output)
	if len(match) != 2 {
		return 0
	}
	pid, err := strconv.Atoi(match[1])
	if err != nil {
		return 0
	}
	return pid
}

func parseLaunchdState(output string) string {
	match := launchctlStatePattern.FindStringSubmatch(output)
	if len(match) != 2 {
		return ""
	}
	return match[1]
}

func launchctlTarget(label string) string {
	return "system/" + label
}

func xmlEscape(value string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&apos;",
	)
	return replacer.Replace(value)
}

func runPrivilegedCommand(name string, args ...string) ([]byte, error) {
	if os.Geteuid() == 0 {
		return runCommand(name, args...)
	}
	return runCommand("sudo", append([]string{name}, args...)...)
}

func runCommand(name string, args ...string) ([]byte, error) {
	out, err := execCombinedOutput(name, args...)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}
