package vpncore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const runTimeout = 20 * time.Second

var (
	execCommandVPNCore        = exec.Command
	execCommandContextVPNCore = exec.CommandContext
)

func Available(cfg ServiceConfig) bool {
	status, err := InspectService(cfg)
	return err == nil && status.Reachable
}

func InspectService(cfg ServiceConfig) (ServiceStatus, error) {
	status, err := inspectExactService(cfg)
	if err != nil {
		return status, err
	}
	if status.Reachable {
		return status, nil
	}

	for _, compat := range compatibilityServiceConfigsVPNCore(cfg) {
		status, err := inspectExactService(compat.ServiceConfig)
		if err != nil {
			return status, err
		}
		if status.Reachable {
			status.Compatibility = compat.Compatibility
			return status, nil
		}
	}

	return status, nil
}

func inspectExactService(cfg ServiceConfig) (ServiceStatus, error) {
	status := ServiceStatus{
		Label:      cfg.Label,
		PlistPath:  cfg.PlistPath,
		SocketPath: cfg.SocketPath,
	}
	resp, err := call(cfg, Request{Action: "ping"})
	if err != nil {
		if isUnavailable(err) {
			return status, nil
		}
		return status, err
	}
	status.Reachable = resp.OK
	status.DaemonPID = resp.DaemonPID
	return status, nil
}

func InstallService(cfg ServiceConfig, binaryPath string, clientUID, clientGID int) error {
	if err := ensureSudoCredentials(); err != nil {
		return fmt.Errorf("sudo authentication: %w", err)
	}
	cleanupCompatibilityServices(cfg)

	plistData := RenderServicePlist(cfg, binaryPath, clientUID, clientGID)
	tmpFile, err := os.CreateTemp("", "vpn-core-*.plist")
	if err != nil {
		return fmt.Errorf("create temp vpn core plist: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.Write(plistData); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("write temp vpn core plist: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp vpn core plist: %w", err)
	}

	if _, err := runPrivilegedCommand("install", "-o", "root", "-g", "wheel", "-m", "0644", tmpPath, cfg.PlistPath); err != nil {
		return fmt.Errorf("install vpn core plist: %w", err)
	}
	_, _ = runPrivilegedCommand("launchctl", "bootout", launchctlTarget(cfg.Label))
	if _, err := runPrivilegedCommand("launchctl", "bootstrap", "system", cfg.PlistPath); err != nil {
		return fmt.Errorf("bootstrap vpn core service: %w", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		status, err := InspectService(cfg)
		if err != nil {
			return err
		}
		if status.Reachable {
			return nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	return fmt.Errorf("vpn core did not become reachable at %s", cfg.SocketPath)
}

func UninstallService(cfg ServiceConfig) error {
	if err := ensureSudoCredentials(); err != nil {
		return fmt.Errorf("sudo authentication: %w", err)
	}
	cleanupCompatibilityServices(cfg)
	uninstallExactService(cfg)
	return nil
}

func cleanupCompatibilityServices(cfg ServiceConfig) {
	for _, compat := range compatibilityServiceConfigsVPNCore(cfg) {
		uninstallExactService(compat.ServiceConfig)
	}
}

func uninstallExactService(cfg ServiceConfig) {
	_, _ = runPrivilegedCommand("launchctl", "bootout", launchctlTarget(cfg.Label))
	_, _ = runPrivilegedCommand("rm", "-f", cfg.PlistPath, cfg.SocketPath)
}

func RunDaemon(cfg ServiceConfig, clientUID, clientGID int) error {
	daemon := serviceDaemon{
		cfg:       cfg,
		clientUID: clientUID,
		clientGID: clientGID,
	}
	return daemon.serve()
}

type serviceDaemon struct {
	cfg       ServiceConfig
	clientUID int
	clientGID int
}

func (d serviceDaemon) serve() error {
	if err := os.MkdirAll(filepath.Dir(d.cfg.SocketPath), 0o755); err != nil {
		return fmt.Errorf("create vpn core socket dir: %w", err)
	}
	_ = os.Remove(d.cfg.SocketPath)

	listener, err := net.Listen("unix", d.cfg.SocketPath)
	if err != nil {
		return fmt.Errorf("listen on vpn core socket: %w", err)
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(d.cfg.SocketPath)
	}()

	if err := os.Chmod(d.cfg.SocketPath, 0o600); err != nil {
		return fmt.Errorf("chmod vpn core socket: %w", err)
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(d.cfg.SocketPath, d.clientUID, d.clientGID); err != nil {
			return fmt.Errorf("chown vpn core socket: %w", err)
		}
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	errCh := make(chan error, 1)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				errCh <- err
				return
			}
			go d.handleConn(conn)
		}
	}()

	select {
	case <-sigCh:
		return nil
	case err := <-errCh:
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}
}

func (d serviceDaemon) handleConn(conn net.Conn) {
	defer conn.Close()

	var request Request
	if err := json.NewDecoder(conn).Decode(&request); err != nil {
		_ = json.NewEncoder(conn).Encode(Response{Error: err.Error()})
		return
	}

	response := Response{OK: true, DaemonPID: os.Getpid()}
	switch request.Action {
	case "ping":
	case "run":
		if err := handleRun(request); err != nil {
			response.OK = false
			response.Error = err.Error()
		}
	case "spawn":
		pid, err := handleSpawn(request)
		if err != nil {
			response.OK = false
			response.Error = err.Error()
		} else {
			response.PID = pid
		}
	case "signal":
		if err := handleSignal(request); err != nil {
			response.OK = false
			response.Error = err.Error()
		}
	default:
		response.OK = false
		response.Error = fmt.Sprintf("unsupported vpn core action %q", request.Action)
	}

	_ = json.NewEncoder(conn).Encode(response)
}

func handleRun(request Request) error {
	if len(request.Command) == 0 {
		return errors.New("missing command")
	}
	if request.LogPath == "" {
		return errors.New("missing log path")
	}

	logFile, err := os.OpenFile(request.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open vpn core log: %w", err)
	}
	defer logFile.Close()

	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()

	cmd := execCommandContextVPNCore(ctx, request.Command[0], request.Command[1:]...)
	cmd.Stdin = strings.NewReader(request.Stdin)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("timed out after %s", runTimeout)
		}
		return err
	}
	return nil
}

func handleSpawn(request Request) (int, error) {
	if len(request.Command) == 0 {
		return 0, errors.New("missing command")
	}
	if request.LogPath == "" {
		return 0, errors.New("missing log path")
	}

	logFile, err := os.OpenFile(request.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return 0, fmt.Errorf("open vpn core log: %w", err)
	}

	cmd := execCommandVPNCore(request.Command[0], request.Command[1:]...)
	if request.Stdin != "" {
		cmd.Stdin = strings.NewReader(request.Stdin)
	}
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if request.SetPGID {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return 0, err
	}

	pid := cmd.Process.Pid
	go func() {
		_ = cmd.Wait()
		_ = logFile.Close()
	}()
	return pid, nil
}

func handleSignal(request Request) error {
	if request.PID <= 0 {
		return errors.New("missing pid")
	}
	if request.Signal == "" {
		return errors.New("missing signal")
	}
	target := request.PID
	if request.Group {
		target = -request.PID
	}
	sig, err := parseSignal(request.Signal)
	if err != nil {
		return err
	}
	return syscall.Kill(target, sig)
}

func parseSignal(value string) (syscall.Signal, error) {
	switch strings.TrimSpace(value) {
	case "INT", "-INT", "SIGINT", "-SIGINT":
		return syscall.SIGINT, nil
	case "TERM", "-TERM", "SIGTERM", "-SIGTERM":
		return syscall.SIGTERM, nil
	case "KILL", "-KILL", "SIGKILL", "-SIGKILL":
		return syscall.SIGKILL, nil
	default:
		return 0, fmt.Errorf("unsupported signal %q", value)
	}
}

func RenderServicePlist(cfg ServiceConfig, binaryPath string, clientUID, clientGID int) []byte {
	var builder strings.Builder
	builder.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	builder.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	builder.WriteString(`<plist version="1.0">` + "\n")
	builder.WriteString(`<dict>` + "\n")
	builder.WriteString(`  <key>Label</key>` + "\n")
	builder.WriteString(`  <string>` + plistEscape(cfg.Label) + `</string>` + "\n")
	builder.WriteString(`  <key>ProgramArguments</key>` + "\n")
	builder.WriteString(`  <array>` + "\n")
	for _, value := range []string{
		binaryPath,
		"_daemon",
		"--socket",
		cfg.SocketPath,
		"--client-uid",
		strconv.Itoa(clientUID),
		"--client-gid",
		strconv.Itoa(clientGID),
	} {
		builder.WriteString(`    <string>` + plistEscape(value) + `</string>` + "\n")
	}
	builder.WriteString(`  </array>` + "\n")
	builder.WriteString(`  <key>RunAtLoad</key>` + "\n")
	builder.WriteString(`  <true/>` + "\n")
	builder.WriteString(`  <key>KeepAlive</key>` + "\n")
	builder.WriteString(`  <true/>` + "\n")
	builder.WriteString(`</dict>` + "\n")
	builder.WriteString(`</plist>` + "\n")
	return []byte(builder.String())
}

func ensureSudoCredentials() error {
	if os.Geteuid() == 0 {
		return nil
	}

	cmd := execCommandVPNCore("sudo", "-n", "true")
	if err := cmd.Run(); err == nil {
		return nil
	}

	if !stdinSupportsPrompt() {
		return fmt.Errorf("sudo credentials are not cached; run `sudo -v` in an interactive shell and retry")
	}

	cmd = execCommandVPNCore("sudo", "-v")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func stdinSupportsPrompt() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}

func runPrivilegedCommand(name string, args ...string) ([]byte, error) {
	if os.Geteuid() == 0 {
		return runCommand(name, args...)
	}
	return runCommand("sudo", append([]string{name}, args...)...)
}

func runCommand(name string, args ...string) ([]byte, error) {
	out, err := execCommandVPNCore(name, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func launchctlTarget(label string) string {
	return "system/" + label
}

func plistEscape(value string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&apos;",
	)
	return replacer.Replace(value)
}
