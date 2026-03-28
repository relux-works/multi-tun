package openconnect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	defaultPrivilegedHelperLabel      = "works.relux.openconnect-tun-helper"
	defaultPrivilegedHelperPlistPath  = "/Library/LaunchDaemons/works.relux.openconnect-tun-helper.plist"
	defaultPrivilegedHelperSocketPath = "/var/run/works.relux.openconnect-tun-helper.sock"
)

type PrivilegedHelperConfig struct {
	Label      string
	PlistPath  string
	SocketPath string
}

type PrivilegedHelperStatus struct {
	Label      string
	PlistPath  string
	SocketPath string
	Reachable  bool
	DaemonPID  int
}

type helperRequest struct {
	Action  string   `json:"action"`
	Command []string `json:"command,omitempty"`
	Cookie  string   `json:"cookie,omitempty"`
	LogPath string   `json:"log_path,omitempty"`
	PID     int      `json:"pid,omitempty"`
	Signal  string   `json:"signal,omitempty"`
}

type helperResponse struct {
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
	DaemonPID int    `json:"daemon_pid,omitempty"`
}

type privilegedHelperDaemon struct {
	socketPath string
	clientUID  int
	clientGID  int
}

func DefaultPrivilegedHelperConfig() PrivilegedHelperConfig {
	return PrivilegedHelperConfig{
		Label:      defaultPrivilegedHelperLabel,
		PlistPath:  defaultPrivilegedHelperPlistPath,
		SocketPath: defaultPrivilegedHelperSocketPath,
	}
}

func resolvePrivilegedMode(mode string) (string, PrivilegedHelperConfig, error) {
	cfg := DefaultPrivilegedHelperConfig()
	mode = strings.TrimSpace(mode)
	if mode == "" {
		mode = PrivilegedModeAuto
	}

	switch mode {
	case PrivilegedModeAuto:
		if os.Geteuid() == 0 {
			return PrivilegedModeDirect, cfg, nil
		}
		if helperAvailable(cfg) {
			return PrivilegedModeHelper, cfg, nil
		}
		return PrivilegedModeSudo, cfg, nil
	case PrivilegedModeSudo:
		if os.Geteuid() == 0 {
			return PrivilegedModeDirect, cfg, nil
		}
		return PrivilegedModeSudo, cfg, nil
	case PrivilegedModeDirect:
		return PrivilegedModeDirect, cfg, nil
	case PrivilegedModeHelper:
		if !helperAvailable(cfg) {
			return "", cfg, fmt.Errorf("privileged helper is not reachable; run `openconnect-tun helper install` once")
		}
		return PrivilegedModeHelper, cfg, nil
	default:
		return "", cfg, fmt.Errorf("unsupported privileged mode %q", mode)
	}
}

func InspectPrivilegedHelper(cfg PrivilegedHelperConfig) (PrivilegedHelperStatus, error) {
	status := PrivilegedHelperStatus{
		Label:      cfg.Label,
		PlistPath:  cfg.PlistPath,
		SocketPath: cfg.SocketPath,
	}
	resp, err := callPrivilegedHelper(cfg.SocketPath, helperRequest{Action: "ping"})
	if err != nil {
		if isHelperUnavailable(err) {
			return status, nil
		}
		return status, err
	}
	status.Reachable = resp.OK
	status.DaemonPID = resp.DaemonPID
	return status, nil
}

func InstallPrivilegedHelper(binaryPath string, clientUID, clientGID int) error {
	cfg := DefaultPrivilegedHelperConfig()
	if err := ensureSudoCredentials(); err != nil {
		return fmt.Errorf("sudo authentication: %w", err)
	}

	plistData := renderPrivilegedHelperPlist(cfg, binaryPath, clientUID, clientGID)
	tmpFile, err := os.CreateTemp("", "openconnect-tun-helper-*.plist")
	if err != nil {
		return fmt.Errorf("create temp helper plist: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.Write(plistData); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("write temp helper plist: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp helper plist: %w", err)
	}

	if _, err := runPrivilegedCommandOpenConnect("install", "-o", "root", "-g", "wheel", "-m", "0644", tmpPath, cfg.PlistPath); err != nil {
		return fmt.Errorf("install helper plist: %w", err)
	}
	_, _ = runPrivilegedCommandOpenConnect("launchctl", "bootout", launchctlTargetOpenConnect(cfg.Label))
	if _, err := runPrivilegedCommandOpenConnect("launchctl", "bootstrap", "system", cfg.PlistPath); err != nil {
		return fmt.Errorf("bootstrap helper service: %w", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		status, err := InspectPrivilegedHelper(cfg)
		if err != nil {
			return err
		}
		if status.Reachable {
			return nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	return fmt.Errorf("privileged helper did not become reachable at %s", cfg.SocketPath)
}

func UninstallPrivilegedHelper() error {
	cfg := DefaultPrivilegedHelperConfig()
	if err := ensureSudoCredentials(); err != nil {
		return fmt.Errorf("sudo authentication: %w", err)
	}
	_, _ = runPrivilegedCommandOpenConnect("launchctl", "bootout", launchctlTargetOpenConnect(cfg.Label))
	_, _ = runPrivilegedCommandOpenConnect("rm", "-f", cfg.PlistPath, cfg.SocketPath)
	return nil
}

func RunPrivilegedHelperDaemon(socketPath string, clientUID, clientGID int) error {
	daemon := privilegedHelperDaemon{
		socketPath: socketPath,
		clientUID:  clientUID,
		clientGID:  clientGID,
	}
	return daemon.serve()
}

func helperConnect(cfg PrivilegedHelperConfig, command []string, cookie, logPath string) error {
	if logPath == "" {
		return errors.New("log path is required for privileged helper connect")
	}
	if _, err := callPrivilegedHelper(cfg.SocketPath, helperRequest{
		Action:  "connect",
		Command: append([]string(nil), command...),
		Cookie:  cookie,
		LogPath: logPath,
	}); err != nil {
		if isHelperUnavailable(err) {
			return fmt.Errorf("privileged helper is unavailable; run `openconnect-tun helper install` once")
		}
		return err
	}
	return nil
}

func helperSignal(cfg PrivilegedHelperConfig, pid int, signal string) error {
	if _, err := callPrivilegedHelper(cfg.SocketPath, helperRequest{
		Action: "signal",
		PID:    pid,
		Signal: signal,
	}); err != nil {
		if isHelperUnavailable(err) {
			return fmt.Errorf("privileged helper is unavailable; run `openconnect-tun helper install` once")
		}
		return err
	}
	return nil
}

func shouldUseHelperSignal(mode string, helperSocketPath string) bool {
	switch strings.TrimSpace(mode) {
	case PrivilegedModeHelper:
		return true
	case "", PrivilegedModeAuto:
		return helperAvailable(defaultHelperConfigForSocket(helperSocketPath))
	default:
		return false
	}
}

func defaultHelperConfigForSocket(socketPath string) PrivilegedHelperConfig {
	cfg := DefaultPrivilegedHelperConfig()
	if strings.TrimSpace(socketPath) != "" {
		cfg.SocketPath = socketPath
	}
	return cfg
}

func currentLogPath(w io.Writer) string {
	file, ok := w.(*os.File)
	if !ok {
		return ""
	}
	return file.Name()
}

func helperAvailable(cfg PrivilegedHelperConfig) bool {
	status, err := InspectPrivilegedHelper(cfg)
	return err == nil && status.Reachable
}

func callPrivilegedHelper(socketPath string, request helperRequest) (helperResponse, error) {
	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return helperResponse{}, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return helperResponse{}, err
	}

	var response helperResponse
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		return helperResponse{}, err
	}
	if !response.OK {
		return response, errors.New(response.Error)
	}
	return response, nil
}

func isHelperUnavailable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	message := err.Error()
	return strings.Contains(message, "connect: no such file") ||
		strings.Contains(message, "connect: connection refused")
}

func (d privilegedHelperDaemon) serve() error {
	if err := os.MkdirAll(filepath.Dir(d.socketPath), 0o755); err != nil {
		return fmt.Errorf("create helper socket dir: %w", err)
	}
	_ = os.Remove(d.socketPath)

	listener, err := net.Listen("unix", d.socketPath)
	if err != nil {
		return fmt.Errorf("listen on helper socket: %w", err)
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(d.socketPath)
	}()

	if err := os.Chmod(d.socketPath, 0o600); err != nil {
		return fmt.Errorf("chmod helper socket: %w", err)
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(d.socketPath, d.clientUID, d.clientGID); err != nil {
			return fmt.Errorf("chown helper socket: %w", err)
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

func (d privilegedHelperDaemon) handleConn(conn net.Conn) {
	defer conn.Close()

	var request helperRequest
	if err := json.NewDecoder(conn).Decode(&request); err != nil {
		_ = json.NewEncoder(conn).Encode(helperResponse{Error: err.Error()})
		return
	}

	response := helperResponse{OK: true, DaemonPID: os.Getpid()}
	switch request.Action {
	case "ping":
	case "connect":
		if err := d.handleConnect(request); err != nil {
			response.OK = false
			response.Error = err.Error()
		}
	case "signal":
		if err := d.handleSignal(request); err != nil {
			response.OK = false
			response.Error = err.Error()
		}
	default:
		response.OK = false
		response.Error = fmt.Sprintf("unsupported helper action %q", request.Action)
	}

	_ = json.NewEncoder(conn).Encode(response)
}

func (d privilegedHelperDaemon) handleConnect(request helperRequest) error {
	if len(request.Command) == 0 {
		return errors.New("missing openconnect command")
	}
	if request.LogPath == "" {
		return errors.New("missing log path")
	}

	logFile, err := os.OpenFile(request.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open helper log: %w", err)
	}
	defer logFile.Close()

	ctx, cancel := context.WithTimeout(context.Background(), openconnectTimeout)
	defer cancel()

	cmd := execCommandContext(ctx, request.Command[0], request.Command[1:]...)
	cmd.Stdin = strings.NewReader(request.Cookie + "\n")
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("timed out after %s", openconnectTimeout)
		}
		return err
	}
	return nil
}

func (d privilegedHelperDaemon) handleSignal(request helperRequest) error {
	if request.PID <= 0 {
		return errors.New("missing pid")
	}
	if request.Signal == "" {
		return errors.New("missing signal")
	}
	return execCommandOpenConnect("kill", request.Signal, strconv.Itoa(request.PID)).Run()
}

func renderPrivilegedHelperPlist(cfg PrivilegedHelperConfig, binaryPath string, clientUID, clientGID int) []byte {
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
		"_helper-daemon",
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

func runPrivilegedCommandOpenConnect(name string, args ...string) ([]byte, error) {
	if os.Geteuid() == 0 {
		return runOpenConnectCommand(name, args...)
	}
	return runOpenConnectCommand("sudo", append([]string{name}, args...)...)
}

func runOpenConnectCommand(name string, args ...string) ([]byte, error) {
	out, err := execCommandOpenConnect(name, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func launchctlTargetOpenConnect(label string) string {
	return "system/" + label
}
