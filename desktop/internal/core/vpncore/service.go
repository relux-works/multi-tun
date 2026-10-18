package vpncore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	runTimeout               = 20 * time.Second
	maxConcurrentConnections = 16
)

var (
	serverReadDeadlineVPNCore  = 5 * time.Second
	serverWriteDeadlineVPNCore = 5 * time.Second
)

var (
	execCommandVPNCore        = exec.Command
	execCommandContextVPNCore = exec.CommandContext
	recvmsgVPNCore            = unix.Recvmsg
)

type commandError struct {
	Name     string
	Args     []string
	ExitCode int
	Output   []byte
	Err      error
}

func (e *commandError) Error() string {
	return fmt.Sprintf("%s %s: %v (%s)", e.Name, strings.Join(e.Args, " "), e.Err, strings.TrimSpace(string(e.Output)))
}

func (e *commandError) Unwrap() error { return e.Err }

func Available(cfg ServiceConfig) bool {
	// Legacy helpers speak the old path-based logging protocol and are visible
	// to status/cleanup only; they are never selected for hardened RPC work.
	status, err := inspectExactService(cfg)
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
	return inspectExactServiceWithTimeout(cfg, rpcResponseTimeoutVPNCore)
}

func inspectExactServiceWithTimeout(cfg ServiceConfig, timeout time.Duration) (ServiceStatus, error) {
	status := ServiceStatus{Label: cfg.Label, PlistPath: cfg.PlistPath, SocketPath: cfg.SocketPath}
	resp, err := callWithTimeout(cfg, Request{Action: "ping"}, timeout)
	if err != nil {
		if isUnavailable(err) {
			return status, nil
		}
		return status, err
	}
	status.Reachable = resp.OK
	status.DaemonPID = resp.DaemonPID
	status.HelperSnapshot = resp.HelperSnapshot
	return status, nil
}

func UninstallService(cfg ServiceConfig) error {
	if cfg.HelperDir != "" {
		if err := verifyHelperRemovalParent(cfg.HelperDir, installVerificationDepsVPNCore()); err != nil {
			return fmt.Errorf("verify helper removal parent: %w", err)
		}
	}
	if err := ensureSudoCredentialsVPNCore(); err != nil {
		return fmt.Errorf("sudo authentication: %w", err)
	}
	compatibilityErr := cleanupCompatibilityServices(cfg)
	uninstallErr := uninstallExactService(cfg)
	return errors.Join(compatibilityErr, uninstallErr)
}

func cleanupCompatibilityServices(cfg ServiceConfig) error {
	var errs []error
	for _, compat := range compatibilityServiceConfigsVPNCore(cfg) {
		if err := uninstallExactService(compat.ServiceConfig); err != nil {
			errs = append(errs, fmt.Errorf("uninstall compatibility service %s: %w", compat.Label, err))
		}
	}
	return errors.Join(errs...)
}

func uninstallExactService(cfg ServiceConfig) error {
	if cfg.HelperDir != "" {
		if err := verifyHelperRemovalParent(cfg.HelperDir, installVerificationDepsVPNCore()); err != nil {
			return fmt.Errorf("verify helper removal parent: %w", err)
		}
	}
	forgetErr := forgetLaunchdLabel(cfg.Label)
	var removalErrs []error
	if _, err := runPrivilegedCommandVPNCore("rm", "-f", cfg.PlistPath, cfg.SocketPath); err != nil {
		removalErrs = append(removalErrs, fmt.Errorf("remove plist and socket: %w", err))
	}
	if cfg.HelperDir != "" {
		if _, err := runPrivilegedCommandVPNCore("rm", "-rf", cfg.HelperDir); err != nil {
			removalErrs = append(removalErrs, fmt.Errorf("remove helper directory: %w", err))
		}
	}
	absentErr := verifyServicePathsAbsent(cfg)
	if forgetErr == nil && absentErr == nil {
		return nil
	}
	return errors.Join(forgetErr, errors.Join(removalErrs...), absentErr)
}

func forgetLaunchdLabel(label string) error {
	_, bootoutErr := runPrivilegedCommandVPNCore("launchctl", "bootout", launchctlTarget(label))
	deadline := installNowVPNCore().Add(launchctlForgetTimeout)
	var lastPrintErr error
	for {
		if _, err := runPrivilegedCommandVPNCore("launchctl", "print", launchctlTarget(label)); err != nil {
			if launchctlServiceAbsent(err) {
				return nil
			}
			lastPrintErr = fmt.Errorf("inspect launchd service %s: %w", label, err)
		} else {
			lastPrintErr = nil
		}
		if !installNowVPNCore().Before(deadline) {
			return errors.Join(bootoutErr, fmt.Errorf("launchd did not forget %s within %s", label, launchctlForgetTimeout), lastPrintErr)
		}
		installSleepVPNCore(launchctlForgetPollDelay)
	}
}

func launchctlServiceAbsent(err error) bool {
	var commandErr *commandError
	if !errors.As(err, &commandErr) {
		return false
	}
	return commandErr.ExitCode == 113 || bytes.Contains(commandErr.Output, []byte("Could not find service"))
}

func verifyServicePathsAbsent(cfg ServiceConfig) error {
	var errs []error
	for _, path := range []string{cfg.PlistPath, cfg.SocketPath, cfg.HelperDir} {
		if path == "" {
			continue
		}
		if _, err := os.Lstat(path); err == nil {
			errs = append(errs, fmt.Errorf("%s still exists", path))
		} else if !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("inspect removed path %s: %w", path, err))
		}
	}
	return errors.Join(errs...)
}

func RunDaemon(cfg ServiceConfig, clientUID, clientGID int, binarySHA256, manifestSHA256 string) error {
	deps := productionVerificationDependencies()
	daemon := newServiceDaemon(cfg, clientUID, clientGID)
	daemon.verify = func() error {
		return verifyDaemonInstallation(cfg, binarySHA256, manifestSHA256, deps)
	}
	daemon.peerUID = localPeerUID
	return daemon.serve()
}

type peerUIDLookup func(*net.UnixConn) (uint32, error)

type serviceDaemon struct {
	cfg       ServiceConfig
	clientUID int
	clientGID int
	requests  *requestTracker
	verify    func() error
	peerUID   peerUIDLookup

	connections chan struct{}
	mutation    sync.Mutex
	children    *childRegistry
}

func newServiceDaemon(cfg ServiceConfig, clientUID, clientGID int) *serviceDaemon {
	return &serviceDaemon{
		cfg:         cfg,
		clientUID:   clientUID,
		clientGID:   clientGID,
		requests:    newRequestTracker(),
		connections: make(chan struct{}, maxConcurrentConnections),
		children:    newChildRegistry(),
	}
}

func (d *serviceDaemon) serve() error {
	if d.verify == nil {
		return errors.New("daemon verification is not configured")
	}
	if err := d.verify(); err != nil {
		return fmt.Errorf("daemon self-verification failed: %w", err)
	}
	if d.peerUID == nil {
		return errors.New("peer credential verification is not configured")
	}
	if err := os.MkdirAll(filepath.Dir(d.cfg.SocketPath), 0o755); err != nil {
		return fmt.Errorf("create vpn core socket dir: %w", err)
	}
	_ = os.Remove(d.cfg.SocketPath)

	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: d.cfg.SocketPath, Net: "unix"})
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
			conn, err := listener.AcceptUnix()
			if err != nil {
				errCh <- err
				return
			}
			d.acceptConnection(conn)
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

func (d *serviceDaemon) acceptConnection(conn *net.UnixConn) {
	uid, err := d.peerUID(conn)
	if err != nil {
		_ = writeResponse(conn, Response{Error: fmt.Sprintf("read peer credentials: %v", err)})
		_ = conn.Close()
		return
	}
	if uid != 0 && uid != uint32(d.clientUID) {
		_ = writeResponse(conn, Response{Error: fmt.Sprintf("peer uid %d is not authorized", uid)})
		_ = conn.Close()
		return
	}
	select {
	case d.connections <- struct{}{}:
		requestID := d.requests.enqueue()
		go func() {
			defer func() { <-d.connections }()
			d.handleConn(conn, requestID)
		}()
	default:
		_ = writeResponse(conn, Response{Error: "vpn core connection limit reached"})
		_ = conn.Close()
	}
}

func (d *serviceDaemon) handleConn(conn *net.UnixConn, requestID uint64) {
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(serverReadDeadlineVPNCore)); err != nil {
		d.requests.abandon(requestID)
		return
	}
	request, logFile, err := readRequest(conn)
	if err != nil {
		d.requests.abandon(requestID)
		_ = writeResponse(conn, Response{Error: err.Error()})
		return
	}
	if logFile != nil && request.Action != "spawn" {
		defer logFile.Close()
	}

	mutating := request.Action == "run" || request.Action == "spawn" || request.Action == "signal"
	if mutating {
		d.mutation.Lock()
		defer d.mutation.Unlock()
	}
	d.requests.begin(requestID, request.Action)
	response := Response{OK: true, DaemonPID: os.Getpid()}
	switch request.Action {
	case "ping":
		response.HelperSnapshot = d.requests.snapshot()
	case "run":
		if err := d.handleRun(request, logFile); err != nil {
			response.OK = false
			response.Error = err.Error()
		}
	case "spawn":
		pid, err := d.handleSpawn(request, logFile)
		if err != nil {
			response.OK = false
			response.Error = err.Error()
			_ = logFile.Close()
		} else {
			response.PID = pid
		}
	case "signal":
		if err := d.handleSignal(request); err != nil {
			response.OK = false
			response.Error = err.Error()
		}
	default:
		response.OK = false
		response.Error = fmt.Sprintf("unsupported vpn core action %q", request.Action)
	}
	d.requests.complete(requestID, response.OK)
	_ = writeResponse(conn, response)
}

func readRequest(conn *net.UnixConn) (Request, *os.File, error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return Request{}, nil, fmt.Errorf("access vpn core request socket: %w", err)
	}
	var payload []byte
	var receivedFDs []int
	closeFDs := func() {
		for _, fd := range receivedFDs {
			_ = unix.Close(fd)
		}
	}
	for !bytes.Contains(payload, []byte{'\n'}) {
		data := make([]byte, 32*1024)
		oob := make([]byte, unix.CmsgSpace(4*4))
		var n, oobn, flags int
		var recvErr error
		readErr := rawConn.Read(func(fd uintptr) bool {
			syscall.ForkLock.RLock()
			defer syscall.ForkLock.RUnlock()

			n, oobn, flags, _, recvErr = recvmsgVPNCore(int(fd), data, oob, unix.MSG_DONTWAIT)
			if errors.Is(recvErr, unix.EAGAIN) || errors.Is(recvErr, unix.EWOULDBLOCK) {
				recvErr = nil
				return false
			}
			if recvErr != nil {
				return true
			}
			if n == 0 && oobn == 0 {
				recvErr = io.EOF
				return true
			}
			if oobn == 0 {
				return true
			}
			messages, parseErr := unix.ParseSocketControlMessage(oob[:oobn])
			if parseErr != nil {
				recvErr = fmt.Errorf("parse passed file descriptor: %w", parseErr)
				return true
			}
			for _, message := range messages {
				fds, parseErr := unix.ParseUnixRights(&message)
				if parseErr != nil {
					recvErr = fmt.Errorf("parse passed file descriptor: %w", parseErr)
					return true
				}
				for _, receivedFD := range fds {
					unix.CloseOnExec(receivedFD)
					receivedFDs = append(receivedFDs, receivedFD)
				}
			}
			return true
		})
		if readErr != nil {
			closeFDs()
			return Request{}, nil, readErr
		}
		if recvErr != nil {
			closeFDs()
			return Request{}, nil, recvErr
		}
		if len(receivedFDs) > 1 {
			closeFDs()
			return Request{}, nil, errors.New("vpn core request received more than one file descriptor")
		}
		if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
			closeFDs()
			return Request{}, nil, errors.New("truncated vpn core request")
		}
		payload = append(payload, data[:n]...)
		if len(payload) > maxRequestBytesVPNCore {
			closeFDs()
			return Request{}, nil, fmt.Errorf("vpn core request exceeds %d bytes", maxRequestBytesVPNCore)
		}
	}
	lineEnd := bytes.IndexByte(payload, '\n')
	if len(bytes.TrimSpace(payload[lineEnd+1:])) != 0 {
		closeFDs()
		return Request{}, nil, errors.New("vpn core request contains trailing data")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload[:lineEnd]))
	decoder.DisallowUnknownFields()
	var request Request
	if err := decoder.Decode(&request); err != nil {
		closeFDs()
		return Request{}, nil, err
	}
	if err := requireJSONEOF(decoder); err != nil {
		closeFDs()
		return Request{}, nil, err
	}

	wantsLog := request.Action == "run" || request.Action == "spawn"
	if wantsLog && len(receivedFDs) != 1 {
		closeFDs()
		return Request{}, nil, errors.New("run/spawn requires exactly one log file descriptor")
	}
	if !wantsLog && len(receivedFDs) != 0 {
		closeFDs()
		return Request{}, nil, errors.New("request does not accept a file descriptor")
	}
	if !wantsLog {
		return request, nil, nil
	}
	fd := receivedFDs[0]
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		closeFDs()
		return Request{}, nil, fmt.Errorf("stat passed log file descriptor: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		closeFDs()
		return Request{}, nil, errors.New("passed log file descriptor is not a regular file")
	}
	file := os.NewFile(uintptr(fd), "vpn-core-client-log")
	if file == nil {
		closeFDs()
		return Request{}, nil, errors.New("wrap passed log file descriptor")
	}
	return request, file, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func writeResponse(conn net.Conn, response Response) error {
	if err := conn.SetWriteDeadline(time.Now().Add(serverWriteDeadlineVPNCore)); err != nil {
		return err
	}
	return json.NewEncoder(conn).Encode(response)
}

func (d *serviceDaemon) handleRun(request Request, logFile *os.File) error {
	if err := validateInterimCommand(request.Command); err != nil {
		return err
	}
	logWriter := newPassedLogWriter(logFile, request.LogMaxLines)
	defer logWriter.Close()
	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()
	cmd := execCommandContextVPNCore(ctx, request.Command[0], request.Command[1:]...)
	cmd.Stdin = strings.NewReader(request.Stdin)
	cmd.Stdout = logWriter
	cmd.Stderr = logWriter
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("timed out after %s", runTimeout)
		}
		return err
	}
	return nil
}

func (d *serviceDaemon) handleSpawn(request Request, logFile *os.File) (int, error) {
	if err := validateInterimCommand(request.Command); err != nil {
		return 0, err
	}
	logWriter := newPassedLogWriter(logFile, request.LogMaxLines)
	cmd := execCommandVPNCore(request.Command[0], request.Command[1:]...)
	if request.Stdin != "" {
		cmd.Stdin = strings.NewReader(request.Stdin)
	}
	cmd.Stdout = logWriter
	cmd.Stderr = logWriter
	if request.SetPGID {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}
	if err := cmd.Start(); err != nil {
		_ = logWriter.Close()
		return 0, err
	}
	pid := cmd.Process.Pid
	d.children.add(pid, request.SetPGID)
	if err := watchProcessExitVPNCore(pid, func() {
		d.children.removeBeforeReap(pid, func() {
			_ = cmd.Wait()
			_ = logWriter.Close()
		})
	}); err != nil {
		d.children.remove(pid)
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = logWriter.Close()
		return 0, fmt.Errorf("watch spawned process %d: %w", pid, err)
	}
	return pid, nil
}

func (d *serviceDaemon) handleSignal(request Request) error {
	if request.PID <= 0 {
		return errors.New("missing pid")
	}
	if request.Signal == "" {
		return errors.New("missing signal")
	}
	sig, err := parseSignal(request.Signal)
	if err != nil {
		return err
	}
	return d.children.signal(request.PID, request.Group, sig)
}

type childRecord struct{ setPGID bool }

type childRegistry struct {
	mu       sync.Mutex
	children map[int]childRecord
}

func newChildRegistry() *childRegistry { return &childRegistry{children: make(map[int]childRecord)} }
func (r *childRegistry) add(pid int, setPGID bool) {
	r.mu.Lock()
	r.children[pid] = childRecord{setPGID: setPGID}
	r.mu.Unlock()
}
func (r *childRegistry) remove(pid int) {
	r.mu.Lock()
	delete(r.children, pid)
	r.mu.Unlock()
}
func (r *childRegistry) removeBeforeReap(pid int, reap func()) {
	r.mu.Lock()
	delete(r.children, pid)
	r.mu.Unlock()
	reap()
}
func (r *childRegistry) get(pid int) (childRecord, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	child, ok := r.children[pid]
	return child, ok
}
func (r *childRegistry) signal(pid int, group bool, sig syscall.Signal) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	child, ok := r.children[pid]
	if !ok {
		return fmt.Errorf("pid %d was not spawned by this vpn core daemon or is no longer its child", pid)
	}
	if group && !child.setPGID {
		return fmt.Errorf("pid %d was not spawned in its own process group", pid)
	}
	target := pid
	if group {
		target = -pid
	}
	return syscall.Kill(target, sig)
}

// validateInterimCommand is a deliberately narrow PR A compatibility shim.
// It reduces generic root execution but does not close H03b: PR B/C replace
// run/spawn with typed actions and root-owned executable snapshots.
func validateInterimCommand(command []string) error {
	if len(command) == 0 {
		return errors.New("missing command")
	}
	executable := command[0]
	if !filepath.IsAbs(executable) || filepath.Clean(executable) != executable {
		return fmt.Errorf("command executable %q must be a clean absolute path", executable)
	}
	// TODO(PR B): remove /bin/sh after resolver cleanup becomes a typed Go action.
	switch executable {
	case "/usr/sbin/scutil", "/usr/sbin/networksetup", "/usr/sbin/tcpdump", "/bin/sh":
		return nil
	}
	switch filepath.Base(executable) {
	case "sing-box", "xray", "openconnect":
		return nil
	default:
		return fmt.Errorf("command executable %q is not in the PR A interim allowlist", executable)
	}
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

func RenderServicePlist(cfg ServiceConfig, binaryPath string, clientUID, clientGID int, binarySHA256, manifestSHA256 string) []byte {
	var builder strings.Builder
	builder.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	builder.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	builder.WriteString(`<plist version="1.0">` + "\n<dict>\n")
	builder.WriteString(`  <key>Label</key>` + "\n  <string>" + plistEscape(cfg.Label) + "</string>\n")
	builder.WriteString(`  <key>ProgramArguments</key>` + "\n  <array>\n")
	for _, value := range []string{
		binaryPath, "_daemon", "--socket", cfg.SocketPath,
		"--client-uid", strconv.Itoa(clientUID), "--client-gid", strconv.Itoa(clientGID),
		"--binary-sha256", binarySHA256, "--manifest-sha256", manifestSHA256,
	} {
		builder.WriteString(`    <string>` + plistEscape(value) + `</string>` + "\n")
	}
	builder.WriteString("  </array>\n  <key>RunAtLoad</key>\n  <true/>\n  <key>KeepAlive</key>\n  <true/>\n</dict>\n</plist>\n")
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
	return err == nil && stat.Mode()&os.ModeCharDevice != 0
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
		exitCode := -1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
		return out, &commandError{
			Name:     name,
			Args:     append([]string(nil), args...),
			ExitCode: exitCode,
			Output:   append([]byte(nil), out...),
			Err:      err,
		}
	}
	return out, nil
}

func launchctlTarget(label string) string { return "system/" + label }

func plistEscape(value string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;").Replace(value)
}
