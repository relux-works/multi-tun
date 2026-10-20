package vpncore

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
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
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	maxConcurrentConnections = 16
	privateSocketFilename    = "vpn-core.sock"
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
		if _, err := runPrivilegedCommandVPNCore("rm", "-rf", cfg.HelperDir, privateSocketDir(cfg)); err != nil {
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
	paths := []string{cfg.PlistPath, cfg.SocketPath, cfg.HelperDir}
	if cfg.HelperDir != "" {
		paths = append(paths, privateSocketDir(cfg))
	}
	for _, path := range paths {
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

	socketVerification  verificationDependencies
	listenUnix          func(string, *net.UnixAddr) (*net.UnixListener, error)
	effectiveUID        func() int
	chownSocket         func(string, int, int) error
	beforeSocketPublish func(string) error
	afterSocketPublish  func(string) error

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

		socketVerification: productionVerificationDependencies(),
		listenUnix:         net.ListenUnix,
		effectiveUID:       os.Geteuid,
		chownSocket:        os.Chown,
	}
}

type socketIdentity struct {
	device uint64
	inode  uint64
}

type publishedUnixSocket struct {
	listener   *net.UnixListener
	publicPath string
	identity   socketIdentity
}

func socketIdentityFromInfo(path string, info os.FileInfo) (socketIdentity, error) {
	if info.Mode()&os.ModeSocket == 0 {
		return socketIdentity{}, fmt.Errorf("%s is not a unix socket", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return socketIdentity{}, fmt.Errorf("inspect unix socket identity for %s", path)
	}
	return socketIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino)}, nil
}

func sameSocketIdentity(left, right socketIdentity) bool {
	return left.device == right.device && left.inode == right.inode
}

func (s *publishedUnixSocket) close() error {
	closeErr := s.listener.Close()
	info, err := os.Lstat(s.publicPath)
	if errors.Is(err, os.ErrNotExist) {
		return closeErr
	}
	if err != nil {
		return errors.Join(closeErr, fmt.Errorf("inspect published vpn core socket during cleanup: %w", err))
	}
	identity, err := socketIdentityFromInfo(s.publicPath, info)
	if err != nil || !sameSocketIdentity(identity, s.identity) {
		return closeErr
	}
	removeErr := os.Remove(s.publicPath)
	if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		removeErr = fmt.Errorf("remove published vpn core socket: %w", removeErr)
	}
	return errors.Join(closeErr, removeErr)
}

// privateSocketDir is where the daemon binds and permissions the socket before it
// atomically publishes it at the public path. It lives next to the helper directory,
// under the same strictly verified root-owned parent.
func privateSocketDir(cfg ServiceConfig) string {
	return filepath.Clean(cfg.HelperDir) + ".run"
}

func (d *serviceDaemon) preparePublishedSocket() (_ *publishedUnixSocket, returnErr error) {
	if d.cfg.HelperDir == "" {
		return nil, errors.New("helper directory is required for private vpn core socket")
	}
	if d.cfg.SocketPath == "" {
		return nil, errors.New("public vpn core socket path is required")
	}
	// The private directory is a sibling of the helper directory, not inside it: the
	// installed helper tree must contain exactly the packaged entries.
	if err := verifySecureDirectory(filepath.Dir(filepath.Clean(d.cfg.HelperDir)), d.socketVerification); err != nil {
		return nil, fmt.Errorf("verify vpn core helper parent for private socket: %w", err)
	}

	privateDir := privateSocketDir(d.cfg)
	if err := os.Mkdir(privateDir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("create private vpn core socket directory: %w", err)
	}
	if err := verifySecureDirectory(privateDir, d.socketVerification); err != nil {
		return nil, fmt.Errorf("verify private vpn core socket directory: %w", err)
	}

	privatePath := filepath.Join(privateDir, privateSocketFilename)
	if err := os.Remove(privatePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("remove stale private vpn core socket: %w", err)
	}
	listener, err := d.listenUnix("unix", &net.UnixAddr{Name: privatePath, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("listen on private vpn core socket: %w", err)
	}
	listener.SetUnlinkOnClose(false)
	defer func() {
		if returnErr != nil {
			_ = listener.Close()
			_ = os.Remove(privatePath)
		}
	}()

	if err := os.Chmod(privatePath, 0o600); err != nil {
		return nil, fmt.Errorf("chmod private vpn core socket: %w", err)
	}
	if d.effectiveUID() == 0 {
		if err := d.chownSocket(privatePath, d.clientUID, d.clientGID); err != nil {
			return nil, fmt.Errorf("chown private vpn core socket: %w", err)
		}
	}
	privateInfo, err := os.Lstat(privatePath)
	if err != nil {
		return nil, fmt.Errorf("inspect prepared private vpn core socket: %w", err)
	}
	privateIdentity, err := socketIdentityFromInfo(privatePath, privateInfo)
	if err != nil {
		return nil, err
	}
	if d.beforeSocketPublish != nil {
		if err := d.beforeSocketPublish(d.cfg.SocketPath); err != nil {
			return nil, fmt.Errorf("before vpn core socket publish: %w", err)
		}
	}
	if err := os.Rename(privatePath, d.cfg.SocketPath); err != nil {
		return nil, fmt.Errorf("atomically publish vpn core socket: %w", err)
	}
	if d.afterSocketPublish != nil {
		if err := d.afterSocketPublish(d.cfg.SocketPath); err != nil {
			return nil, fmt.Errorf("after vpn core socket publish: %w", err)
		}
	}
	publicInfo, err := os.Lstat(d.cfg.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("inspect published vpn core socket: %w", err)
	}
	publicIdentity, err := socketIdentityFromInfo(d.cfg.SocketPath, publicInfo)
	if err != nil {
		return nil, err
	}
	if !sameSocketIdentity(privateIdentity, publicIdentity) {
		return nil, errors.New("published vpn core socket identity changed during startup")
	}
	return &publishedUnixSocket{
		listener:   listener,
		publicPath: d.cfg.SocketPath,
		identity:   publicIdentity,
	}, nil
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
	publishedSocket, err := d.preparePublishedSocket()
	if err != nil {
		return err
	}
	defer func() {
		_ = publishedSocket.close()
	}()
	listener := publishedSocket.listener

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
	if logFile != nil && request.Action != "singbox.start" {
		defer logFile.Close()
	}

	mutating := request.Action != "ping"
	if mutating {
		d.mutation.Lock()
		defer d.mutation.Unlock()
	}
	d.requests.begin(requestID, request.Action)
	response := Response{OK: true, DaemonPID: os.Getpid()}
	switch request.Action {
	case "ping":
		response.HelperSnapshot = d.requests.snapshot()
	case "singbox.start":
		pid, handle, err := d.handleSingBoxStart(request, logFile)
		if err != nil {
			_ = logFile.Close()
			response.OK = false
			response.Error = err.Error()
		} else {
			response.PID = pid
			response.Handle = handle
		}
	case "dns.scutil":
		responseError(&response, d.handleSCUtil(request))
	case "dns.networksetup":
		responseError(&response, d.handleNetworkSetup(request))
	case "resolver.cleanup":
		responseError(&response, d.handleResolverCleanup())
	case "tcpdump.start":
		pid, handle, err := d.handleTCPDumpStart(request)
		if err != nil {
			response.OK = false
			response.Error = err.Error()
		} else {
			response.PID = pid
			response.Handle = handle
		}
	case "signal":
		path, err := d.handleSignal(request)
		if err != nil {
			response.OK = false
			response.Error = err.Error()
		} else {
			response.Path = path
		}
	default:
		response.OK = false
		response.Error = fmt.Sprintf("unsupported vpn core action %q", request.Action)
	}
	d.requests.complete(requestID, response.OK)
	_ = writeResponse(conn, response)
}

func responseError(response *Response, err error) {
	if err != nil {
		response.OK = false
		response.Error = err.Error()
	}
}

const controlBufferBytesVPNCore = 4096

// rightsFromControl returns every descriptor carried by SCM_RIGHTS messages
// in a received control buffer, tolerating a malformed or truncated buffer:
// headers are walked with their lengths clamped to the received bytes and
// only complete descriptor slots are read.
func rightsFromControl(oob []byte) []int {
	var fds []int
	headerLen := unix.CmsgLen(0)
	for len(oob) >= unix.SizeofCmsghdr {
		header := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
		messageLen := int(header.Len)
		if messageLen < headerLen {
			break
		}
		end := min(messageLen, len(oob))
		if header.Level == unix.SOL_SOCKET && header.Type == unix.SCM_RIGHTS {
			for offset := headerLen; offset+4 <= end; offset += 4 {
				if fd := int(int32(binary.NativeEndian.Uint32(oob[offset : offset+4]))); fd >= 0 {
					fds = append(fds, fd)
				}
			}
		}
		next := unix.CmsgSpace(messageLen - headerLen)
		if next <= 0 || next > len(oob) {
			break
		}
		oob = oob[next:]
	}
	return fds
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
		// Large enough for Darwin's per-message SCM_RIGHTS limit, so the kernel
		// never installs descriptors whose numbers we cannot see.
		oob := make([]byte, controlBufferBytesVPNCore)
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
			// Track every descriptor the kernel installed before judging the
			// buffer: a malformed or truncated control message must still have
			// its rights closed, never dropped.
			for _, receivedFD := range rightsFromControl(oob[:oobn]) {
				unix.CloseOnExec(receivedFD)
				receivedFDs = append(receivedFDs, receivedFD)
			}
			if _, parseErr := unix.ParseSocketControlMessage(oob[:oobn]); parseErr != nil {
				recvErr = fmt.Errorf("parse passed file descriptor: %w", parseErr)
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
	if !knownAction(request.Action) {
		closeFDs()
		return Request{}, nil, fmt.Errorf("unsupported vpn core action %q", request.Action)
	}
	if err := validateRequestShape(request); err != nil {
		closeFDs()
		return Request{}, nil, err
	}

	wantsLog := request.Action == "singbox.start"
	if wantsLog && len(receivedFDs) != 1 {
		closeFDs()
		return Request{}, nil, errors.New("singbox.start requires exactly one log file descriptor")
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

func validateRequestShape(request Request) error {
	unexpected := false
	switch request.Action {
	case "ping":
		unexpected = len(request.ConfigJSON) != 0 || request.Stdin != "" || request.LogMaxLines != 0 || request.Handle != "" || request.Signal != "" || request.SetPGID || request.Service != "" || len(request.Servers) != 0 || request.Interface != "" || len(request.Filter) != 0 || request.ApplePCAPNG || request.RunAsUser
	case "singbox.start":
		unexpected = request.Stdin != "" || request.Handle != "" || request.Signal != "" || request.Service != "" || len(request.Servers) != 0 || request.Interface != "" || len(request.Filter) != 0 || request.ApplePCAPNG || request.RunAsUser
		if request.LogMaxLines < 0 || request.LogMaxLines > 1_000_000 {
			return errors.New("singbox.start log_max_lines is outside 0..1000000")
		}
	case "dns.scutil":
		unexpected = len(request.ConfigJSON) != 0 || request.LogMaxLines != 0 || request.Handle != "" || request.Signal != "" || request.SetPGID || request.Service != "" || len(request.Servers) != 0 || request.Interface != "" || len(request.Filter) != 0 || request.ApplePCAPNG || request.RunAsUser
	case "dns.networksetup":
		unexpected = len(request.ConfigJSON) != 0 || request.Stdin != "" || request.LogMaxLines != 0 || request.Handle != "" || request.Signal != "" || request.SetPGID || request.Interface != "" || len(request.Filter) != 0 || request.ApplePCAPNG || request.RunAsUser
		if len(request.Service) > 256 || len(request.Servers) > 64 {
			return errors.New("dns.networksetup fields exceed their size limits")
		}
	case "resolver.cleanup":
		unexpected = len(request.ConfigJSON) != 0 || request.Stdin != "" || request.LogMaxLines != 0 || request.Handle != "" || request.Signal != "" || request.SetPGID || request.Service != "" || len(request.Servers) != 0 || request.Interface != "" || len(request.Filter) != 0 || request.ApplePCAPNG || request.RunAsUser
	case "tcpdump.start":
		unexpected = len(request.ConfigJSON) != 0 || request.Stdin != "" || request.LogMaxLines != 0 || request.Handle != "" || request.Signal != "" || request.SetPGID || request.Service != "" || len(request.Servers) != 0
	case "signal":
		unexpected = len(request.ConfigJSON) != 0 || request.Stdin != "" || request.LogMaxLines != 0 || request.SetPGID || request.Service != "" || len(request.Servers) != 0 || request.Interface != "" || len(request.Filter) != 0 || request.ApplePCAPNG || request.RunAsUser
	}
	if unexpected {
		return fmt.Errorf("vpn core action %q contains fields outside its typed schema", request.Action)
	}
	return nil
}

func knownAction(action string) bool {
	switch action {
	case "ping", "singbox.start", "dns.scutil", "dns.networksetup", "resolver.cleanup", "tcpdump.start", "signal":
		return true
	default:
		return false
	}
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

func (d *serviceDaemon) handleSignal(request Request) (string, error) {
	if len(request.Handle) != 48 {
		return "", errors.New("handle must be a 48-character opaque token")
	}
	if _, err := hex.DecodeString(request.Handle); err != nil || request.Handle != strings.ToLower(request.Handle) {
		return "", errors.New("handle must be lowercase hexadecimal")
	}
	if request.Signal == "" {
		return "", errors.New("missing signal")
	}
	sig, err := parseSignal(request.Signal)
	if err != nil {
		return "", err
	}
	return d.children.signal(request.Handle, sig)
}

type childRecord struct {
	pid        int
	setPGID    bool
	resultPath string
}

type childRegistry struct {
	mu       sync.Mutex
	children map[string]childRecord
}

func newChildRegistry() *childRegistry { return &childRegistry{children: make(map[string]childRecord)} }
func (r *childRegistry) add(pid int, setPGID bool, resultPath string) (string, error) {
	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate child handle: %w", err)
	}
	handle := hex.EncodeToString(raw[:])
	r.mu.Lock()
	r.children[handle] = childRecord{pid: pid, setPGID: setPGID, resultPath: resultPath}
	r.mu.Unlock()
	return handle, nil
}
func (r *childRegistry) remove(handle string) {
	r.mu.Lock()
	delete(r.children, handle)
	r.mu.Unlock()
}
func (r *childRegistry) removeBeforeReap(handle string, reap func()) {
	r.mu.Lock()
	delete(r.children, handle)
	r.mu.Unlock()
	reap()
}
func (r *childRegistry) get(handle string) (childRecord, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	child, ok := r.children[handle]
	return child, ok
}
func (r *childRegistry) signal(handle string, sig syscall.Signal) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	child, ok := r.children[handle]
	if !ok {
		return "", errors.New("handle was not returned by this vpn core daemon or was already consumed")
	}
	target := child.pid
	if child.setPGID {
		target = -child.pid
	}
	if err := syscall.Kill(target, sig); err != nil {
		return "", err
	}
	return child.resultPath, nil
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
