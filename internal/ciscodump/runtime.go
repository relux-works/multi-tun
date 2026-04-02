package ciscodump

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"multi-tun/internal/vpncore"
)

const (
	defaultInterface        = "pktap,all"
	defaultFilter           = "tcp or udp"
	defaultPcapFileName     = "traffic-capture.pcap"
	defaultOCSCInterface    = "lo0"
	defaultOCSCFilter       = "tcp and host 127.0.0.1"
	defaultOCSCPcapFileName = "localhost-loopback.pcap"
	defaultStopTimeout      = 5 * time.Second
	snapshotTimestampFormat = "20060102T150405.000Z"
	defaultProbePort        = 443
	hostLookupTimeout       = 2 * time.Second
	hostDialTimeout         = 3 * time.Second
	hostHTTPTimeout         = 4 * time.Second
	tcpdumpBackendDirect    = "direct"
	tcpdumpBackendVPNCore   = "vpn-core"
	tcpdumpBackendSudo      = "sudo"
)

var (
	execCommandCiscoDump        = exec.Command
	execCommandContextCiscoDump = exec.CommandContext
	vpnCoreAvailableCiscoDump   = func() bool {
		return vpncore.Available(vpncore.DefaultServiceConfig())
	}
	vpnCoreSpawnDetachedCiscoDump = func(command []string, logPath string, setPGID bool) (int, error) {
		return vpncore.SpawnDetached(vpncore.DefaultServiceConfig(), command, "", logPath, setPGID)
	}
	vpnCoreSignalCiscoDump = func(pid int, signal string, group bool) error {
		return vpncore.Signal(vpncore.DefaultServiceConfig(), pid, signal, group)
	}
	currentProcessRegex     = regexp.MustCompile(`(?i)(/opt/cisco|/Applications/Cisco|/Applications/AnyConnect|\.cisco/hostscan/bin64/cscan|vpnagentd|vpnui|acwebhelper|cscan|acextension|acsockext)`)
	defaultProbeHosts       = []string{"gitlab.services.corp.example", "portal.corp.example"}
	defaultProbeNameservers = []string{"10.23.16.4", "10.23.0.23"}
)

type StartOptions struct {
	Interface        string
	Filter           string
	TcpdumpBinary    string
	NoTcpdump        bool
	NoHostProbes     bool
	ProbeHosts       []string
	ProbeNameservers []string
}

type DaemonOptions struct {
	CacheDir       string
	SessionID      string
	MetadataPath   string
	ArtifactDir    string
	PcapPath       string
	OCSCPcapPath   string
	Interface      string
	Filter         string
	TcpdumpBinary  string
	NoTcpdump      bool
	SnapshotPeriod time.Duration
}

type fileStamp struct {
	size    int64
	modTime time.Time
}

type monitorState struct {
	lastProcessDigest string
	lastSocketDigest  string
	lastNetworkDigest string
	copiedFiles       map[string]fileStamp
	snapshotCount     int
}

type captureIterationResult struct {
	processErr error
	socketErr  error
	networkErr error
	probeErr   error
	fileErr    error
}

type socketSnapshot struct {
	content string
	digest  string
}

type runningTCPDump struct {
	pid  int
	stop func(time.Duration) error
}

func Start(cacheDir string, options StartOptions) (CurrentSession, error) {
	cacheDir = ResolveCacheDir(cacheDir)
	if current, err := LoadCurrent(cacheDir); err == nil {
		alive, _, aliveErr := SessionAlive(current)
		if aliveErr != nil {
			return CurrentSession{}, aliveErr
		}
		if alive {
			return CurrentSession{}, fmt.Errorf("dump session %s is already active (pid=%d)", current.ID, current.PID)
		}
		if err := ClearCurrent(cacheDir); err != nil {
			return CurrentSession{}, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return CurrentSession{}, err
	}

	if err := os.MkdirAll(SessionsDir(cacheDir), 0o755); err != nil {
		return CurrentSession{}, err
	}
	if err := os.MkdirAll(RuntimeDir(cacheDir), 0o755); err != nil {
		return CurrentSession{}, err
	}

	sessionID := time.Now().UTC().Format(sessionTimestampFormat)
	logPath := filepath.Join(SessionsDir(cacheDir), logFilePrefix+sessionID+".log")
	metadataPath := filepath.Join(SessionsDir(cacheDir), metadataFilePrefix+sessionID+".json")
	artifactDir := filepath.Join(SessionsDir(cacheDir), logFilePrefix+sessionID)
	if err := os.MkdirAll(artifactDir, 0o755); err != nil {
		return CurrentSession{}, err
	}

	interfaceName := resolveInterface(options.Interface)
	filter := resolveFilter(options.Filter)
	tcpdumpBinary := strings.TrimSpace(options.TcpdumpBinary)
	tcpdumpBackend := ""
	if !options.NoTcpdump {
		var err error
		tcpdumpBinary, err = resolveTcpdumpBinary(tcpdumpBinary)
		if err != nil {
			return CurrentSession{}, err
		}
		tcpdumpBackend = resolveTCPDumpBackend()
		if tcpdumpBackend == tcpdumpBackendSudo {
			if err := ensureSudoCredentials(); err != nil {
				return CurrentSession{}, fmt.Errorf("sudo authentication: %w", err)
			}
		}
	}

	pcapPath := ""
	ocscPcapPath := ""
	if !options.NoTcpdump {
		if shouldStartOCSCLoopbackCapture(interfaceName, filter) {
			pcapPath = filepath.Join(artifactDir, defaultPcapFileName)
			ocscPcapPath = filepath.Join(artifactDir, defaultOCSCPcapFileName)
		} else {
			pcapPath = filepath.Join(artifactDir, defaultOCSCPcapFileName)
		}
	}

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return CurrentSession{}, err
	}
	defer logFile.Close()

	executablePath, err := os.Executable()
	if err != nil {
		return CurrentSession{}, err
	}

	current := CurrentSession{
		ID:               sessionID,
		StartedAt:        time.Now().UTC(),
		LogPath:          logPath,
		MetadataPath:     metadataPath,
		ArtifactDir:      artifactDir,
		PcapPath:         pcapPath,
		OCSCPcapPath:     ocscPcapPath,
		Interface:        interfaceName,
		Filter:           filter,
		TcpdumpEnabled:   !options.NoTcpdump,
		TcpdumpBackend:   tcpdumpBackend,
		ProbeHosts:       resolveProbeHosts(options.ProbeHosts, options.NoHostProbes),
		ProbeNameservers: resolveProbeNameservers(options.ProbeNameservers, options.NoHostProbes),
	}
	writeLogHeader(logFile, current)

	args := []string{
		"__daemon",
		"--cache-dir", cacheDir,
		"--session-id", sessionID,
		"--metadata-path", metadataPath,
		"--artifact-dir", artifactDir,
		"--interface", interfaceName,
		"--filter", filter,
	}
	if pcapPath != "" {
		args = append(args, "--pcap-path", pcapPath)
	}
	if ocscPcapPath != "" {
		args = append(args, "--ocsc-pcap-path", ocscPcapPath)
	}
	if options.NoTcpdump {
		args = append(args, "--no-tcpdump")
	} else {
		args = append(args, "--tcpdump-binary", tcpdumpBinary)
	}

	cmd := execCommandCiscoDump(executablePath, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return CurrentSession{}, err
	}

	current.PID = cmd.Process.Pid
	if err := SaveMetadata(current); err != nil {
		_ = killProcessGroup(current.PID, syscall.SIGKILL)
		return CurrentSession{}, err
	}
	if err := SaveCurrent(cacheDir, current); err != nil {
		_ = killProcessGroup(current.PID, syscall.SIGKILL)
		return CurrentSession{}, err
	}
	if err := waitForStableStart(current, 400*time.Millisecond); err != nil {
		_ = ClearCurrent(cacheDir)
		lastLine := LastRelevantLogLine(logPath)
		if lastLine != "" {
			return CurrentSession{}, fmt.Errorf("%w; last_log_line: %s", err, lastLine)
		}
		return CurrentSession{}, err
	}
	return current, nil
}

func RunDaemon(options DaemonOptions) error {
	if options.SnapshotPeriod <= 0 {
		options.SnapshotPeriod = time.Second
	}
	current, err := LoadCurrent(options.CacheDir)
	if err != nil {
		return err
	}
	if current.ID != options.SessionID {
		return fmt.Errorf("current session mismatch: have %s want %s", current.ID, options.SessionID)
	}

	snapshotDir := filepath.Join(current.ArtifactDir, "snapshots")
	logMirrorDir := filepath.Join(current.ArtifactDir, "cisco-logs")
	if err := os.MkdirAll(snapshotDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(logMirrorDir, 0o755); err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "phase: daemon_start\n")
	fmt.Fprintf(os.Stdout, "artifact_dir: %s\n", current.ArtifactDir)
	if current.PcapPath != "" {
		fmt.Fprintf(os.Stdout, "pcap_file: %s\n", current.PcapPath)
	}
	if current.OCSCPcapPath != "" {
		fmt.Fprintf(os.Stdout, "ocsc_pcap_file: %s\n", current.OCSCPcapPath)
	}
	if current.TcpdumpBackend != "" {
		fmt.Fprintf(os.Stdout, "tcpdump_backend: %s\n", current.TcpdumpBackend)
	}
	if len(current.ProbeHosts) > 0 {
		fmt.Fprintf(os.Stdout, "probe_hosts: %s\n", strings.Join(current.ProbeHosts, ", "))
	}
	if len(current.ProbeNameservers) > 0 {
		fmt.Fprintf(os.Stdout, "probe_nameservers: %s\n", strings.Join(current.ProbeNameservers, ", "))
	}

	var primaryCapture runningTCPDump
	var ocscCapture runningTCPDump
	if current.TcpdumpEnabled {
		primaryCapture, err = startTCPDump(current, options.TcpdumpBinary, current.Interface, current.Filter, current.PcapPath)
		if err != nil {
			return err
		}
		current.TcpdumpPID = primaryCapture.pid
		if current.OCSCPcapPath != "" {
			ocscCapture, err = startTCPDump(current, options.TcpdumpBinary, defaultOCSCInterface, defaultOCSCFilter, current.OCSCPcapPath)
			if err != nil {
				_ = primaryCapture.stop(defaultStopTimeout)
				return err
			}
			current.OCSCTcpdumpPID = ocscCapture.pid
		}
		if err := SaveMetadata(current); err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "tcpdump_pid: %d\n", current.TcpdumpPID)
		if current.OCSCTcpdumpPID > 0 {
			fmt.Fprintf(os.Stdout, "ocsc_tcpdump_pid: %d\n", current.OCSCTcpdumpPID)
		}
	}

	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	monitor := &monitorState{copiedFiles: map[string]fileStamp{}}
	logCaptureIterationErrors("", monitor.captureState(current))

	ticker := time.NewTicker(options.SnapshotPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			fmt.Fprintf(os.Stdout, "phase: stopping\n")
			logCaptureIterationErrors("final_", monitor.captureStateWithoutHostProbes(current))
			if primaryCapture.stop != nil {
				if err := primaryCapture.stop(defaultStopTimeout); err != nil {
					fmt.Fprintf(os.Stdout, "tcpdump_stop_error: %v\n", err)
				}
			}
			if ocscCapture.stop != nil {
				if err := ocscCapture.stop(defaultStopTimeout); err != nil {
					fmt.Fprintf(os.Stdout, "ocsc_tcpdump_stop_error: %v\n", err)
				}
			}
			if ocscPcapPath := resolveOCSCPcapPath(current); ocscPcapPath != "" {
				artifacts, err := AnalyzeOCSCArtifactDir(current.ArtifactDir, ocscPcapPath)
				if err != nil {
					fmt.Fprintf(os.Stdout, "ocsc_analysis_error: %v\n", err)
				} else if artifacts.FrameCount > 0 {
					current.OCSCFrameCount = artifacts.FrameCount
					current.OCSCInterestingFrameCount = artifacts.InterestingFrameCount
					current.OCSCTimelinePath = artifacts.TimelinePath
					current.OCSCSummaryPath = artifacts.SummaryPath
					fmt.Fprintf(os.Stdout, "ocsc_frames: %d\n", artifacts.FrameCount)
					fmt.Fprintf(os.Stdout, "ocsc_interesting_frames: %d\n", artifacts.InterestingFrameCount)
					fmt.Fprintf(os.Stdout, "ocsc_timeline: %s\n", artifacts.TimelinePath)
					fmt.Fprintf(os.Stdout, "ocsc_summary: %s\n", artifacts.SummaryPath)
				}
			}
			stoppedAt := time.Now().UTC()
			current.StoppedAt = &stoppedAt
			current.SnapshotCount = monitor.snapshotCount
			if err := SaveMetadata(current); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "phase: stopped\n")
			return nil
		case <-ticker.C:
			logCaptureIterationErrors("", monitor.captureState(current))
			current.SnapshotCount = monitor.snapshotCount
			_ = SaveMetadata(current)
		}
	}
}

func Stop(cacheDir string, force bool, timeout time.Duration) (CurrentSession, string, error) {
	cacheDir = ResolveCacheDir(cacheDir)
	current, err := LoadCurrent(cacheDir)
	if err != nil {
		return CurrentSession{}, "", err
	}

	alive, _, err := SessionAlive(current)
	if err != nil {
		return CurrentSession{}, "", err
	}
	if !alive {
		if err := ClearCurrent(cacheDir); err != nil {
			return CurrentSession{}, "", err
		}
		return current, "stale", nil
	}

	if err := syscall.Kill(current.PID, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		return CurrentSession{}, "", err
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		alive, _, err := SessionAlive(current)
		if err != nil {
			return CurrentSession{}, "", err
		}
		if !alive {
			if current.MetadataPath != "" {
				if refreshed, loadErr := LoadMetadata(current.MetadataPath); loadErr == nil {
					current = refreshed
				}
			}
			current = captureFinalStopHostProbes(current)
			if err := ClearCurrent(cacheDir); err != nil {
				return CurrentSession{}, "", err
			}
			return current, "stopped", nil
		}
		time.Sleep(200 * time.Millisecond)
	}

	if !force {
		return current, "timeout", fmt.Errorf("timeout waiting for dump session %s to stop", current.ID)
	}
	if err := killProcessGroup(current.PID, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return CurrentSession{}, "", err
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		alive, _, err := SessionAlive(current)
		if err != nil {
			return CurrentSession{}, "", err
		}
		if !alive {
			if current.MetadataPath != "" {
				if refreshed, loadErr := LoadMetadata(current.MetadataPath); loadErr == nil {
					current = refreshed
				}
			}
			current = captureFinalStopHostProbes(current)
			if err := ClearCurrent(cacheDir); err != nil {
				return CurrentSession{}, "", err
			}
			return current, "killed", nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return current, "timeout", fmt.Errorf("timeout waiting for forced dump session %s to stop", current.ID)
}

func waitForStableStart(current CurrentSession, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		alive, _, err := SessionAlive(current)
		if err != nil {
			return err
		}
		if !alive {
			return fmt.Errorf("dump daemon exited during startup")
		}
		if time.Now().After(deadline) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func resolveInterface(value string) string {
	if strings.TrimSpace(value) == "" {
		return defaultInterface
	}
	return strings.TrimSpace(value)
}

func resolveFilter(value string) string {
	if strings.TrimSpace(value) == "" {
		return defaultFilter
	}
	return strings.TrimSpace(value)
}

func resolveTCPDumpBackend() string {
	switch {
	case os.Geteuid() == 0:
		return tcpdumpBackendDirect
	case vpnCoreAvailableCiscoDump():
		return tcpdumpBackendVPNCore
	default:
		return tcpdumpBackendSudo
	}
}

func shouldStartOCSCLoopbackCapture(interfaceName, filter string) bool {
	return strings.TrimSpace(interfaceName) != defaultOCSCInterface ||
		strings.TrimSpace(filter) != defaultOCSCFilter
}

func resolveOCSCPcapPath(current CurrentSession) string {
	if strings.TrimSpace(current.OCSCPcapPath) != "" {
		return strings.TrimSpace(current.OCSCPcapPath)
	}
	if strings.TrimSpace(current.PcapPath) == "" {
		return ""
	}
	if strings.TrimSpace(current.Interface) == defaultOCSCInterface && strings.TrimSpace(current.Filter) == defaultOCSCFilter {
		return strings.TrimSpace(current.PcapPath)
	}
	return ""
}

func resolveProbeHosts(values []string, disabled bool) []string {
	if disabled {
		return nil
	}
	normalized := normalizeTrimmedList(values)
	if len(normalized) == 0 {
		return append([]string(nil), defaultProbeHosts...)
	}
	return normalized
}

func resolveProbeNameservers(values []string, disabled bool) []string {
	if disabled {
		return nil
	}
	normalized := normalizeTrimmedList(values)
	if len(normalized) == 0 {
		return append([]string(nil), defaultProbeNameservers...)
	}
	return normalized
}

func normalizeTrimmedList(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func resolveTcpdumpBinary(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value != "" {
		return value, nil
	}
	if path, err := exec.LookPath("tcpdump"); err == nil {
		return path, nil
	}
	if _, err := os.Stat("/usr/sbin/tcpdump"); err == nil {
		return "/usr/sbin/tcpdump", nil
	}
	return "", errors.New("tcpdump binary not found; install it or pass --tcpdump-binary")
}

func ensureSudoCredentials() error {
	cmd := execCommandCiscoDump("sudo", "-v")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func startTCPDump(current CurrentSession, binary, interfaceName, filter, pcapPath string) (runningTCPDump, error) {
	command := buildTCPDumpCommand(binary, interfaceName, pcapPath, filter, currentUsername())
	switch current.TcpdumpBackend {
	case "", tcpdumpBackendSudo:
		args := append([]string{"-n"}, command...)
		cmd := execCommandCiscoDump("sudo", args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stdout
		if err := cmd.Start(); err != nil {
			return runningTCPDump{}, fmt.Errorf("start tcpdump: %w", err)
		}
		return runningTCPDump{
			pid: cmd.Process.Pid,
			stop: func(timeout time.Duration) error {
				return stopChildProcess(cmd, timeout)
			},
		}, nil
	case tcpdumpBackendDirect:
		cmd := execCommandCiscoDump(command[0], command[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stdout
		if err := cmd.Start(); err != nil {
			return runningTCPDump{}, fmt.Errorf("start tcpdump: %w", err)
		}
		return runningTCPDump{
			pid: cmd.Process.Pid,
			stop: func(timeout time.Duration) error {
				return stopChildProcess(cmd, timeout)
			},
		}, nil
	case tcpdumpBackendVPNCore:
		pid, err := vpnCoreSpawnDetachedCiscoDump(command, current.LogPath, false)
		if err != nil {
			return runningTCPDump{}, fmt.Errorf("start tcpdump via vpn-core: %w", err)
		}
		return runningTCPDump{
			pid: pid,
			stop: func(timeout time.Duration) error {
				return stopDetachedPID(pid, timeout)
			},
		}, nil
	default:
		return runningTCPDump{}, fmt.Errorf("unsupported tcpdump backend %q", current.TcpdumpBackend)
	}
}

func buildTCPDumpCommand(binary, interfaceName, pcapPath, filter, username string) []string {
	args := []string{binary, "-i", interfaceName, "-s", "0", "-U"}
	if strings.HasPrefix(interfaceName, "pktap") {
		args = append(args, "--apple-pcapng")
	}
	if username != "" {
		args = append(args, "-Z", username)
	}
	args = append(args, "-w", pcapPath)
	args = append(args, strings.Fields(filter)...)
	return args
}

func logCaptureIterationErrors(prefix string, result captureIterationResult) {
	if result.processErr != nil {
		fmt.Fprintf(os.Stdout, "%sprocess_snapshot_error: %v\n", prefix, result.processErr)
	}
	if result.socketErr != nil {
		fmt.Fprintf(os.Stdout, "%ssocket_snapshot_error: %v\n", prefix, result.socketErr)
	}
	if result.networkErr != nil {
		fmt.Fprintf(os.Stdout, "%snetwork_snapshot_error: %v\n", prefix, result.networkErr)
	}
	if result.probeErr != nil {
		fmt.Fprintf(os.Stdout, "%sprobe_snapshot_error: %v\n", prefix, result.probeErr)
	}
	if result.fileErr != nil {
		fmt.Fprintf(os.Stdout, "%slog_copy_error: %v\n", prefix, result.fileErr)
	}
}

func currentUsername() string {
	if value := strings.TrimSpace(os.Getenv("USER")); value != "" {
		return value
	}
	current, err := user.Current()
	if err != nil {
		return ""
	}
	return current.Username
}

func stopChildProcess(cmd *exec.Cmd, timeout time.Duration) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		if err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
		return nil
	case <-time.After(timeout):
		if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
		<-done
		return nil
	}
}

func stopDetachedPID(pid int, timeout time.Duration) error {
	if pid <= 0 {
		return nil
	}
	if err := vpnCoreSignalCiscoDump(pid, "TERM", false); err != nil {
		return err
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		alive, err := ProcessAlive(pid)
		if err != nil {
			return err
		}
		if !alive {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	if err := vpnCoreSignalCiscoDump(pid, "KILL", false); err != nil {
		return err
	}

	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		alive, err := ProcessAlive(pid)
		if err != nil {
			return err
		}
		if !alive {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for detached tcpdump pid %d to stop", pid)
}

func killProcessGroup(pid int, sig syscall.Signal) error {
	if pid <= 0 {
		return nil
	}
	return syscall.Kill(-pid, sig)
}

func (m *monitorState) captureState(current CurrentSession) captureIterationResult {
	return m.captureStateWithOptions(current, true)
}

func (m *monitorState) captureStateWithoutHostProbes(current CurrentSession) captureIterationResult {
	return m.captureStateWithOptions(current, false)
}

func (m *monitorState) captureStateWithOptions(current CurrentSession, includeHostProbes bool) captureIterationResult {
	var result captureIterationResult

	lines, err := interestingProcessLines()
	if err != nil {
		result.processErr = err
	} else {
		if err := m.snapshotProcesses(current, lines); err != nil {
			result.processErr = err
		}
		if err := m.snapshotSockets(current, lines); err != nil {
			result.socketErr = err
		}
		networkChanged, err := m.snapshotNetwork(current)
		if err != nil {
			result.networkErr = err
		} else if includeHostProbes && networkChanged {
			if err := m.snapshotHostProbes(current, "network_change"); err != nil {
				result.probeErr = err
			}
		}
	}
	if err := m.copyRelevantCiscoFiles(current.ArtifactDir); err != nil {
		result.fileErr = err
	}

	return result
}

func (m *monitorState) snapshotProcesses(current CurrentSession, lines []string) error {
	digest := processSnapshotDigest(lines)
	if digest == m.lastProcessDigest {
		return nil
	}
	m.lastProcessDigest = digest
	m.snapshotCount++

	timestamp := time.Now().UTC().Format(snapshotTimestampFormat)
	snapshotPath := filepath.Join(current.ArtifactDir, "snapshots", "processes-"+timestamp+".txt")
	var builder strings.Builder
	builder.WriteString("timestamp: " + time.Now().UTC().Format(time.RFC3339) + "\n")
	builder.WriteString("session_id: " + current.ID + "\n")
	builder.WriteString("process_count: " + strconv.Itoa(len(lines)) + "\n")
	builder.WriteString("\n")
	if len(lines) == 0 {
		builder.WriteString("no matching Cisco processes\n")
	} else {
		for _, line := range lines {
			builder.WriteString(line)
			builder.WriteString("\n")
		}
	}
	if err := os.WriteFile(snapshotPath, []byte(builder.String()), 0o644); err != nil {
		return err
	}

	for _, pid := range extractPIDs(lines) {
		if err := captureLsof(current.ArtifactDir, pid, timestamp, current.TcpdumpEnabled); err != nil {
			fmt.Fprintf(os.Stdout, "lsof_snapshot_error pid=%d: %v\n", pid, err)
		}
	}
	return nil
}

func interestingProcessLines() ([]string, error) {
	out, err := execCommandCiscoDump("ps", "axo", "pid=,ppid=,pgid=,etime=,command=").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("ps: %w", err)
	}
	return interestingProcessLinesFromOutput(string(out)), nil
}

func interestingProcessLinesFromOutput(output string) []string {
	lines := strings.Split(output, "\n")
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if currentProcessRegex.MatchString(line) {
			result = append(result, line)
		}
	}
	sort.Strings(result)
	return result
}

func processSnapshotDigest(lines []string) string {
	normalized := make([]string, 0, len(lines))
	for _, line := range lines {
		normalized = append(normalized, normalizeProcessLineForDigest(line))
	}
	return strings.Join(normalized, "\n")
}

func normalizeProcessLineForDigest(line string) string {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return strings.TrimSpace(line)
	}
	command := strings.Join(fields[4:], " ")
	return strings.Join([]string{fields[0], fields[1], fields[2], command}, " ")
}

func extractPIDs(lines []string) []int {
	var result []int
	seen := map[int]struct{}{}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		if _, ok := seen[pid]; ok {
			continue
		}
		seen[pid] = struct{}{}
		result = append(result, pid)
	}
	sort.Ints(result)
	return result
}

func captureLsof(artifactDir string, pid int, timestamp string, useSudo bool) error {
	path := filepath.Join(artifactDir, "snapshots", fmt.Sprintf("lsof-%d-%s.txt", pid, timestamp))
	out, err := runCommandCombined(useSudo, "lsof", "-nP", "-p", strconv.Itoa(pid))
	var builder strings.Builder
	builder.WriteString("pid: " + strconv.Itoa(pid) + "\n")
	builder.WriteString("command: " + formatCommandLine(useSudo, "lsof", "-nP", "-p", strconv.Itoa(pid)) + "\n")
	if err != nil {
		builder.WriteString("error: " + err.Error() + "\n")
	}
	builder.WriteString("\n")
	builder.Write(out)
	return os.WriteFile(path, []byte(builder.String()), 0o644)
}

func (m *monitorState) snapshotSockets(current CurrentSession, lines []string) error {
	snapshot := buildSocketSnapshot(lines, current.TcpdumpEnabled)
	digest := strings.TrimSpace(snapshot.digest)
	if digest == "" {
		digest = "empty"
	}
	if digest == m.lastSocketDigest {
		return nil
	}
	m.lastSocketDigest = digest

	timestamp := time.Now().UTC().Format(snapshotTimestampFormat)
	path := filepath.Join(current.ArtifactDir, "snapshots", "sockets-"+timestamp+".txt")

	var builder strings.Builder
	builder.WriteString("timestamp: " + time.Now().UTC().Format(time.RFC3339) + "\n")
	builder.WriteString("session_id: " + current.ID + "\n")
	builder.WriteString("process_count: " + strconv.Itoa(len(lines)) + "\n")
	builder.WriteString("privileged: " + strconv.FormatBool(current.TcpdumpEnabled) + "\n")
	builder.WriteString("\n")
	builder.WriteString(snapshot.content)
	if !strings.HasSuffix(snapshot.content, "\n") {
		builder.WriteString("\n")
	}

	return os.WriteFile(path, []byte(builder.String()), 0o644)
}

func (m *monitorState) snapshotNetwork(current CurrentSession) (bool, error) {
	snapshot := buildNetworkSnapshot()
	digest := strings.TrimSpace(snapshot.digest)
	if digest == "" {
		digest = "empty"
	}
	if digest == m.lastNetworkDigest {
		return false, nil
	}
	m.lastNetworkDigest = digest
	m.snapshotCount++

	timestamp := time.Now().UTC().Format(snapshotTimestampFormat)
	path := filepath.Join(current.ArtifactDir, "snapshots", "network-"+timestamp+".txt")

	var builder strings.Builder
	builder.WriteString("timestamp: " + time.Now().UTC().Format(time.RFC3339) + "\n")
	builder.WriteString("session_id: " + current.ID + "\n\n")
	builder.WriteString(snapshot.content)
	if !strings.HasSuffix(snapshot.content, "\n") {
		builder.WriteString("\n")
	}

	if err := os.WriteFile(path, []byte(builder.String()), 0o644); err != nil {
		return false, err
	}
	return true, nil
}

func (m *monitorState) snapshotHostProbes(current CurrentSession, trigger string) error {
	if len(current.ProbeHosts) == 0 {
		return nil
	}

	m.snapshotCount++
	timestamp := time.Now().UTC().Format(snapshotTimestampFormat)
	trigger = strings.TrimSpace(trigger)
	if trigger == "" {
		trigger = "snapshot"
	}
	trigger = strings.ReplaceAll(trigger, " ", "-")
	path := filepath.Join(current.ArtifactDir, "snapshots", "host-probes-"+trigger+"-"+timestamp+".txt")

	var builder strings.Builder
	builder.WriteString("timestamp: " + time.Now().UTC().Format(time.RFC3339) + "\n")
	builder.WriteString("session_id: " + current.ID + "\n")
	builder.WriteString("trigger: " + trigger + "\n")
	builder.WriteString("probe_hosts: " + strings.Join(current.ProbeHosts, ", ") + "\n")
	if len(current.ProbeNameservers) > 0 {
		builder.WriteString("probe_nameservers: " + strings.Join(current.ProbeNameservers, ", ") + "\n")
	}
	builder.WriteString("\n")

	content := buildHostProbeSnapshot(current)
	builder.WriteString(content)
	if !strings.HasSuffix(content, "\n") {
		builder.WriteString("\n")
	}

	return os.WriteFile(path, []byte(builder.String()), 0o644)
}

func buildHostProbeSnapshot(current CurrentSession) string {
	type probeTask struct {
		title   string
		timeout time.Duration
		name    string
		args    []string
	}

	var tasks []probeTask
	for _, host := range current.ProbeHosts {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}

		tasks = append(tasks,
			probeTask{title: "probe_dscacheutil " + host, timeout: hostLookupTimeout, name: "dscacheutil", args: []string{"-q", "host", "-a", "name", host}},
			probeTask{title: "probe_route_get " + host, timeout: hostLookupTimeout, name: "route", args: []string{"-n", "get", host}},
			probeTask{title: "probe_dig_system " + host, timeout: hostLookupTimeout, name: "dig", args: []string{"+time=1", "+tries=1", "+short", host}},
		)
		for _, nameserver := range current.ProbeNameservers {
			nameserver = strings.TrimSpace(nameserver)
			if nameserver == "" {
				continue
			}
			tasks = append(tasks, probeTask{
				title:   "probe_dig " + host + " @" + nameserver,
				timeout: hostLookupTimeout,
				name:    "dig",
				args:    []string{"+time=1", "+tries=1", "+short", "@" + nameserver, host},
			})
		}
		tasks = append(tasks,
			probeTask{
				title:   "probe_tcp_443 " + host,
				timeout: hostDialTimeout,
				name:    "nc",
				args:    []string{"-G", strconv.Itoa(int(hostDialTimeout / time.Second)), "-vz", host, strconv.Itoa(defaultProbePort)},
			},
			probeTask{
				title:   "probe_https " + host,
				timeout: hostHTTPTimeout,
				name:    "curl",
				args: []string{
					"-ksS",
					"-o", "/dev/null",
					"-D", "-",
					"--connect-timeout", strconv.Itoa(int(hostDialTimeout / time.Second)),
					"--max-time", strconv.Itoa(int(hostHTTPTimeout / time.Second)),
					"-w", "\\nhttp_code=%{http_code}\\nremote_ip=%{remote_ip}\\nremote_port=%{remote_port}\\nurl_effective=%{url_effective}\\nssl_verify_result=%{ssl_verify_result}\\n",
					"https://" + host,
				},
			},
		)
	}
	if len(tasks) == 0 {
		return "output: <empty>\n"
	}

	sections := make([]string, len(tasks))
	var wg sync.WaitGroup
	wg.Add(len(tasks))
	for i, task := range tasks {
		go func(index int, task probeTask) {
			defer wg.Done()
			sections[index] = captureCommandSectionWithTimeout(task.title, task.timeout, false, task.name, task.args...)
		}(i, task)
	}
	wg.Wait()

	return strings.Join(sections, "\n\n")
}

func captureFinalStopHostProbes(current CurrentSession) CurrentSession {
	if len(current.ProbeHosts) == 0 || strings.TrimSpace(current.ArtifactDir) == "" {
		return current
	}

	monitor := &monitorState{snapshotCount: current.SnapshotCount}
	if err := monitor.snapshotHostProbes(current, "final_stop"); err != nil {
		appendRuntimeLogLine(current.LogPath, fmt.Sprintf("final_stop_probe_error: %v", err))
		return current
	}

	current.SnapshotCount = monitor.snapshotCount
	if err := SaveMetadata(current); err != nil {
		appendRuntimeLogLine(current.LogPath, fmt.Sprintf("final_stop_probe_metadata_error: %v", err))
	}
	return current
}

func appendRuntimeLogLine(path, line string) {
	path = strings.TrimSpace(path)
	line = strings.TrimSpace(line)
	if path == "" || line == "" {
		return
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer file.Close()
	_, _ = fmt.Fprintf(file, "%s\n", line)
}

func buildSocketSnapshot(lines []string, useSudo bool) socketSnapshot {
	var sections []string
	var digestParts []string
	pids := extractPIDs(lines)
	pidList := joinPIDs(pids)
	trackedProcesses := strings.Join(lines, "\n")

	sections = append(sections, formatSnapshotSection(
		"tracked_processes",
		"",
		nil,
		trackedProcesses,
	))
	digestParts = append(digestParts, "tracked_processes\n"+trackedProcesses)

	if pidList != "" {
		trackedNetworkOut, trackedNetworkErr := runCommandCombined(useSudo, "lsof", "-nP", "-a", "-p", pidList, "-i")
		sections = append(sections, formatSnapshotSection(
			"tracked_network_sockets",
			formatCommandLine(useSudo, "lsof", "-nP", "-a", "-p", pidList, "-i"),
			trackedNetworkErr,
			string(trackedNetworkOut),
		))
		digestParts = append(digestParts, "tracked_network_sockets\n"+strings.Join(normalizeLsofSocketOutput(string(trackedNetworkOut)), "\n"))

		trackedUnixOut, trackedUnixErr := runCommandCombined(useSudo, "lsof", "-nP", "-a", "-p", pidList, "-U")
		sections = append(sections, formatSnapshotSection(
			"tracked_unix_sockets",
			formatCommandLine(useSudo, "lsof", "-nP", "-a", "-p", pidList, "-U"),
			trackedUnixErr,
			string(trackedUnixOut),
		))
		digestParts = append(digestParts, "tracked_unix_sockets\n"+strings.Join(normalizeLines(string(trackedUnixOut)), "\n"))
	}

	allLoopbackLsofOut, allLoopbackLsofErr := runCommandCombined(useSudo, "lsof", "-nP", "-iTCP")
	allLoopbackLsofLines := filterLoopbackLsofLines(string(allLoopbackLsofOut))
	sections = append(sections, formatSnapshotSection(
		"all_loopback_tcp_lsof",
		formatCommandLine(useSudo, "lsof", "-nP", "-iTCP"),
		allLoopbackLsofErr,
		strings.Join(allLoopbackLsofLines, "\n"),
	))
	digestParts = append(digestParts, "all_loopback_tcp_lsof\n"+strings.Join(normalizeLsofSocketOutput(strings.Join(allLoopbackLsofLines, "\n")), "\n"))

	out, err := runCommandCombined(false, "netstat", "-anv", "-p", "tcp")
	trackedLoopbackNetstat := filterLoopbackNetstatLines(string(out), pids)
	sections = append(sections, formatSnapshotSection(
		"tracked_loopback_tcp_netstat",
		formatCommandLine(false, "netstat", "-anv", "-p", "tcp"),
		err,
		strings.Join(trackedLoopbackNetstat, "\n"),
	))
	allLoopbackNetstat := filterLoopbackNetstatLines(string(out), nil)
	sections = append(sections, formatSnapshotSection(
		"all_loopback_tcp_netstat",
		formatCommandLine(false, "netstat", "-anv", "-p", "tcp"),
		err,
		strings.Join(allLoopbackNetstat, "\n"),
	))
	digestParts = append(digestParts, "all_loopback_tcp_netstat\n"+strings.Join(normalizeNetstatLines(allLoopbackNetstat), "\n"))

	return socketSnapshot{
		content: strings.Join(sections, "\n\n"),
		digest:  strings.Join(digestParts, "\n\n"),
	}
}

func buildNetworkSnapshot() socketSnapshot {
	var sections []string
	var digestParts []string

	scutilDNSOut, scutilDNSErr := runCommandCombined(false, "scutil", "--dns")
	sections = append(sections, formatSnapshotSection(
		"scutil_dns",
		formatCommandLine(false, "scutil", "--dns"),
		scutilDNSErr,
		string(scutilDNSOut),
	))
	digestParts = append(digestParts, "scutil_dns\n"+strings.TrimSpace(string(scutilDNSOut)))

	scutilProxyOut, scutilProxyErr := runCommandCombined(false, "scutil", "--proxy")
	sections = append(sections, formatSnapshotSection(
		"scutil_proxy",
		formatCommandLine(false, "scutil", "--proxy"),
		scutilProxyErr,
		string(scutilProxyOut),
	))
	digestParts = append(digestParts, "scutil_proxy\n"+strings.TrimSpace(string(scutilProxyOut)))

	resolverSnapshot, resolverErr := readResolverDirSnapshot("/etc/resolver")
	sections = append(sections, formatSnapshotSection(
		"resolver_dir",
		"filesystem:/etc/resolver",
		resolverErr,
		resolverSnapshot,
	))
	digestParts = append(digestParts, "resolver_dir\n"+strings.TrimSpace(resolverSnapshot))

	routeOut, routeErr := runCommandCombined(false, "netstat", "-rn", "-f", "inet")
	sections = append(sections, formatSnapshotSection(
		"netstat_inet_routes",
		formatCommandLine(false, "netstat", "-rn", "-f", "inet"),
		routeErr,
		string(routeOut),
	))
	digestParts = append(digestParts, "netstat_inet_routes\n"+strings.TrimSpace(string(routeOut)))

	return socketSnapshot{
		content: strings.Join(sections, "\n\n"),
		digest:  strings.Join(digestParts, "\n\n"),
	}
}

func captureCommandSection(title string, useSudo bool, name string, args ...string) string {
	out, err := runCommandCombined(useSudo, name, args...)
	return formatSnapshotSection(title, formatCommandLine(useSudo, name, args...), err, string(out))
}

func captureCommandSectionWithTimeout(title string, timeout time.Duration, useSudo bool, name string, args ...string) string {
	out, err := runCommandCombinedWithTimeout(timeout, useSudo, name, args...)
	return formatSnapshotSection(title, formatCommandLine(useSudo, name, args...), err, string(out))
}

func formatSnapshotSection(title, command string, err error, output string) string {
	var builder strings.Builder
	builder.WriteString("== " + title + " ==\n")
	if command != "" {
		builder.WriteString("command: " + command + "\n")
	}
	if err != nil {
		builder.WriteString("error: " + err.Error() + "\n")
	}
	output = strings.TrimSpace(output)
	if output == "" {
		builder.WriteString("output: <empty>\n")
		return builder.String()
	}
	builder.WriteString(output)
	builder.WriteString("\n")
	return builder.String()
}

func readResolverDirSnapshot(dir string) (string, error) {
	info, err := os.Stat(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "directory missing", nil
		}
		return "", err
	}
	if !info.IsDir() {
		return "not a directory", nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)

	var builder strings.Builder
	builder.WriteString("directory: " + dir + "\n")
	if len(names) == 0 {
		builder.WriteString("files: <empty>\n")
		return builder.String(), nil
	}
	for _, name := range names {
		path := filepath.Join(dir, name)
		builder.WriteString("--- " + path + "\n")
		raw, err := os.ReadFile(path)
		if err != nil {
			builder.WriteString("error: " + err.Error() + "\n")
			continue
		}
		builder.Write(raw)
		if len(raw) == 0 || raw[len(raw)-1] != '\n' {
			builder.WriteString("\n")
		}
	}
	return builder.String(), nil
}

func filterLoopbackLsofLines(output string) []string {
	lines := strings.Split(output, "\n")
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "COMMAND ") {
			result = append(result, trimmed)
			continue
		}
		if strings.Contains(trimmed, "127.0.0.1:") || strings.Contains(trimmed, "127.0.0.1.") || strings.Contains(trimmed, "[::1]:") || strings.Contains(trimmed, "::1.") || strings.Contains(strings.ToLower(trimmed), "localhost:") || strings.Contains(strings.ToLower(trimmed), "localhost.") {
			result = append(result, trimmed)
		}
	}
	return result
}

func filterLoopbackNetstatLines(output string, pids []int) []string {
	lines := strings.Split(output, "\n")
	headers := make([]string, 0, 2)
	matches := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "Active "):
			headers = append(headers, line)
		case strings.HasPrefix(line, "Proto "):
			headers = append(headers, line)
		case (strings.Contains(line, "127.0.0.1.") || strings.Contains(line, "::1.") || strings.Contains(line, "localhost.")) && netstatLineMatchesTrackedPIDs(line, pids):
			matches = append(matches, line)
		}
	}
	if len(matches) == 0 {
		return nil
	}
	return append(headers, matches...)
}

func normalizeNetstatLines(lines []string) []string {
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "Active ") || strings.HasPrefix(trimmed, "Proto ") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 6 {
			result = append(result, trimmed)
			continue
		}
		normalized := []string{fields[0], fields[3], fields[4], fields[5]}
		if len(fields) >= 11 {
			normalized = append(normalized, fields[10])
		}
		result = append(result, strings.Join(normalized, " "))
	}
	return result
}

func normalizeLsofSocketOutput(output string) []string {
	lines := strings.Split(output, "\n")
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "COMMAND ") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 3 {
			result = append(result, trimmed)
			continue
		}
		normalized := []string{fields[0], fields[1]}
		if len(fields) >= 2 {
			normalized = append(normalized, fields[len(fields)-2:]...)
		}
		result = append(result, strings.Join(normalized, " "))
	}
	return result
}

func normalizeLines(output string) []string {
	lines := strings.Split(output, "\n")
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		result = append(result, trimmed)
	}
	return result
}

func netstatLineMatchesTrackedPIDs(line string, pids []int) bool {
	if len(pids) == 0 {
		return true
	}
	for _, pid := range pids {
		pidToken := ":" + strconv.Itoa(pid)
		if strings.Contains(line, pidToken+" ") || strings.HasSuffix(line, pidToken) {
			return true
		}
	}
	return false
}

func joinPIDs(pids []int) string {
	if len(pids) == 0 {
		return ""
	}
	parts := make([]string, 0, len(pids))
	for _, pid := range pids {
		parts = append(parts, strconv.Itoa(pid))
	}
	return strings.Join(parts, ",")
}

func runCommandCombined(useSudo bool, name string, args ...string) ([]byte, error) {
	command := name
	commandArgs := args
	if useSudo {
		command = "sudo"
		commandArgs = append([]string{"-n", name}, args...)
	}
	cmd := execCommandCiscoDump(command, commandArgs...)
	return cmd.CombinedOutput()
}

func runCommandCombinedWithTimeout(timeout time.Duration, useSudo bool, name string, args ...string) ([]byte, error) {
	if timeout <= 0 {
		return runCommandCombined(useSudo, name, args...)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	command := name
	commandArgs := args
	if useSudo {
		command = "sudo"
		commandArgs = append([]string{"-n", name}, args...)
	}
	cmd := execCommandContextCiscoDump(ctx, command, commandArgs...)
	out, err := cmd.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		if len(out) == 0 {
			out = []byte("command timed out\n")
		}
		return out, fmt.Errorf("timed out after %s", timeout)
	}
	return out, err
}

func formatCommandLine(useSudo bool, name string, args ...string) string {
	parts := make([]string, 0, len(args)+3)
	if useSudo {
		parts = append(parts, "sudo", "-n")
	}
	parts = append(parts, name)
	parts = append(parts, args...)
	return strings.Join(parts, " ")
}

func (m *monitorState) copyRelevantCiscoFiles(artifactDir string) error {
	for _, source := range relevantCiscoSources() {
		info, err := os.Stat(source)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		}
		stamp := fileStamp{size: info.Size(), modTime: info.ModTime().UTC()}
		if previous, ok := m.copiedFiles[source]; ok && previous == stamp {
			continue
		}
		target := filepath.Join(artifactDir, "cisco-logs", filepath.Base(source))
		if err := copyFile(source, target); err != nil {
			return err
		}
		m.copiedFiles[source] = stamp
	}
	return nil
}

func relevantCiscoSources() []string {
	homeDir, _ := os.UserHomeDir()
	sources := collectRegularFiles(filepath.Join(homeDir, ".cisco", "hostscan", "log"), 1)
	sources = append(sources, latestUIHistoryFiles(filepath.Join(homeDir, ".cisco", "vpn", "log"), 3)...)
	sources = append(sources, collectRegularFiles(filepath.Join(homeDir, ".cisco", "vpn", "cache"), 4)...)
	return uniqueSortedStrings(sources)
}

func latestUIHistoryFiles(dir string, limit int) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	type candidate struct {
		path    string
		modTime time.Time
	}
	var files []candidate
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "UIHistory_") || !strings.HasSuffix(entry.Name(), ".txt") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		files = append(files, candidate{
			path:    filepath.Join(dir, entry.Name()),
			modTime: info.ModTime(),
		})
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i].modTime.After(files[j].modTime)
	})
	if len(files) > limit {
		files = files[:limit]
	}
	result := make([]string, 0, len(files))
	for _, file := range files {
		result = append(result, file.path)
	}
	return result
}

func copyFile(source, target string) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(target)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}

func collectRegularFiles(root string, maxDepth int) []string {
	var files []string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if path == root {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return nil
		}
		depth := strings.Count(rel, string(os.PathSeparator))
		if d.IsDir() {
			if depth >= maxDepth {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type().IsRegular() {
			files = append(files, path)
		}
		return nil
	})
	sort.Strings(files)
	return files
}

func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	sort.Strings(values)
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}
