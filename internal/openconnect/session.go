package openconnect

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	sessionTimestampFormat = "20060102T150405Z"
	logFilePrefix          = "openconnect-session-"
	metadataFilePrefix     = "session-"
	runtimeFileName        = "current-session.json"
	orphanCleanupLogName   = "orphan-cleanup.log"
)

var cleanupOrphanedResolverStateOpenConnect = cleanupOrphanedResolverState

type CurrentSession struct {
	ID               string    `json:"id"`
	PID              int       `json:"pid"`
	StartedAt        time.Time `json:"started_at"`
	LogPath          string    `json:"log_path"`
	MetadataPath     string    `json:"metadata_path"`
	Server           string    `json:"server"`
	ResolvedFrom     string    `json:"resolved_from,omitempty"`
	Mode             string    `json:"mode"`
	PrivilegedMode   string    `json:"privileged_mode,omitempty"`
	Script           string    `json:"script"`
	Command          []string  `json:"command"`
	Interface        string    `json:"interface,omitempty"`
	Profile          string    `json:"profile,omitempty"`
	IncludeRoutes    []string  `json:"include_routes,omitempty"`
	VPNDomains       []string  `json:"vpn_domains,omitempty"`
	BypassSuffixes   []string  `json:"bypass_suffixes,omitempty"`
	VPNNameservers   []string  `json:"vpn_nameservers,omitempty"`
	HelperSocketPath string    `json:"helper_socket_path,omitempty"`
}

type OverlayDNS struct {
	Domains       []string
	Nameservers   []string
	RouteExcludes []string
}

type stopSnapshot struct {
	VPNBinary  string
	CiscoState State
	Info       *ConnectionInfo
	Runtime    *RuntimeStatus
	Routes     []string
	ScutilDNS  string
	RouteTable string
}

type connectConvergenceExpectations struct {
	RouteOverrides bool
	DNSShim        bool
	ProbeSync      bool
}

type connectConvergenceState struct {
	ConnectEventSeen  bool
	ConnectExitSeen   bool
	ConnectExitCode   int
	RouteOverrideSeen bool
	DNSShimSeen       bool
	ProbeSyncSeen     bool
	ProbeSyncSuccess  bool
	PendingProbeSync  int
}

func DefaultCacheDir() string {
	if dir := os.Getenv("XDG_CACHE_HOME"); dir != "" {
		return filepath.Join(dir, "openconnect-tun")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".cache", "openconnect-tun")
	}
	return filepath.Join(".cache", "openconnect-tun")
}

func ResolveCacheDir(cacheDir string) string {
	cacheDir = strings.TrimSpace(cacheDir)
	if cacheDir == "" {
		return DefaultCacheDir()
	}
	return cacheDir
}

func SessionsDir(cacheDir string) string {
	return filepath.Join(cacheDir, "sessions")
}

func RuntimeDir(cacheDir string) string {
	return filepath.Join(cacheDir, "runtime")
}

func CurrentPath(cacheDir string) string {
	return filepath.Join(RuntimeDir(cacheDir), runtimeFileName)
}

func LoadCurrent(cacheDir string) (CurrentSession, error) {
	raw, err := os.ReadFile(CurrentPath(cacheDir))
	if err != nil {
		return CurrentSession{}, err
	}

	var current CurrentSession
	if err := json.Unmarshal(raw, &current); err != nil {
		return CurrentSession{}, err
	}
	return current, nil
}

func ActiveOverlayDNS(cacheDir string) (*OverlayDNS, error) {
	current, err := LoadCurrent(ResolveCacheDir(cacheDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	alive, _, err := SessionAlive(current)
	if err != nil {
		return nil, err
	}
	if !alive {
		return nil, nil
	}

	spec := supplementalResolverSpecForConnect(current.Mode, current.Server, ConnectOptions{
		IncludeRoutes:  append([]string(nil), current.IncludeRoutes...),
		VPNDomains:     append([]string(nil), current.VPNDomains...),
		BypassSuffixes: append([]string(nil), current.BypassSuffixes...),
		VPNNameservers: append([]string(nil), current.VPNNameservers...),
	})
	if spec == nil || len(spec.Domains) == 0 || len(spec.Nameservers) == 0 {
		return nil, nil
	}

	return &OverlayDNS{
		Domains:       append([]string(nil), spec.Domains...),
		Nameservers:   append([]string(nil), spec.Nameservers...),
		RouteExcludes: append([]string(nil), spec.RouteOverrides...),
	}, nil
}

func SaveCurrent(cacheDir string, current CurrentSession) error {
	if err := os.MkdirAll(RuntimeDir(cacheDir), 0o755); err != nil {
		return err
	}
	return saveJSON(CurrentPath(cacheDir), current)
}

func ClearCurrent(cacheDir string) error {
	err := os.Remove(CurrentPath(cacheDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func SaveMetadata(current CurrentSession) error {
	if current.MetadataPath == "" {
		return errors.New("metadata path is required")
	}
	return saveJSON(current.MetadataPath, current)
}

func ProcessAlive(pid int) (bool, error) {
	if pid <= 0 {
		return false, nil
	}
	err := syscall.Kill(pid, 0)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, syscall.ESRCH) {
		return false, nil
	}
	if errors.Is(err, syscall.EPERM) {
		return true, nil
	}
	return false, err
}

func SessionAlive(current CurrentSession) (bool, int, error) {
	alive, err := ProcessAlive(current.PID)
	if err != nil {
		return false, current.PID, err
	}
	return alive, current.PID, nil
}

func connectConvergenceExpectationsForSession(current CurrentSession) connectConvergenceExpectations {
	spec := supplementalResolverSpecForConnect(current.Mode, current.Server, ConnectOptions{
		IncludeRoutes:  append([]string(nil), current.IncludeRoutes...),
		VPNDomains:     append([]string(nil), current.VPNDomains...),
		BypassSuffixes: append([]string(nil), current.BypassSuffixes...),
		VPNNameservers: append([]string(nil), current.VPNNameservers...),
	})
	if spec == nil {
		return connectConvergenceExpectations{}
	}
	return connectConvergenceExpectations{
		RouteOverrides: len(spec.RouteOverrides) > 0,
		DNSShim:        !spec.UseScutilState && strings.TrimSpace(spec.Label) != "" && len(spec.Domains) > 0 && len(spec.Nameservers) > 0,
	}
}

func (expect connectConvergenceExpectations) required() bool {
	return expect.RouteOverrides || expect.DNSShim || expect.ProbeSync
}

func (state connectConvergenceState) ready(expect connectConvergenceExpectations) (bool, error) {
	if !state.ConnectEventSeen || !state.ConnectExitSeen {
		return false, nil
	}
	if state.ConnectExitCode != 0 {
		return false, fmt.Errorf("split-include wrapper exited with status %d", state.ConnectExitCode)
	}
	if expect.RouteOverrides && !state.RouteOverrideSeen {
		return false, nil
	}
	if expect.DNSShim && !state.DNSShimSeen {
		return false, nil
	}
	if expect.ProbeSync {
		if !state.ProbeSyncSeen || !state.ProbeSyncSuccess || state.PendingProbeSync > 0 {
			return false, nil
		}
	}
	return true, nil
}

func waitForPostConnectConvergence(current CurrentSession, timeout time.Duration) error {
	expect := connectConvergenceExpectationsForSession(current)
	if !expect.required() {
		return nil
	}

	deadline := time.Now().Add(timeout)
	lastState := connectConvergenceState{}
	for {
		alive, pid, err := SessionAlive(current)
		if err != nil {
			return err
		}
		if pid > 0 {
			current.PID = pid
		}
		if !alive {
			return fmt.Errorf("openconnect exited while applying split-include routes and dns")
		}

		state, err := readConnectConvergenceState(current.LogPath)
		if err == nil {
			lastState = state
			ready, readyErr := state.ready(expect)
			if readyErr != nil {
				return readyErr
			}
			if ready {
				return nil
			}
		}

		if time.Now().After(deadline) {
			if lastState.ConnectEventSeen {
				return fmt.Errorf(
					"timed out waiting for split-include routes and dns (route_override=%t dns_shim=%t probe_sync=%t)",
					lastState.RouteOverrideSeen,
					lastState.DNSShimSeen,
					!expect.ProbeSync || (lastState.ProbeSyncSeen && lastState.ProbeSyncSuccess && lastState.PendingProbeSync == 0),
				)
			}
			return fmt.Errorf("timed out waiting for split-include connect hooks to start")
		}
		time.Sleep(150 * time.Millisecond)
	}
}

func probeHostsForSession(current CurrentSession) []string {
	spec := supplementalResolverSpecForConnect(current.Mode, current.Server, ConnectOptions{
		IncludeRoutes:  append([]string(nil), current.IncludeRoutes...),
		VPNDomains:     append([]string(nil), current.VPNDomains...),
		BypassSuffixes: append([]string(nil), current.BypassSuffixes...),
		VPNNameservers: append([]string(nil), current.VPNNameservers...),
	})
	if spec == nil || len(spec.ProbeHosts) == 0 {
		return nil
	}
	return append([]string(nil), spec.ProbeHosts...)
}

func waitForProbeRouteWarmup(current CurrentSession, timeout time.Duration) error {
	hosts := probeHostsForSession(current)
	if len(hosts) == 0 {
		return nil
	}

	deadline := time.Now().Add(timeout)
	for {
		alive, pid, err := SessionAlive(current)
		if err != nil {
			return err
		}
		if pid > 0 {
			current.PID = pid
		}
		if !alive {
			return fmt.Errorf("openconnect exited while warming hostname routes")
		}

		ready, err := probeRouteWarmupReady(current.LogPath, hosts)
		if err == nil && ready {
			return nil
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for hostname route warmup")
		}
		time.Sleep(150 * time.Millisecond)
	}
}

func probeRouteWarmupReady(logPath string, hosts []string) (bool, error) {
	logPath = strings.TrimSpace(logPath)
	if logPath == "" || len(hosts) == 0 {
		return false, nil
	}

	file, err := os.Open(logPath)
	if err != nil {
		return false, err
	}
	defer file.Close()

	remaining := map[string]struct{}{}
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		remaining[host] = struct{}{}
	}
	if len(remaining) == 0 {
		return false, nil
	}

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "vpnc_wrapper_probe_route_sync: apply ") {
			continue
		}
		for host := range remaining {
			if strings.Contains(line, "apply "+host+" ") {
				delete(remaining, host)
			}
		}
		if len(remaining) == 0 {
			return true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return false, err
	}
	return false, nil
}

func readConnectConvergenceState(logPath string) (connectConvergenceState, error) {
	logPath = strings.TrimSpace(logPath)
	if logPath == "" {
		return connectConvergenceState{}, nil
	}

	file, err := os.Open(logPath)
	if err != nil {
		return connectConvergenceState{}, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	state := connectConvergenceState{}
	connectActive := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "vpnc_wrapper_reason:"):
			reason := strings.TrimSpace(strings.TrimPrefix(line, "vpnc_wrapper_reason:"))
			switch reason {
			case "connect", "reconnect", "attempt-reconnect":
				state = connectConvergenceState{ConnectEventSeen: true}
				connectActive = true
			default:
				connectActive = false
			}
		case !connectActive:
			continue
		case strings.HasPrefix(line, "vpnc_wrapper_route_override: begin"):
			state.RouteOverrideSeen = true
		case strings.HasPrefix(line, "vpnc_wrapper_dns_shim: apply"):
			state.DNSShimSeen = true
		case strings.HasPrefix(line, "vpnc_wrapper_probe_route_sync_begin: apply "):
			state.ProbeSyncSeen = true
			state.PendingProbeSync++
		case strings.HasPrefix(line, "vpnc_wrapper_probe_route_sync: apply "):
			state.ProbeSyncSeen = true
			state.ProbeSyncSuccess = true
		case strings.HasPrefix(line, "vpnc_wrapper_probe_route_sync_end: apply "):
			state.ProbeSyncSeen = true
			if state.PendingProbeSync > 0 {
				state.PendingProbeSync--
			}
		case strings.HasPrefix(line, "vpnc_wrapper_base_exit:"):
			exitCode, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "vpnc_wrapper_base_exit:")))
			if err != nil {
				return connectConvergenceState{}, fmt.Errorf("parse connect wrapper exit: %w", err)
			}
			state.ConnectExitSeen = true
			state.ConnectExitCode = exitCode
			connectActive = false
		}
	}
	if err := scanner.Err(); err != nil {
		return connectConvergenceState{}, err
	}
	return state, nil
}

func Stop(cacheDir string, timeout time.Duration) (CurrentSession, string, error) {
	current, err := LoadCurrent(cacheDir)
	if errors.Is(err, os.ErrNotExist) {
		pid, pidErr := findOpenConnectPID()
		if pidErr != nil {
			current = CurrentSession{}
		} else {
			current = CurrentSession{PID: pid}
		}
	} else if err != nil {
		return CurrentSession{}, "", err
	}

	alive, _, err := SessionAlive(current)
	if err != nil {
		return CurrentSession{}, "", err
	}
	if current.PID <= 0 {
		if current.ID != "" {
			if err := ClearCurrent(cacheDir); err != nil {
				return CurrentSession{}, "", err
			}
			cleaned, cleanupErr := cleanupOrphanedResolverStateOpenConnect(cacheDir)
			if cleanupErr != nil {
				return CurrentSession{}, "", cleanupErr
			}
			if cleaned {
				return current, "cleared_starting_cleaned", nil
			}
			return current, "cleared_starting", nil
		}
		cleaned, cleanupErr := cleanupOrphanedResolverStateOpenConnect(cacheDir)
		if cleanupErr != nil {
			return CurrentSession{}, "", cleanupErr
		}
		if cleaned {
			return current, "cleaned_orphaned", nil
		}
		return current, "none", nil
	}
	if !alive {
		if err := ClearCurrent(cacheDir); err != nil {
			return CurrentSession{}, "", err
		}
		cleaned, cleanupErr := cleanupOrphanedResolverStateOpenConnect(cacheDir)
		if cleanupErr != nil {
			return CurrentSession{}, "", cleanupErr
		}
		if cleaned {
			return current, "stale_cleaned", nil
		}
		return current, "stale", nil
	}

	_ = appendPreStopSnapshot(cacheDir, current)

	privilegedMode := current.PrivilegedMode
	if privilegedMode == "" {
		privilegedMode = PrivilegedModeAuto
	}
	if err := interruptOpenConnectPID(current.PID, privilegedMode, current.HelperSocketPath); err != nil {
		return CurrentSession{}, "", fmt.Errorf("failed to stop openconnect pid %d: %w", current.PID, err)
	}

	termSent := false
	killSent := false
	termDeadline := time.Now().Add(timeout / 3)
	if timeout < 3*time.Second {
		termDeadline = time.Now().Add(timeout / 2)
	}
	killDeadline := time.Now().Add((timeout * 2) / 3)
	if timeout < 3*time.Second {
		killDeadline = time.Now().Add((timeout * 3) / 4)
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		alive, _, err := SessionAlive(current)
		if err != nil {
			return CurrentSession{}, "", err
		}
		if !alive {
			if err := waitForSessionCleanup(cacheDir, current, time.Until(deadline)); err != nil {
				return CurrentSession{}, "", err
			}
			if current.ID != "" {
				if err := ClearCurrent(cacheDir); err != nil {
					return CurrentSession{}, "", err
				}
				return current, "stopped", nil
			}
			return current, "stopped_untracked", nil
		}
		now := time.Now()
		if !termSent && now.After(termDeadline) {
			_ = terminateOpenConnectPID(current.PID, privilegedMode, current.HelperSocketPath)
			termSent = true
		}
		if !killSent && now.After(killDeadline) {
			_ = killOpenConnectPID(current.PID, privilegedMode, current.HelperSocketPath)
			killSent = true
		}
		time.Sleep(200 * time.Millisecond)
	}

	if !killSent {
		_ = killOpenConnectPID(current.PID, privilegedMode, current.HelperSocketPath)
	}
	finalDeadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(finalDeadline) {
		alive, _, err := SessionAlive(current)
		if err != nil {
			return CurrentSession{}, "", err
		}
		if !alive {
			if err := waitForSessionCleanup(cacheDir, current, time.Until(finalDeadline)); err != nil {
				return CurrentSession{}, "", err
			}
			if current.ID != "" {
				if err := ClearCurrent(cacheDir); err != nil {
					return CurrentSession{}, "", err
				}
				return current, "stopped_forced", nil
			}
			return current, "stopped_untracked_forced", nil
		}
		time.Sleep(150 * time.Millisecond)
	}

	return current, "timeout", fmt.Errorf("timeout waiting for openconnect pid %d to stop", current.PID)
}

func waitForSessionCleanup(cacheDir string, current CurrentSession, timeout time.Duration) error {
	if current.ID == "" || timeout <= 0 {
		return nil
	}
	deadline := time.Now().Add(timeout)
	for {
		pending, err := sessionCleanupPending(cacheDir, current)
		if err != nil {
			return err
		}
		if !pending {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for openconnect session %s cleanup to finish", current.ID)
		}
		time.Sleep(150 * time.Millisecond)
	}
}

func sessionCleanupPending(cacheDir string, current CurrentSession) (bool, error) {
	helperPath := filepath.Join(SessionsDir(cacheDir), logFilePrefix+current.ID+"-helpers", "script-wrapper.sh")
	alive, err := helperProcessAlive(helperPath)
	if err != nil {
		return false, err
	}
	if alive {
		return true, nil
	}

	spec := supplementalResolverSpecForConnect(current.Mode, current.Server, ConnectOptions{
		IncludeRoutes:  append([]string(nil), current.IncludeRoutes...),
		VPNDomains:     append([]string(nil), current.VPNDomains...),
		BypassSuffixes: append([]string(nil), current.BypassSuffixes...),
		VPNNameservers: append([]string(nil), current.VPNNameservers...),
	})
	if spec == nil {
		return false, nil
	}
	if spec.UseScutilState {
		serviceID := supplementalResolverServiceID(current.ID, spec.Label)
		for _, suffix := range []string{"DNS", "IPv4"} {
			exists, err := dynamicStoreKeyExists("State:/Network/Service/" + serviceID + "/" + suffix)
			if err != nil {
				return false, err
			}
			if exists {
				return true, nil
			}
		}
	}
	for _, domain := range spec.Domains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}
		if _, err := os.Stat(filepath.Join("/etc/resolver", domain)); err == nil {
			return true, nil
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
	}
	return false, nil
}

func helperProcessAlive(helperPath string) (bool, error) {
	helperPath = strings.TrimSpace(helperPath)
	if helperPath == "" {
		return false, nil
	}
	out, err := exec.Command("ps", "-axo", "command=").CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("ps helper lookup: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, helperPath) {
			return true, nil
		}
	}
	return false, nil
}

func dynamicStoreKeyExists(key string) (bool, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return false, nil
	}
	cmd := exec.Command("scutil")
	cmd.Stdin = strings.NewReader("show " + key + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("scutil show %s: %w", key, err)
	}
	text := string(out)
	if strings.Contains(text, "No such key") {
		return false, nil
	}
	return strings.TrimSpace(text) != "", nil
}

func waitForStableStart(current CurrentSession, timeout time.Duration) (int, error) {
	deadline := time.Now().Add(timeout)
	for {
		alive, pid, err := SessionAlive(current)
		if err != nil {
			return current.PID, err
		}
		if !alive {
			return current.PID, fmt.Errorf("openconnect exited during startup")
		}
		if time.Now().After(deadline) {
			if pid > 0 {
				return pid, nil
			}
			return current.PID, nil
		}
		time.Sleep(150 * time.Millisecond)
	}
}

func appendPreStopSnapshot(cacheDir string, current CurrentSession) error {
	if strings.TrimSpace(current.LogPath) == "" {
		return nil
	}
	file, err := os.OpenFile(current.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	writePreStopSnapshot(file, current, collectPreStopSnapshot())
	return nil
}

func collectPreStopSnapshot() stopSnapshot {
	snapshot := stopSnapshot{}
	if state, vpnBinary, err := DetectState(); err == nil {
		snapshot.CiscoState = state
		snapshot.VPNBinary = vpnBinary
	}
	if info, _, err := GetConnectionInfo(); err == nil {
		snapshot.Info = info
	}
	if runtime, err := CurrentRuntime(); err == nil {
		snapshot.Runtime = runtime
	}
	if routes, err := CurrentRoutes(); err == nil {
		snapshot.Routes = routes
	}
	snapshot.ScutilDNS = commandCombinedOutput("scutil", "--dns")
	snapshot.RouteTable = commandCombinedOutput("netstat", "-rn", "-f", "inet")
	return snapshot
}

func writePreStopSnapshot(w io.Writer, current CurrentSession, snapshot stopSnapshot) {
	_, _ = fmt.Fprintf(w, "=== pre-stop snapshot ===\n")
	_, _ = fmt.Fprintf(w, "captured_at: %s\n", time.Now().UTC().Format(time.RFC3339))
	if current.ID != "" {
		_, _ = fmt.Fprintf(w, "pre_stop_session_id: %s\n", current.ID)
	}
	if current.Mode != "" {
		_, _ = fmt.Fprintf(w, "pre_stop_session_mode: %s\n", current.Mode)
	}
	if current.Server != "" {
		_, _ = fmt.Fprintf(w, "pre_stop_session_server: %s\n", current.Server)
	}
	if current.Interface != "" {
		_, _ = fmt.Fprintf(w, "pre_stop_session_interface: %s\n", current.Interface)
	}
	if snapshot.VPNBinary != "" {
		_, _ = fmt.Fprintf(w, "pre_stop_vpn_binary: %s\n", snapshot.VPNBinary)
	}
	if snapshot.CiscoState != "" {
		_, _ = fmt.Fprintf(w, "pre_stop_cisco_state: %s\n", snapshot.CiscoState)
	}
	if snapshot.Info != nil {
		if snapshot.Info.State != "" {
			_, _ = fmt.Fprintf(w, "pre_stop_state: %s\n", snapshot.Info.State)
		}
		if snapshot.Info.ServerAddr != "" {
			_, _ = fmt.Fprintf(w, "pre_stop_server_addr: %s\n", snapshot.Info.ServerAddr)
		}
		if snapshot.Info.ClientAddr != "" {
			_, _ = fmt.Fprintf(w, "pre_stop_client_addr: %s\n", snapshot.Info.ClientAddr)
		}
		if snapshot.Info.TunnelMode != "" {
			_, _ = fmt.Fprintf(w, "pre_stop_tunnel_mode: %s\n", snapshot.Info.TunnelMode)
		}
		if snapshot.Info.Duration != "" {
			_, _ = fmt.Fprintf(w, "pre_stop_duration: %s\n", snapshot.Info.Duration)
		}
	}
	if snapshot.Runtime != nil {
		_, _ = fmt.Fprintf(w, "pre_stop_openconnect_pid: %d\n", snapshot.Runtime.PID)
		if snapshot.Runtime.Interface != "" {
			_, _ = fmt.Fprintf(w, "pre_stop_openconnect_interface: %s\n", snapshot.Runtime.Interface)
		}
		if snapshot.Runtime.Uptime != "" {
			_, _ = fmt.Fprintf(w, "pre_stop_openconnect_uptime: %s\n", snapshot.Runtime.Uptime)
		}
	}
	if len(snapshot.Routes) > 0 {
		_, _ = fmt.Fprintf(w, "pre_stop_live_routes: %s\n", strings.Join(snapshot.Routes, ", "))
	}
	if snapshot.ScutilDNS != "" {
		_, _ = fmt.Fprintf(w, "pre_stop_scutil_dns_begin\n%s\npre_stop_scutil_dns_end\n", snapshot.ScutilDNS)
	}
	if snapshot.RouteTable != "" {
		_, _ = fmt.Fprintf(w, "pre_stop_route_table_begin\n%s\npre_stop_route_table_end\n", snapshot.RouteTable)
	}
	_, _ = fmt.Fprintf(w, "=== end pre-stop snapshot ===\n")
}

func commandCombinedOutput(name string, args ...string) string {
	out, err := execCommandOpenConnect(name, args...).CombinedOutput()
	if err != nil && len(out) == 0 {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func writeLogHeader(file *os.File, current CurrentSession) {
	_, _ = fmt.Fprintf(file, "=== openconnect-tun session start ===\n")
	_, _ = fmt.Fprintf(file, "session_id: %s\n", current.ID)
	_, _ = fmt.Fprintf(file, "started_at: %s\n", current.StartedAt.Format(time.RFC3339))
	_, _ = fmt.Fprintf(file, "server: %s\n", current.Server)
	if current.ResolvedFrom != "" {
		_, _ = fmt.Fprintf(file, "resolved_from: %s\n", current.ResolvedFrom)
	}
	if current.Profile != "" {
		_, _ = fmt.Fprintf(file, "profile: %s\n", current.Profile)
	}
	_, _ = fmt.Fprintf(file, "mode: %s\n", current.Mode)
	if current.PrivilegedMode != "" {
		_, _ = fmt.Fprintf(file, "privileged_mode: %s\n", current.PrivilegedMode)
	}
	if current.HelperSocketPath != "" {
		_, _ = fmt.Fprintf(file, "helper_socket: %s\n", current.HelperSocketPath)
	}
	_, _ = fmt.Fprintf(file, "script: %s\n", current.Script)
	_, _ = fmt.Fprintf(file, "routes: %s\n", joinOrNone(current.IncludeRoutes))
	_, _ = fmt.Fprintf(file, "vpn_domains: %s\n", joinOrNone(current.VPNDomains))
	_, _ = fmt.Fprintf(file, "bypass_suffixes: %s\n", joinOrNone(current.BypassSuffixes))
	_, _ = fmt.Fprintf(file, "vpn_nameservers: %s\n", joinOrNone(current.VPNNameservers))
	_, _ = fmt.Fprintf(file, "command: %s\n", joinOrNone(current.Command))
	_, _ = fmt.Fprintf(file, "--- openconnect output follows ---\n")
}

func saveJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

var ansiRegexp = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func LastRelevantLogLine(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(ansiRegexp.ReplaceAllString(lines[i], ""))
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "==="),
			strings.HasPrefix(line, "session_id:"),
			strings.HasPrefix(line, "started_at:"),
			strings.HasPrefix(line, "server:"),
			strings.HasPrefix(line, "resolved_from:"),
			strings.HasPrefix(line, "profile:"),
			strings.HasPrefix(line, "mode:"),
			strings.HasPrefix(line, "privileged_mode:"),
			strings.HasPrefix(line, "helper_socket:"),
			strings.HasPrefix(line, "script:"),
			strings.HasPrefix(line, "routes:"),
			strings.HasPrefix(line, "vpn_domains:"),
			strings.HasPrefix(line, "bypass_suffixes:"),
			strings.HasPrefix(line, "vpn_nameservers:"),
			strings.HasPrefix(line, "command:"),
			strings.HasPrefix(line, "---"):
			continue
		}
		return line
	}
	return ""
}

func joinOrNone(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, ", ")
}

func cleanupOrphanedResolverState(cacheDir string) (bool, error) {
	if state, _, err := DetectState(); err == nil && state == StateConnected {
		return false, nil
	}
	if !orphanedResolverArtifactsPresent() {
		return false, nil
	}

	cacheDir = ResolveCacheDir(cacheDir)
	if err := os.MkdirAll(RuntimeDir(cacheDir), 0o755); err != nil {
		return true, fmt.Errorf("prepare orphan cleanup runtime dir: %w", err)
	}
	logPath := filepath.Join(RuntimeDir(cacheDir), orphanCleanupLogName)
	command := []string{"/bin/sh", "-c", orphanedResolverCleanupScript()}

	mode, helperCfg, err := resolvePrivilegedMode(PrivilegedModeAuto)
	if err != nil {
		return true, fmt.Errorf("resolve privileged mode for orphan cleanup: %w", err)
	}
	switch mode {
	case PrivilegedModeHelper:
		if err := helperRun(helperCfg, command, "", logPath); err != nil {
			return true, fmt.Errorf("run orphan cleanup via helper: %w", err)
		}
	default:
		if mode == PrivilegedModeSudo {
			if err := ensureSudoCredentials(); err != nil {
				return true, fmt.Errorf("sudo authentication for orphan cleanup: %w", err)
			}
		}
		execName, execArgs := elevatedCommand(mode, command...)
		cmd := execCommandOpenConnect(execName, execArgs...)
		logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return true, fmt.Errorf("open orphan cleanup log: %w", err)
		}
		cmd.Stdout = logFile
		cmd.Stderr = logFile
		runErr := cmd.Run()
		_ = logFile.Close()
		if runErr != nil {
			return true, fmt.Errorf("run orphan cleanup: %w", runErr)
		}
	}

	if orphanedResolverArtifactsPresent() {
		return true, fmt.Errorf("orphaned openconnect resolver artifacts still present after cleanup")
	}
	return true, nil
}

func orphanedResolverArtifactsPresent() bool {
	for _, domain := range orphanedResolverArtifactDomains() {
		if _, err := os.Stat(filepath.Join("/etc/resolver", domain)); err == nil {
			return true
		}
	}
	return false
}

func orphanedResolverArtifactDomains() []string {
	domains := []string{
		"bypass.corp.example",
		"vpn-gw2.corp.example",
	}
	if spec := supplementalResolverSpecForServer("vpn-gw2.corp.example/outside"); spec != nil {
		domains = append(domains, spec.Domains...)
	}
	return uniqueStrings(domains)
}

func orphanedResolverCleanupScript() string {
	return `set -eu

if [ ! -d /etc/resolver ]; then
  exit 0
fi

for f in /etc/resolver/*; do
  [ -f "$f" ] || continue
  first_line=$(head -n 1 "$f" 2>/dev/null || true)
  case "$first_line" in
    '# Added by openconnect-tun DNS shim'*|'# Added by openconnect-tun public bypass'*)
      rm -f "$f"
      ;;
  esac
done
`
}
