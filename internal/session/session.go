package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"multi-tun/internal/config"
	"multi-tun/internal/model"
	"multi-tun/internal/vpncore"
)

const (
	sessionTimestampFormat = "20060102T150405Z"
	logFilePrefix          = "sing-box-session-"
	metadataFilePrefix     = "session-"
	runtimeFileName        = "current-session.json"
	startupResolveTimeout  = 8 * time.Second
	startupResolveInterval = 300 * time.Millisecond
	resolveProbeTimeout    = 1500 * time.Millisecond
	resolveProbeSuccesses  = 2
)

var (
	execLookPath           = exec.LookPath
	execCommand            = exec.Command
	launchdPIDSession      = launchdPID
	stopLaunchdSessionFunc = stopLaunchdSession
	routeGetHostSession    = func(host string) ([]byte, error) {
		return execCommand(routePath, "-n", "get", host).CombinedOutput()
	}
	networkConnectionListSession = func() ([]byte, error) {
		return execCommand(scutilPath, "--nc", "list").CombinedOutput()
	}
	vpnCoreAvailableSession = func() bool {
		return vpncore.Available(vpncore.DefaultServiceConfig())
	}
	vpnCoreSpawnDetachedSession = func(command []string, logPath string, setPGID bool) (int, error) {
		return vpncore.SpawnDetached(vpncore.DefaultServiceConfig(), command, "", logPath, setPGID)
	}
	vpnCoreSignalSession = func(pid int, signal string, group bool) error {
		return vpncore.Signal(vpncore.DefaultServiceConfig(), pid, signal, group)
	}
	startupSessionAlive = func(current CurrentSession) (bool, int, error) {
		return SessionAlive(current)
	}
	startupResolveHost = func(ctx context.Context, host string) ([]string, error) {
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
		if err != nil {
			return nil, err
		}
		seen := map[string]struct{}{}
		result := make([]string, 0, len(ips))
		for _, ip := range ips {
			value := ip.String()
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
			return nil, fmt.Errorf("empty result")
		}
		return result, nil
	}
	startupScutilDNSDump = func() ([]byte, error) {
		return execCommand(scutilPath, "--dns").CombinedOutput()
	}
)

type StartOptions struct {
	Mode              string
	BypassSuffixes    []string
	InterfaceName     string
	TunAddresses      []string
	OverlayDNSActive  bool
	OverlayDNSDomains []string
	SystemDNSServers  []string
	PrivilegedLaunch  config.PrivilegedLaunchConfig
}

type CurrentSession struct {
	ID                       string    `json:"id"`
	PID                      int       `json:"pid"`
	StartedAt                time.Time `json:"started_at"`
	ConfigPath               string    `json:"config_path"`
	LogPath                  string    `json:"log_path"`
	MetadataPath             string    `json:"metadata_path"`
	ProfileID                string    `json:"profile_id"`
	ProfileName              string    `json:"profile_name"`
	ProfileEndpoint          string    `json:"profile_endpoint"`
	Mode                     string    `json:"mode"`
	BypassSuffixes           []string  `json:"bypass_suffixes"`
	Command                  []string  `json:"command"`
	LaunchMode               string    `json:"launch_mode,omitempty"`
	LaunchLabel              string    `json:"launch_label,omitempty"`
	LaunchPlistPath          string    `json:"launch_plist_path,omitempty"`
	DNSHandoffMode           string    `json:"dns_handoff_mode,omitempty"`
	DNSHandoffService        string    `json:"dns_handoff_service,omitempty"`
	DNSHandoffServiceID      string    `json:"dns_handoff_service_id,omitempty"`
	DNSHandoffInterface      string    `json:"dns_handoff_interface,omitempty"`
	DNSHandoffServers        []string  `json:"dns_handoff_servers,omitempty"`
	DNSHandoffRestoreServers []string  `json:"dns_handoff_restore_servers,omitempty"`
	DNSHandoffRestoreAuto    bool      `json:"dns_handoff_restore_auto,omitempty"`
}

func Start(cacheDir, configPath string, profile model.Profile, options StartOptions) (CurrentSession, error) {
	executable, err := execLookPath("sing-box")
	if err != nil {
		return CurrentSession{}, err
	}

	launchMode, err := resolveLaunchMode(options.Mode, options.PrivilegedLaunch)
	if err != nil {
		return CurrentSession{}, err
	}

	now := time.Now().UTC()
	sessionID := now.Format(sessionTimestampFormat)
	logPath := filepath.Join(SessionsDir(cacheDir), logFilePrefix+sessionID+".log")
	metadataPath := filepath.Join(SessionsDir(cacheDir), metadataFilePrefix+sessionID+".json")

	if err := os.MkdirAll(SessionsDir(cacheDir), 0o755); err != nil {
		return CurrentSession{}, err
	}
	if err := os.MkdirAll(RuntimeDir(cacheDir), 0o755); err != nil {
		return CurrentSession{}, err
	}

	command := logicalCommand(executable, configPath, launchMode)
	session := CurrentSession{
		ID:              sessionID,
		StartedAt:       now,
		ConfigPath:      configPath,
		LogPath:         logPath,
		MetadataPath:    metadataPath,
		ProfileID:       profile.ID,
		ProfileName:     profile.DisplayName(),
		ProfileEndpoint: profile.Endpoint(),
		Mode:            options.Mode,
		BypassSuffixes:  append([]string(nil), options.BypassSuffixes...),
		Command:         command,
		LaunchMode:      launchMode,
	}
	if launchMode == config.LaunchModeLaunchd {
		session.LaunchLabel = options.PrivilegedLaunch.Label
		session.LaunchPlistPath = options.PrivilegedLaunch.PlistPath
	}

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return CurrentSession{}, err
	}
	writeLogHeader(logFile, session, profile)
	if err := guardNestedTunnelStartup(profile, options.Mode); err != nil {
		_, _ = fmt.Fprintf(logFile, "startup_guard_failed: %v\n", err)
		_ = logFile.Close()
		return CurrentSession{}, err
	}

	var release func() error
	switch launchMode {
	case config.LaunchModeHelper:
		_ = logFile.Close()
		pid, err := startWithVPNCore(session, executable)
		if err != nil {
			return CurrentSession{}, err
		}
		session.PID = pid
	default:
		cmd, err := startProcessSession(logFile, executable, configPath, launchMode)
		_ = logFile.Close()
		if err != nil {
			return CurrentSession{}, err
		}
		session.PID = cmd.Process.Pid
		release = cmd.Process.Release
	}

	if err := saveJSON(metadataPath, session); err != nil {
		_ = stopStartedSession(session)
		return CurrentSession{}, err
	}

	pid, err := waitForStableStart(session, 1500*time.Millisecond)
	if err != nil {
		_ = stopStartedSession(session)
		_ = ClearCurrent(cacheDir)
		if release != nil {
			_ = release()
		}
		if last := LastRelevantLogLine(logPath); last != "" {
			return CurrentSession{}, fmt.Errorf("sing-box exited during startup: %s; inspect %s", last, logPath)
		}
		return CurrentSession{}, fmt.Errorf("sing-box exited during startup; inspect %s", logPath)
	}
	if pid > 0 {
		session.PID = pid
	}

	if err := applySystemDNSHandoff(&session, options); err != nil {
		_ = stopStartedSession(session)
		_ = ClearCurrent(cacheDir)
		return CurrentSession{}, fmt.Errorf("configure system DNS: %w", err)
	}
	if err := waitForStartupDNSReadiness(session, options, startupResolveTimeout, startupResolveInterval); err != nil {
		_ = stopStartedSession(session)
		_ = ClearCurrent(cacheDir)
		return CurrentSession{}, err
	}

	if err := saveJSON(metadataPath, session); err != nil {
		_ = stopStartedSession(session)
		return CurrentSession{}, err
	}

	if err := SaveCurrent(cacheDir, session); err != nil {
		_ = stopStartedSession(session)
		return CurrentSession{}, err
	}
	if release != nil {
		if err := release(); err != nil {
			return CurrentSession{}, err
		}
	}

	return session, nil
}

func Stop(cacheDir string, launch config.PrivilegedLaunchConfig, force bool, timeout time.Duration) (CurrentSession, string, error) {
	current, err := ResolveCurrent(cacheDir, launch)
	if err != nil {
		return CurrentSession{}, "", err
	}

	alive, pid, err := SessionAlive(current)
	if err != nil {
		return CurrentSession{}, "", err
	}
	if pid > 0 {
		current.PID = pid
	}
	if !alive {
		if err := restoreSystemDNSHandoff(current); err != nil {
			return CurrentSession{}, "", err
		}
		if err := ClearCurrent(cacheDir); err != nil {
			return CurrentSession{}, "", err
		}
		return current, "stale", nil
	}

	switch current.LaunchMode {
	case config.LaunchModeHelper:
		if err := stopHelperSession(current, force, timeout); err != nil {
			return CurrentSession{}, "", err
		}
		if err := restoreSystemDNSHandoff(current); err != nil {
			return CurrentSession{}, "", err
		}
		if err := ClearCurrent(cacheDir); err != nil {
			return CurrentSession{}, "", err
		}
		return current, "stopped", nil
	case config.LaunchModeLaunchd:
		if err := stopLaunchdSessionFunc(current, timeout); err != nil {
			return CurrentSession{}, "", err
		}
		if err := restoreSystemDNSHandoff(current); err != nil {
			return CurrentSession{}, "", err
		}
		if err := ClearCurrent(cacheDir); err != nil {
			return CurrentSession{}, "", err
		}
		return current, "stopped", nil
	default:
		return stopProcessSession(cacheDir, current, force, timeout)
	}
}

func ResolveCurrent(cacheDir string, launch config.PrivilegedLaunchConfig) (CurrentSession, error) {
	current, err := LoadCurrent(cacheDir)
	if err == nil {
		return current, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return CurrentSession{}, err
	}

	current, found, err := resolveLegacyLaunchdCurrent(cacheDir, launch)
	if err != nil {
		return CurrentSession{}, err
	}
	if found {
		return current, nil
	}

	return CurrentSession{}, os.ErrNotExist
}

func resolveLegacyLaunchdCurrent(cacheDir string, launch config.PrivilegedLaunchConfig) (CurrentSession, bool, error) {
	label := strings.TrimSpace(launch.Label)
	if label == "" {
		return CurrentSession{}, false, nil
	}

	pid, err := launchdPIDSession(label)
	if err != nil {
		return CurrentSession{}, false, err
	}
	if pid <= 0 {
		return CurrentSession{}, false, nil
	}

	current, found, err := latestLaunchdSessionMetadata(cacheDir, label)
	if err != nil {
		return CurrentSession{}, false, err
	}
	if !found {
		current = CurrentSession{
			ID: "legacy-launchd-" + strings.ReplaceAll(label, ".", "-"),
		}
	}

	current.PID = pid
	current.LaunchMode = config.LaunchModeLaunchd
	if current.LaunchLabel == "" {
		current.LaunchLabel = label
	}
	if current.LaunchPlistPath == "" {
		current.LaunchPlistPath = launch.PlistPath
	}
	return current, true, nil
}

func latestLaunchdSessionMetadata(cacheDir string, label string) (CurrentSession, bool, error) {
	entries, err := os.ReadDir(SessionsDir(cacheDir))
	if errors.Is(err, os.ErrNotExist) {
		return CurrentSession{}, false, nil
	}
	if err != nil {
		return CurrentSession{}, false, err
	}

	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i]
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, metadataFilePrefix) || filepath.Ext(name) != ".json" {
			continue
		}

		raw, err := os.ReadFile(filepath.Join(SessionsDir(cacheDir), name))
		if err != nil {
			continue
		}

		var current CurrentSession
		if err := json.Unmarshal(raw, &current); err != nil {
			continue
		}
		if current.LaunchMode != config.LaunchModeLaunchd || current.LaunchLabel != label {
			continue
		}
		return current, true, nil
	}

	return CurrentSession{}, false, nil
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
	if alive {
		return true, current.PID, nil
	}

	if current.LaunchMode != config.LaunchModeLaunchd || current.LaunchLabel == "" {
		return false, current.PID, nil
	}

	pid, err := launchdPIDSession(current.LaunchLabel)
	if err != nil {
		return false, current.PID, err
	}
	if pid <= 0 {
		return false, current.PID, nil
	}
	return true, pid, nil
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

func startProcessSession(logFile *os.File, executable, configPath, launchMode string) (*exec.Cmd, error) {
	execName, args, err := processCommand(executable, configPath, launchMode)
	if err != nil {
		return nil, err
	}

	cmd := execCommand(execName, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Stdin = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

func stopProcessSession(cacheDir string, current CurrentSession, force bool, timeout time.Duration) (CurrentSession, string, error) {
	if err := signalGroup(current.PID, syscall.SIGTERM); err != nil {
		return CurrentSession{}, "", err
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		alive, _, err := SessionAlive(current)
		if err != nil {
			return CurrentSession{}, "", err
		}
		if !alive {
			if err := restoreSystemDNSHandoff(current); err != nil {
				return CurrentSession{}, "", err
			}
			if err := ClearCurrent(cacheDir); err != nil {
				return CurrentSession{}, "", err
			}
			return current, "stopped", nil
		}
		time.Sleep(200 * time.Millisecond)
	}

	if !force {
		return current, "timeout", fmt.Errorf("timeout waiting for sing-box pid %d to stop", current.PID)
	}

	if err := signalGroup(current.PID, syscall.SIGKILL); err != nil {
		return CurrentSession{}, "", err
	}
	for i := 0; i < 10; i++ {
		alive, _, err := SessionAlive(current)
		if err != nil {
			return CurrentSession{}, "", err
		}
		if !alive {
			if err := restoreSystemDNSHandoff(current); err != nil {
				return CurrentSession{}, "", err
			}
			if err := ClearCurrent(cacheDir); err != nil {
				return CurrentSession{}, "", err
			}
			return current, "killed", nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	return current, "timeout", fmt.Errorf("failed to stop sing-box pid %d", current.PID)
}

func stopStartedSession(current CurrentSession) error {
	restoreErr := restoreSystemDNSHandoff(current)
	switch current.LaunchMode {
	case config.LaunchModeHelper:
		if err := killHelperSession(current); err != nil {
			return err
		}
	case config.LaunchModeLaunchd:
		if err := stopLaunchdSessionFunc(current, 1500*time.Millisecond); err != nil {
			return err
		}
	default:
		if err := signalGroup(current.PID, syscall.SIGKILL); err != nil {
			return err
		}
	}
	if restoreErr != nil {
		return restoreErr
	}
	return nil
}

func resolveLaunchMode(renderMode string, launch config.PrivilegedLaunchConfig) (string, error) {
	mode := strings.TrimSpace(launch.Mode)
	if mode == "" {
		mode = config.LaunchModeAuto
	}

	if renderMode != config.RenderModeTun {
		switch mode {
		case config.LaunchModeAuto:
			return config.LaunchModeDirect, nil
		case config.LaunchModeDirect, config.LaunchModeSudo, config.LaunchModeHelper:
			return mode, nil
		case config.LaunchModeLaunchd:
			return "", fmt.Errorf("render.privileged_launch.mode=launchd is only supported in tun mode")
		default:
			return "", fmt.Errorf("unsupported launch mode %q", mode)
		}
	}

	switch mode {
	case config.LaunchModeAuto:
		if vpnCoreAvailableSession() {
			return config.LaunchModeHelper, nil
		}
		if os.Geteuid() == 0 {
			return config.LaunchModeDirect, nil
		}
		return config.LaunchModeSudo, nil
	case config.LaunchModeDirect, config.LaunchModeSudo, config.LaunchModeHelper:
		return mode, nil
	case config.LaunchModeLaunchd:
		if runtime.GOOS != "darwin" {
			return "", fmt.Errorf("render.privileged_launch.mode=launchd is only supported on macOS")
		}
		return config.LaunchModeHelper, nil
	default:
		return "", fmt.Errorf("unsupported launch mode %q", mode)
	}
}

func logicalCommand(executable, configPath, launchMode string) []string {
	switch launchMode {
	case config.LaunchModeSudo:
		if os.Geteuid() == 0 {
			return []string{executable, "run", "-c", configPath}
		}
		return []string{"sudo", executable, "run", "-c", configPath}
	default:
		return []string{executable, "run", "-c", configPath}
	}
}

func processCommand(executable, configPath, launchMode string) (string, []string, error) {
	switch launchMode {
	case config.LaunchModeDirect:
		return executable, []string{"run", "-c", configPath}, nil
	case config.LaunchModeSudo:
		if err := ensureSudo(); err != nil {
			return "", nil, fmt.Errorf("sudo authentication: %w", err)
		}
		if os.Geteuid() == 0 {
			return executable, []string{"run", "-c", configPath}, nil
		}
		return "sudo", []string{executable, "run", "-c", configPath}, nil
	default:
		return "", nil, fmt.Errorf("unsupported launch mode %q", launchMode)
	}
}

func ensureSudo() error {
	if os.Geteuid() == 0 {
		return nil
	}
	cmd := execCommand("sudo", "-v")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func writeLogHeader(file *os.File, current CurrentSession, profile model.Profile) {
	_, _ = fmt.Fprintf(file, "=== vless-tun session start ===\n")
	_, _ = fmt.Fprintf(file, "session_id: %s\n", current.ID)
	_, _ = fmt.Fprintf(file, "started_at: %s\n", current.StartedAt.Format(time.RFC3339))
	_, _ = fmt.Fprintf(file, "profile: %s | %s | %s\n", profile.ID, profile.DisplayName(), profile.Endpoint())
	_, _ = fmt.Fprintf(file, "config_path: %s\n", current.ConfigPath)
	_, _ = fmt.Fprintf(file, "mode: %s\n", current.Mode)
	_, _ = fmt.Fprintf(file, "launch_mode: %s\n", current.LaunchMode)
	if current.LaunchLabel != "" {
		_, _ = fmt.Fprintf(file, "launch_label: %s\n", current.LaunchLabel)
	}
	if current.LaunchPlistPath != "" {
		_, _ = fmt.Fprintf(file, "launch_plist_path: %s\n", current.LaunchPlistPath)
	}
	_, _ = fmt.Fprintf(file, "bypasses: %s\n", joinOrNone(current.BypassSuffixes))
	_, _ = fmt.Fprintf(file, "command: %s\n", joinOrNone(current.Command))
	_, _ = fmt.Fprintf(file, "--- sing-box output follows ---\n")
}

func guardNestedTunnelStartup(profile model.Profile, mode string) error {
	if runtime.GOOS != "darwin" || mode != config.RenderModeTun {
		return nil
	}

	upstreamHost := strings.TrimSpace(profile.Host)
	if upstreamHost == "" {
		return nil
	}

	iface, err := routeInterfaceForHost(upstreamHost)
	if err != nil {
		return fmt.Errorf("inspect upstream route for %s: %w", upstreamHost, err)
	}
	if !isVPNInterfaceName(iface) {
		return nil
	}

	services, servicesErr := connectedVPNServiceNames()
	if servicesErr != nil {
		return fmt.Errorf("upstream VLESS route %s currently goes via %s; refusing nested tun startup", profile.Endpoint(), iface)
	}

	if len(services) == 0 {
		return fmt.Errorf("upstream VLESS route %s currently goes via %s; refusing nested tun startup", profile.Endpoint(), iface)
	}

	return fmt.Errorf("upstream VLESS route %s currently goes via %s; refusing nested tun startup while active VPN services are connected: %s", profile.Endpoint(), iface, strings.Join(services, ", "))
}

func routeInterfaceForHost(host string) (string, error) {
	out, err := routeGetHostSession(host)
	if err != nil {
		return "", err
	}
	return parseDefaultInterface(string(out))
}

func isVPNInterfaceName(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	switch {
	case strings.HasPrefix(value, "utun"),
		strings.HasPrefix(value, "tun"),
		strings.HasPrefix(value, "ppp"),
		strings.HasPrefix(value, "ipsec"):
		return true
	default:
		return false
	}
}

func connectedVPNServiceNames() ([]string, error) {
	out, err := networkConnectionListSession()
	if err != nil {
		return nil, err
	}

	var result []string
	seen := map[string]struct{}{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "(Connected)") {
			continue
		}
		start := strings.Index(line, "\"")
		end := strings.LastIndex(line, "\"")
		if start < 0 || end <= start {
			continue
		}
		name := strings.TrimSpace(line[start+1 : end])
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		result = append(result, name)
	}
	return result, nil
}

func saveJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

func signalGroup(pid int, signal syscall.Signal) error {
	err := syscall.Kill(-pid, signal)
	if errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}

func waitForStableStart(current CurrentSession, timeout time.Duration) (int, error) {
	deadline := time.Now().Add(timeout)
	for {
		alive, pid, err := SessionAlive(current)
		if err != nil {
			return current.PID, err
		}
		if !alive {
			return current.PID, fmt.Errorf("sing-box exited during startup")
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

func waitForStartupDNSReadiness(current CurrentSession, options StartOptions, timeout, interval time.Duration) error {
	if !shouldWaitStartupDNSReadiness(current, options) {
		return nil
	}

	hosts := startupReadinessHosts()
	deadline := time.Now().Add(timeout)
	consecutiveSuccesses := 0
	lastIssue := "pending"
	lastLoggedIssue := ""
	appendSessionLog(current.LogPath, "startup_readiness_begin hosts=%s timeout=%s method=%s\n", strings.Join(hosts, ","), timeout, current.DNSHandoffMode)

	for {
		alive, pid, err := startupSessionAlive(current)
		if err != nil {
			return fmt.Errorf("check sing-box during startup readiness: %w", err)
		}
		if pid > 0 {
			current.PID = pid
		}
		if !alive {
			return fmt.Errorf("sing-box exited during startup readiness; inspect %s", current.LogPath)
		}

		ready, issue := startupDNSReady(current, hosts)
		if ready {
			consecutiveSuccesses++
			if consecutiveSuccesses >= resolveProbeSuccesses {
				appendSessionLog(current.LogPath, "startup_readiness_ok hosts=%s checks=%d\n", strings.Join(hosts, ","), consecutiveSuccesses)
				return nil
			}
		} else {
			consecutiveSuccesses = 0
			lastIssue = issue
			if issue != "" && issue != lastLoggedIssue {
				appendSessionLog(current.LogPath, "startup_readiness_pending reason=%s\n", issue)
				lastLoggedIssue = issue
			}
		}

		if time.Now().After(deadline) {
			appendSessionLog(current.LogPath, "startup_readiness_failed reason=%s\n", lastIssue)
			return fmt.Errorf("timed out waiting for public DNS readiness (%s); inspect %s", lastIssue, current.LogPath)
		}
		time.Sleep(interval)
	}
}

func shouldWaitStartupDNSReadiness(current CurrentSession, options StartOptions) bool {
	return runtime.GOOS == "darwin" &&
		current.Mode == config.RenderModeTun &&
		options.OverlayDNSActive &&
		len(startupReadinessHosts()) > 0
}

func startupDNSReady(current CurrentSession, hosts []string) (bool, string) {
	if current.DNSHandoffMode == dnsHandoffModeScutil {
		raw, err := startupScutilDNSDump()
		if err != nil {
			return false, fmt.Sprintf("scutil --dns: %v", err)
		}
		if !scutilDNSHandoffVisible(string(raw), current) {
			return false, fmt.Sprintf("scutil handoff not visible for %s", current.DNSHandoffInterface)
		}
	}

	for _, host := range hosts {
		ctx, cancel := context.WithTimeout(context.Background(), resolveProbeTimeout)
		ips, err := startupResolveHost(ctx, host)
		cancel()
		if err != nil {
			return false, fmt.Sprintf("resolve %s: %v", host, err)
		}
		if len(ips) == 0 {
			return false, fmt.Sprintf("resolve %s: empty result", host)
		}
	}

	return true, ""
}

func startupReadinessHosts() []string {
	return []string{"github.com", "yandex.ru"}
}

func scutilDNSHandoffVisible(output string, current CurrentSession) bool {
	interfaceName := strings.TrimSpace(current.DNSHandoffInterface)
	if interfaceName == "" || len(current.DNSHandoffServers) == 0 {
		return false
	}

	for _, block := range strings.Split(output, "\n\n") {
		if !strings.Contains(block, "("+interfaceName+")") {
			continue
		}
		for _, server := range current.DNSHandoffServers {
			if strings.Contains(block, "nameserver[0] : "+server) || strings.Contains(block, "nameserver[1] : "+server) {
				return true
			}
		}
	}
	return false
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
			strings.HasPrefix(line, "profile:"),
			strings.HasPrefix(line, "config_path:"),
			strings.HasPrefix(line, "mode:"),
			strings.HasPrefix(line, "launch_mode:"),
			strings.HasPrefix(line, "launch_label:"),
			strings.HasPrefix(line, "launch_plist_path:"),
			strings.HasPrefix(line, "bypasses:"),
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
