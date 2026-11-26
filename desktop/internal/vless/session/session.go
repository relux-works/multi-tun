package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"multi-tun/desktop/internal/core/vpncore"
	"multi-tun/desktop/internal/processidentity"
	"multi-tun/desktop/internal/vless/config"
	"multi-tun/desktop/internal/vless/model"
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
	logLevelDebug          = "debug"
	logLevelInfo           = "info"
	logLevelWarn           = "warn"
	logLevelError          = "error"
)

var (
	execLookPath           = exec.LookPath
	execCommand            = exec.Command
	launchdPIDSession      = launchdPID
	processIdentitySession = processidentity.Read
	processAliveSession    = ProcessAlive
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
	vpnCoreStartSingBoxSession = func(configJSON []byte, logPath string, maxLines int, setPGID bool) (int, string, error) {
		return vpncore.StartSingBox(vpncore.DefaultServiceConfig(), configJSON, logPath, setPGID, vpncore.LogOptions{MaxLines: maxLines})
	}
	vpnCoreSignalSession = func(handle, signal string) error {
		_, err := vpncore.Signal(vpncore.DefaultServiceConfig(), handle, signal)
		return err
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
	Engine            string
	BypassSuffixes    []string
	InterfaceName     string
	TunAddresses      []string
	OverlayDNSActive  bool
	OverlayDNSDomains []string
	SystemDNSServers  []string
	PrivilegedLaunch  config.PrivilegedLaunchConfig
	Sidecars          []SidecarOptions
	LogMaxLines       int
	ResolvedServer    string
	ResolvedAlias     string
	ResolvedName      string
	ResolvedID        string
	ResolutionReason  string
	SnapshotFetchedAt *time.Time
}

type SidecarOptions struct {
	Name       string
	Executable string
	Args       []string
}

type CurrentSession struct {
	ID                       string           `json:"id"`
	PID                      int              `json:"pid"`
	Handle                   string           `json:"handle,omitempty"`
	StartedAt                time.Time        `json:"started_at"`
	ProcessComm              string           `json:"process_comm,omitempty"`
	ProcessStart             time.Time        `json:"process_start,omitempty"`
	Engine                   string           `json:"engine,omitempty"`
	InterfaceName            string           `json:"interface_name,omitempty"`
	ConfigPath               string           `json:"config_path"`
	LogPath                  string           `json:"log_path"`
	LogMaxLines              int              `json:"log_max_lines,omitempty"`
	MetadataPath             string           `json:"metadata_path"`
	ProfileID                string           `json:"profile_id"`
	ProfileName              string           `json:"profile_name"`
	ProfileEndpoint          string           `json:"profile_endpoint"`
	ResolvedServer           string           `json:"resolved_server,omitempty"`
	ResolvedAlias            string           `json:"resolved_alias,omitempty"`
	ResolvedProfileName      string           `json:"resolved_profile_name,omitempty"`
	ResolvedProfileID        string           `json:"resolved_profile_id,omitempty"`
	ResolutionReason         string           `json:"resolution_reason,omitempty"`
	SnapshotFetchedAt        *time.Time       `json:"snapshot_fetched_at,omitempty"`
	Mode                     string           `json:"mode"`
	BypassSuffixes           []string         `json:"bypass_suffixes"`
	Command                  []string         `json:"command"`
	Sidecars                 []SidecarSession `json:"sidecars,omitempty"`
	LaunchMode               string           `json:"launch_mode,omitempty"`
	LaunchLabel              string           `json:"launch_label,omitempty"`
	LaunchPlistPath          string           `json:"launch_plist_path,omitempty"`
	DNSHandoffMode           string           `json:"dns_handoff_mode,omitempty"`
	DNSHandoffService        string           `json:"dns_handoff_service,omitempty"`
	DNSHandoffServiceID      string           `json:"dns_handoff_service_id,omitempty"`
	DNSHandoffInterface      string           `json:"dns_handoff_interface,omitempty"`
	DNSHandoffServers        []string         `json:"dns_handoff_servers,omitempty"`
	DNSHandoffRestoreServers []string         `json:"dns_handoff_restore_servers,omitempty"`
	DNSHandoffRestoreAuto    bool             `json:"dns_handoff_restore_auto,omitempty"`
	// Start options a restart needs that are not otherwise recorded. Older
	// records lack them; StartOptionsRecorded says whether they are present.
	StartOptionsRecorded bool     `json:"start_options_recorded,omitempty"`
	TunAddresses         []string `json:"tun_addresses,omitempty"`
	OverlayDNSActive     bool     `json:"overlay_dns_active,omitempty"`
	OverlayDNSDomains    []string `json:"overlay_dns_domains,omitempty"`
	SystemDNSServers     []string `json:"system_dns_servers,omitempty"`
}

type SidecarSession struct {
	ProcessComm  string    `json:"process_comm,omitempty"`
	ProcessStart time.Time `json:"process_start,omitempty"`
	Name         string    `json:"name"`
	PID          int       `json:"pid"`
	Command      []string  `json:"command,omitempty"`
	LogPath      string    `json:"log_path,omitempty"`
}

func Start(cacheDir, configPath string, profile model.Profile, options StartOptions) (CurrentSession, error) {
	launchMode, err := resolveLaunchMode(options.Mode, options.PrivilegedLaunch)
	if err != nil {
		return CurrentSession{}, notStarted(err)
	}
	executable := "sing-box"
	if launchMode != config.LaunchModeHelper {
		executable, err = execLookPath("sing-box")
		if err != nil {
			return CurrentSession{}, notStarted(err)
		}
	}

	now := time.Now().UTC()
	sessionID := now.Format(sessionTimestampFormat)
	logPath := filepath.Join(SessionsDir(cacheDir), logFilePrefix+sessionID+".log")
	metadataPath := filepath.Join(SessionsDir(cacheDir), metadataFilePrefix+sessionID+".json")

	if err := os.MkdirAll(SessionsDir(cacheDir), 0o755); err != nil {
		return CurrentSession{}, notStarted(err)
	}
	if err := os.MkdirAll(RuntimeDir(cacheDir), 0o755); err != nil {
		return CurrentSession{}, notStarted(err)
	}

	command := logicalCommand(executable, configPath, launchMode)
	session := CurrentSession{
		ID:                  sessionID,
		StartedAt:           now,
		Engine:              firstNonEmpty(options.Engine, config.EngineSingbox),
		InterfaceName:       strings.TrimSpace(options.InterfaceName),
		ConfigPath:          configPath,
		LogPath:             logPath,
		MetadataPath:        metadataPath,
		ProfileID:           profile.ID,
		ProfileName:         profile.DisplayName(),
		ProfileEndpoint:     profile.Endpoint(),
		ResolvedServer:      options.ResolvedServer,
		ResolvedAlias:       options.ResolvedAlias,
		ResolvedProfileName: options.ResolvedName,
		ResolvedProfileID:   options.ResolvedID,
		ResolutionReason:    options.ResolutionReason,
		SnapshotFetchedAt:   options.SnapshotFetchedAt,
		Mode:                options.Mode,
		BypassSuffixes:      append([]string(nil), options.BypassSuffixes...),
		Command:             command,
		LaunchMode:          launchMode,
	}
	recordStartOptions(&session, options)
	if launchMode == config.LaunchModeLaunchd {
		session.LaunchLabel = options.PrivilegedLaunch.Label
		session.LaunchPlistPath = options.PrivilegedLaunch.PlistPath
	}
	if launchMode == config.LaunchModeHelper {
		session.LogMaxLines = options.LogMaxLines
	}

	var logFile io.WriteCloser
	if launchMode == config.LaunchModeHelper {
		logFile, err = openSessionLog(logPath, options.LogMaxLines)
	} else {
		logFile, err = os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	}
	if err != nil {
		return CurrentSession{}, notStarted(err)
	}
	writeLogHeader(logFile, session, profile)
	if err := guardNestedTunnelStartup(profile, options.Mode); err != nil {
		writeSessionLog(logFile, logLevelError, "startup_guard_failed: %v\n", err)
		_ = logFile.Close()
		return CurrentSession{}, notStarted(err)
	}

	if err := cleanupOrphanSidecars(options.Sidecars, logFile, 1500*time.Millisecond); err != nil {
		writeSessionLog(logFile, logLevelError, "orphan_sidecar_cleanup_failed: %v\n", err)
		_ = logFile.Close()
		return CurrentSession{}, err
	}

	sidecars, err := startSidecars(cacheDir, sessionID, options.Sidecars)
	if err != nil {
		writeSessionLog(logFile, logLevelError, "sidecar_start_failed: %v\n", err)
		cleanupErr := cleanupOrphanSidecars(options.Sidecars, logFile, 1500*time.Millisecond)
		if cleanupErr != nil {
			writeSessionLog(logFile, logLevelError, "sidecar_start_cleanup_failed: %v\n", cleanupErr)
		}
		_ = logFile.Close()
		if cleanupErr != nil {
			// A sidecar may have started and may still run: this start cannot say what is left.
			return CurrentSession{}, errors.Join(err, fmt.Errorf("cleaning up after the failed sidecar start also failed: %w", cleanupErr))
		}
		return CurrentSession{}, notStarted(err)
	}
	session.Sidecars = sidecars

	var release func() error
	switch launchMode {
	case config.LaunchModeHelper:
		_ = logFile.Close()
		pid, handle, err := startWithVPNCore(session)
		if err != nil {
			stopErr := stopSidecars(sidecars, true, 1500*time.Millisecond)
			var refused *vpncore.RefusedError
			if stopErr == nil && errors.As(err, &refused) {
				// The helper answered with a refusal, so it holds no child for this request.
				return CurrentSession{}, notStarted(err)
			}
			// Without the helper's answer (a lost or late reply) it may have started sing-box and
			// still hold it. This start has no PID or handle for it, so it returns no session and
			// no ErrNothingStarted: the caller must treat the outcome as unknown.
			return CurrentSession{}, errors.Join(err, stopErr)
		}
		session.PID = pid
		session.Handle = handle
	default:
		processLogFile, ok := logFile.(*os.File)
		if !ok {
			_ = logFile.Close()
			_ = stopSidecars(sidecars, true, 1500*time.Millisecond)
			return CurrentSession{}, fmt.Errorf("launch mode %s requires file-backed logging", launchMode)
		}
		cmd, err := startProcessSession(processLogFile, executable, configPath, launchMode)
		_ = logFile.Close()
		if err != nil {
			stopErr := stopSidecars(sidecars, true, 1500*time.Millisecond)
			if stopErr == nil && launchMode != config.LaunchModeLaunchd {
				// The process failed to start, so nothing of this start runs.
				return CurrentSession{}, notStarted(err)
			}
			// launchd may have loaded the job before failing; sidecars may still run.
			session.Sidecars = sidecars
			return session, errors.Join(err, stopErr)
		}
		session.PID = cmd.Process.Pid
		release = cmd.Process.Release
	}

	// Startup error paths below stop the process with stopStartedSession.
	// That is safe even before identity checks pass. In direct and sudo modes
	// this invocation holds the unreaped cmd.Process, so the PID cannot belong
	// to an unrelated process yet. In helper mode killHelperSession signals by
	// the opaque handle of the child the hardened vpn-core still holds, never
	// by PID, and refuses a record without a handle.
	if err := recordProcessIdentity(&session); err != nil {
		stopErr := stopStartedSession(session)
		if release != nil {
			_ = release()
		}
		return failedStart(session, stopErr, err)
	}
	if err := saveJSON(metadataPath, session); err != nil {
		stopErr := stopStartedSession(session)
		return failedStart(session, stopErr, err)
	}

	pid, err := waitForStableStart(session, 1500*time.Millisecond)
	if err != nil {
		if errors.Is(err, errSessionLivenessUnknown) {
			persistErr := SaveCurrent(cacheDir, session)
			if release != nil {
				_ = release()
			}
			return session, errors.Join(err, persistErr)
		}
		stopErr := stopStartedSession(session)
		_ = ClearCurrent(cacheDir)
		if release != nil {
			_ = release()
		}
		if last := LastRelevantLogLine(logPath); last != "" {
			return failedStart(session, stopErr, fmt.Errorf("sing-box exited during startup: %s; inspect %s", last, logPath))
		}
		return failedStart(session, stopErr, fmt.Errorf("sing-box exited during startup; inspect %s", logPath))
	}
	if pid > 0 && pid != session.PID {
		session.PID = pid
		if err := recordProcessIdentity(&session); err != nil {
			stopErr := stopStartedSession(session)
			_ = ClearCurrent(cacheDir)
			return failedStart(session, stopErr, err)
		}
	}

	if err := applySystemDNSHandoff(&session, options); err != nil {
		stopErr := stopStartedSession(session)
		_ = ClearCurrent(cacheDir)
		return failedStart(session, stopErr, fmt.Errorf("configure system DNS: %w", err))
	}
	if err := waitForStartupDNSReadiness(session, options, startupResolveTimeout, startupResolveInterval); err != nil {
		stopErr := stopStartedSession(session)
		_ = ClearCurrent(cacheDir)
		return failedStart(session, stopErr, err)
	}

	if err := saveJSON(metadataPath, session); err != nil {
		stopErr := stopStartedSession(session)
		return failedStart(session, stopErr, err)
	}

	if err := SaveCurrent(cacheDir, session); err != nil {
		stopErr := stopStartedSession(session)
		return failedStart(session, stopErr, err)
	}
	if release != nil {
		if err := release(); err != nil {
			// The session runs and is recorded; return it so the caller can reconcile it.
			return session, err
		}
	}

	return session, nil
}

func Stop(cacheDir string, launch config.PrivilegedLaunchConfig, force bool, timeout time.Duration) (CurrentSession, string, error) {
	current, err := ResolveCurrent(cacheDir, launch)
	if err != nil {
		return CurrentSession{}, "", err
	}
	return stopResolved(cacheDir, current, force, timeout, func() error { return ClearCurrent(cacheDir) })
}

// stopResolved stops the given session and then calls clear to drop its record. It never reads
// the current record again, so a caller can bind the stop to a session it has already checked.
func stopResolved(cacheDir string, current CurrentSession, force bool, timeout time.Duration, clear func() error) (CurrentSession, string, error) {
	alive, pid, err := SessionAlive(current)
	if err != nil {
		return CurrentSession{}, "", err
	}
	if pid > 0 {
		current.PID = pid
	}
	if !alive {
		if err := stopSidecars(current.Sidecars, force, timeout); err != nil {
			return CurrentSession{}, "", err
		}
		if err := restoreSystemDNSHandoff(current); err != nil {
			return CurrentSession{}, "", err
		}
		if err := clear(); err != nil {
			return CurrentSession{}, "", err
		}
		return current, "stale", nil
	}

	switch current.LaunchMode {
	case config.LaunchModeHelper:
		if err := stopHelperSession(current, force, timeout); err != nil {
			return CurrentSession{}, "", err
		}
		if err := stopSidecars(current.Sidecars, force, timeout); err != nil {
			return CurrentSession{}, "", err
		}
		if err := restoreSystemDNSHandoff(current); err != nil {
			return CurrentSession{}, "", err
		}
		if err := clear(); err != nil {
			return CurrentSession{}, "", err
		}
		return current, "stopped", nil
	case config.LaunchModeLaunchd:
		if err := stopLaunchdSessionFunc(current, timeout); err != nil {
			return CurrentSession{}, "", err
		}
		if err := stopSidecars(current.Sidecars, force, timeout); err != nil {
			return CurrentSession{}, "", err
		}
		if err := restoreSystemDNSHandoff(current); err != nil {
			return CurrentSession{}, "", err
		}
		if err := clear(); err != nil {
			return CurrentSession{}, "", err
		}
		return current, "stopped", nil
	default:
		return stopProcessSession(cacheDir, current, force, timeout, clear)
	}
}

// boundLaunchdLabel refuses a launchd record whose label is missing or differs from the configured
// launch label. The label selects the service a privileged `launchctl bootout` acts on, so it must
// come from the configuration, never from the (user-writable) record alone.
func boundLaunchdLabel(current CurrentSession, launch config.PrivilegedLaunchConfig) error {
	if current.LaunchMode != config.LaunchModeLaunchd {
		return nil
	}
	want := strings.TrimSpace(launch.Label)
	if want == "" || current.LaunchLabel != want {
		return fmt.Errorf("%w: record label %q, configured label %q", errLaunchdLabelMismatch, current.LaunchLabel, want)
	}
	return nil
}

// errLaunchdLabelMismatch marks a launchd record that is not bound to the configured label; nothing
// is booted out for it.
var errLaunchdLabelMismatch = errors.New("refusing to stop a launchd session whose label is not the configured one")

func ResolveCurrent(cacheDir string, launch config.PrivilegedLaunchConfig) (CurrentSession, error) {
	current, err := LoadCurrent(cacheDir)
	if err == nil {
		if err := boundLaunchdLabel(current, launch); err != nil {
			return CurrentSession{}, err
		}
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
	return withCurrentRecordLock(cacheDir, func() error {
		return saveJSON(CurrentPath(cacheDir), current)
	})
}

func ClearCurrent(cacheDir string) error {
	return withCurrentRecordLock(cacheDir, func() error { return removeCurrentRecord(cacheDir) })
}

func removeCurrentRecord(cacheDir string) error {
	err := os.Remove(CurrentPath(cacheDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// withCurrentRecordLock runs fn while holding an exclusive per-cache lock (flock on
// runtime/current.lock). Every write and removal of the current-session record takes it, so a
// compare-and-remove cannot be split by another writer in this or another vless-tun process.
func withCurrentRecordLock(cacheDir string, fn func() error) error {
	if err := os.MkdirAll(RuntimeDir(cacheDir), 0o755); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(RuntimeDir(cacheDir), "current.lock"), os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("lock the current-session record: %w", err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	return fn()
}

// SameSession reports whether two records describe the same running session. Both must carry a
// complete identity (see completeIdentity), and every part must match: session IDs have one-second
// resolution, so two starts in the same second can share one, and the launch mode picks the stop
// path. Two records with missing parts never match, not even each other.
func SameSession(a, b CurrentSession) bool {
	if !completeIdentity(a) || !completeIdentity(b) {
		return false
	}
	return a.ID == b.ID &&
		a.PID == b.PID &&
		a.LaunchMode == b.LaunchMode &&
		a.ProcessComm == b.ProcessComm &&
		a.ProcessStart.Equal(b.ProcessStart) &&
		a.Handle == b.Handle &&
		a.LaunchLabel == b.LaunchLabel
}

// completeIdentity reports whether a record names one process unambiguously: a session ID, a PID,
// a launch mode, the recorded process name and start time as a pair (never the name alone), and
// the handle or label its mode stops through.
func completeIdentity(s CurrentSession) bool {
	if s.ID == "" {
		return false
	}
	if s.PID <= 0 {
		return false
	}
	if s.LaunchMode == "" {
		return false
	}
	if s.ProcessComm == "" {
		return false
	}
	if s.ProcessStart.IsZero() {
		return false
	}
	if s.LaunchMode == config.LaunchModeHelper && s.Handle == "" {
		return false
	}
	if s.LaunchMode == config.LaunchModeLaunchd && s.LaunchLabel == "" {
		return false
	}
	return true
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
	alive, err := processAliveSession(current.PID)
	if err != nil {
		return false, current.PID, err
	}
	if alive {
		matches, err := sessionProcessMatches(current)
		launchdByLabel := current.LaunchMode == config.LaunchModeLaunchd && current.LaunchLabel != ""
		if errors.Is(err, errIncompleteRecordedIdentity) && launchdByLabel {
			// A launchd session is identified and stopped by its label, never by this PID:
			// leave the PID alone and ask launchd below.
			matches, err = false, nil
		}
		if err != nil {
			// Unknown identity: refuse to call the process ours or gone, so
			// callers neither signal a possibly unrelated process nor drop
			// the record of a possibly genuine one.
			return false, current.PID, err
		}
		if matches {
			return true, current.PID, nil
		}
		// The recorded PID now belongs to another process. A launchd-managed
		// session may still be running under a new PID; ask launchd below.
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

// recordProcessIdentity stores the observed command name and start time of
// the process holding session.PID right after it is known, so later liveness
// checks compare against the real process, not against an estimate. It is
// only called for a process this invocation just spawned, so a lookup that
// still fails after one retry is a startup failure, never a silent downgrade
// to the weaker name-only check used for legacy records.
func recordProcessIdentity(session *CurrentSession) error {
	comm, started, err := processIdentitySession(session.PID)
	if err != nil && !errors.Is(err, errProcessIdentityUnsupported) {
		time.Sleep(identityRetryDelay)
		comm, started, err = processIdentitySession(session.PID)
	}
	if errors.Is(err, errProcessIdentityUnsupported) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("record identity of sing-box pid %d: %w", session.PID, err)
	}
	session.ProcessComm = comm
	session.ProcessStart = started
	return nil
}

var identityRetryDelay = 100 * time.Millisecond

// sessionProcessMatches reports whether the live process at the session's PID is the recorded main
// process. Only the recorded process name and start time as a pair identify it: a name alone is
// shared by any later process of the same program, so a record without the pair is unverifiable
// and returns errIncompleteRecordedIdentity, never "alive" (which leads to a signal) or "gone".
func sessionProcessMatches(current CurrentSession) (bool, error) {
	if current.ProcessComm == "" || current.ProcessStart.IsZero() {
		return false, fmt.Errorf("%w (pid %d)", errIncompleteRecordedIdentity, current.PID)
	}
	comm, started, err := processIdentitySession(current.PID)
	if errors.Is(err, errProcessIdentityUnsupported) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("verify identity of pid %d: %w", current.PID, err)
	}
	return processidentity.Matches(comm, started, current.ProcessComm, current.ProcessStart, ""), nil
}

// errIncompleteRecordedIdentity marks a main-process record (written by an older client) without
// the process name and start time pair; that process is neither signalled nor treated as gone.
var errIncompleteRecordedIdentity = errors.New("cannot verify the process: its record has no process name and start time; stop it with the client that started it")

// signalProcessGroupSession signals a session's process group; tests replace it with a spy.
var signalProcessGroupSession = signalGroup

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

func startSidecars(cacheDir, sessionID string, options []SidecarOptions) ([]SidecarSession, error) {
	if len(options) == 0 {
		return nil, nil
	}

	sidecars := make([]SidecarSession, 0, len(options))
	for _, option := range options {
		sidecar, err := startSidecar(cacheDir, sessionID, option)
		if err != nil {
			_ = stopSidecars(sidecars, true, 1500*time.Millisecond)
			return nil, err
		}
		sidecars = append(sidecars, sidecar)
	}
	return sidecars, nil
}

func startSidecar(cacheDir, sessionID string, option SidecarOptions) (SidecarSession, error) {
	name := strings.TrimSpace(option.Name)
	if name == "" {
		name = "sidecar"
	}
	executable := strings.TrimSpace(option.Executable)
	if executable == "" {
		return SidecarSession{}, fmt.Errorf("%s sidecar executable is required", name)
	}
	resolvedExecutable, err := execLookPath(executable)
	if err != nil {
		return SidecarSession{}, fmt.Errorf("%s sidecar executable %q: %w", name, executable, err)
	}

	logPath := filepath.Join(SessionsDir(cacheDir), safeSidecarName(name)+"-session-"+sessionID+".log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return SidecarSession{}, err
	}
	defer logFile.Close()

	command := append([]string{resolvedExecutable}, option.Args...)
	_, _ = fmt.Fprintf(logFile, "=== vless-tun sidecar start ===\n")
	_, _ = fmt.Fprintf(logFile, "session_id: %s\n", sessionID)
	_, _ = fmt.Fprintf(logFile, "sidecar: %s\n", name)
	_, _ = fmt.Fprintf(logFile, "command: %s\n", joinOrNone(command))
	_, _ = fmt.Fprintf(logFile, "--- %s output follows ---\n", name)

	cmd := execCommand(resolvedExecutable, option.Args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Stdin = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return SidecarSession{}, err
	}
	sidecar := SidecarSession{
		Name: name, PID: cmd.Process.Pid, Command: command, LogPath: logPath,
	}
	if err := recordSidecarIdentity(&sidecar); err != nil {
		// This unreaped child was started by this invocation; its PID cannot be reused.
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return SidecarSession{}, err
	}
	if err := cmd.Process.Release(); err != nil {
		return SidecarSession{}, err
	}
	startedSidecar, err := waitForSidecarStart(sidecar, option, 500*time.Millisecond)
	if err != nil {
		return SidecarSession{}, err
	}
	return startedSidecar, nil
}

func waitForSidecarStart(sidecar SidecarSession, option SidecarOptions, timeout time.Duration) (SidecarSession, error) {
	deadline := time.Now().Add(timeout)
	for {
		alive, err := sidecarProcessAliveSession(sidecar.PID)
		if err != nil {
			return SidecarSession{}, err
		}
		if !alive {
			if discovered, found, err := findRunningSidecar(option); err != nil {
				return SidecarSession{}, err
			} else if found {
				sidecar.PID = discovered.PID
				if err := recordSidecarIdentity(&sidecar); err != nil {
					return SidecarSession{}, err
				}
				return sidecar, nil
			}
			if last := LastRelevantLogLine(sidecar.LogPath); last != "" {
				return SidecarSession{}, fmt.Errorf("%s sidecar exited during startup: %s; inspect %s", sidecar.Name, last, sidecar.LogPath)
			}
			return SidecarSession{}, fmt.Errorf("%s sidecar exited during startup; inspect %s", sidecar.Name, sidecar.LogPath)
		}
		if time.Now().After(deadline) {
			return sidecar, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func stopSidecars(sidecars []SidecarSession, force bool, timeout time.Duration) error {
	for i := len(sidecars) - 1; i >= 0; i-- {
		if err := stopSidecar(sidecars[i], force, timeout); err != nil {
			return err
		}
	}
	return nil
}

func recordSidecarIdentity(sidecar *SidecarSession) error {
	current := CurrentSession{PID: sidecar.PID}
	if err := recordProcessIdentity(&current); err != nil {
		return err
	}
	sidecar.ProcessComm, sidecar.ProcessStart = current.ProcessComm, current.ProcessStart
	return nil
}

func sidecarAlive(sidecar SidecarSession) (bool, error) {
	alive, err := sidecarProcessAliveSession(sidecar.PID)
	if err != nil || !alive {
		return alive, err
	}
	// Like the main process, a live sidecar is identified only by its recorded name and start pair
	// (sessionProcessMatches); a record without it (an older client) is unverifiable, never signalled.
	matches, err := sessionProcessMatches(CurrentSession{PID: sidecar.PID, ProcessComm: sidecar.ProcessComm, ProcessStart: sidecar.ProcessStart})
	if err != nil {
		return false, fmt.Errorf("sidecar %q: %w", sidecar.Name, err)
	}
	return matches, nil
}

func stopSidecar(sidecar SidecarSession, force bool, timeout time.Duration) error {
	alive, err := sidecarAlive(sidecar)
	if err != nil {
		return err
	}
	if !alive {
		return nil
	}
	if err := sidecarSignalGroupSession(sidecar.PID, syscall.SIGTERM); err != nil {
		return err
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		alive, err := sidecarAlive(sidecar)
		if err != nil {
			return err
		}
		if !alive {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !force {
		return fmt.Errorf("timeout waiting for %s sidecar pid %d to stop", sidecar.Name, sidecar.PID)
	}
	alive, err = sidecarAlive(sidecar)
	if err != nil {
		return err
	}
	if !alive {
		return nil
	}
	if err := sidecarSignalGroupSession(sidecar.PID, syscall.SIGKILL); err != nil {
		return err
	}
	return nil
}

func safeSidecarName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = regexp.MustCompile(`[^a-z0-9._-]+`).ReplaceAllString(value, "-")
	value = strings.Trim(value, "-.")
	if value == "" {
		return "sidecar"
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func stopProcessSession(cacheDir string, current CurrentSession, force bool, timeout time.Duration, clear func() error) (CurrentSession, string, error) {
	if err := signalProcessGroupSession(current.PID, syscall.SIGTERM); err != nil {
		return CurrentSession{}, "", err
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		alive, _, err := SessionAlive(current)
		if err != nil {
			return CurrentSession{}, "", err
		}
		if !alive {
			if err := stopSidecars(current.Sidecars, force, timeout); err != nil {
				return CurrentSession{}, "", err
			}
			if err := restoreSystemDNSHandoff(current); err != nil {
				return CurrentSession{}, "", err
			}
			if err := clear(); err != nil {
				return CurrentSession{}, "", err
			}
			return current, "stopped", nil
		}
		time.Sleep(200 * time.Millisecond)
	}

	if !force {
		return current, "timeout", fmt.Errorf("timeout waiting for sing-box pid %d to stop", current.PID)
	}

	if err := signalProcessGroupSession(current.PID, syscall.SIGKILL); err != nil {
		return CurrentSession{}, "", err
	}
	for i := 0; i < 10; i++ {
		alive, _, err := SessionAlive(current)
		if err != nil {
			return CurrentSession{}, "", err
		}
		if !alive {
			if err := stopSidecars(current.Sidecars, true, 1500*time.Millisecond); err != nil {
				return CurrentSession{}, "", err
			}
			if err := restoreSystemDNSHandoff(current); err != nil {
				return CurrentSession{}, "", err
			}
			if err := clear(); err != nil {
				return CurrentSession{}, "", err
			}
			return current, "killed", nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	return current, "timeout", fmt.Errorf("failed to stop sing-box pid %d", current.PID)
}

// failedStart reports a start that failed after its process was launched and then stopped. The
// session always comes back, so the caller can confirm that the process and its sidecars are gone
// before it starts anything else; a failed stop is joined to the error.
func failedStart(session CurrentSession, stopErr, err error) (CurrentSession, error) {
	if stopErr != nil {
		return session, errors.Join(err, fmt.Errorf("stopping the failed start also failed: %w", stopErr))
	}
	return session, err
}

// ErrNothingStarted marks a Start error that proves nothing of that start is left running: it
// failed before any process was launched, the helper refused the start, or the process failed
// to launch and every sidecar was stopped. Any other Start error, with or without a returned
// session, may have left a process running.
var ErrNothingStarted = errors.New("nothing of the failed start is running")

type notStartedError struct{ err error }

func (e notStartedError) Error() string        { return e.err.Error() }
func (e notStartedError) Unwrap() error        { return e.err }
func (e notStartedError) Is(target error) bool { return target == ErrNothingStarted }

func notStarted(err error) error { return notStartedError{err: err} }

// SessionStopped reports whether a session's main process and every sidecar are gone. Any
// identity or liveness lookup error is returned, never read as gone.
func SessionStopped(current CurrentSession) (bool, error) {
	alive, _, err := SessionAlive(current)
	if err != nil {
		return false, err
	}
	if alive {
		return false, nil
	}
	for _, sidecar := range current.Sidecars {
		alive, err := sidecarAlive(sidecar)
		if err != nil {
			return false, fmt.Errorf("sidecar %s: %w", sidecar.Name, err)
		}
		if alive {
			return false, nil
		}
	}
	return true, nil
}

// StopReturned stops a session that a failed Start returned, through what that start recorded: the
// helper's opaque handle, or the process group only while the recorded process identity still
// matches; then its sidecars. It never reads or writes the current-session record.
func StopReturned(current CurrentSession) error {
	if current.LaunchMode != config.LaunchModeHelper {
		alive, _, err := SessionAlive(current)
		if err != nil {
			return err
		}
		if !alive {
			return stopSidecars(current.Sidecars, true, 1500*time.Millisecond)
		}
	} else if current.Handle == "" {
		return errors.New("the helper returned no handle for this start; it cannot be stopped from here")
	}
	return stopStartedSession(current)
}

// SaveCurrentIfAbsent records the session as current only when no current record exists, so it
// never overwrites another session's record.
func SaveCurrentIfAbsent(cacheDir string, current CurrentSession) error {
	data, err := json.MarshalIndent(current, "", "  ")
	if err != nil {
		return err
	}
	return withCurrentRecordLock(cacheDir, func() error {
		f, err := os.OpenFile(CurrentPath(cacheDir), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return err
		}
		if _, err := f.Write(append(data, '\n')); err != nil {
			_ = f.Close()
			_ = os.Remove(CurrentPath(cacheDir))
			return err
		}
		return f.Close()
	})
}

// StopIfCurrent stops the current session only when its record is the expected session (SameSession:
// ID, PID, helper handle, process start); a record of any other session is left alone and reported.
// The stop acts on the checked record, not on whatever record is current when the signal goes out.
func StopIfCurrent(cacheDir string, expected CurrentSession, launch config.PrivilegedLaunchConfig, force bool, timeout time.Duration) (CurrentSession, string, error) {
	current, err := LoadCurrent(cacheDir)
	if err != nil {
		return CurrentSession{}, "", err
	}
	if !SameSession(current, expected) {
		return CurrentSession{}, "", fmt.Errorf("the current record is session %s (pid %d), not %s (pid %d); left alone", current.ID, current.PID, expected.ID, expected.PID)
	}
	if err := boundLaunchdLabel(current, launch); err != nil {
		return CurrentSession{}, "", err
	}
	// Stop exactly the checked session, never a record read again later, and drop the record only
	// while it still is that session: a start that replaced it meanwhile keeps its record.
	return stopResolved(cacheDir, current, force, timeout, func() error { return clearCurrentIfSame(cacheDir, current) })
}

// afterCurrentRecordCompare runs between the compare and the remove of clearCurrentIfSame; tests
// use it to write another record at exactly that point.
var afterCurrentRecordCompare = func() {}

// clearCurrentIfSame removes the current record only while it is the given session. The read, the
// compare and the remove run under the record lock, so no writer can come in between.
func clearCurrentIfSame(cacheDir string, expected CurrentSession) error {
	return withCurrentRecordLock(cacheDir, func() error {
		current, err := LoadCurrent(cacheDir)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if !SameSession(current, expected) {
			return nil
		}
		afterCurrentRecordCompare()
		return removeCurrentRecord(cacheDir)
	})
}

func stopStartedSession(current CurrentSession) error {
	restoreErr := restoreSystemDNSHandoff(current)
	var stopErr error
	switch current.LaunchMode {
	case config.LaunchModeHelper:
		if err := killHelperSession(current); err != nil {
			stopErr = err
		}
	case config.LaunchModeLaunchd:
		if err := stopLaunchdSessionFunc(current, 1500*time.Millisecond); err != nil {
			stopErr = err
		}
	default:
		if err := signalProcessGroupSession(current.PID, syscall.SIGKILL); err != nil {
			stopErr = err
		}
	}
	if err := stopSidecars(current.Sidecars, true, 1500*time.Millisecond); err != nil && stopErr == nil {
		stopErr = err
	}
	if stopErr != nil {
		return stopErr
	}
	if restoreErr != nil {
		return restoreErr
	}
	return nil
}

// recordStartOptions copies into a session record the start options a later
// restart needs and that the record does not otherwise keep.
func recordStartOptions(session *CurrentSession, options StartOptions) {
	session.StartOptionsRecorded = true
	session.TunAddresses = append([]string(nil), options.TunAddresses...)
	session.OverlayDNSActive = options.OverlayDNSActive
	session.OverlayDNSDomains = append([]string(nil), options.OverlayDNSDomains...)
	session.SystemDNSServers = append([]string(nil), options.SystemDNSServers...)
}

// ResolveLaunchMode returns the launch mode a start would use (auto resolves
// to helper when the shared vpn-core helper is installed).
func ResolveLaunchMode(renderMode string, launch config.PrivilegedLaunchConfig) (string, error) {
	return resolveLaunchMode(renderMode, launch)
}

func resolveLaunchMode(renderMode string, launch config.PrivilegedLaunchConfig) (string, error) {
	if renderMode != config.RenderModeTun {
		return "", fmt.Errorf("unsupported render mode %q", renderMode)
	}

	mode := strings.TrimSpace(launch.Mode)
	if mode == "" {
		mode = config.LaunchModeAuto
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
			return "", fmt.Errorf("launch.mode=launchd is only supported on macOS")
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

func writeLogHeader(file interface{ Write([]byte) (int, error) }, current CurrentSession, profile model.Profile) {
	_, _ = fmt.Fprintf(file, "=== vless-tun session start ===\n")
	_, _ = fmt.Fprintf(file, "session_id: %s\n", current.ID)
	_, _ = fmt.Fprintf(file, "started_at: %s\n", current.StartedAt.Format(time.RFC3339))
	_, _ = fmt.Fprintf(file, "profile: %s | %s | %s\n", profile.ID, profile.DisplayName(), profile.Endpoint())
	if current.ResolvedServer != "" && current.ResolvedAlias != "" {
		_, _ = fmt.Fprintf(file, "resolved: %s/%s -> %s (%s) via %s\n", current.ResolvedServer, current.ResolvedAlias, current.ResolvedProfileName, current.ResolvedProfileID, current.ResolutionReason)
		if current.SnapshotFetchedAt != nil {
			_, _ = fmt.Fprintf(file, "snapshot_fetched_at: %s\n", current.SnapshotFetchedAt.Format(time.RFC3339))
		}
	}
	_, _ = fmt.Fprintf(file, "engine: %s\n", firstNonEmpty(current.Engine, config.EngineSingbox))
	_, _ = fmt.Fprintf(file, "config_path: %s\n", current.ConfigPath)
	if current.LogMaxLines > 0 {
		_, _ = fmt.Fprintf(file, "log_max_lines: %d\n", current.LogMaxLines)
	}
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
	_, _ = fmt.Fprintf(file, "--- tunnel frontend output follows ---\n")
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

var errSessionLivenessUnknown = errors.New("session liveness is unknown")

func waitForStableStart(current CurrentSession, timeout time.Duration) (int, error) {
	deadline := time.Now().Add(timeout)
	for {
		alive, pid, err := SessionAlive(current)
		if err != nil {
			return current.PID, fmt.Errorf("%w: %w", errSessionLivenessUnknown, err)
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
	appendSessionLog(current, logLevelInfo, "startup_readiness_begin hosts=%s timeout=%s method=%s\n", strings.Join(hosts, ","), timeout, current.DNSHandoffMode)

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
				appendSessionLog(current, logLevelInfo, "startup_readiness_ok hosts=%s checks=%d\n", strings.Join(hosts, ","), consecutiveSuccesses)
				return nil
			}
		} else {
			consecutiveSuccesses = 0
			lastIssue = issue
			if issue != "" && issue != lastLoggedIssue {
				appendSessionLog(current, logLevelDebug, "startup_readiness_pending reason=%s\n", issue)
				lastLoggedIssue = issue
			}
		}

		if time.Now().After(deadline) {
			appendSessionLog(current, logLevelWarn, "startup_readiness_failed reason=%s\n", lastIssue)
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
			strings.HasPrefix(line, "engine:"),
			strings.HasPrefix(line, "sidecar:"),
			strings.HasPrefix(line, "config_path:"),
			strings.HasPrefix(line, "log_max_lines:"),
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
