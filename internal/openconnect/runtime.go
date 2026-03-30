package openconnect

import (
	"bufio"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"
)

const (
	authTimeout        = 5 * time.Minute
	openconnectTimeout = 20 * time.Second
	postConnectTimeout = 20 * time.Second
	probeWarmupTimeout = 8 * time.Second
)

const (
	ConnectModeFull         = "full"
	ConnectModeSplitInclude = "split-include"
)

const (
	PrivilegedModeAuto   = "auto"
	PrivilegedModeSudo   = "sudo"
	PrivilegedModeDirect = "direct"
	PrivilegedModeHelper = "helper"
)

var (
	execLookPathOpenConnect        = exec.LookPath
	execCommandOpenConnect         = exec.Command
	lookupHostOpenConnect          = net.LookupHost
	systemLookupHostOpenConnect    = lookupHostViaSystemSourcesOpenConnect
	userHomeDirOpenConnect         = os.UserHomeDir
	stdinSupportsPromptOpenConnect = func() bool {
		return term.IsTerminal(int(os.Stdin.Fd()))
	}
	serverCertSHA1OpenConnect = fetchServerCertSHA1
	newSAMLHTTPClient         = func(jar http.CookieJar, checkRedirect func(*http.Request, []*http.Request) error) *http.Client {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		dialer := &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		transport.DialContext = func(ctx context.Context, network string, address string) (net.Conn, error) {
			resolvedAddress, err := resolveOpenConnectDialAddress(address)
			if err != nil {
				return dialer.DialContext(ctx, network, address)
			}
			return dialer.DialContext(ctx, network, resolvedAddress)
		}
		return &http.Client{
			Timeout:       authTimeout,
			Jar:           jar,
			CheckRedirect: checkRedirect,
			Transport:     transport,
		}
	}
)

type Credentials struct {
	Username   string
	Password   string
	TOTPSecret string
}

type ConnectOptions struct {
	Server         string
	Profile        string
	Auth           string
	Mode           string
	PrivilegedMode string
	IncludeRoutes  []string
	VPNDomains     []string
	VPNNameservers []string
	Credentials    Credentials
	ProfilePaths   []string
	CacheDir       string
	ProgressWriter io.Writer
	DryRun         bool
}

type ConnectResult struct {
	SessionID      string
	Server         string
	Mode           string
	PrivilegedMode string
	PID            int
	Interface      string
	Script         string
	Command        []string
	ResolvedFrom   string
	LogPath        string
}

type RuntimeStatus struct {
	PID       int
	Interface string
	Uptime    string
}

type supplementalResolverSpec struct {
	Label                string
	Nameservers          []string
	Domains              []string
	SearchDomain         string
	SearchCleanupDomains []string
	ProbeHosts           []string
	RouteOverrides       []string
	ManageSearchResolver bool
	UseScutilState       bool
	ServiceID            string
}

type authResult struct {
	Cookie      string `json:"cookie"`
	Host        string `json:"host"`
	ConnectURL  string `json:"connect_url"`
	Fingerprint string `json:"fingerprint"`
	Resolve     string `json:"resolve"`
}

type authHelperSpec struct {
	Args    []string
	Env     []string
	Cleanup func()
}

type samlAuthReplyVariant struct {
	Name string
	XML  string
}

type samlAuthReplyFollowup struct {
	State   *samlAuthState
	Snippet string
}

func (f *samlAuthReplyFollowup) Error() string {
	return fmt.Sprintf("SAML auth-reply returned follow-up auth-request: %s", f.Snippet)
}

type samlAuthReplyContinue struct {
	State   *samlAuthState
	Snippet string
}

func (c *samlAuthReplyContinue) Error() string {
	return fmt.Sprintf("SAML auth-reply returned continuation auth-request: %s", c.Snippet)
}

type vpnAuthCookie struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Domain string `json:"domain"`
	Path   string `json:"path"`
}

type vpnAuthResult struct {
	Cookie     string          `json:"cookie"`
	URL        string          `json:"url"`
	CookieName string          `json:"cookie_name"`
	Cookies    []vpnAuthCookie `json:"cookies"`
}

type aggregateAuthClientProfile struct {
	Version         string
	DeviceID        string
	ComputerName    string
	DeviceType      string
	PlatformVersion string
	UniqueID        string
	UniqueIDGlobal  string
	MacAddresses    []string
	AuthMethods     []string
}

type nativeCSDConfig struct {
	LibPath        string
	PythonPath     string
	HostURL        string
	FQDN           string
	Group          string
	ResultURL      string
	ServerCertHash string
	AllowUpdates   string
	LangSel        string
	VPNClient      string
}

func Connect(options ConnectOptions) (ConnectResult, error) {
	ocPath, err := execLookPathOpenConnect("openconnect")
	if err != nil {
		return ConnectResult{}, fmt.Errorf("openconnect not found in PATH")
	}

	cacheDir := ResolveCacheDir(options.CacheDir)
	if current, err := LoadCurrent(cacheDir); err == nil {
		alive, _, aliveErr := SessionAlive(current)
		if aliveErr != nil {
			return ConnectResult{}, aliveErr
		}
		if alive {
			return ConnectResult{}, fmt.Errorf("openconnect session %s is already active (pid=%d)", current.ID, current.PID)
		}
		if err := ClearCurrent(cacheDir); err != nil {
			return ConnectResult{}, err
		}
	} else if !os.IsNotExist(err) {
		return ConnectResult{}, err
	}

	server, resolvedFrom, err := resolveConnectServer(options)
	if err != nil {
		return ConnectResult{}, err
	}

	mode := strings.TrimSpace(options.Mode)
	if mode == "" {
		mode = ConnectModeFull
	}
	switch mode {
	case ConnectModeFull, ConnectModeSplitInclude:
	default:
		return ConnectResult{}, fmt.Errorf("unsupported mode %q", mode)
	}

	script, err := resolveScript(mode, options.IncludeRoutes, options.VPNDomains)
	if err != nil {
		return ConnectResult{}, err
	}

	if options.DryRun {
		privilegedMode, _, err := resolvePrivilegedMode(options.PrivilegedMode)
		if err != nil {
			return ConnectResult{}, err
		}
		command := buildOpenConnectCommandPreview(ocPath, server, script, privilegedMode)
		return ConnectResult{
			Server:         server,
			Mode:           mode,
			PrivilegedMode: privilegedMode,
			Script:         script,
			Command:        command,
			ResolvedFrom:   resolvedFrom,
		}, nil
	}

	privilegedMode, helperCfg, err := resolvePrivilegedMode(options.PrivilegedMode)
	if err != nil {
		return ConnectResult{}, err
	}
	if privilegedMode == PrivilegedModeSudo {
		if err := ensureSudoCredentials(); err != nil {
			return ConnectResult{}, fmt.Errorf("sudo authentication: %w", err)
		}
	}

	if err := os.MkdirAll(SessionsDir(cacheDir), 0o755); err != nil {
		return ConnectResult{}, err
	}
	if err := os.MkdirAll(RuntimeDir(cacheDir), 0o755); err != nil {
		return ConnectResult{}, err
	}

	now := time.Now().UTC()
	sessionID := now.Format(sessionTimestampFormat)
	logPath := filepath.Join(SessionsDir(cacheDir), logFilePrefix+sessionID+".log")
	metadataPath := filepath.Join(SessionsDir(cacheDir), metadataFilePrefix+sessionID+".json")
	scriptExec := script
	scriptWrapperErr := error(nil)
	if wrappedScript, err := prepareScriptDiagnosticsWrapper(cacheDir, sessionID, logPath, script, supplementalResolverSpecForConnect(mode, server, options)); err != nil {
		scriptWrapperErr = err
	} else if strings.TrimSpace(wrappedScript) != "" {
		scriptExec = wrappedScript
	}
	command := buildOpenConnectCommandPreview(ocPath, server, scriptExec, privilegedMode)

	current := CurrentSession{
		ID:             sessionID,
		StartedAt:      now,
		LogPath:        logPath,
		MetadataPath:   metadataPath,
		Server:         server,
		ResolvedFrom:   resolvedFrom,
		Mode:           mode,
		PrivilegedMode: privilegedMode,
		Script:         script,
		Command:        command,
		Profile:        options.Profile,
		IncludeRoutes:  append([]string(nil), options.IncludeRoutes...),
		VPNDomains:     append([]string(nil), options.VPNDomains...),
		VPNNameservers: append([]string(nil), options.VPNNameservers...),
	}
	if privilegedMode == PrivilegedModeHelper {
		current.HelperSocketPath = helperCfg.SocketPath
	}

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return ConnectResult{}, err
	}
	defer logFile.Close()

	writeLogHeader(logFile, current)
	if scriptWrapperErr != nil {
		writeLogf(logFile, "script_wrapper_error: %v", scriptWrapperErr)
	} else if strings.TrimSpace(scriptExec) != "" && scriptExec != script {
		writeLogf(logFile, "script_wrapper: %s", scriptExec)
	}
	if strings.TrimSpace(scriptExec) != "" {
		writeLogf(logFile, "script_exec: %s", scriptExec)
	}
	writeProgressf(options.ProgressWriter, "starting openconnect session %s", current.ID)
	writeProgressf(options.ProgressWriter, "log_file: %s", current.LogPath)
	writeProgressf(options.ProgressWriter, "phase: authenticating")

	if err := SaveMetadata(current); err != nil {
		return ConnectResult{}, err
	}

	auth, err := authenticate(server, options, ocPath, logFile, options.ProgressWriter)
	if err != nil {
		_ = ClearCurrent(cacheDir)
		return ConnectResult{}, formatConnectError(err, logPath)
	}

	writeProgressf(options.ProgressWriter, "phase: connecting to %s", server)
	pid, iface, err := connectWithCookie(auth, ocPath, scriptExec, logFile, privilegedMode, helperCfg)
	if err != nil {
		_ = ClearCurrent(cacheDir)
		return ConnectResult{}, formatConnectError(err, logPath)
	}

	current.PID = pid
	current.Interface = iface

	pid, err = waitForStableStart(current, 1500*time.Millisecond)
	if err != nil {
		_ = interruptOpenConnectPID(current.PID, privilegedMode, current.HelperSocketPath)
		_ = ClearCurrent(cacheDir)
		return ConnectResult{}, formatConnectError(err, logPath)
	}
	if pid > 0 {
		current.PID = pid
	}
	current.Interface = firstNonEmpty(
		findOpenConnectInterfaceFromLog(current.LogPath),
		findTrackedOpenConnectInterface(current.PID),
		findOpenConnectInterface(current.PID),
		current.Interface,
	)
	if connectConvergenceExpectationsForSession(current).required() {
		writeProgressf(options.ProgressWriter, "phase: applying split-include routes and dns")
		if err := waitForPostConnectConvergence(current, postConnectTimeout); err != nil {
			_ = interruptOpenConnectPID(current.PID, privilegedMode, current.HelperSocketPath)
			_ = ClearCurrent(cacheDir)
			return ConnectResult{}, formatConnectError(err, logPath)
		}
	}
	if probeHosts := probeHostsForSession(current); len(probeHosts) > 0 {
		writeProgressf(options.ProgressWriter, "phase: warming hostname routes")
		if err := waitForProbeRouteWarmup(current, probeWarmupTimeout); err != nil {
			writeProgressf(options.ProgressWriter, "warmup: hostname routes still converging")
		}
	}

	if err := SaveMetadata(current); err != nil {
		_ = interruptOpenConnectPID(current.PID, privilegedMode, current.HelperSocketPath)
		_ = ClearCurrent(cacheDir)
		return ConnectResult{}, err
	}
	if err := SaveCurrent(cacheDir, current); err != nil {
		_ = interruptOpenConnectPID(current.PID, privilegedMode, current.HelperSocketPath)
		return ConnectResult{}, err
	}
	writeProgressf(options.ProgressWriter, "phase: connected pid=%d interface=%s", current.PID, firstNonEmpty(current.Interface, "unknown"))

	return ConnectResult{
		SessionID:      current.ID,
		Server:         server,
		Mode:           mode,
		PrivilegedMode: privilegedMode,
		PID:            current.PID,
		Interface:      current.Interface,
		Script:         script,
		Command:        command,
		ResolvedFrom:   resolvedFrom,
		LogPath:        logPath,
	}, nil
}

func Disconnect(cacheDir string, timeout time.Duration) (CurrentSession, string, error) {
	return Stop(ResolveCacheDir(cacheDir), timeout)
}

func CurrentRuntime() (*RuntimeStatus, error) {
	pid, err := findOpenConnectPID()
	if err != nil {
		return nil, nil
	}
	return &RuntimeStatus{
		PID:       pid,
		Interface: firstNonEmpty(findTrackedOpenConnectInterface(pid), findOpenConnectInterface(pid)),
		Uptime:    getProcessUptime(pid),
	}, nil
}

func CurrentRoutes() ([]string, error) {
	runtime, err := CurrentRuntime()
	if err != nil {
		return nil, err
	}
	if runtime == nil || runtime.Interface == "" {
		return []string{}, nil
	}
	return getRoutesForInterface(runtime.Interface), nil
}

func resolveConnectServer(options ConnectOptions) (server string, resolvedFrom string, err error) {
	if strings.TrimSpace(options.Server) != "" {
		return strings.TrimSpace(options.Server), "flag", nil
	}
	if strings.TrimSpace(options.Profile) == "" {
		return "", "", fmt.Errorf("either --server or --profile is required")
	}
	host, err := ResolveServerFromProfiles(options.ProfilePaths, options.Profile)
	if err != nil {
		return "", "", err
	}
	return host.Address, host.Name, nil
}

func resolveScript(mode string, includeRoutes []string, vpnDomains []string) (string, error) {
	switch mode {
	case ConnectModeFull:
		script := findVPNCScript()
		if script == "" {
			return "", fmt.Errorf("vpnc-script not found")
		}
		return script, nil
	case ConnectModeSplitInclude:
		vpnSlicePath, err := execLookPathOpenConnect("vpn-slice")
		if err != nil {
			return "", fmt.Errorf("vpn-slice not found in PATH")
		}
		args := []string{vpnSlicePath}
		if len(vpnDomains) > 0 {
			args = append(args, "--domains-vpn-dns", strings.Join(vpnDomains, ","))
		}
		args = append(args, includeRoutes...)
		return strings.Join(args, " "), nil
	default:
		return "", fmt.Errorf("unsupported mode %q", mode)
	}
}

func prepareScriptDiagnosticsWrapper(cacheDir, sessionID, logPath, baseScript string, supplemental *supplementalResolverSpec) (string, error) {
	baseScript = strings.TrimSpace(baseScript)
	if baseScript == "" {
		return "", nil
	}
	helperDir := filepath.Join(SessionsDir(cacheDir), logFilePrefix+sessionID+"-helpers")
	if err := os.MkdirAll(helperDir, 0o755); err != nil {
		return "", fmt.Errorf("create script helper dir: %w", err)
	}
	pyCompatDir, err := prepareVPNslicePythonCompat(helperDir, baseScript)
	if err != nil {
		return "", err
	}
	if supplemental != nil {
		cloned := *supplemental
		cloned.ServiceID = supplementalResolverServiceID(sessionID, supplemental.Label)
		cloned.SearchDomain = firstNonEmpty(cloned.SearchDomain, firstNonEmpty(cloned.Domains...))
		supplemental = &cloned
	}
	routeOverrides := []string(nil)
	if supplemental != nil {
		routeOverrides = append(routeOverrides, supplemental.RouteOverrides...)
	}
	wrapperPath := filepath.Join(helperDir, "script-wrapper.sh")
	if err := writeExecutableFile(wrapperPath, scriptDiagnosticsWrapperScript(logPath, baseScript, supplemental, pyCompatDir, routeOverrides)); err != nil {
		return "", err
	}
	return wrapperPath, nil
}

func prepareVPNslicePythonCompat(helperDir string, baseScript string) (string, error) {
	if !strings.Contains(baseScript, "vpn-slice") {
		return "", nil
	}
	pyCompatDir := filepath.Join(helperDir, "pycompat")
	distutilsDir := filepath.Join(pyCompatDir, "distutils")
	if err := os.MkdirAll(distutilsDir, 0o755); err != nil {
		return "", fmt.Errorf("create vpn-slice pycompat dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(distutilsDir, "__init__.py"), []byte(vpnSliceDistutilsCompatInit), 0o644); err != nil {
		return "", fmt.Errorf("write vpn-slice pycompat __init__: %w", err)
	}
	if err := os.WriteFile(filepath.Join(distutilsDir, "version.py"), []byte(vpnSliceDistutilsCompatVersion), 0o644); err != nil {
		return "", fmt.Errorf("write vpn-slice pycompat version: %w", err)
	}
	return pyCompatDir, nil
}

func supplementalResolverSpecForServer(server string) *supplementalResolverSpec {
	server = strings.ToLower(strings.TrimSpace(server))
	if !strings.Contains(server, ".corp.example") || !strings.Contains(server, "/outside") {
		return nil
	}
	return &supplementalResolverSpec{
		Label:        "corp-outside",
		SearchDomain: "region.corp.example",
		Nameservers: []string{
			"10.23.16.4",
			"10.23.0.23",
		},
		Domains: []string{
			"inside.corp.example",
			"region.corp.example",
			"edge.region.corp.example",
			"corp.example",
			"corp-it.example",
			"corp-it.internal",
			"erp.example",
			"short.example",
			"corp-sec.example",
			"branch.example",
			"branch.corp.example",
			"lab.corp.example",
			"intra.corp.example",
			"docs.example",
			"analytics.example",
			"tabs.example",
			"bank.example",
			"tickets.example",
			"retail.example",
			"workspace.example",
			"media.example",
			"auth.example",
			"fleet.example",
			"security.example",
		},
		SearchCleanupDomains: []string{
			"inside.corp.example",
			"region.corp.example",
			"edge.region.corp.example",
			"corp.example",
			"corp-it.example",
			"corp-it.internal",
			"erp.example",
			"short.example",
			"corp-sec.example",
			"branch.example",
			"branch.corp.example",
			"lab.corp.example",
			"intra.corp.example",
			"docs.example",
			"analytics.example",
			"tabs.example",
			"bank.example",
			"tickets.example",
			"retail.example",
			"workspace.example",
			"media.example",
			"auth.example",
			"fleet.example",
			"security.example",
		},
		ProbeHosts: []string{
			"gitlab.services.corp.example",
		},
		ManageSearchResolver: true,
	}
}

func supplementalResolverSpecForConnect(mode string, server string, options ConnectOptions) *supplementalResolverSpec {
	switch mode {
	case ConnectModeFull:
		return supplementalResolverSpecForServer(server)
	case ConnectModeSplitInclude:
		serverSpec := supplementalResolverSpecForServer(server)
		if len(options.VPNDomains) == 0 && serverSpec != nil {
			options.VPNDomains = append([]string(nil), serverSpec.Domains...)
		}
		if len(options.VPNNameservers) == 0 && serverSpec != nil {
			options.VPNNameservers = append([]string(nil), serverSpec.Nameservers...)
		}
		if len(options.VPNDomains) == 0 || len(options.VPNNameservers) == 0 {
			return nil
		}
		routeOverrides := make([]string, 0, len(options.VPNNameservers)+len(options.IncludeRoutes))
		for _, nameserver := range options.VPNNameservers {
			nameserver = strings.TrimSpace(nameserver)
			if net.ParseIP(nameserver) == nil {
				continue
			}
			routeOverrides = append(routeOverrides, nameserver+"/32")
		}
		routeOverrides = append(routeOverrides, options.IncludeRoutes...)
		domains := append([]string(nil), options.VPNDomains...)
		cleanupDomains := append([]string(nil), options.VPNDomains...)
		searchDomain := firstNonEmpty(firstNonEmpty(options.VPNDomains...), "")
		if serverSpec != nil {
			domains = append(domains, serverSpec.Domains...)
			cleanupDomains = append(cleanupDomains, serverSpec.SearchCleanupDomains...)
			searchDomain = firstNonEmpty(serverSpec.SearchDomain, firstNonEmpty(options.VPNDomains...))
		}
		return &supplementalResolverSpec{
			Label:                "split-include",
			Nameservers:          append([]string(nil), options.VPNNameservers...),
			Domains:              uniqueStrings(domains),
			SearchDomain:         searchDomain,
			SearchCleanupDomains: uniqueStrings(cleanupDomains),
			ProbeHosts: []string{
				"gitlab.services.corp.example",
			},
			RouteOverrides:       uniqueStrings(routeOverrides),
			ManageSearchResolver: true,
		}
	default:
		return nil
	}
}

func shellQuote(value string) string {
	if value == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

func shellLines(values []string) string {
	filtered := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		filtered = append(filtered, value)
	}
	return strings.Join(filtered, "\n")
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	return result
}

func supplementalResolverServiceID(sessionID, label string) string {
	sum := sha1.Sum([]byte("openconnect-tun:" + strings.TrimSpace(sessionID) + ":" + strings.TrimSpace(label)))
	token := strings.ToUpper(hex.EncodeToString(sum[:16]))
	return fmt.Sprintf("%s-%s-%s-%s-%s", token[0:8], token[8:12], token[12:16], token[16:20], token[20:32])
}

func scriptDiagnosticsWrapperScript(logPath, baseScript string, supplemental *supplementalResolverSpec, pyCompatDir string, routeOverrides []string) string {
	shimLabel := ""
	shimNameservers := ""
	shimDomains := ""
	shimSearchDomain := ""
	searchCleanupDomains := ""
	probeHosts := ""
	manageSearchResolver := "0"
	useScutilState := "0"
	scutilServiceID := ""
	if supplemental != nil {
		shimLabel = supplemental.Label
		shimNameservers = shellLines(supplemental.Nameservers)
		shimDomains = shellLines(supplemental.Domains)
		shimSearchDomain = supplemental.SearchDomain
		searchCleanupDomains = shellLines(supplemental.SearchCleanupDomains)
		probeHosts = shellLines(supplemental.ProbeHosts)
		if supplemental.ManageSearchResolver {
			manageSearchResolver = "1"
		}
		if supplemental.UseScutilState {
			useScutilState = "1"
		}
		scutilServiceID = supplemental.ServiceID
	}
	routeOverrideLines := shellLines(routeOverrides)
	return fmt.Sprintf(`#!/bin/sh
set +e

helper_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
search_backup="$helper_dir/search.tailscale.backup"
default_gateway_file="$helper_dir/default-gateway"
default_interface_file="$helper_dir/default-interface"
log_file=%s
base_command=%s
shim_label=%s
shim_nameservers=%s
shim_domains=%s
shim_search_domain=%s
search_cleanup_domains=%s
probe_hosts=%s
manage_search_resolver=%s
use_scutil_state=%s
scutil_service_id=%s
vpn_slice_pycompat=%s
route_overrides=%s
diag_probes_enabled="${OPENCONNECT_TUN_DIAG_PROBES:-0}"

backup_search_resolver() {
  [ "$manage_search_resolver" = "1" ] || return 0
  [ -f /etc/resolver/search.tailscale ] || return 0
  [ -f "$search_backup" ] || cp /etc/resolver/search.tailscale "$search_backup"
}

restore_search_resolver() {
  [ "$manage_search_resolver" = "1" ] || return 0
  [ -f "$search_backup" ] || return 0
  mkdir -p /etc/resolver || return 0
  cp "$search_backup" /etc/resolver/search.tailscale
  printf 'vpnc_wrapper_dns_shim: restored search.tailscale\n' >> "$log_file" 2>&1
}

sanitize_search_resolver() {
  [ "$manage_search_resolver" = "1" ] || return 0
  [ -f /etc/resolver/search.tailscale ] || return 0
  [ -n "$search_cleanup_domains" ] || return 0
  cleanup_compact=$(printf '%%s\n' "$search_cleanup_domains" | tr '\n' ' ')
  [ -n "$cleanup_compact" ] || return 0
  tmp_path=$(mktemp "/tmp/openconnect-tun-search.XXXXXX") || return 0
  if while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      search\ *)
        set -- $line
        shift
        out="search"
        for domain in "$@"; do
          case " $cleanup_compact " in
            *" $domain "*) ;;
            *) out="$out $domain" ;;
          esac
        done
        printf '%%s\n' "$out"
        ;;
      *)
        printf '%%s\n' "$line"
        ;;
    esac
  done < /etc/resolver/search.tailscale > "$tmp_path"; then
    mv "$tmp_path" /etc/resolver/search.tailscale
    printf 'vpnc_wrapper_dns_shim: sanitized search.tailscale\n' >> "$log_file" 2>&1
  else
    rm -f "$tmp_path"
  fi
}

capture_default_route() {
  gateway=$(/sbin/route -n get default 2>/dev/null | awk '/^[[:space:]]*gateway:/{print $2; exit}')
  iface=$(/sbin/route -n get default 2>/dev/null | awk '/^[[:space:]]*interface:/{print $2; exit}')
  if [ -n "$gateway" ]; then
    printf '%%s\n' "$gateway" > "$default_gateway_file"
  fi
  if [ -n "$iface" ]; then
    printf '%%s\n' "$iface" > "$default_interface_file"
  fi
  if [ -n "$gateway" ] || [ -n "$iface" ]; then
    printf 'vpnc_wrapper_default_route: gateway=%%s interface=%%s\n' "$gateway" "$iface" >> "$log_file" 2>&1
  else
    printf 'vpnc_wrapper_default_route_failed\n' >> "$log_file" 2>&1
  fi
}

load_default_gateway() {
  if [ -f "$default_gateway_file" ]; then
    cat "$default_gateway_file"
    return 0
  fi
  /sbin/route -n get default 2>/dev/null | awk '/^[[:space:]]*gateway:/{print $2; exit}'
}

load_default_interface() {
  if [ -f "$default_interface_file" ]; then
    cat "$default_interface_file"
    return 0
  fi
  /sbin/route -n get default 2>/dev/null | awk '/^[[:space:]]*interface:/{print $2; exit}'
}

pin_vpn_gateway_route() {
  [ -n "${VPNGATEWAY:-}" ] || return 0
  gateway=$(load_default_gateway)
  iface=$(load_default_interface)
  if [ -z "$gateway" ]; then
    printf 'vpnc_wrapper_vpngateway_route_failed: %%s no-default-gateway\n' "$VPNGATEWAY" >> "$log_file" 2>&1
    return 0
  fi
  /sbin/route -n delete -host "$VPNGATEWAY" >/dev/null 2>&1 || true
  if /sbin/route -n add -host "$VPNGATEWAY" "$gateway" >/dev/null 2>&1; then
    printf 'vpnc_wrapper_vpngateway_route: %%s -> %%s (%%s)\n' "$VPNGATEWAY" "$gateway" "$iface" >> "$log_file" 2>&1
  elif /sbin/route -n change -host "$VPNGATEWAY" "$gateway" >/dev/null 2>&1; then
    printf 'vpnc_wrapper_vpngateway_route: %%s -> %%s (%%s)\n' "$VPNGATEWAY" "$gateway" "$iface" >> "$log_file" 2>&1
  else
    printf 'vpnc_wrapper_vpngateway_route_failed: %%s -> %%s (%%s)\n' "$VPNGATEWAY" "$gateway" "$iface" >> "$log_file" 2>&1
  fi
}

remove_scoped_default_route() {
  [ -n "${TUNDEV:-}" ] || return 0
  if /sbin/route -n get -ifscope "$TUNDEV" default >/dev/null 2>&1; then
    if /sbin/route -n delete -ifscope "$TUNDEV" default >/dev/null 2>&1; then
      printf 'vpnc_wrapper_default_route_remove: %%s\n' "$TUNDEV" >> "$log_file" 2>&1
    elif /sbin/route -n delete default -ifscope "$TUNDEV" >/dev/null 2>&1; then
      printf 'vpnc_wrapper_default_route_remove: %%s\n' "$TUNDEV" >> "$log_file" 2>&1
    else
      printf 'vpnc_wrapper_default_route_remove_failed: %%s\n' "$TUNDEV" >> "$log_file" 2>&1
    fi
  fi
}

remove_vpn_gateway_route() {
  [ -n "${VPNGATEWAY:-}" ] || return 0
  if /sbin/route -n delete -host "$VPNGATEWAY" >/dev/null 2>&1; then
    printf 'vpnc_wrapper_vpngateway_route_remove: %%s\n' "$VPNGATEWAY" >> "$log_file" 2>&1
  fi
}

enforce_route_overrides() {
  [ -n "$route_overrides" ] || return 0
  [ -n "${TUNDEV:-}" ] || return 0
  printf 'vpnc_wrapper_route_override: begin %%s\n' "$TUNDEV" >> "$log_file" 2>&1
  printf '%%s\n' "$route_overrides" | while IFS= read -r cidr; do
    [ -n "$cidr" ] || continue
    /sbin/route -n delete -net "$cidr" >/dev/null 2>&1 || true
    if /sbin/route -n add -net "$cidr" -interface "$TUNDEV" >/dev/null 2>&1; then
      printf 'vpnc_wrapper_route_override: %%s -> %%s\n' "$cidr" "$TUNDEV" >> "$log_file" 2>&1
    elif /sbin/route -n change -net "$cidr" -interface "$TUNDEV" >/dev/null 2>&1; then
      printf 'vpnc_wrapper_route_override: %%s -> %%s\n' "$cidr" "$TUNDEV" >> "$log_file" 2>&1
    else
      printf 'vpnc_wrapper_route_override_failed: %%s -> %%s\n' "$cidr" "$TUNDEV" >> "$log_file" 2>&1
    fi
    case "$cidr" in
      */32)
        host=${cidr%%/*}
        /sbin/route -n delete -host "$host" >/dev/null 2>&1 || true
        if /sbin/route -n add -host "$host" -interface "$TUNDEV" >/dev/null 2>&1; then
          printf 'vpnc_wrapper_route_override_host: %%s -> %%s\n' "$host" "$TUNDEV" >> "$log_file" 2>&1
        elif /sbin/route -n change -host "$host" -interface "$TUNDEV" >/dev/null 2>&1; then
          printf 'vpnc_wrapper_route_override_host: %%s -> %%s\n' "$host" "$TUNDEV" >> "$log_file" 2>&1
        else
          printf 'vpnc_wrapper_route_override_host_failed: %%s -> %%s\n' "$host" "$TUNDEV" >> "$log_file" 2>&1
        fi
        ;;
    esac
  done
}

filter_probe_host_addresses() {
  awk '
    {
      value=$1
      if (value ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
        print value
        next
      }
      if (value ~ /:/ && value ~ /^[0-9A-Fa-f:]+$/) {
        print value
      }
    }
  ' | awk '!seen[$0]++'
}

resolve_probe_host_addresses() {
  host=$1
  addresses=$(/usr/bin/perl -e 'alarm shift @ARGV; exec @ARGV' 4 dscacheutil -q host -a name "$host" 2>/dev/null | awk '/^ip_address:/ {print $2}' | filter_probe_host_addresses)
  if [ -z "$addresses" ] && command -v dig >/dev/null 2>&1 && [ -n "$shim_nameservers" ]; then
    addresses=$(printf '%%s\n' "$shim_nameservers" | while IFS= read -r ns; do
      [ -n "$ns" ] || continue
      dig +time=2 +tries=1 +short @"$ns" "$host" 2>/dev/null || true
    done | filter_probe_host_addresses)
  fi
  printf '%%s\n' "$addresses"
}

resolve_probe_host_addresses_vpn_dns() {
  host=$1
  [ -n "$shim_nameservers" ] || return 0
  command -v dig >/dev/null 2>&1 || return 0
  printf '%%s\n' "$shim_nameservers" | while IFS= read -r ns; do
    [ -n "$ns" ] || continue
    dig +time=1 +tries=1 +short @"$ns" "$host" 2>/dev/null || true
  done | filter_probe_host_addresses
}

resolve_probe_host_addresses_for_apply() {
  host=$1
  addresses=$(resolve_probe_host_addresses_vpn_dns "$host")
  if [ -z "$addresses" ]; then
    addresses=$(/usr/bin/perl -e 'alarm shift @ARGV; exec @ARGV' 2 dscacheutil -q host -a name "$host" 2>/dev/null | awk '/^ip_address:/ {print $2}' | filter_probe_host_addresses)
  fi
  printf '%%s\n' "$addresses"
}

resolve_probe_host_addresses_with_retry() {
  host=$1
  action=$2
  attempts=${3:-8}
  while [ "$attempts" -gt 0 ]; do
    case "$action" in
      apply)
        addresses=$(resolve_probe_host_addresses_for_apply "$host")
        ;;
      *)
        addresses=$(resolve_probe_host_addresses "$host")
        ;;
    esac
    if [ -n "$addresses" ]; then
      printf '%%s\n' "$addresses"
      return 0
    fi
    attempts=$((attempts - 1))
    if [ "$attempts" -le 0 ]; then
      break
    fi
    printf 'vpnc_wrapper_probe_route_sync_retry: %%s %%s remaining=%%s\n' "$action" "$host" "$attempts" >> "$log_file" 2>&1
    sleep 1
  done
  return 0
}

sync_probe_host_routes() {
  action=$1
  [ -n "$probe_hosts" ] || return 0
  [ -n "${TUNDEV:-}" ] || return 0
  printf '%%s\n' "$probe_hosts" | while IFS= read -r host; do
    [ -n "$host" ] || continue
    printf 'vpnc_wrapper_probe_route_sync_begin: %%s %%s %%s\n' "$action" "$host" "$TUNDEV" >> "$log_file" 2>&1
    case "$action" in
      apply)
        addresses=$(resolve_probe_host_addresses_with_retry "$host" "$action" 6)
        ;;
      *)
        addresses=$(resolve_probe_host_addresses "$host")
        ;;
    esac
    if [ -z "$addresses" ]; then
      printf 'vpnc_wrapper_probe_route_sync_resolve_failed: %%s %%s\n' "$action" "$host" >> "$log_file" 2>&1
      printf 'vpnc_wrapper_probe_route_sync_end: %%s %%s %%s\n' "$action" "$host" "$TUNDEV" >> "$log_file" 2>&1
      continue
    fi
    printf '%%s\n' "$addresses" | while IFS= read -r addr; do
      [ -n "$addr" ] || continue
      /sbin/route -n delete -host "$addr" >/dev/null 2>&1 || true
      case "$action" in
        apply)
          if /sbin/route -n add -host "$addr" -interface "$TUNDEV" >/dev/null 2>&1; then
            printf 'vpnc_wrapper_probe_route_sync: %%s %%s %%s -> %%s\n' "$action" "$host" "$addr" "$TUNDEV" >> "$log_file" 2>&1
          elif /sbin/route -n change -host "$addr" -interface "$TUNDEV" >/dev/null 2>&1; then
            printf 'vpnc_wrapper_probe_route_sync: %%s %%s %%s -> %%s\n' "$action" "$host" "$addr" "$TUNDEV" >> "$log_file" 2>&1
          else
            printf 'vpnc_wrapper_probe_route_sync_failed: %%s %%s %%s -> %%s\n' "$action" "$host" "$addr" "$TUNDEV" >> "$log_file" 2>&1
          fi
          ;;
        remove)
          printf 'vpnc_wrapper_probe_route_sync: %%s %%s %%s\n' "$action" "$host" "$addr" >> "$log_file" 2>&1
          ;;
      esac
    done
    printf 'vpnc_wrapper_probe_route_sync_end: %%s %%s %%s\n' "$action" "$host" "$TUNDEV" >> "$log_file" 2>&1
  done
}

launch_probe_host_route_warmup() {
  [ -n "$probe_hosts" ] || return 0
  [ -n "${TUNDEV:-}" ] || return 0
  if command -v nohup >/dev/null 2>&1; then
    env TUNDEV="$TUNDEV" VPNGATEWAY="${VPNGATEWAY:-}" nohup "$0" --probe-sync-apply >/dev/null 2>&1 &
  else
    env TUNDEV="$TUNDEV" VPNGATEWAY="${VPNGATEWAY:-}" "$0" --probe-sync-apply >/dev/null 2>&1 &
  fi
  warmup_pid=$!
  if [ -n "$warmup_pid" ]; then
    printf 'vpnc_wrapper_probe_route_sync_async: apply %%s pid=%%s\n' "$TUNDEV" "$warmup_pid" >> "$log_file" 2>&1
  else
    printf 'vpnc_wrapper_probe_route_sync_async_failed: apply %%s\n' "$TUNDEV" >> "$log_file" 2>&1
    sync_probe_host_routes apply
  fi
}

apply_dns_shim() {
  [ "$use_scutil_state" = "1" ] && return 0
  [ -n "$shim_label" ] || return 0
  mkdir -p /etc/resolver || return 0
  backup_search_resolver
  printf 'vpnc_wrapper_dns_shim: apply %%s\n' "$shim_label" >> "$log_file" 2>&1
  printf '%%s\n' "$shim_domains" | while IFS= read -r domain; do
    [ -n "$domain" ] || continue
    resolver_path="/etc/resolver/$domain"
    tmp_path=$(mktemp "/tmp/openconnect-tun-resolver.XXXXXX") || exit 1
    {
      printf '# Added by openconnect-tun DNS shim (%%s)\n' "$shim_label"
      printf 'nameserver %%s\n' $shim_nameservers
    } > "$tmp_path"
    mv "$tmp_path" "$resolver_path"
  done
  restore_search_resolver
  sanitize_search_resolver
}

apply_scutil_state() {
  [ "$use_scutil_state" = "1" ] || return 0
  [ -n "$scutil_service_id" ] || return 0
  [ -n "${TUNDEV:-}" ] || return 0
  [ -n "$shim_nameservers" ] || return 0
  domain_name=$shim_search_domain
  [ -n "$domain_name" ] || domain_name=$(printf '%%s\n' "$shim_domains" | sed -n '1p')
  [ -n "$domain_name" ] || return 0
  tunnel_ip=$(ifconfig "$TUNDEV" 2>/dev/null | awk '/inet / {print $2; exit}')
  cmd_file=$(mktemp "/tmp/openconnect-tun-scutil.XXXXXX") || return 0
  {
    echo "d.init"
    printf 'd.add ConfirmedServiceID %%s\n' "$scutil_service_id"
    printf 'd.add DomainName %%s\n' "$domain_name"
    printf 'd.add InterfaceName %%s\n' "$TUNDEV"
    printf 'd.add SearchDomains * %%s\n' "$domain_name"
    printf 'd.add ServerAddresses *'
    printf ' %%s' $shim_nameservers
    printf '\n'
    printf 'd.add SupplementalMatchDomains *'
    printf ' %%s' $shim_domains
    printf '\n'
    printf 'set State:/Network/Service/%%s/DNS\n' "$scutil_service_id"
    if [ -n "$tunnel_ip" ]; then
      echo "d.init"
      printf 'd.add Addresses * %%s\n' "$tunnel_ip"
      printf 'd.add InterfaceName %%s\n' "$TUNDEV"
      printf 'd.add Router %%s\n' "$tunnel_ip"
      if [ -n "${VPNGATEWAY:-}" ]; then
        printf 'd.add ServerAddress %%s\n' "$VPNGATEWAY"
      fi
      printf 'set State:/Network/Service/%%s/IPv4\n' "$scutil_service_id"
    fi
  } > "$cmd_file"
  if scutil < "$cmd_file" >> "$log_file" 2>&1; then
    printf 'vpnc_wrapper_scutil_state: apply %%s %%s\n' "$shim_label" "$scutil_service_id" >> "$log_file" 2>&1
  else
    printf 'vpnc_wrapper_scutil_state_failed: apply %%s %%s\n' "$shim_label" "$scutil_service_id" >> "$log_file" 2>&1
  fi
  rm -f "$cmd_file"
}

remove_scutil_state() {
  [ "$use_scutil_state" = "1" ] || return 0
  [ -n "$scutil_service_id" ] || return 0
  cmd_file=$(mktemp "/tmp/openconnect-tun-scutil.XXXXXX") || return 0
  {
    printf 'remove State:/Network/Service/%%s/DNS\n' "$scutil_service_id"
    printf 'remove State:/Network/Service/%%s/IPv4\n' "$scutil_service_id"
  } > "$cmd_file"
  if scutil < "$cmd_file" >> "$log_file" 2>&1; then
    printf 'vpnc_wrapper_scutil_state: remove %%s %%s\n' "$shim_label" "$scutil_service_id" >> "$log_file" 2>&1
  else
    printf 'vpnc_wrapper_scutil_state_failed: remove %%s %%s\n' "$shim_label" "$scutil_service_id" >> "$log_file" 2>&1
  fi
  rm -f "$cmd_file"
}

remove_dns_shim() {
  [ "$use_scutil_state" = "1" ] && return 0
  [ -n "$shim_label" ] || return 0
  backup_search_resolver
  printf 'vpnc_wrapper_dns_shim: remove %%s\n' "$shim_label" >> "$log_file" 2>&1
  printf '%%s\n' "$shim_domains" | while IFS= read -r domain; do
    [ -n "$domain" ] || continue
    resolver_path="/etc/resolver/$domain"
    [ -f "$resolver_path" ] || continue
    if head -n 1 "$resolver_path" 2>/dev/null | grep -Fq '# Added by openconnect-tun DNS shim'; then
      rm -f "$resolver_path"
    fi
  done
  restore_search_resolver
  sanitize_search_resolver
}

clear_split_include_resolvers() {
  [ "$use_scutil_state" = "1" ] || return 0
  [ -n "$shim_domains" ] || return 0
  mkdir -p /etc/resolver || return 0
  printf 'vpnc_wrapper_dns_shim: clear split-include resolvers\n' >> "$log_file" 2>&1
  printf '%%s\n' "$shim_domains" | while IFS= read -r domain; do
    [ -n "$domain" ] || continue
    rm -f "/etc/resolver/$domain"
  done
  sanitize_search_resolver
}

log_snapshot() {
  label=$1
  {
    printf 'vpnc_wrapper_snapshot: %%s\n' "$label"
    printf 'vpnc_wrapper_scutil_dns_begin\n'
    scutil --dns 2>&1 || true
    printf 'vpnc_wrapper_scutil_dns_end\n'
    if [ -n "$scutil_service_id" ]; then
      printf 'vpnc_wrapper_scutil_state_begin\n'
      scutil <<EOF 2>&1 || true
show State:/Network/Service/$scutil_service_id/DNS
show State:/Network/Service/$scutil_service_id/IPv4
EOF
      printf 'vpnc_wrapper_scutil_state_end\n'
    fi
    printf 'vpnc_wrapper_routes_begin\n'
    netstat -rn -f inet 2>&1 || true
    printf 'vpnc_wrapper_routes_end\n'
    printf 'vpnc_wrapper_resolver_begin\n'
    if [ -d /etc/resolver ]; then
      ls -la /etc/resolver 2>&1 || true
      for f in /etc/resolver/*; do
        [ -f "$f" ] || continue
        printf -- '--- %%s\n' "$f"
        sed -n '1,120p' "$f" 2>&1 || true
      done
    else
      echo "/etc/resolver missing"
    fi
    printf 'vpnc_wrapper_resolver_end\n'
  } >> "$log_file" 2>&1
}

log_probe_snapshot() {
  [ -n "$probe_hosts" ] || return 0
  printf '%%s\n' "$probe_hosts" | while IFS= read -r host; do
    [ -n "$host" ] || continue
    {
      printf 'vpnc_wrapper_probe_begin: %%s\n' "$host"
      printf 'vpnc_wrapper_probe_dscacheutil_begin\n'
      dscacheutil -q host -a name "$host" 2>&1 || true
      printf 'vpnc_wrapper_probe_dscacheutil_end\n'
      printf 'vpnc_wrapper_probe_route_begin\n'
      route -n get "$host" 2>&1 || true
      printf 'vpnc_wrapper_probe_route_end\n'
      if command -v dig >/dev/null 2>&1 && [ -n "$shim_nameservers" ]; then
        printf '%%s\n' "$shim_nameservers" | while IFS= read -r ns; do
          [ -n "$ns" ] || continue
          printf 'vpnc_wrapper_probe_dig_begin: %%s @%%s\n' "$host" "$ns"
          dig +time=2 +tries=1 +short @"$ns" "$host" 2>&1 || true
          printf 'vpnc_wrapper_probe_dig_end: %%s @%%s\n' "$host" "$ns"
        done
      fi
      printf 'vpnc_wrapper_probe_end: %%s\n' "$host"
    } >> "$log_file" 2>&1
  done
}

if [ "${1:-}" = "--probe-sync-apply" ]; then
  sync_probe_host_routes apply
  exit 0
fi

{
  printf 'vpnc_wrapper_event: begin\n'
  printf 'vpnc_wrapper_reason: %%s\n' "${reason:-unknown}"
  printf 'vpnc_wrapper_base_command: %%s\n' "$base_command"
  printf 'vpnc_wrapper_env_begin\n'
  env | LC_ALL=C sort | grep -E '^(reason|TUNDEV|VPNGATEWAY|VPNPID|LOG_LEVEL|IDLE_TIMEOUT|INTERNAL_IP4_|INTERNAL_IP6_|CISCO_)=' || true
  printf 'vpnc_wrapper_env_end\n'
} >> "$log_file" 2>&1

log_snapshot before
case "${reason:-}" in
  pre-init)
    capture_default_route
    [ "$diag_probes_enabled" = "1" ] && log_probe_snapshot
    ;;
esac
if [ -n "$vpn_slice_pycompat" ]; then
  if [ -n "${PYTHONPATH:-}" ]; then
    export PYTHONPATH="$vpn_slice_pycompat:$PYTHONPATH"
  else
    export PYTHONPATH="$vpn_slice_pycompat"
  fi
  printf 'vpnc_wrapper_pythonpath: %%s\n' "$PYTHONPATH" >> "$log_file" 2>&1
fi
/bin/sh -c "$base_command"
rc=$?
case "${reason:-}" in
  pre-init)
    if [ "$rc" -eq 0 ]; then
      pin_vpn_gateway_route
    fi
    ;;
  disconnect)
    remove_vpn_gateway_route
    sync_probe_host_routes remove
    remove_scutil_state
    clear_split_include_resolvers
    remove_dns_shim
    ;;
  connect|reconnect|attempt-reconnect)
    if [ "$rc" -eq 0 ]; then
      pin_vpn_gateway_route
      remove_scoped_default_route
      enforce_route_overrides
      apply_scutil_state
      clear_split_include_resolvers
      apply_dns_shim
      launch_probe_host_route_warmup
    fi
    ;;
esac
{
  printf 'vpnc_wrapper_base_exit: %%s\n' "$rc"
} >> "$log_file" 2>&1
log_snapshot after
case "${reason:-}" in
  connect|reconnect|attempt-reconnect|pre-init)
    [ "$diag_probes_enabled" = "1" ] && log_probe_snapshot
    ;;
esac
exit "$rc"
`, shellQuote(logPath), shellQuote(baseScript), shellQuote(shimLabel), shellQuote(shimNameservers), shellQuote(shimDomains), shellQuote(shimSearchDomain), shellQuote(searchCleanupDomains), shellQuote(probeHosts), shellQuote(manageSearchResolver), shellQuote(useScutilState), shellQuote(scutilServiceID), shellQuote(pyCompatDir), shellQuote(routeOverrideLines))
}

const vpnSliceDistutilsCompatInit = `from .version import LooseVersion
`

const vpnSliceDistutilsCompatVersion = `from __future__ import annotations

import re
from functools import total_ordering


def _normalize(value: str):
    parts = []
    for chunk in re.split(r"[^0-9A-Za-z]+", str(value)):
        if not chunk:
            continue
        if chunk.isdigit():
            parts.append((0, int(chunk)))
        else:
            parts.append((1, chunk.lower()))
    return tuple(parts)


@total_ordering
class LooseVersion:
    def __init__(self, vstring: str):
        self.vstring = str(vstring)
        self.version = _normalize(self.vstring)

    def _coerce(self, other):
        if isinstance(other, LooseVersion):
            return other
        return LooseVersion(str(other))

    def __eq__(self, other):
        other = self._coerce(other)
        return self.version == other.version

    def __lt__(self, other):
        other = self._coerce(other)
        return self.version < other.version

    def __repr__(self):
        return "LooseVersion(%r)" % (self.vstring,)
`

func authenticate(server string, options ConnectOptions, ocPath string, logWriter io.Writer, progressWriter io.Writer) (*authResult, error) {
	if normalizeAuthMode(options.Auth) == "aggregate" {
		return authenticateWithSAML(server, options, ocPath, logWriter, progressWriter)
	}
	return authenticateWithOpenConnect(server, options, ocPath, logWriter, progressWriter)
}

func normalizeAuthMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "saml", "password":
		return "aggregate"
	case "openconnect":
		return "openconnect"
	case "aggregate":
		return "aggregate"
	default:
		return strings.ToLower(strings.TrimSpace(raw))
	}
}

type samlAuthState struct {
	SSOLoginURL     string
	OpaqueXML       string
	HostScanTicket  string
	HostScanToken   string
	HostScanWaitURI string
	BaseHost        string
	RequestURL      string
	ReplyURL        string
	GroupAccess     string
	AuthMethod      string
	ClientProfile   aggregateAuthClientProfile
	CookieJar       http.CookieJar
}

func authenticateWithSAML(server string, options ConnectOptions, ocPath string, logWriter io.Writer, progressWriter io.Writer) (*authResult, error) {
	writeLogf(logWriter, "auth_backend: aggregate-auth + vpn-auth + native-csd")
	writeProgressf(progressWriter, "auth_stage: fetching_saml_config")

	clientProfile := detectAggregateAuthClientProfile()
	state, err := fetchSAMLAuthState(server, clientProfile, logWriter)
	if err != nil {
		return nil, err
	}

	scannedHostScanToken := ""
	seenHostScanTokens := map[string]struct{}{}
	deferredPostSSOHostScan := false
	for hostScanPass := 0; hostScanPass < 4; hostScanPass++ {
		if strings.TrimSpace(state.HostScanTicket) == "" || strings.TrimSpace(state.HostScanToken) == "" {
			break
		}
		if _, seen := seenHostScanTokens[state.HostScanToken]; seen {
			break
		}

		writeProgressf(progressWriter, "auth_stage: csd_hostscan")
		if err := performHostScan(ocPath, state, logWriter); err != nil {
			return nil, err
		}
		if err := waitForHostScan(state, logWriter); err != nil {
			return nil, err
		}

		scannedHostScanToken = state.HostScanToken
		seenHostScanTokens[state.HostScanToken] = struct{}{}

		refreshedState, err := fetchSAMLAuthStateWithJar(firstNonEmpty(state.RequestURL, state.ReplyURL, server), server, state.CookieJar, clientProfile, logWriter)
		if err != nil {
			return nil, err
		}
		refreshedState.CookieJar = state.CookieJar
		if shouldPreferSSOAfterHostScan(server, seenHostScanTokens, refreshedState) {
			writeLogf(logWriter, "aggregate_auth_followup: auth-request after successful hostscan; deferring latest hostscan challenge until after sso")
			state = refreshedState
			deferredPostSSOHostScan = true
			break
		}
		state = refreshedState
	}
	if hasPendingHostScanChallenge(state, seenHostScanTokens) && !deferredPostSSOHostScan {
		writeProgressf(progressWriter, "auth_stage: csd_hostscan_stuck")
		writeLogf(logWriter, "auth_error: ASA kept issuing new host-scan challenges after %d successful passes; latest ticket=%s token=%s", len(seenHostScanTokens), state.HostScanTicket, state.HostScanToken)
		return nil, fmt.Errorf("ASA kept issuing new host-scan challenges after %d successful passes; latest ticket=%s token=%s", len(seenHostScanTokens), state.HostScanTicket, state.HostScanToken)
	}

	if deferredPostSSOHostScan {
		for _, rawURL := range []string{state.RequestURL, state.ReplyURL} {
			if err := storeSAMLHostScanCookie(state, rawURL); err != nil {
				return nil, fmt.Errorf("prepare pending hostscan cookie for browser: %w", err)
			}
		}
	}

	presetCookiesJSON, presetCookieNames, err := marshalBrowserPresetCookies(state, nil)
	if err != nil {
		return nil, err
	}
	if presetCookieNames != "" {
		writeLogf(logWriter, "aggregate_auth_browser_cookies_preset: %s", presetCookieNames)
	}

	browserAuth, err := authenticateWithVPNAuthURL(state.SSOLoginURL, options.Credentials, presetCookiesJSON, logWriter, progressWriter)
	if err != nil {
		return nil, err
	}
	if deferredPostSSOHostScan {
		writeLogf(logWriter, "aggregate_auth_followup: running deferred hostscan challenge after sso")
		writeProgressf(progressWriter, "auth_stage: csd_hostscan")
		if err := performHostScan(ocPath, state, logWriter); err != nil {
			return nil, err
		}
		if err := waitForHostScan(state, logWriter); err != nil {
			return nil, err
		}
		scannedHostScanToken = state.HostScanToken
	}
	if scannedHostScanToken != "" {
		state.HostScanToken = scannedHostScanToken
	}
	currentBrowserAuth := browserAuth
	for authReplyPass := 0; authReplyPass < 3; authReplyPass++ {
		if err := storeASAWebViewCookies(state, currentBrowserAuth, logWriter); err != nil {
			return nil, err
		}

		result, err := completeSAMLAuth(state, server, currentBrowserAuth.Cookie, logWriter)
		if err == nil {
			writeProgressf(progressWriter, "auth_stage: cookie_obtained")
			return result, nil
		}

		var continuation *samlAuthReplyContinue
		if errors.As(err, &continuation) && continuation != nil && continuation.State != nil {
			state = continuation.State
			writeLogf(logWriter, "aggregate_auth_followup: auth-reply returned continuation auth-request; retrying current sso-token without browser")
			continue
		}

		var followup *samlAuthReplyFollowup
		if !errors.As(err, &followup) || followup == nil || followup.State == nil || strings.TrimSpace(followup.State.SSOLoginURL) == "" {
			return nil, err
		}

		state = followup.State
		presetCookiesJSON, presetCookieNames, marshalErr := marshalBrowserPresetCookies(state, currentBrowserAuth)
		if marshalErr != nil {
			return nil, marshalErr
		}
		if presetCookieNames != "" {
			writeLogf(logWriter, "aggregate_auth_browser_cookies_preset: %s", presetCookieNames)
		}
		writeLogf(logWriter, "aggregate_auth_followup: auth-reply returned auth-request; repeating browser flow")
		currentBrowserAuth, err = authenticateWithVPNAuthURL(state.SSOLoginURL, options.Credentials, presetCookiesJSON, logWriter, progressWriter)
		if err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("SAML auth-reply follow-up loop exhausted without session-token")
}

func hasPendingHostScanChallenge(state *samlAuthState, seenTokens map[string]struct{}) bool {
	if state == nil {
		return false
	}
	if strings.TrimSpace(state.HostScanTicket) == "" || strings.TrimSpace(state.HostScanToken) == "" {
		return false
	}
	_, seen := seenTokens[state.HostScanToken]
	return !seen
}

func shouldPreferSSOAfterHostScan(server string, seenTokens map[string]struct{}, state *samlAuthState) bool {
	if state == nil || len(seenTokens) == 0 {
		return false
	}
	if strings.TrimSpace(state.SSOLoginURL) == "" {
		return false
	}
	if strings.TrimSpace(state.HostScanTicket) == "" || strings.TrimSpace(state.HostScanToken) == "" {
		return false
	}
	return strings.TrimSpace(state.RequestURL) != fmt.Sprintf("https://%s", strings.TrimSpace(server))
}

func authenticateWithOpenConnect(server string, options ConnectOptions, ocPath string, logWriter io.Writer, progressWriter io.Writer) (*authResult, error) {
	writeLogf(logWriter, "auth_backend: openconnect --authenticate")
	writeProgressf(progressWriter, "auth_stage: openconnect_authenticate")

	helpers, err := prepareOpenConnectAuthHelpers(ocPath, server, options, logWriter)
	if err != nil {
		return nil, err
	}
	if helpers.Cleanup != nil {
		defer helpers.Cleanup()
	}

	targetURL, usergroup := resolveOpenConnectAuthTarget(server)
	clientProfile := detectAggregateAuthClientProfile()
	localHostname := detectOpenConnectLocalHostname(clientProfile)
	cmdArgs := appendOpenConnectClientIdentityArgs([]string{
		"--authenticate",
		"--protocol=anyconnect",
	}, clientProfile, localHostname)
	if strings.TrimSpace(os.Getenv("OPENCONNECT_TUN_DEBUG_HTTP")) == "1" {
		cmdArgs = append(cmdArgs, "--verbose", "--verbose", "--verbose", "--dump-http-traffic")
		writeLogf(logWriter, "authenticate_debug_http: enabled")
	}
	if options.Credentials.Username != "" {
		cmdArgs = append(cmdArgs, "--user", options.Credentials.Username)
	}
	if usergroup != "" {
		cmdArgs = append(cmdArgs, "--usergroup", usergroup)
	}
	cmdArgs = append(cmdArgs, helpers.Args...)
	cmdArgs = append(cmdArgs, targetURL)
	writeLogf(logWriter, "authenticate_command: %s %s", ocPath, strings.Join(cmdArgs, " "))

	ctx, cancel := context.WithTimeout(context.Background(), authTimeout)
	defer cancel()

	stageWriter := newAuthStageWriter(logWriter, progressWriter, false)
	defer stageWriter.Flush()

	cmd := execCommandContext(ctx, ocPath, cmdArgs...)
	if len(helpers.Env) > 0 {
		cmd.Env = append(os.Environ(), helpers.Env...)
	}
	cmd.Stderr = stageWriter
	out, err := cmd.Output()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("openconnect --authenticate timed out after %s", authTimeout)
	}
	if err != nil {
		return nil, fmt.Errorf("openconnect --authenticate failed: %w", err)
	}
	result, err := parseAuthenticateOutput(string(out))
	if err != nil {
		return nil, err
	}
	logAuthResult(logWriter, "openconnect", result)
	writeProgressf(progressWriter, "auth_stage: cookie_obtained")
	return result, nil
}

func detectOpenConnectLocalHostname(profile aggregateAuthClientProfile) string {
	if value := strings.TrimSpace(commandOutput("scutil", "--get", "LocalHostName")); value != "" {
		return value
	}
	value := strings.TrimSpace(profile.ComputerName)
	value = strings.ReplaceAll(value, " ", "-")
	return value
}

func appendOpenConnectClientIdentityArgs(args []string, profile aggregateAuthClientProfile, localHostname string) []string {
	args = append(args, "--useragent=AnyConnect")
	if osType := firstNonEmpty(strings.TrimSpace(profile.DeviceID), "mac-intel"); osType != "" {
		args = append(args, "--os="+osType)
	}
	if version := strings.TrimSpace(profile.Version); version != "" {
		args = append(args, "--version-string", version)
	}
	if localHostname = strings.TrimSpace(localHostname); localHostname != "" {
		args = append(args, "--local-hostname", localHostname)
	}
	return args
}

func fetchSAMLAuthState(server string, clientProfile aggregateAuthClientProfile, logWriter io.Writer) (*samlAuthState, error) {
	return fetchSAMLAuthStateWithJar(server, server, nil, clientProfile, logWriter)
}

func fetchSAMLAuthStateWithJar(requestTarget string, groupAccess string, jar http.CookieJar, clientProfile aggregateAuthClientProfile, logWriter io.Writer) (*samlAuthState, error) {
	requestURL, err := normalizeHTTPSRequestURL(requestTarget)
	if err != nil {
		return nil, err
	}
	initXML := buildAggregateAuthInitXML(groupAccess, clientProfile)
	writeLogf(logWriter, "aggregate_auth_init_url: %s", requestURL)
	if jar == nil {
		var err error
		jar, err = cookiejar.New(nil)
		if err != nil {
			return nil, fmt.Errorf("create SAML cookie jar: %w", err)
		}
	}

	req, err := http.NewRequest(http.MethodPost, requestURL, strings.NewReader(initXML))
	if err != nil {
		return nil, fmt.Errorf("build SAML init request: %w", err)
	}
	req.Header.Set("User-Agent", "AnyConnect")
	req.Header.Set("Content-Type", "application/xml; charset=utf-8")
	req.Header.Set("X-Aggregate-Auth", "1")
	req.Header.Set("X-Transcend-Version", "1")

	resp, err := newSAMLHTTPClient(jar, nil).Do(req)
	if err != nil {
		return nil, fmt.Errorf("SAML init request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read SAML init response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("SAML init request failed with HTTP %d", resp.StatusCode)
	}

	response := string(body)
	state, err := parseSAMLAuthStateFromResponse(response, requestURL, groupAccess, clientProfile, jar)
	if err != nil {
		return nil, err
	}
	writeLogf(logWriter, "aggregate_auth_sso_login: %s", state.SSOLoginURL)
	writeLogf(logWriter, "aggregate_auth_reply_url: %s", state.ReplyURL)
	if state.HostScanTicket != "" && state.HostScanToken != "" {
		writeLogf(logWriter, "aggregate_auth_hostscan: ticket=%s token=%s wait_uri=%s", state.HostScanTicket, state.HostScanToken, state.HostScanWaitURI)
	}
	return state, nil
}

func parseSAMLAuthContinuationState(response string, requestURL string, groupAccess string, clientProfile aggregateAuthClientProfile, jar http.CookieJar) (*samlAuthState, error) {
	opaqueXML := extractXMLElement(response, "<opaque", "</opaque>")
	if opaqueXML == "" {
		return nil, fmt.Errorf("missing opaque block in aggregate auth response")
	}

	baseHost := extractBaseHost(groupAccess, "")
	replyURL := requestURL
	if normalizedGroupURL, err := normalizeHTTPSRequestURL(groupAccess); err == nil {
		replyURL = normalizedGroupURL
	}
	return &samlAuthState{
		SSOLoginURL:     "",
		OpaqueXML:       opaqueXML,
		HostScanTicket:  extractXMLTag(response, "host-scan-ticket"),
		HostScanToken:   extractXMLTag(response, "host-scan-token"),
		HostScanWaitURI: extractXMLTag(response, "host-scan-wait-uri"),
		BaseHost:        baseHost,
		RequestURL:      requestURL,
		ReplyURL:        replyURL,
		GroupAccess:     groupAccess,
		AuthMethod:      extractLastXMLTag(opaqueXML, "auth-method"),
		ClientProfile:   clientProfile,
		CookieJar:       jar,
	}, nil
}

func parseSAMLAuthStateFromResponse(response string, requestURL string, groupAccess string, clientProfile aggregateAuthClientProfile, jar http.CookieJar) (*samlAuthState, error) {
	ssoLoginURL := html.UnescapeString(extractXMLTag(response, "sso-v2-login"))
	if ssoLoginURL == "" {
		message := extractXMLTag(response, "message")
		if message == "" {
			message = "missing sso-v2-login in aggregate auth response"
		}
		return nil, fmt.Errorf("%s", message)
	}

	opaqueXML := extractXMLElement(response, "<opaque", "</opaque>")
	if opaqueXML == "" {
		return nil, fmt.Errorf("missing opaque block in aggregate auth response")
	}

	baseHost := extractBaseHost(groupAccess, ssoLoginURL)
	replyURL := requestURL
	if normalizedGroupURL, err := normalizeHTTPSRequestURL(groupAccess); err == nil {
		replyURL = normalizedGroupURL
	}
	state := &samlAuthState{
		SSOLoginURL:     ssoLoginURL,
		OpaqueXML:       opaqueXML,
		HostScanTicket:  extractXMLTag(response, "host-scan-ticket"),
		HostScanToken:   extractXMLTag(response, "host-scan-token"),
		HostScanWaitURI: extractXMLTag(response, "host-scan-wait-uri"),
		BaseHost:        baseHost,
		RequestURL:      requestURL,
		ReplyURL:        replyURL,
		GroupAccess:     groupAccess,
		AuthMethod:      extractLastXMLTag(opaqueXML, "auth-method"),
		ClientProfile:   clientProfile,
		CookieJar:       jar,
	}
	return state, nil
}

func authenticateWithVPNAuthURL(loginURL string, creds Credentials, presetCookiesJSON string, logWriter io.Writer, progressWriter io.Writer) (*vpnAuthResult, error) {
	vpnAuthPath, err := execLookPathOpenConnect("vpn-auth")
	if err != nil {
		return nil, fmt.Errorf("vpn-auth not found: %w", err)
	}

	cmdArgs := []string{"--url", loginURL}
	if creds.Username != "" {
		cmdArgs = append(cmdArgs, "--username", creds.Username)
	}
	if creds.Password != "" {
		cmdArgs = append(cmdArgs, "--password", creds.Password)
	}
	if creds.TOTPSecret != "" {
		cmdArgs = append(cmdArgs, "--totp-secret", creds.TOTPSecret)
	}

	writeLogf(logWriter, "sso_browser_command: %s %s", vpnAuthPath, strings.Join(cmdArgs, " "))
	writeProgressf(progressWriter, "auth_stage: vpn_auth")

	ctx, cancel := context.WithTimeout(context.Background(), authTimeout)
	defer cancel()

	stageWriter := newAuthStageWriter(logWriter, progressWriter, creds.TOTPSecret != "")
	defer stageWriter.Flush()

	cmd := execCommandContext(ctx, vpnAuthPath, cmdArgs...)
	if strings.TrimSpace(presetCookiesJSON) != "" {
		cmd.Env = append(os.Environ(), "VPN_AUTH_PRESET_COOKIES_JSON="+presetCookiesJSON)
	}
	cmd.Stderr = stageWriter
	out, err := cmd.Output()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("vpn-auth timed out after %s", authTimeout)
	}
	if err != nil {
		return nil, fmt.Errorf("vpn-auth failed: %w", err)
	}

	var result vpnAuthResult
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, fmt.Errorf("parse vpn-auth JSON: %w", err)
	}
	if strings.TrimSpace(result.Cookie) == "" {
		return nil, fmt.Errorf("vpn-auth returned empty SSO token")
	}
	result.Cookie = strings.TrimSpace(result.Cookie)
	result.CookieName = strings.TrimSpace(result.CookieName)
	return &result, nil
}

func completeSAMLAuth(state *samlAuthState, server string, samlToken string, logWriter io.Writer) (*authResult, error) {
	replyVariants := buildSAMLAuthReplyXMLVariants(state, samlToken)
	targets := orderedUniqueStrings(state.ReplyURL, state.RequestURL)
	if len(targets) == 0 {
		return nil, fmt.Errorf("missing SAML auth-reply target")
	}

	var lastErr error
	var preferredContinuation error
	var preferredFollowup error
	for _, targetURL := range targets {
		for _, replyVariant := range replyVariants {
			result, err := completeSAMLAuthAtTarget(state, server, samlToken, replyVariant, targetURL, logWriter)
			if err == nil {
				return result, nil
			}
			var continuation *samlAuthReplyContinue
			if preferredContinuation == nil && errors.As(err, &continuation) && continuation != nil && continuation.State != nil {
				preferredContinuation = err
			}
			var followup *samlAuthReplyFollowup
			if preferredFollowup == nil && errors.As(err, &followup) && followup != nil && followup.State != nil && strings.TrimSpace(followup.State.SSOLoginURL) != "" {
				preferredFollowup = err
			}
			lastErr = err
		}
	}
	if preferredContinuation != nil {
		return nil, preferredContinuation
	}
	if preferredFollowup != nil {
		return nil, preferredFollowup
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("SAML auth-reply failed without targets")
	}
	return nil, lastErr
}

func completeSAMLAuthAtTarget(state *samlAuthState, server string, samlToken string, replyVariant samlAuthReplyVariant, targetURL string, logWriter io.Writer) (*authResult, error) {
	if err := storeSAMLHostScanCookie(state, targetURL); err != nil {
		return nil, fmt.Errorf("prepare SAML auth-reply cookies: %w", err)
	}
	if err := storeSAMLCookie(state, targetURL, "acSamlv2Token", samlToken); err != nil {
		return nil, fmt.Errorf("prepare SAML token cookie: %w", err)
	}
	if tunnelGroup := deriveTunnelGroupCookie(state); tunnelGroup != "" {
		if err := storeSAMLCookie(state, targetURL, "tg", tunnelGroup); err != nil {
			return nil, fmt.Errorf("prepare SAML tunnel-group cookie: %w", err)
		}
		writeLogf(logWriter, "aggregate_auth_reply_tg: target=%s value=%s", targetURL, tunnelGroup)
	}
	if normalizedGroupURL, err := normalizeHTTPSRequestURL(state.GroupAccess); err == nil {
		if err := storeSAMLHostScanCookie(state, normalizedGroupURL); err != nil {
			return nil, fmt.Errorf("prepare SAML group hostscan cookie: %w", err)
		}
		if err := storeSAMLCookie(state, normalizedGroupURL, "acSamlv2Token", samlToken); err != nil {
			return nil, fmt.Errorf("prepare SAML group token cookie: %w", err)
		}
		if tunnelGroup := deriveTunnelGroupCookie(state); tunnelGroup != "" {
			if err := storeSAMLCookie(state, normalizedGroupURL, "tg", tunnelGroup); err != nil {
				return nil, fmt.Errorf("prepare SAML group tunnel-group cookie: %w", err)
			}
		}
	}
	writeLogf(logWriter, "aggregate_auth_reply_url_final: %s", targetURL)
	writeLogf(logWriter, "aggregate_auth_reply_variant: target=%s name=%s", targetURL, replyVariant.Name)
	writeLogf(logWriter, "aggregate_auth_reply_cookies: %s", describeCookiesForURL(state.CookieJar, targetURL))

	req, err := http.NewRequest(http.MethodPost, targetURL, strings.NewReader(replyVariant.XML))
	if err != nil {
		return nil, fmt.Errorf("build SAML auth-reply request: %w", err)
	}
	req.Header.Set("User-Agent", "AnyConnect")
	req.Header.Set("Content-Type", "application/xml; charset=utf-8")
	req.Header.Set("X-Aggregate-Auth", "1")
	req.Header.Set("X-Transcend-Version", "1")

	resp, err := newSAMLHTTPClient(state.CookieJar, nil).Do(req)
	if err != nil {
		return nil, fmt.Errorf("SAML auth-reply failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read SAML auth-reply response: %w", err)
	}
	response := string(body)
	snippet := strings.TrimSpace(response)
	if len(snippet) > 400 {
		snippet = snippet[:400]
	}
	writeLogf(logWriter, "aggregate_auth_reply_status: target=%s status=%s", targetURL, resp.Status)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		writeLogf(logWriter, "aggregate_auth_reply_error: target=%s snippet=%s", targetURL, snippet)
		return nil, fmt.Errorf("SAML auth-reply failed with HTTP %d", resp.StatusCode)
	}

	sessionToken := extractXMLTag(response, "session-token")
	if sessionToken == "" {
		writeLogf(logWriter, "aggregate_auth_reply_error: target=%s snippet=%s", targetURL, snippet)
		if strings.Contains(response, "type=\"auth-request\"") {
			followupState, err := parseSAMLAuthStateFromResponse(response, targetURL, state.GroupAccess, state.ClientProfile, state.CookieJar)
			if err == nil {
				return nil, &samlAuthReplyFollowup{State: followupState, Snippet: snippet}
			}
			continuationState, continuationErr := parseSAMLAuthContinuationState(response, targetURL, state.GroupAccess, state.ClientProfile, state.CookieJar)
			if continuationErr == nil {
				return nil, &samlAuthReplyContinue{State: continuationState, Snippet: snippet}
			}
		}
		return nil, fmt.Errorf("ASA auth-reply did not return session-token: %s", snippet)
	}

	result := &authResult{
		Cookie:     sessionToken,
		Host:       state.BaseHost,
		ConnectURL: fmt.Sprintf("https://%s", server),
		Resolve:    resolveOpenConnectResolve(server),
	}
	logAuthResult(logWriter, "aggregate_auth", result)
	return result, nil
}

func performHostScan(ocPath string, state *samlAuthState, logWriter io.Writer) error {
	csd, err := prepareCSDWrapper(ocPath, state.GroupAccess)
	if err != nil {
		return err
	}
	if csd.Cleanup != nil {
		defer csd.Cleanup()
	}
	for _, env := range csd.Env {
		switch {
		case strings.HasPrefix(env, "OPENCONNECT_TUN_NATIVE_CSD_LIB="):
			writeLogf(logWriter, "hostscan_csd_wrapper: native libcsd via %s", strings.TrimPrefix(env, "OPENCONNECT_TUN_NATIVE_CSD_LIB="))
		case strings.HasPrefix(env, "OPENCONNECT_TUN_CSD_POST_BIN="):
			writeLogf(logWriter, "hostscan_csd_wrapper: %s", strings.TrimPrefix(env, "OPENCONNECT_TUN_CSD_POST_BIN="))
		}
	}

	cmdArgs := []string{"/dev/null", "-ticket", state.HostScanTicket, "-stub", state.HostScanToken}
	writeLogf(logWriter, "hostscan_command: %s %s", csd.WrapperPath, strings.Join(cmdArgs, " "))

	ctx, cancel := context.WithTimeout(context.Background(), authTimeout)
	defer cancel()

	var output strings.Builder
	cmd := execCommandContext(ctx, csd.WrapperPath, cmdArgs...)
	cmd.Env = append(os.Environ(), append(csd.Env, "CSD_HOSTNAME="+state.BaseHost)...)
	cmd.Stdout = io.MultiWriter(logWriter, &output)
	cmd.Stderr = io.MultiWriter(logWriter, &output)

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("host-scan timed out after %s", authTimeout)
		}
		return fmt.Errorf("host-scan failed: %w", err)
	}
	if !strings.Contains(output.String(), "TOKEN_SUCCESS") {
		return fmt.Errorf("host-scan did not report TOKEN_SUCCESS")
	}
	if token := strings.TrimSpace(readFileIfExists(csd.TokenPath)); token != "" {
		state.HostScanToken = token
		writeLogf(logWriter, "hostscan_token_source: token.xml")
	}
	return nil
}

func waitForHostScan(state *samlAuthState, logWriter io.Writer) error {
	if strings.TrimSpace(state.HostScanWaitURI) == "" {
		return nil
	}
	waitURL := fmt.Sprintf("https://%s%s", state.BaseHost, state.HostScanWaitURI)
	if err := storeSAMLHostScanCookie(state, waitURL); err != nil {
		return fmt.Errorf("prepare host-scan wait cookies: %w", err)
	}
	client := newSAMLHTTPClient(state.CookieJar, func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	})

	currentURL := waitURL
	for redirectCount := 0; redirectCount < 5; redirectCount++ {
		req, err := http.NewRequest(http.MethodGet, currentURL, nil)
		if err != nil {
			return fmt.Errorf("build host-scan wait request: %w", err)
		}
		req.Header.Set("User-Agent", "AnyConnect")
		if redirectCount == 0 {
			req.Header.Set("X-Aggregate-Auth", "1")
			req.Header.Set("X-Transcend-Version", "1")
		}

		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("host-scan wait request failed: %w", err)
		}

		location := strings.TrimSpace(resp.Header.Get("Location"))
		writeLogf(logWriter, "hostscan_wait_status: %s", resp.Status)
		if location != "" {
			writeLogf(logWriter, "hostscan_wait_location: %s", location)
		}

		switch resp.StatusCode {
		case http.StatusOK:
			resp.Body.Close()
			state.RequestURL = currentURL
			return nil
		case http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
			resp.Body.Close()
			if location == "" {
				return fmt.Errorf("host-scan wait redirect missing Location header")
			}
			nextURL, err := resp.Location()
			if err != nil {
				return fmt.Errorf("parse host-scan wait redirect: %w", err)
			}
			currentURL = nextURL.String()
			continue
		default:
			resp.Body.Close()
			return fmt.Errorf("host-scan wait returned HTTP %d", resp.StatusCode)
		}
	}
	return fmt.Errorf("host-scan wait exceeded redirect limit")
}

func normalizeHTTPSRequestURL(raw string) (string, error) {
	parsed, err := parseHTTPSURL(raw)
	if err != nil {
		return "", err
	}
	return parsed.String(), nil
}

func buildAggregateAuthInitXML(server string, clientProfile aggregateAuthClientProfile) string {
	return fmt.Sprintf(
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?><config-auth client=\"vpn\" type=\"init\" aggregate-auth-version=\"2\"><version who=\"vpn\">%s</version>%s%s<group-access>https://%s</group-access>%s</config-auth>",
		html.EscapeString(defaultAggregateAuthClientProfile(clientProfile).Version),
		buildAggregateAuthDeviceIDXML(clientProfile),
		buildAggregateAuthMACListXML(clientProfile),
		html.EscapeString(server),
		buildAggregateAuthCapabilitiesXML(clientProfile.AuthMethods),
	)
}

func buildSAMLAuthReplyXML(state *samlAuthState, samlToken string) string {
	clientProfile := defaultAggregateAuthClientProfile(state.ClientProfile)
	return fmt.Sprintf(
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?><config-auth client=\"vpn\" type=\"auth-reply\" aggregate-auth-version=\"2\"><version who=\"vpn\">%s</version>%s%s<session-token/><session-id/>%s<auth><sso-token>%s</sso-token></auth></config-auth>",
		html.EscapeString(clientProfile.Version),
		buildAggregateAuthDeviceIDXML(clientProfile),
		buildAggregateAuthReplyContextXML(state),
		state.OpaqueXML,
		html.EscapeString(strings.TrimSpace(samlToken)),
	)
}

func buildSAMLAuthReplyXMLVariants(state *samlAuthState, samlToken string) []samlAuthReplyVariant {
	variants := []samlAuthReplyVariant{
		{Name: "placeholders_only", XML: buildSAMLAuthReplyXML(state, samlToken)},
		{Name: "capabilities_and_placeholders", XML: buildSAMLAuthReplyXMLWithOptions(state, samlToken, true, true, false)},
		{Name: "capabilities_only", XML: buildSAMLAuthReplyXMLWithOptions(state, samlToken, true, false, false)},
		{Name: "full_profile_and_placeholders", XML: buildSAMLAuthReplyXMLWithOptions(state, samlToken, true, true, true)},
		{Name: "full_profile_only", XML: buildSAMLAuthReplyXMLWithOptions(state, samlToken, true, false, true)},
	}

	seen := map[string]struct{}{}
	out := make([]samlAuthReplyVariant, 0, len(variants))
	for _, variant := range variants {
		if _, ok := seen[variant.XML]; ok {
			continue
		}
		seen[variant.XML] = struct{}{}
		out = append(out, variant)
	}
	return out
}

func buildSAMLAuthReplyXMLWithOptions(state *samlAuthState, samlToken string, includeCapabilities bool, includePlaceholders bool, includeFullProfile bool) string {
	authMethod := strings.TrimSpace(state.AuthMethod)
	if authMethod == "" {
		authMethod = "single-sign-on-v2"
	}
	clientProfile := defaultAggregateAuthClientProfile(state.ClientProfile)

	var builder strings.Builder
	builder.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?><config-auth client=\"vpn\" type=\"auth-reply\" aggregate-auth-version=\"2\">")
	builder.WriteString("<version who=\"vpn\">")
	builder.WriteString(html.EscapeString(clientProfile.Version))
	builder.WriteString("</version>")
	builder.WriteString(buildAggregateAuthDeviceIDXML(clientProfile))
	if includeFullProfile {
		builder.WriteString(buildAggregateAuthMACListXML(clientProfile))
	}
	if includeCapabilities {
		if includeFullProfile {
			builder.WriteString(buildAggregateAuthCapabilitiesXML(clientProfile.AuthMethods))
		} else {
			builder.WriteString("<capabilities><auth-method>")
			builder.WriteString(html.EscapeString(authMethod))
			builder.WriteString("</auth-method></capabilities>")
		}
	}
	builder.WriteString(buildAggregateAuthReplyContextXML(state))
	if includePlaceholders {
		builder.WriteString("<session-token/><session-id/>")
	}
	builder.WriteString(state.OpaqueXML)
	builder.WriteString("<auth><sso-token>")
	builder.WriteString(html.EscapeString(strings.TrimSpace(samlToken)))
	builder.WriteString("</sso-token></auth></config-auth>")
	return builder.String()
}

func buildAggregateAuthReplyContextXML(state *samlAuthState) string {
	if state == nil {
		return ""
	}
	var builder strings.Builder
	if groupSelect := strings.TrimSpace(deriveTunnelGroupCookie(state)); groupSelect != "" {
		builder.WriteString("<group-select>")
		builder.WriteString(html.EscapeString(groupSelect))
		builder.WriteString("</group-select>")
	}
	if hostScanToken := strings.TrimSpace(state.HostScanToken); hostScanToken != "" {
		builder.WriteString("<host-scan-token>")
		builder.WriteString(html.EscapeString(hostScanToken))
		builder.WriteString("</host-scan-token>")
	}
	return builder.String()
}

func defaultAggregateAuthClientProfile(profile aggregateAuthClientProfile) aggregateAuthClientProfile {
	if strings.TrimSpace(profile.Version) == "" {
		profile.Version = "4.10.07061"
	}
	if strings.TrimSpace(profile.DeviceID) == "" {
		profile.DeviceID = "mac-intel"
	}
	if len(profile.AuthMethods) == 0 {
		profile.AuthMethods = []string{
			"multiple-cert",
			"single-sign-on",
			"single-sign-on-v2",
			"single-sign-on-external-browser",
		}
	}
	return profile
}

func buildAggregateAuthDeviceIDXML(profile aggregateAuthClientProfile) string {
	profile = defaultAggregateAuthClientProfile(profile)
	var attrs []string
	if value := strings.TrimSpace(profile.ComputerName); value != "" {
		attrs = append(attrs, fmt.Sprintf("computer-name=\"%s\"", html.EscapeString(value)))
	}
	if value := strings.TrimSpace(profile.DeviceType); value != "" {
		attrs = append(attrs, fmt.Sprintf("device-type=\"%s\"", html.EscapeString(value)))
	}
	if value := strings.TrimSpace(profile.PlatformVersion); value != "" {
		attrs = append(attrs, fmt.Sprintf("platform-version=\"%s\"", html.EscapeString(value)))
	}
	if value := strings.TrimSpace(profile.UniqueID); value != "" {
		attrs = append(attrs, fmt.Sprintf("unique-id=\"%s\"", html.EscapeString(value)))
	}
	if value := strings.TrimSpace(profile.UniqueIDGlobal); value != "" {
		attrs = append(attrs, fmt.Sprintf("unique-id-global=\"%s\"", html.EscapeString(value)))
	}
	if len(attrs) == 0 {
		return fmt.Sprintf("<device-id>%s</device-id>", html.EscapeString(profile.DeviceID))
	}
	return fmt.Sprintf("<device-id %s>%s</device-id>", strings.Join(attrs, " "), html.EscapeString(profile.DeviceID))
}

func buildAggregateAuthMACListXML(profile aggregateAuthClientProfile) string {
	if len(profile.MacAddresses) == 0 {
		return ""
	}
	var builder strings.Builder
	builder.WriteString("<mac-address-list>")
	for _, mac := range profile.MacAddresses {
		if strings.TrimSpace(mac) == "" {
			continue
		}
		builder.WriteString("<mac-address>")
		builder.WriteString(html.EscapeString(mac))
		builder.WriteString("</mac-address>")
	}
	builder.WriteString("</mac-address-list>")
	return builder.String()
}

func buildAggregateAuthCapabilitiesXML(authMethods []string) string {
	if len(authMethods) == 0 {
		authMethods = defaultAggregateAuthClientProfile(aggregateAuthClientProfile{}).AuthMethods
	}
	var builder strings.Builder
	builder.WriteString("<capabilities>")
	for _, method := range authMethods {
		method = strings.TrimSpace(method)
		if method == "" {
			continue
		}
		builder.WriteString("<auth-method>")
		builder.WriteString(html.EscapeString(method))
		builder.WriteString("</auth-method>")
	}
	builder.WriteString("</capabilities>")
	return builder.String()
}

func detectAggregateAuthClientProfile() aggregateAuthClientProfile {
	profile := defaultAggregateAuthClientProfile(aggregateAuthClientProfile{})
	if version := readAnyConnectVersion(); version != "" {
		profile.Version = version
	}
	if computerName := strings.TrimSpace(commandOutput("scutil", "--get", "ComputerName")); computerName != "" {
		profile.ComputerName = computerName
	} else if hostname, err := os.Hostname(); err == nil && strings.TrimSpace(hostname) != "" {
		profile.ComputerName = strings.TrimSpace(hostname)
	}
	if deviceType := strings.TrimSpace(commandOutput("sysctl", "-n", "hw.model")); deviceType != "" {
		profile.DeviceType = deviceType
	}
	if platformVersion := strings.TrimSpace(commandOutput("sw_vers", "-productVersion")); platformVersion != "" {
		profile.PlatformVersion = platformVersion
	}
	platformUUID := parsePlatformUUIDOutput(commandOutput("ioreg", "-rd1", "-c", "IOPlatformExpertDevice"))
	uniqueID, uniqueIDGlobal := readAnyConnectUDIDs()
	if uniqueID != "" {
		profile.UniqueID = uniqueID
	}
	if uniqueIDGlobal != "" {
		profile.UniqueIDGlobal = uniqueIDGlobal
	}
	if profile.UniqueIDGlobal == "" && platformUUID != "" {
		sum := sha1.Sum([]byte(platformUUID))
		profile.UniqueIDGlobal = strings.ToUpper(hex.EncodeToString(sum[:]))
	}
	if profile.UniqueID == "" && platformUUID != "" {
		sum := sha256.Sum256([]byte(platformUUID))
		profile.UniqueID = strings.ToUpper(hex.EncodeToString(sum[:]))
	}
	profile.MacAddresses = listMACAddresses()
	return profile
}

func readAnyConnectVersion() string {
	const anyConnectInfo = "/Applications/Cisco/Cisco AnyConnect Secure Mobility Client.app/Contents/Info.plist"
	if _, err := os.Stat(anyConnectInfo); err != nil {
		return ""
	}
	return strings.TrimSpace(commandOutput("defaults", "read", anyConnectInfo, "CFBundleShortVersionString"))
}

func readAnyConnectUDIDs() (uniqueID string, uniqueIDGlobal string) {
	candidates := []string{
		"/Applications/Cisco/Cisco AnyConnect DART.app/Contents/Resources/dartcli",
	}
	if dartCLI, err := execLookPathOpenConnect("dartcli"); err == nil {
		candidates = append(candidates, dartCLI)
	}
	seen := map[string]struct{}{}
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		if _, err := os.Stat(candidate); err != nil {
			continue
		}
		uniqueIDGlobal = parseAnyConnectUDIDOutput(commandOutput(candidate, "-u"))
		uniqueID = parseAnyConnectUDIDOutput(commandOutput(candidate, "-ul"))
		if uniqueID != "" || uniqueIDGlobal != "" {
			return uniqueID, uniqueIDGlobal
		}
	}
	return "", ""
}

func parseAnyConnectUDIDOutput(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "UDID") {
			continue
		}
		if idx := strings.Index(line, ":"); idx >= 0 {
			return strings.TrimSpace(line[idx+1:])
		}
	}
	return ""
}

func parsePlatformUUIDOutput(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "IOPlatformUUID") {
			continue
		}
		parts := strings.Split(line, "\"")
		if len(parts) < 4 {
			continue
		}
		return strings.TrimSpace(strings.ToUpper(parts[3]))
	}
	return ""
}

func listMACAddresses() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	seen := map[string]struct{}{}
	var macs []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(iface.HardwareAddr) == 0 {
			continue
		}
		mac := strings.ToUpper(iface.HardwareAddr.String())
		if mac == "" {
			continue
		}
		if _, ok := seen[mac]; ok {
			continue
		}
		seen[mac] = struct{}{}
		macs = append(macs, mac)
	}
	sort.Strings(macs)
	return macs
}

func commandOutput(name string, args ...string) string {
	out, err := execCommandOpenConnect(name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func readFileIfExists(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

func storeSAMLHostScanCookie(state *samlAuthState, rawURL string) error {
	if state == nil || state.CookieJar == nil || strings.TrimSpace(state.HostScanToken) == "" {
		return nil
	}
	return storeSAMLCookie(state, rawURL, "sdesktop", state.HostScanToken)
}

func storeSAMLCookie(state *samlAuthState, rawURL string, name string, value string) error {
	if state == nil || state.CookieJar == nil || strings.TrimSpace(name) == "" || strings.TrimSpace(value) == "" {
		return nil
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	state.CookieJar.SetCookies(parsed, []*http.Cookie{{
		Name:   strings.TrimSpace(name),
		Value:  strings.TrimSpace(value),
		Path:   "/",
		Secure: parsed.Scheme == "https",
	}})
	return nil
}

func describeCookiesForURL(jar http.CookieJar, rawURL string) string {
	if jar == nil || strings.TrimSpace(rawURL) == "" {
		return "none"
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "invalid_url"
	}
	cookies := jar.Cookies(parsed)
	if len(cookies) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(cookies))
	for _, cookie := range cookies {
		parts = append(parts, fmt.Sprintf("%s=%d", cookie.Name, len(cookie.Value)))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

func storeASAWebViewCookies(state *samlAuthState, result *vpnAuthResult, logWriter io.Writer) error {
	if state == nil || state.CookieJar == nil || result == nil || len(result.Cookies) == 0 {
		return nil
	}
	parsed, err := url.Parse(state.ReplyURL)
	if err != nil {
		return err
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if host == "" {
		return nil
	}

	imported := make([]string, 0, len(result.Cookies))
	for _, browserCookie := range result.Cookies {
		if !cookieDomainMatchesHost(browserCookie.Domain, host) {
			continue
		}
		name := strings.TrimSpace(browserCookie.Name)
		value := strings.TrimSpace(browserCookie.Value)
		if name == "" || value == "" {
			continue
		}
		path := strings.TrimSpace(browserCookie.Path)
		if path == "" {
			path = "/"
		}
		state.CookieJar.SetCookies(parsed, []*http.Cookie{{
			Name:   name,
			Value:  value,
			Path:   path,
			Secure: true,
		}})
		imported = append(imported, name)
	}
	if len(imported) == 0 {
		return nil
	}
	sort.Strings(imported)
	writeLogf(logWriter, "aggregate_auth_browser_cookies_imported: %s", strings.Join(imported, ", "))
	return nil
}

func cookieDomainMatchesHost(cookieDomain string, host string) bool {
	cookieDomain = strings.ToLower(strings.TrimSpace(cookieDomain))
	host = strings.ToLower(strings.TrimSpace(host))
	if cookieDomain == "" || host == "" {
		return false
	}
	cookieDomain = strings.TrimPrefix(cookieDomain, ".")
	return cookieDomain == host || strings.HasSuffix(host, "."+cookieDomain)
}

func marshalBrowserPresetCookies(state *samlAuthState, browserAuth *vpnAuthResult) (jsonString string, summary string, err error) {
	if state == nil || state.CookieJar == nil {
		return "", "", nil
	}

	targets := []string{
		strings.TrimSpace(state.ReplyURL),
		strings.TrimSpace(state.RequestURL),
	}
	if strings.TrimSpace(state.BaseHost) != "" {
		targets = append(targets, fmt.Sprintf("https://%s/+webvpn+/index.html", strings.TrimSpace(state.BaseHost)))
	}

	type presetCookie struct {
		Name   string `json:"name"`
		Value  string `json:"value"`
		Domain string `json:"domain"`
		Path   string `json:"path"`
	}

	seen := map[string]presetCookie{}
	for _, rawURL := range targets {
		if rawURL == "" {
			continue
		}
		parsed, parseErr := url.Parse(rawURL)
		if parseErr != nil {
			continue
		}
		for _, cookie := range state.CookieJar.Cookies(parsed) {
			name := strings.TrimSpace(cookie.Name)
			value := strings.TrimSpace(cookie.Value)
			if name == "" || value == "" {
				continue
			}
			if !shouldIncludeStateBrowserPresetCookie(name) {
				continue
			}
			path := strings.TrimSpace(cookie.Path)
			if path == "" {
				path = "/"
			}
			key := name + "|" + path
			seen[key] = presetCookie{
				Name:   name,
				Value:  value,
				Domain: parsed.Hostname(),
				Path:   path,
			}
		}
	}
	if browserAuth != nil {
		for _, cookie := range browserAuth.Cookies {
			name := strings.TrimSpace(cookie.Name)
			value := strings.TrimSpace(cookie.Value)
			domain := strings.TrimSpace(cookie.Domain)
			if name == "" || value == "" || domain == "" {
				continue
			}
			if cookieDomainMatchesHost(domain, state.BaseHost) {
				continue
			}
			if shouldSkipBrowserPresetCookie(name) {
				continue
			}
			path := strings.TrimSpace(cookie.Path)
			if path == "" {
				path = "/"
			}
			key := strings.ToLower(domain) + "|" + name + "|" + path
			seen[key] = presetCookie{
				Name:   name,
				Value:  value,
				Domain: domain,
				Path:   path,
			}
		}
	}
	if len(seen) == 0 {
		return "", "", nil
	}

	cookies := make([]presetCookie, 0, len(seen))
	names := make([]string, 0, len(seen))
	for _, cookie := range seen {
		cookies = append(cookies, cookie)
		names = append(names, cookie.Name)
	}
	sort.Slice(cookies, func(i, j int) bool {
		if cookies[i].Name == cookies[j].Name {
			return cookies[i].Path < cookies[j].Path
		}
		return cookies[i].Name < cookies[j].Name
	})
	sort.Strings(names)

	data, marshalErr := json.Marshal(cookies)
	if marshalErr != nil {
		return "", "", fmt.Errorf("marshal preset browser cookies: %w", marshalErr)
	}
	return string(data), strings.Join(names, ", "), nil
}

func shouldIncludeStateBrowserPresetCookie(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "sdesktop", "webvpnlogin", "webvpnlang":
		return true
	default:
		return false
	}
}

func shouldSkipBrowserPresetCookie(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "acsamlv2token", "webvpn":
		return true
	default:
		return false
	}
}

func extractBaseHost(server string, ssoLoginURL string) string {
	if trimmed := strings.TrimSpace(ssoLoginURL); trimmed != "" {
		if parsed, err := http.NewRequest(http.MethodGet, trimmed, nil); err == nil && parsed.URL.Host != "" {
			return parsed.URL.Host
		}
	}
	if parsed, err := http.NewRequest(http.MethodGet, "https://"+server, nil); err == nil && parsed.URL.Host != "" {
		return parsed.URL.Host
	}
	return strings.Split(strings.TrimSpace(server), "/")[0]
}

func extractXMLTag(body string, tag string) string {
	startTag := "<" + tag + ">"
	endTag := "</" + tag + ">"
	start := strings.Index(body, startTag)
	if start < 0 {
		return ""
	}
	start += len(startTag)
	end := strings.Index(body[start:], endTag)
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(body[start : start+end])
}

func extractLastXMLTag(body string, tag string) string {
	startTag := "<" + tag + ">"
	endTag := "</" + tag + ">"
	start := strings.LastIndex(body, startTag)
	if start < 0 {
		return ""
	}
	start += len(startTag)
	end := strings.Index(body[start:], endTag)
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(body[start : start+end])
}

func extractXMLElement(body string, startPrefix string, endTag string) string {
	start := strings.Index(body, startPrefix)
	if start < 0 {
		return ""
	}
	end := strings.Index(body[start:], endTag)
	if end < 0 {
		return ""
	}
	end += start + len(endTag)
	return strings.TrimSpace(body[start:end])
}

func prepareOpenConnectAuthHelpers(ocPath string, server string, options ConnectOptions, logWriter io.Writer) (*authHelperSpec, error) {
	authMode := strings.ToLower(strings.TrimSpace(options.Auth))
	useBrowserWrapper := authMode == "" || authMode == "saml" || authMode == "openconnect"
	csdPostPath := findOpenConnectCSDPostScript(ocPath)
	nativeCSD, nativeErr := resolveNativeCSDConfigForServer(server)
	if !useBrowserWrapper && csdPostPath == "" && nativeCSD == nil {
		return &authHelperSpec{}, nil
	}

	helperDir, err := os.MkdirTemp("", "openconnect-auth-")
	if err != nil {
		return nil, fmt.Errorf("create auth helper dir: %w", err)
	}
	cleanup := func() {
		_ = os.RemoveAll(helperDir)
	}

	spec := &authHelperSpec{Cleanup: cleanup}

	if useBrowserWrapper {
		browserWrapperPath := filepath.Join(helperDir, "external-browser.sh")
		if err := writeExecutableFile(browserWrapperPath, externalBrowserWrapperScript()); err != nil {
			cleanup()
			return nil, err
		}
		spec.Args = append(spec.Args, "--external-browser", browserWrapperPath)

		vpnAuthPath, vpnAuthErr := execLookPathOpenConnect("vpn-auth")
		pythonPath, pythonErr := execLookPathOpenConnect("python3")
		curlPath, curlErr := execLookPathOpenConnect("curl")
		if vpnAuthErr == nil && pythonErr == nil && curlErr == nil {
			spec.Env = append(spec.Env,
				"OPENCONNECT_TUN_BROWSER_MODE=vpn_auth",
				"OPENCONNECT_TUN_VPN_AUTH_BIN="+vpnAuthPath,
				"OPENCONNECT_TUN_JSON_PYTHON="+pythonPath,
				"OPENCONNECT_TUN_CURL_BIN="+curlPath,
			)
			if options.Credentials.Username != "" {
				spec.Env = append(spec.Env, "OPENCONNECT_TUN_VPN_AUTH_USERNAME="+options.Credentials.Username)
			}
			if options.Credentials.Password != "" {
				spec.Env = append(spec.Env, "OPENCONNECT_TUN_VPN_AUTH_PASSWORD="+options.Credentials.Password)
			}
			if options.Credentials.TOTPSecret != "" {
				spec.Env = append(spec.Env, "OPENCONNECT_TUN_VPN_AUTH_TOTP_SECRET="+options.Credentials.TOTPSecret)
			}
			writeLogf(logWriter, "authenticate_external_browser: %s (vpn-auth)", browserWrapperPath)
		} else {
			openPath, err := execLookPathOpenConnect("open")
			if err != nil {
				cleanup()
				return nil, fmt.Errorf("no browser launcher available for SAML flow (vpn-auth=%v python3=%v curl=%v open=%w)", vpnAuthErr, pythonErr, curlErr, err)
			}
			spec.Env = append(spec.Env,
				"OPENCONNECT_TUN_BROWSER_MODE=open",
				"OPENCONNECT_TUN_OPEN_BIN="+openPath,
			)
			writeLogf(logWriter, "authenticate_external_browser: %s (system browser fallback)", browserWrapperPath)
		}
	}

	if nativeErr != nil {
		writeLogf(logWriter, "authenticate_csd_native_unavailable: %v", nativeErr)
	}

	if csdPostPath != "" || nativeCSD != nil {
		csd, err := prepareCSDWrapperWithDir(csdPostPath, helperDir, nativeCSD)
		if err != nil {
			cleanup()
			return nil, err
		}
		spec.Args = append(spec.Args, "--csd-wrapper", csd.WrapperPath)
		spec.Env = append(spec.Env, csd.Env...)
		switch {
		case nativeCSD != nil:
			writeLogf(logWriter, "authenticate_csd_wrapper: native libcsd via %s", nativeCSD.LibPath)
			writeLogf(logWriter, "authenticate_csd_native: host=%s fqdn=%s group=%s url=%s", nativeCSD.HostURL, nativeCSD.FQDN, nativeCSD.Group, nativeCSD.ResultURL)
		case csdPostPath != "":
			writeLogf(logWriter, "authenticate_csd_wrapper: %s", csdPostPath)
		}
	}

	return spec, nil
}

type csdWrapperSpec struct {
	WrapperPath string
	TokenPath   string
	Env         []string
	Cleanup     func()
}

func prepareCSDWrapper(ocPath string, server string) (*csdWrapperSpec, error) {
	csdPostPath := findOpenConnectCSDPostScript(ocPath)
	var nativeCSD *nativeCSDConfig
	if strings.TrimSpace(server) != "" {
		nativeCSD, _ = resolveNativeCSDConfigForServer(server)
	}
	if csdPostPath == "" && nativeCSD == nil {
		return nil, fmt.Errorf("csd-post.sh not found")
	}
	helperDir, err := os.MkdirTemp("", "openconnect-csd-")
	if err != nil {
		return nil, fmt.Errorf("create CSD helper dir: %w", err)
	}
	spec, err := prepareCSDWrapperWithDir(csdPostPath, helperDir, nativeCSD)
	if err != nil {
		_ = os.RemoveAll(helperDir)
		return nil, err
	}
	spec.Cleanup = func() {
		_ = os.RemoveAll(helperDir)
	}
	return spec, nil
}

func prepareCSDWrapperWithDir(csdPostPath string, helperDir string, native *nativeCSDConfig) (*csdWrapperSpec, error) {
	for name, content := range map[string]string{
		"csd-wrapper.sh": csdWrapperScript(),
		"csd-native.py":  nativeCSDPythonScript(),
		"curl":           curlShimScript(),
		"pidof":          pidofShimScript(),
		"stat":           statShimScript(),
		"xmlstarlet":     xmlstarletShimScript(),
	} {
		if err := writeExecutableFile(filepath.Join(helperDir, name), content); err != nil {
			return nil, err
		}
	}
	env := []string{}
	if strings.TrimSpace(csdPostPath) != "" {
		env = append(env, "OPENCONNECT_TUN_CSD_POST_BIN="+csdPostPath)
	}
	if native != nil {
		env = append(env,
			"OPENCONNECT_TUN_NATIVE_CSD_LIB="+native.LibPath,
			"OPENCONNECT_TUN_NATIVE_CSD_PYTHON="+native.PythonPath,
			"OPENCONNECT_TUN_NATIVE_CSD_HOST="+native.HostURL,
			"OPENCONNECT_TUN_NATIVE_CSD_FQDN="+native.FQDN,
			"OPENCONNECT_TUN_NATIVE_CSD_GROUP="+native.Group,
			"OPENCONNECT_TUN_NATIVE_CSD_URL="+native.ResultURL,
			"OPENCONNECT_TUN_NATIVE_CSD_SERVER_CERTHASH="+native.ServerCertHash,
			"OPENCONNECT_TUN_NATIVE_CSD_ALLOW_UPDATES="+firstNonEmpty(native.AllowUpdates, "1"),
			"OPENCONNECT_TUN_NATIVE_CSD_LANGSEL="+firstNonEmpty(native.LangSel, "langselen"),
			"OPENCONNECT_TUN_NATIVE_CSD_VPNCLIENT="+firstNonEmpty(native.VPNClient, "1"),
		)
	}
	return &csdWrapperSpec{
		WrapperPath: filepath.Join(helperDir, "csd-wrapper.sh"),
		TokenPath:   filepath.Join(helperDir, "csd-token.txt"),
		Env:         env,
	}, nil
}

type authStageWriter struct {
	logWriter      io.Writer
	progressWriter io.Writer
	pending        string
	lastStage      string
	hasTOTP        bool
}

func newAuthStageWriter(logWriter, progressWriter io.Writer, hasTOTP bool) *authStageWriter {
	return &authStageWriter{
		logWriter:      logWriter,
		progressWriter: progressWriter,
		hasTOTP:        hasTOTP,
	}
}

func (w *authStageWriter) Write(p []byte) (int, error) {
	if w.logWriter != nil {
		_, _ = w.logWriter.Write(p)
	}
	if w.progressWriter == nil {
		return len(p), nil
	}

	w.pending += string(p)
	for {
		idx := strings.IndexByte(w.pending, '\n')
		if idx < 0 {
			break
		}
		line := strings.TrimSpace(w.pending[:idx])
		w.pending = w.pending[idx+1:]
		w.emitStage(line)
	}
	return len(p), nil
}

func (w *authStageWriter) Flush() {
	if w.progressWriter == nil {
		return
	}
	line := strings.TrimSpace(w.pending)
	w.pending = ""
	w.emitStage(line)
}

func (w *authStageWriter) emitStage(line string) {
	if line == "" {
		return
	}
	stage := classifyAuthStage(line, w.hasTOTP)
	if stage == "" || stage == w.lastStage {
		return
	}
	w.lastStage = stage
	writeProgressf(w.progressWriter, "auth_stage: %s", stage)
}

func classifyAuthStage(line string, hasTOTP bool) string {
	normalized := strings.ToLower(strings.TrimSpace(line))
	switch {
	case strings.Contains(normalized, "full flow: fetching saml config"):
		return "fetching_saml_config"
	case strings.Contains(normalized, "manual mode"):
		return "manual_login_required"
	case strings.Contains(normalized, "auto-login mode"):
		return "auto_login_enabled"
	case strings.Contains(normalized, "page type: login"):
		return "login_page"
	case strings.Contains(normalized, "auto-filling credentials"):
		return "autofilling_credentials"
	case strings.Contains(normalized, "page type: otp") && hasTOTP:
		return "otp_page_autofilling_totp"
	case strings.Contains(normalized, "page type: otp"):
		return "otp_page_waiting_for_second_factor"
	default:
		return ""
	}
}

func logAuthResult(logWriter io.Writer, source string, result *authResult) {
	if result == nil {
		return
	}
	writeLogf(logWriter, "%s host: %s", source, result.Host)
	if result.ConnectURL != "" {
		writeLogf(logWriter, "%s connect_url: %s", source, result.ConnectURL)
	}
	if result.Resolve != "" {
		writeLogf(logWriter, "%s resolve: %s", source, result.Resolve)
	}
	if result.Fingerprint != "" {
		writeLogf(logWriter, "%s fingerprint: present", source)
	}
}

func parseAuthenticateOutput(output string) (*authResult, error) {
	values := parseShellVariables(output)
	result := &authResult{
		Cookie:      values["COOKIE"],
		Host:        values["HOST"],
		ConnectURL:  values["CONNECT_URL"],
		Fingerprint: values["FINGERPRINT"],
		Resolve:     values["RESOLVE"],
	}
	if result.Cookie == "" {
		return nil, fmt.Errorf("no COOKIE in openconnect authenticate output")
	}
	return result, nil
}

func parseShellVariables(output string) map[string]string {
	result := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		result[parts[0]] = strings.Trim(parts[1], "'\"")
	}
	return result
}

func connectWithCookie(auth *authResult, ocPath, script string, logWriter io.Writer, privilegedMode string, helperCfg PrivilegedHelperConfig) (int, string, error) {
	connectURL := auth.ConnectURL
	if connectURL == "" {
		connectURL = fmt.Sprintf("https://%s", auth.Host)
	}

	clientProfile := detectAggregateAuthClientProfile()
	localHostname := detectOpenConnectLocalHostname(clientProfile)
	cmdArgs := appendOpenConnectClientIdentityArgs([]string{
		ocPath,
		"--cookie-on-stdin",
		"--protocol=anyconnect",
		"--background",
	}, clientProfile, localHostname)
	if script != "" {
		cmdArgs = append(cmdArgs, "--script", script)
	}
	if auth.Fingerprint != "" {
		cmdArgs = append(cmdArgs, "--servercert", auth.Fingerprint)
	}
	if auth.Resolve != "" {
		cmdArgs = append(cmdArgs, "--resolve", auth.Resolve)
	}
	cmdArgs = append(cmdArgs, connectURL)

	switch privilegedMode {
	case PrivilegedModeHelper:
		writeLogf(logWriter, "connect_command: helper %s", strings.Join(cmdArgs, " "))
		if err := helperConnect(helperCfg, cmdArgs, auth.Cookie, currentLogPath(logWriter)); err != nil {
			return 0, "", fmt.Errorf("openconnect failed: %w", err)
		}
	default:
		execName, execArgs := elevatedCommand(privilegedMode, cmdArgs...)
		writeLogf(logWriter, "connect_command: %s", strings.Join(append([]string{execName}, execArgs...), " "))

		ctx, cancel := context.WithTimeout(context.Background(), openconnectTimeout)
		defer cancel()

		cmd := execCommandContext(ctx, execName, execArgs...)
		cmd.Stdin = strings.NewReader(auth.Cookie + "\n")
		cmd.Stdout = logWriter
		cmd.Stderr = logWriter

		err := cmd.Run()
		if ctx.Err() == context.DeadlineExceeded {
			err = fmt.Errorf("timed out after %s", openconnectTimeout)
		}
		if err != nil {
			return 0, "", fmt.Errorf("openconnect failed: %w", err)
		}
	}

	pid, err := findOpenConnectPID()
	if err != nil {
		return 0, "", err
	}
	return pid, findOpenConnectInterface(pid), nil
}

func buildOpenConnectCommandPreview(ocPath, server, script string, privilegedMode string) []string {
	clientProfile := detectAggregateAuthClientProfile()
	localHostname := detectOpenConnectLocalHostname(clientProfile)
	command := appendOpenConnectClientIdentityArgs([]string{
		ocPath,
		"--cookie-on-stdin",
		"--protocol=anyconnect",
		"--background",
	}, clientProfile, localHostname)
	if script != "" {
		command = append(command, "--script", script)
	}
	command = append(command, fmt.Sprintf("https://%s", server))
	if privilegedMode != PrivilegedModeSudo {
		return command
	}
	return append([]string{"sudo", "-n"}, command...)
}

func findOpenConnectPID() (int, error) {
	out, err := execCommandOpenConnect("pgrep", "-x", "openconnect").Output()
	if err != nil {
		return 0, fmt.Errorf("openconnect process not found")
	}
	return findOpenConnectPIDFromOutput(string(out))
}

func findOpenConnectPIDFromOutput(output string) (int, error) {
	lines := strings.Fields(strings.TrimSpace(output))
	if len(lines) == 0 {
		return 0, fmt.Errorf("openconnect process not found")
	}
	pid, err := strconv.Atoi(lines[len(lines)-1])
	if err != nil {
		return 0, fmt.Errorf("invalid openconnect pid: %w", err)
	}
	return pid, nil
}

func findOpenConnectCSDPostScript(ocPath string) string {
	seen := map[string]struct{}{}
	addCandidate := func(candidates *[]string, path string) {
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		path = filepath.Clean(path)
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = struct{}{}
		*candidates = append(*candidates, path)
	}

	candidates := []string{}
	resolvedPath := ""
	if strings.TrimSpace(ocPath) != "" {
		if realPath, err := filepath.EvalSymlinks(ocPath); err == nil {
			resolvedPath = realPath
		}
	}

	for _, path := range []string{resolvedPath, ocPath} {
		addCandidate(&candidates, deriveOpenConnectOptLibexecPath(path))
	}
	for _, path := range []string{resolvedPath, ocPath} {
		addCandidate(&candidates, deriveOpenConnectInstallLibexecPath(path))
	}
	addCandidate(&candidates, "/opt/homebrew/opt/openconnect/libexec/openconnect/csd-post.sh")
	addCandidate(&candidates, "/usr/local/opt/openconnect/libexec/openconnect/csd-post.sh")
	addCandidate(&candidates, "/usr/libexec/openconnect/csd-post.sh")

	for _, candidate := range candidates {
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}

func deriveOpenConnectOptLibexecPath(ocPath string) string {
	if strings.TrimSpace(ocPath) == "" {
		return ""
	}
	clean := filepath.Clean(ocPath)
	marker := filepath.Join("Cellar", "openconnect")
	idx := strings.Index(clean, marker)
	if idx < 0 {
		return ""
	}
	root := strings.TrimRight(clean[:idx], string(os.PathSeparator))
	if root == "" {
		root = string(os.PathSeparator)
	}
	return filepath.Join(root, "opt", "openconnect", "libexec", "openconnect", "csd-post.sh")
}

func deriveOpenConnectInstallLibexecPath(ocPath string) string {
	if strings.TrimSpace(ocPath) == "" {
		return ""
	}
	if filepath.Base(ocPath) != "openconnect" {
		return ""
	}
	binDir := filepath.Dir(ocPath)
	if filepath.Base(binDir) != "bin" {
		return ""
	}
	return filepath.Join(filepath.Dir(binDir), "libexec", "openconnect", "csd-post.sh")
}

func findVPNCScript() string {
	candidates := []string{
		"/opt/homebrew/etc/vpnc/vpnc-script",
		"/usr/local/etc/vpnc/vpnc-script",
		"/etc/vpnc/vpnc-script",
	}
	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

func findOpenConnectInterface(pid int) string {
	out, err := execCommandOpenConnect("ifconfig").Output()
	if err != nil {
		return ""
	}

	var lastUtun string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "utun") && strings.Contains(line, ":") {
			lastUtun = strings.SplitN(line, ":", 2)[0]
		}
		if lastUtun != "" && strings.Contains(line, "inet ") &&
			!strings.Contains(line, "127.0.0.1") &&
			!strings.Contains(line, "inet6 fe80") {
			if isVPNInterface(lastUtun) {
				return lastUtun
			}
		}
	}
	return ""
}

func findTrackedOpenConnectInterface(pid int) string {
	if pid <= 0 {
		return ""
	}
	current, err := LoadCurrent(ResolveCacheDir(""))
	if err != nil || current.PID != pid {
		return ""
	}
	return firstNonEmpty(findOpenConnectInterfaceFromLog(current.LogPath), current.Interface)
}

func findOpenConnectInterfaceFromLog(logPath string) string {
	logPath = strings.TrimSpace(logPath)
	if logPath == "" {
		return ""
	}
	file, err := os.Open(logPath)
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var lastIface string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.Contains(line, "InterfaceName :"):
			iface := strings.TrimSpace(strings.TrimPrefix(line, "InterfaceName :"))
			if strings.HasPrefix(iface, "utun") {
				lastIface = iface
			}
		case strings.HasPrefix(line, "TUNDEV="):
			iface := strings.TrimSpace(strings.TrimPrefix(line, "TUNDEV="))
			if strings.HasPrefix(iface, "utun") {
				lastIface = iface
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return ""
	}
	return lastIface
}

func isVPNInterface(iface string) bool {
	out, err := execCommandOpenConnect("ifconfig", iface).Output()
	if err != nil {
		return false
	}
	output := string(out)
	return strings.Contains(output, "inet ") &&
		(strings.Contains(output, "inet 10.") ||
			strings.Contains(output, "inet 172.") ||
			strings.Contains(output, "inet 192.168."))
}

func getProcessUptime(pid int) string {
	out, err := execCommandOpenConnect("ps", "-o", "etime=", "-p", fmt.Sprintf("%d", pid)).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func getRoutesForInterface(iface string) []string {
	out, err := execCommandOpenConnect("netstat", "-rn", "-f", "inet").Output()
	if err != nil {
		return []string{}
	}
	routes := []string{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[3] != iface {
			continue
		}
		dest := fields[0]
		if dest == "default" {
			routes = append(routes, "0.0.0.0/0")
			continue
		}
		if cidr := destToCIDR(dest); cidr != "" {
			routes = append(routes, cidr)
		}
	}
	return routes
}

func destToCIDR(dest string) string {
	if strings.Contains(dest, "/") {
		return dest
	}
	if !strings.Contains(dest, ".") {
		return ""
	}
	parts := strings.Split(dest, ".")
	switch len(parts) {
	case 4:
		return dest + "/32"
	case 3:
		return dest + ".0/24"
	case 2:
		return dest + ".0.0/16"
	case 1:
		return dest + ".0.0.0/8"
	default:
		return ""
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func ensureSudoCredentials() error {
	if os.Geteuid() == 0 {
		return nil
	}
	cmd := execCommandOpenConnect("sudo", "-n", "true")
	if err := cmd.Run(); err == nil {
		return nil
	}
	if !stdinSupportsPromptOpenConnect() {
		return fmt.Errorf("sudo credentials are not cached; run `sudo -v` in an interactive shell and retry")
	}
	cmd = execCommandOpenConnect("sudo", "-v")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func elevatedCommand(mode string, args ...string) (string, []string) {
	if os.Geteuid() == 0 || mode != PrivilegedModeSudo {
		return args[0], args[1:]
	}
	return "sudo", append([]string{"-n"}, args...)
}

func interruptOpenConnectPID(pid int, mode string, helperSocketPath string) error {
	return signalOpenConnectPID(pid, "-INT", mode, helperSocketPath)
}

func terminateOpenConnectPID(pid int, mode string, helperSocketPath string) error {
	return signalOpenConnectPID(pid, "-TERM", mode, helperSocketPath)
}

func killOpenConnectPID(pid int, mode string, helperSocketPath string) error {
	return signalOpenConnectPID(pid, "-KILL", mode, helperSocketPath)
}

func signalOpenConnectPID(pid int, signal string, mode string, helperSocketPath string) error {
	if pid <= 0 {
		return nil
	}
	if shouldUseHelperSignal(mode, helperSocketPath) {
		return helperSignal(defaultHelperConfigForSocket(helperSocketPath), pid, signal)
	}
	if mode == PrivilegedModeSudo {
		if err := ensureSudoCredentials(); err != nil {
			return fmt.Errorf("sudo authentication: %w", err)
		}
	}
	execName, execArgs := elevatedCommand(mode, "kill", signal, fmt.Sprintf("%d", pid))
	return execCommandOpenConnect(execName, execArgs...).Run()
}

func execCommandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, name, args...)
}

func writeExecutableFile(path string, content string) error {
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		return fmt.Errorf("write helper %s: %w", path, err)
	}
	return nil
}

func externalBrowserWrapperScript() string {
	return `#!/bin/sh
set -eu

if [ "$#" -lt 1 ]; then
  echo "external-browser wrapper requires URL argument" >&2
  exit 1
fi

url=$1
browser_mode=${OPENCONNECT_TUN_BROWSER_MODE:-vpn_auth}
if [ "$browser_mode" = "open" ]; then
  open_bin=${OPENCONNECT_TUN_OPEN_BIN:-open}
  exec "$open_bin" "$url"
fi

vpn_auth_bin=${OPENCONNECT_TUN_VPN_AUTH_BIN:-vpn-auth}
json_python=${OPENCONNECT_TUN_JSON_PYTHON:-python3}
curl_bin=${OPENCONNECT_TUN_CURL_BIN:-curl}

set -- "$vpn_auth_bin" --url "$url"
if [ -n "${OPENCONNECT_TUN_VPN_AUTH_USERNAME:-}" ]; then
  set -- "$@" --username "$OPENCONNECT_TUN_VPN_AUTH_USERNAME"
fi
if [ -n "${OPENCONNECT_TUN_VPN_AUTH_PASSWORD:-}" ]; then
  set -- "$@" --password "$OPENCONNECT_TUN_VPN_AUTH_PASSWORD"
fi
if [ -n "${OPENCONNECT_TUN_VPN_AUTH_TOTP_SECRET:-}" ]; then
  set -- "$@" --totp-secret "$OPENCONNECT_TUN_VPN_AUTH_TOTP_SECRET"
fi

if ! result=$("$@"); then
  echo "vpn-auth external-browser helper failed" >&2
  exit 1
fi

if ! callback_url=$(printf '%s' "$result" | "$json_python" -c 'import json, sys, urllib.parse
data = json.load(sys.stdin)
url = data.get("url", "")
if url:
    print(url)
    raise SystemExit(0)
cookie = data.get("cookie", "")
if cookie:
    print("http://localhost:29786/api/sso/" + urllib.parse.quote(cookie, safe=""))
    raise SystemExit(0)
raise SystemExit(1)
'); then
  echo "vpn-auth external-browser helper did not return a callback URL" >&2
  exit 1
fi

case "$callback_url" in
  http://localhost:29786/*|http://[::1]:29786/*)
    ;;
  *)
    echo "vpn-auth external-browser helper returned unexpected callback URL: $callback_url" >&2
    exit 1
    ;;
esac

"$curl_bin" --silent --show-error "$callback_url" >/dev/null
`
}

func csdWrapperScript() string {
	return `#!/bin/bash
set -eu

helper_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
csd_post_bin=${OPENCONNECT_TUN_CSD_POST_BIN:-}
native_python=${OPENCONNECT_TUN_NATIVE_CSD_PYTHON:-}
native_lib=${OPENCONNECT_TUN_NATIVE_CSD_LIB:-}

if [ -n "$native_python" ] && [ -n "$native_lib" ]; then
  exec "$native_python" "$helper_dir/csd-native.py" "$@"
fi

if [ -z "$csd_post_bin" ]; then
  echo "neither native libcsd nor OPENCONNECT_TUN_CSD_POST_BIN is configured" >&2
  exit 1
fi

args=()
rewrite_stub=0
for arg in "$@"; do
  if [ "$rewrite_stub" -eq 1 ]; then
    args+=("0")
    rewrite_stub=0
    continue
  fi
  if [ "$arg" = "-stub" ]; then
    args+=("$arg")
    rewrite_stub=1
    continue
  fi
  args+=("$arg")
done

PATH="$helper_dir:$PATH" exec "$csd_post_bin" "${args[@]}"
`
}

func nativeCSDPythonScript() string {
	return `#!/usr/bin/env python3
import ctypes
import os
import sys


ARG_ALLOW_UPDATES = 35
ARG_TICKET = 37
ARG_LANGSEL = 48
ARG_STUB = 49
ARG_GROUP = 50
ARG_VPNCLIENT = 51
ARG_HOST = 34
ARG_URL = 52
ARG_SERVER_CERTHASH = 53
ARG_FQDN = 56


def parse_ticket(argv):
    ticket = ""
    skip_next = False
    for idx, arg in enumerate(argv):
        if skip_next:
            skip_next = False
            continue
        if arg == "-ticket" and idx + 1 < len(argv):
            return argv[idx + 1]
        if arg == "-stub":
            skip_next = True
    return ticket


def require_env(name):
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"native libcsd helper missing {name}")
    return value


def set_arg(lib, arg_id, value):
    encoded = str(value).encode("utf-8")
    rc = lib.csd_setarg(arg_id, ctypes.c_char_p(encoded))
    if rc != 0:
        raise SystemExit(f"native libcsd csd_setarg({arg_id}) failed with {rc}")


def main():
    ticket = parse_ticket(sys.argv[1:])
    if not ticket:
        raise SystemExit("native libcsd helper missing -ticket")

    lib_path = require_env("OPENCONNECT_TUN_NATIVE_CSD_LIB")
    host = require_env("OPENCONNECT_TUN_NATIVE_CSD_HOST")
    fqdn = require_env("OPENCONNECT_TUN_NATIVE_CSD_FQDN")
    group = require_env("OPENCONNECT_TUN_NATIVE_CSD_GROUP")
    result_url = require_env("OPENCONNECT_TUN_NATIVE_CSD_URL")
    server_certhash = require_env("OPENCONNECT_TUN_NATIVE_CSD_SERVER_CERTHASH")
    allow_updates = os.environ.get("OPENCONNECT_TUN_NATIVE_CSD_ALLOW_UPDATES", "1").strip() or "1"
    langsel = os.environ.get("OPENCONNECT_TUN_NATIVE_CSD_LANGSEL", "langselen").strip() or "langselen"
    vpnclient = os.environ.get("OPENCONNECT_TUN_NATIVE_CSD_VPNCLIENT", "1").strip() or "1"

    sys.stderr.write(
        f"openconnect-tun native libcsd start host={host} fqdn={fqdn} group={group} ticket={ticket}\n"
    )

    lib = ctypes.CDLL(lib_path)
    lib.csd_init.restype = ctypes.c_int
    lib.csd_setarg.argtypes = [ctypes.c_int, ctypes.c_char_p]
    lib.csd_setarg.restype = ctypes.c_int
    lib.csd_prelogin.restype = ctypes.c_int
    lib.csd_run.restype = ctypes.c_int
    lib.csd_free.restype = ctypes.c_int
    try:
        lib.csd_detach.restype = ctypes.c_int
    except AttributeError:
        lib.csd_detach = None

    if lib.csd_init() != 0:
        raise SystemExit("native libcsd csd_init failed")

    success = False
    detached = False
    try:
        set_arg(lib, ARG_ALLOW_UPDATES, allow_updates)
        set_arg(lib, ARG_HOST, host)
        set_arg(lib, ARG_TICKET, ticket)
        set_arg(lib, ARG_LANGSEL, langsel)
        set_arg(lib, ARG_STUB, "0")
        set_arg(lib, ARG_GROUP, group)
        set_arg(lib, ARG_VPNCLIENT, vpnclient)
        set_arg(lib, ARG_URL, result_url)
        set_arg(lib, ARG_SERVER_CERTHASH, server_certhash)
        set_arg(lib, ARG_FQDN, fqdn)

        prelogin_rc = lib.csd_prelogin()
        if prelogin_rc != 0:
            raise SystemExit(f"native libcsd csd_prelogin failed with {prelogin_rc}")

        run_rc = lib.csd_run()
        if run_rc != 0:
            raise SystemExit(f"native libcsd csd_run failed with {run_rc}")
        success = True

        if lib.csd_detach is not None:
            detach_rc = lib.csd_detach()
            if detach_rc != 0:
                sys.stderr.write(f"openconnect-tun native libcsd detach_rc={detach_rc}; keeping context resident\n")
            else:
                detached = True
                sys.stderr.write("openconnect-tun native libcsd detached scanner lifecycle from helper\n")
        else:
            sys.stderr.write("openconnect-tun native libcsd has no csd_detach; keeping context resident\n")
    finally:
        if not success:
            free_rc = lib.csd_free()
            if free_rc != 0:
                sys.stderr.write(f"openconnect-tun native libcsd free_rc={free_rc}\n")
        elif not detached:
            sys.stderr.write("openconnect-tun native libcsd skipping csd_free after successful run\n")

    sys.stdout.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
    sys.stdout.write("<hostscan><status>TOKEN_SUCCESS</status></hostscan>\n")


if __name__ == "__main__":
    main()
`
}

func pidofShimScript() string {
	return `#!/bin/sh
set -eu

if [ "$#" -lt 1 ]; then
  exit 1
fi

exec pgrep -x "$1"
`
}

func statShimScript() string {
	return `#!/bin/sh
set -eu

if [ "$#" -eq 3 ] && [ "$1" = "-c" ] && [ "$2" = "%Y" ]; then
  exec /usr/bin/stat -f %m "$3"
fi

exec /usr/bin/stat "$@"
`
}

func xmlstarletShimScript() string {
	return `#!/bin/sh
set -eu

if [ "$#" -eq 1 ] && [ "$1" = "--version" ]; then
  echo "xmlstarlet shim 1.0"
  exit 0
fi

if [ "$#" -eq 4 ] && [ "$1" = "sel" ] && [ "$2" = "-t" ] && [ "$3" = "-v" ]; then
  xpath=$4
  exec python3 -c '
import sys
import xml.etree.ElementTree as ET

xpath = sys.argv[1]
data = sys.stdin.read()
root = ET.fromstring(data)

if xpath == "/hostscan/token":
    node = root.find("./token")
    if node is not None and node.text is not None:
        sys.stdout.write(node.text)
    raise SystemExit(0)

if xpath == "/data/hostscan/field/@value":
    for field in root.findall("./hostscan/field"):
        value = field.attrib.get("value")
        if value:
            sys.stdout.write(value + "\n")
    raise SystemExit(0)

raise SystemExit(1)
' "$xpath"
fi

echo "xmlstarlet shim does not support: $*" >&2
exit 1
`
}

func curlShimScript() string {
	return `#!/bin/sh
set -eu

helper_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
real_curl_bin=${OPENCONNECT_TUN_REAL_CURL_BIN:-/usr/bin/curl}
data_cache="$helper_dir/csd-data.xml"
wa_diagnose_path=${OPENCONNECT_TUN_WA_DIAGNOSE_PATH:-${HOME:-}/.cisco/hostscan/log/waDiagnose.txt}

url=
data_binary=
need_data_binary=0
for arg in "$@"; do
  if [ "$need_data_binary" -eq 1 ]; then
    data_binary=$arg
    need_data_binary=0
    continue
  fi
  case "$arg" in
    --data-binary)
      need_data_binary=1
      ;;
    --data-binary=*)
      data_binary=${arg#--data-binary=}
      ;;
    http://*|https://*)
      url=$arg
      ;;
  esac
done

case "$url" in
  */+CSCOE+/sdesktop/token.xml*)
    tmp=$(mktemp "$helper_dir/curl-token.XXXXXX")
    if "$real_curl_bin" "$@" >"$tmp"; then
      cp "$tmp" "$helper_dir/csd-token.xml"
      /usr/bin/python3 - "$tmp" "$helper_dir/csd-token.txt" <<'PY'
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

token_xml = Path(sys.argv[1])
token_txt = Path(sys.argv[2])

try:
    root = ET.fromstring(token_xml.read_text(encoding="utf-8"))
except Exception:
    raise SystemExit(0)

node = root.find("./token")
if node is not None and node.text:
    token_txt.write_text(node.text.strip(), encoding="utf-8")
PY
      cat "$tmp"
      rm -f "$tmp"
      exit 0
    fi
    rc=$?
    cat "$tmp" || true
    rm -f "$tmp"
    exit "$rc"
    ;;
  */CACHE/sdesktop/data.xml)
    tmp=$(mktemp "$helper_dir/curl-data.XXXXXX")
    if "$real_curl_bin" "$@" >"$tmp"; then
      cp "$tmp" "$data_cache"
      cat "$tmp"
      rm -f "$tmp"
      exit 0
    fi
    rc=$?
    cat "$tmp" || true
    rm -f "$tmp"
    exit "$rc"
    ;;
  */+CSCOE+/sdesktop/scan.xml*)
    case "$data_binary" in
      @*)
        response_file=${data_binary#@}
        if [ -f "$response_file" ] && [ -f "$data_cache" ]; then
          /usr/bin/python3 - "$data_cache" "$response_file" "$wa_diagnose_path" <<'PY'
from pathlib import Path
import json
import sys
import xml.etree.ElementTree as ET

data_path = Path(sys.argv[1])
response_path = Path(sys.argv[2])
wa_diagnose_path = Path(sys.argv[3]).expanduser()

try:
    root = ET.parse(data_path).getroot()
except Exception:
    raise SystemExit(0)

lines = []
seen = set()

def add_line(line):
    if line not in seen:
        seen.add(line)
        lines.append(line)

def escape(value):
    return value.replace("\\", "\\\\").replace('"', '\\"')

def first_value(params, keys):
    for key in keys:
        value = params.get(key, "")
        if value:
            return value
    return ""

def normalize_scalar(value):
    if value is None:
        return ""
    return str(value).strip()

def normalize_timestamp(value):
    value = normalize_scalar(value)
    if value.isdigit():
        return value
    return "0"

def add_antimalware(product, lastupdate="0"):
    full_label = product.strip()
    if not full_label:
        return
    labels = [full_label]
    if "|" in full_label:
        labels.append(full_label.split("|", 1)[0].strip())
        version = full_label.split("|", 1)[1].strip()
    else:
        version = ""
    for label in labels:
        if not label:
            continue
        escaped_label = escape(label)
        add_line(f'endpoint.am["{escaped_label}"]={{}};')
        add_line(f'endpoint.am["{escaped_label}"].exists="true";')
        add_line(f'endpoint.am["{escaped_label}"].description="{escape(full_label)}";')
        if version:
            add_line(f'endpoint.am["{escaped_label}"].version="{escape(version)}";')
        add_line(f'endpoint.am["{escaped_label}"].lastupdate="{escape(normalize_timestamp(lastupdate))}";')

def add_firewall(label, version="", enabled=True):
    escaped_label = escape(label)
    add_line(f'endpoint.fw["{escaped_label}"]={{}};')
    add_line(f'endpoint.fw["{escaped_label}"].exists="true";')
    add_line(f'endpoint.fw["{escaped_label}"].description="{escape(label)}";')
    if version:
        add_line(f'endpoint.fw["{escaped_label}"].version="{escape(version)}";')
    if enabled is True:
        add_line(f'endpoint.fw["{escaped_label}"].enabled="ok";')
    elif enabled is False:
        add_line(f'endpoint.fw["{escaped_label}"].enabled="false";')

def add_device_protection(protected, protected_info):
    if not protected:
        return
    add_line('endpoint.device.protection="protected";')
    protected_info = normalize_scalar(protected_info)
    if protected_info:
        add_line(f'endpoint.device.protection_version="{escape(protected_info)}";')

def find_method_result(product, method_name):
    for method in product.get("methods") or []:
        if method.get("method_name") != method_name:
            continue
        result = method.get("result")
        if isinstance(result, dict):
            return result
    return None

def load_wa_diagnose(path):
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None

    antimalware = []
    antimalware_seen = set()
    firewalls = []
    firewalls_seen = set()

    for product in payload.get("detected_products") or []:
        if not isinstance(product, dict):
            continue
        sig_name = normalize_scalar(product.get("sig_name"))
        if not sig_name:
            continue

        version_result = find_method_result(product, "GetVersion") or {}
        version = normalize_scalar(version_result.get("version"))

        definition_result = find_method_result(product, "GetDefinitionState") or {}
        definition_entries = definition_result.get("definitions") or []
        added_from_definitions = False
        for definition in definition_entries:
            if not isinstance(definition, dict):
                continue
            if normalize_scalar(definition.get("type")) != "antimalware":
                continue
            definition_name = normalize_scalar(definition.get("name")) or sig_name
            definition_version = normalize_scalar(definition.get("version")) or version
            label = definition_name
            if definition_version:
                label = f"{definition_name}|{definition_version}"
            last_update = normalize_timestamp(definition.get("last_update"))
            key = (label, last_update)
            if key in antimalware_seen:
                continue
            antimalware_seen.add(key)
            antimalware.append({"label": label, "lastupdate": last_update})
            added_from_definitions = True

        realtime_result = find_method_result(product, "GetRealTimeProtectionState") or {}
        realtime_details = realtime_result.get("details")
        if (
            not added_from_definitions
            and realtime_result.get("enabled") is True
            and isinstance(realtime_details, dict)
            and (realtime_details.get("antivirus") or realtime_details.get("antispyware"))
        ):
            label = sig_name
            if version:
                label = f"{sig_name}|{version}"
            key = (label, "0")
            if key not in antimalware_seen:
                antimalware_seen.add(key)
                antimalware.append({"label": label, "lastupdate": "0"})

        firewall_result = find_method_result(product, "GetFirewallState") or {}
        if firewall_result.get("enabled") is True:
            key = sig_name
            if key not in firewalls_seen:
                firewalls_seen.add(key)
                firewalls.append({"label": sig_name, "version": version, "enabled": True})

    system_info = payload.get("system_info") or {}
    return {
        "protected": system_info.get("protected") is True,
        "protected_info": normalize_scalar(system_info.get("protected_info")),
        "antimalware": antimalware,
        "firewalls": firewalls,
    }

wa_diagnose = None
if wa_diagnose_path.is_file():
    wa_diagnose = load_wa_diagnose(wa_diagnose_path)

if wa_diagnose is not None:
    add_device_protection(wa_diagnose.get("protected"), wa_diagnose.get("protected_info"))
    for product in wa_diagnose.get("antimalware") or []:
        add_antimalware(product.get("label", ""), product.get("lastupdate", "0"))
    for firewall in wa_diagnose.get("firewalls") or []:
        add_firewall(firewall.get("label", ""), firewall.get("version", ""), firewall.get("enabled"))

if not (wa_diagnose and (wa_diagnose.get("antimalware") or wa_diagnose.get("firewalls"))):
    for field in root.findall("./hostscan/field"):
        value = field.attrib.get("value", "")
        if not value.startswith("secinsp_"):
            continue
        parts = value.split("~", 2)
        if len(parts) < 3:
            continue
        params = {}
        for item in parts[2].split(";"):
            if "=" not in item:
                continue
            key, raw_value = item.split("=", 1)
            params[key] = raw_value

        am_enforce = first_value(params, ["am_enforce.mac", "am_enforce"])
        am_count = first_value(params, ["am_count.mac", "am_count"])
        product = first_value(params, ["am_product.mac", "am_product"])
        if am_enforce == "1" and am_count not in ("", "0") and product:
            add_antimalware(product)

if lines:
    with response_path.open("a", encoding="utf-8") as fh:
        fh.write("\n")
        for line in lines:
            fh.write(line + "\n")
    sys.stderr.write("openconnect-tun csd augment start\n")
    for line in lines:
        sys.stderr.write(line + "\n")
    sys.stderr.write("openconnect-tun csd augment end\n")
PY
        fi
        ;;
    esac
    ;;
esac

exec "$real_curl_bin" "$@"
`
}

func writeLogf(logWriter io.Writer, format string, args ...any) {
	if logWriter == nil {
		return
	}
	_, _ = fmt.Fprintf(logWriter, format+"\n", args...)
}

func writeProgressf(progressWriter io.Writer, format string, args ...any) {
	if progressWriter == nil {
		return
	}
	_, _ = fmt.Fprintf(progressWriter, format+"\n", args...)
}

func formatConnectError(err error, logPath string) error {
	if last := LastRelevantLogLine(logPath); last != "" {
		return fmt.Errorf("%w; last_log_line: %s; inspect %s", err, last, logPath)
	}
	return fmt.Errorf("%w; inspect %s", err, logPath)
}

func resolveNativeCSDConfigForServer(server string) (*nativeCSDConfig, error) {
	parsed, err := parseHTTPSURL(server)
	if err != nil {
		return nil, err
	}
	return buildNativeCSDConfig(parsed.Hostname(), parsed.Port(), strings.Trim(parsed.Path, "/"))
}

func buildNativeCSDConfig(fqdn string, port string, group string) (*nativeCSDConfig, error) {
	fqdn = strings.TrimSpace(fqdn)
	if fqdn == "" {
		return nil, fmt.Errorf("native libcsd requires fqdn")
	}
	libPath := findCiscoLibCSD()
	if libPath == "" {
		return nil, fmt.Errorf("native libcsd not found")
	}
	pythonPath, err := execLookPathOpenConnect("python3")
	if err != nil {
		return nil, fmt.Errorf("python3 not found: %w", err)
	}
	resolvedHost, err := resolveNativeCSDHostURL(fqdn)
	if err != nil {
		return nil, err
	}
	fingerprint, err := serverCertSHA1OpenConnect(fqdn, port)
	if err != nil {
		return nil, err
	}
	return &nativeCSDConfig{
		LibPath:        libPath,
		PythonPath:     pythonPath,
		HostURL:        resolvedHost,
		FQDN:           fqdn,
		Group:          strings.TrimSpace(group),
		ResultURL:      fmt.Sprintf("https://%s/CACHE/sdesktop/install/result.htm", fqdn),
		ServerCertHash: "sha1:" + fingerprint,
		AllowUpdates:   "1",
		LangSel:        "langselen",
		VPNClient:      "1",
	}, nil
}

func parseHTTPSURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty server")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse server %q: %w", raw, err)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("server %q does not include host", raw)
	}
	return parsed, nil
}

func resolveOpenConnectAuthTarget(server string) (targetURL string, usergroup string) {
	targetURL = fmt.Sprintf("https://%s", strings.TrimSpace(server))
	parsed, err := parseHTTPSURL(targetURL)
	if err != nil || parsed.Host == "" {
		return targetURL, ""
	}
	usergroup = strings.Trim(parsed.Path, "/")
	return "https://" + parsed.Host, usergroup
}

func resolveNativeCSDHostURL(fqdn string) (string, error) {
	hosts, err := lookupOpenConnectHosts(fqdn)
	if err != nil {
		return "", fmt.Errorf("resolve native libcsd host %s: %w", fqdn, err)
	}
	selected := selectPreferredHost(hosts)
	if selected == "" {
		return "", fmt.Errorf("resolve native libcsd host %s: no usable addresses", fqdn)
	}
	if strings.Contains(selected, ":") && !strings.HasPrefix(selected, "[") {
		selected = "[" + selected + "]"
	}
	return "https://" + selected, nil
}

func resolveOpenConnectDialAddress(address string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", err
	}
	if ip := net.ParseIP(strings.Trim(strings.TrimSpace(host), "[]")); ip != nil {
		return address, nil
	}
	hosts, err := lookupOpenConnectHosts(host)
	if err != nil {
		return "", err
	}
	selected := selectPreferredHost(hosts)
	if selected == "" {
		return "", fmt.Errorf("resolve host %s: no usable addresses", host)
	}
	return net.JoinHostPort(selected, port), nil
}

func lookupOpenConnectHosts(host string) ([]string, error) {
	hosts, err := lookupHostOpenConnect(host)
	if len(hosts) > 0 {
		return hosts, nil
	}
	if fallback := systemLookupHostOpenConnect(host); len(fallback) > 0 {
		return fallback, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func lookupHostViaDSCacheutilOpenConnect(host string) []string {
	output := commandOutput("dscacheutil", "-q", "host", "-a", "name", strings.TrimSpace(host))
	if output == "" {
		return nil
	}
	seen := make(map[string]struct{})
	var hosts []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "ip_address:") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(line, "ip_address:"))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		hosts = append(hosts, value)
	}
	return hosts
}

func lookupHostViaSystemSourcesOpenConnect(host string) []string {
	if hosts := lookupHostViaDSCacheutilOpenConnect(host); len(hosts) > 0 {
		return hosts
	}
	return lookupHostAliasesCacheOpenConnect(host)
}

func lookupHostAliasesCacheOpenConnect(host string) []string {
	cachePath := filepath.Join(ResolveCacheDir(""), "host-aliases.json")
	raw, err := os.ReadFile(cachePath)
	if err != nil {
		return nil
	}
	aliases := map[string][]string{}
	if err := json.Unmarshal(raw, &aliases); err != nil {
		return nil
	}
	values := aliases[strings.ToLower(strings.TrimSpace(host))]
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{})
	var hosts []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		hosts = append(hosts, value)
	}
	return hosts
}

func resolveOpenConnectResolve(server string) string {
	parsed, err := parseHTTPSURL(server)
	if err != nil {
		return ""
	}
	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return ""
	}
	hosts, err := lookupOpenConnectHosts(host)
	if err != nil {
		return ""
	}
	selected := selectPreferredHost(hosts)
	if selected == "" {
		return ""
	}
	return fmt.Sprintf("%s:%s", host, selected)
}

func selectPreferredHost(hosts []string) string {
	for _, host := range hosts {
		if ip := net.ParseIP(strings.TrimSpace(host)); ip != nil && ip.To4() != nil {
			return ip.String()
		}
	}
	for _, host := range hosts {
		if ip := net.ParseIP(strings.TrimSpace(host)); ip != nil {
			return ip.String()
		}
	}
	return ""
}

func orderedUniqueStrings(values ...string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func deriveTunnelGroupCookie(state *samlAuthState) string {
	if state == nil {
		return ""
	}
	for _, candidate := range []string{
		extractXMLTag(state.OpaqueXML, "group-alias"),
		path.Base(strings.Trim(strings.TrimSpace(state.GroupAccess), "/")),
		extractXMLTag(state.OpaqueXML, "tunnel-group"),
	} {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" || candidate == "." || candidate == "/" {
			continue
		}
		return candidate
	}
	return ""
}

func findCiscoLibCSD() string {
	homeDir, err := userHomeDirOpenConnect()
	if err != nil {
		return ""
	}
	candidates := []string{
		filepath.Join(homeDir, ".cisco", "vpn", "cache", "lib64_appid", "libcsd.dylib"),
		filepath.Join(homeDir, ".cisco", "hostscan", "lib64", "libcsd.dylib"),
	}
	for _, candidate := range candidates {
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}

func fetchServerCertSHA1(host string, port string) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", fmt.Errorf("empty host")
	}
	if strings.TrimSpace(port) == "" {
		port = "443"
	}
	address := net.JoinHostPort(host, port)
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return "", fmt.Errorf("read server certificate for %s: %w", address, err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", fmt.Errorf("read server certificate for %s: no peer certificate", address)
	}
	sum := sha1.Sum(state.PeerCertificates[0].Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:])), nil
}
