package openconnectcli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"multi-tun/internal/keychain"
	"multi-tun/internal/openconnect"
	"multi-tun/internal/openconnectcfg"
)

type App struct {
	stdout io.Writer
	stderr io.Writer
}

type statusView struct {
	State       openconnect.State
	StateSource string
	Duration    string
	CiscoState  openconnect.State
}

var keychainGet = keychain.Get

func New(stdout, stderr io.Writer) *App {
	return &App{stdout: stdout, stderr: stderr}
}

func deriveStatusView(ciscoState openconnect.State, info *openconnect.ConnectionInfo, runtime *openconnect.RuntimeStatus) statusView {
	view := statusView{
		State:       ciscoState,
		StateSource: "cisco_cli",
	}

	if info != nil {
		if info.State != openconnect.StateUnknown {
			view.State = info.State
		}
		if info.Duration != "" {
			view.Duration = info.Duration
		}
	}

	if runtime != nil {
		view.State = openconnect.StateConnected
		view.StateSource = "openconnect_runtime"
		if runtime.Uptime != "" {
			view.Duration = runtime.Uptime
		}
		if ciscoState != "" && ciscoState != openconnect.StateUnknown && ciscoState != openconnect.StateConnected {
			view.CiscoState = ciscoState
		}
	}

	if view.State == "" {
		view.State = openconnect.StateUnknown
	}

	return view
}

func (a *App) Run(args []string) int {
	if len(args) == 0 {
		a.printUsage()
		return 0
	}

	switch args[0] {
	case "help", "-h", "--help":
		a.printUsage()
		return 0
	case "start":
		return a.runStart(args[1:])
	case "run":
		return a.runRun(args[1:])
	case "connect":
		return a.runRun(args[1:])
	case "reconnect":
		return a.runReconnect(args[1:])
	case "stop":
		return a.runStop(args[1:])
	case "disconnect":
		return a.runStop(args[1:])
	case "helper":
		return a.runHelper(args[1:])
	case "routes":
		return a.runRoutes(args[1:])
	case "status":
		return a.runStatus(args[1:])
	case "profiles":
		return a.runProfiles(args[1:])
	case "inspect-profiles":
		return a.runInspectProfiles(args[1:])
	case "_helper-daemon":
		return a.runHelperDaemon(args[1:])
	default:
		fmt.Fprintf(a.stderr, "unknown command %q\n\n", args[0])
		a.printUsage()
		return 2
	}
}

func (a *App) runStatus(args []string) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	configPath := fs.String("config", "", "Path to openconnect-tun config file")
	cacheDir := fs.String("cache-dir", "", "Override cache dir for session metadata and logs")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, resolvedConfigPath, err := openconnectcfg.LoadOptional(*configPath)
	if err != nil {
		fmt.Fprintf(a.stderr, "status failed: %v\n", err)
		return 1
	}
	resolvedCacheDir := resolveCacheDir(*cacheDir, cfg)
	state, vpnBinary, err := openconnect.DetectState()
	if err != nil {
		fmt.Fprintf(a.stderr, "status failed: %v\n", err)
		return 1
	}
	info, _, err := openconnect.GetConnectionInfo()
	if err != nil {
		fmt.Fprintf(a.stderr, "status failed: %v\n", err)
		return 1
	}
	runtime, err := openconnect.CurrentRuntime()
	if err != nil {
		fmt.Fprintf(a.stderr, "status failed: %v\n", err)
		return 1
	}
	profiles, _, err := openconnect.ListProfiles()
	if err != nil {
		fmt.Fprintf(a.stderr, "status failed: %v\n", err)
		return 1
	}
	current, currentState, _, currentErr := currentSessionState(resolvedCacheDir)
	if currentErr != nil {
		fmt.Fprintf(a.stderr, "status failed: %v\n", currentErr)
		return 1
	}

	fmt.Fprintf(a.stdout, "config: %s\n", resolvedConfigPath)
	fmt.Fprintf(a.stdout, "cache_dir: %s\n", resolvedCacheDir)
	fmt.Fprintf(a.stdout, "session: %s\n", currentState)
	if current != nil {
		fmt.Fprintf(a.stdout, "session_id: %s\n", current.ID)
		fmt.Fprintf(a.stdout, "session_mode: %s\n", current.Mode)
		if current.PrivilegedMode != "" {
			fmt.Fprintf(a.stdout, "session_privileged_mode: %s\n", current.PrivilegedMode)
		}
		fmt.Fprintf(a.stdout, "session_server: %s\n", current.Server)
		fmt.Fprintf(a.stdout, "started_at: %s\n", current.StartedAt.Format(time.RFC3339))
		if current.ResolvedFrom != "" {
			fmt.Fprintf(a.stdout, "resolved_from: %s\n", current.ResolvedFrom)
		}
		if current.Interface != "" {
			fmt.Fprintf(a.stdout, "session_interface: %s\n", current.Interface)
		}
		if current.LogPath != "" {
			fmt.Fprintf(a.stdout, "log_file: %s\n", current.LogPath)
		}
		if current.HelperSocketPath != "" {
			fmt.Fprintf(a.stdout, "helper_socket: %s\n", current.HelperSocketPath)
		}
		if current.Script != "" {
			fmt.Fprintf(a.stdout, "script: %s\n", current.Script)
		}
		if len(current.IncludeRoutes) > 0 {
			fmt.Fprintf(a.stdout, "routes_requested: %s\n", strings.Join(current.IncludeRoutes, ", "))
		}
		if len(current.VPNDomains) > 0 {
			fmt.Fprintf(a.stdout, "vpn_domains: %s\n", strings.Join(current.VPNDomains, ", "))
		}
		if len(current.VPNNameservers) > 0 {
			fmt.Fprintf(a.stdout, "vpn_nameservers: %s\n", strings.Join(current.VPNNameservers, ", "))
		}
		if currentState == "starting" || currentState == "stale" {
			if last := openconnect.LastRelevantLogLine(current.LogPath); last != "" {
				fmt.Fprintf(a.stdout, "last_log_line: %s\n", last)
			}
		}
	}
	if vpnBinary == "" {
		fmt.Fprintln(a.stdout, "vpn_binary: missing")
	} else {
		fmt.Fprintf(a.stdout, "vpn_binary: %s\n", vpnBinary)
	}
	view := deriveStatusView(state, info, runtime)
	fmt.Fprintf(a.stdout, "state: %s\n", view.State)
	fmt.Fprintf(a.stdout, "state_source: %s\n", view.StateSource)
	if view.CiscoState != "" {
		fmt.Fprintf(a.stdout, "cisco_state: %s\n", view.CiscoState)
	}
	if info != nil && info.State == openconnect.StateConnected {
		if info.ServerAddr != "" {
			fmt.Fprintf(a.stdout, "server: %s\n", info.ServerAddr)
		}
		if info.ClientAddr != "" {
			fmt.Fprintf(a.stdout, "client_addr: %s\n", info.ClientAddr)
		}
		if info.TunnelMode != "" {
			fmt.Fprintf(a.stdout, "tunnel_mode: %s\n", info.TunnelMode)
		}
	}
	if view.Duration != "" {
		fmt.Fprintf(a.stdout, "duration: %s\n", view.Duration)
	}
	if runtime != nil {
		fmt.Fprintf(a.stdout, "openconnect_pid: %d\n", runtime.PID)
		if runtime.Interface != "" {
			fmt.Fprintf(a.stdout, "openconnect_interface: %s\n", runtime.Interface)
		}
		if runtime.Uptime != "" {
			fmt.Fprintf(a.stdout, "openconnect_uptime: %s\n", runtime.Uptime)
		}
	}
	fmt.Fprintf(a.stdout, "cli_profiles: %d\n", len(profiles))
	for _, profile := range profiles {
		fmt.Fprintf(a.stdout, "- %s\n", profile.Name)
	}
	return 0
}

type runOptions struct {
	configPath     string
	resolvedConfig string
	cacheDir       string
	server         string
	profile        string
	auth           string
	mode           string
	username       string
	password       string
	totpSecret     string
	vpnDomains     []string
	vpnNameservers []string
	includeRoutes  []string
	dryRun         bool
}

func (a *App) runRun(args []string) int {
	options, exitCode, err := a.parseRunOptions("run", args)
	if err != nil {
		return exitCode
	}
	return a.executeRun(options, false, "run")
}

func (a *App) runStart(args []string) int {
	options, exitCode, err := a.parseRunOptions("start", args)
	if err != nil {
		return exitCode
	}
	return a.executeRun(options, false, "start")
}

func (a *App) runReconnect(args []string) int {
	options, exitCode, err := a.parseRunOptions("reconnect", args)
	if err != nil {
		return exitCode
	}
	return a.executeRun(options, true, "reconnect")
}

func (a *App) parseRunOptions(name string, args []string) (runOptions, int, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(a.stderr)

	configPath := fs.String("config", "", "Path to openconnect-tun config file")
	cacheDir := fs.String("cache-dir", "", "Override cache dir for session metadata and logs")
	server := fs.String("server", "", "Explicit ASA endpoint, for example vpn-gw2.corp.example/outside")
	profile := fs.String("profile", "", "Profile name from AnyConnect XML, for example 'Ural Outside extended'")
	auth := fs.String("auth", "aggregate", "Authentication mode: aggregate, openconnect, or password; aggregate is the default live path")
	mode := fs.String("mode", "", "Connection mode: full or split-include")
	username := fs.String("username", "", "Optional username for browser-assisted SAML auto-login")
	password := fs.String("password", "", "Optional password for browser-assisted SAML auto-login")
	totpSecret := fs.String("totp-secret", "", "Optional TOTP secret for browser-assisted SAML auto-login")
	domainList := fs.String("vpn-domains", "", "Comma-separated domains that should use VPN DNS in split-include mode")
	includeRoutes := multiValueFlag{}
	fs.Var(&includeRoutes, "route", "Included route/host/alias for split-include mode; may be repeated")
	dryRun := fs.Bool("dry-run", false, "Print resolved plan without starting openconnect")

	if err := fs.Parse(args); err != nil {
		return runOptions{}, 2, err
	}

	cfg, resolvedConfigPath, err := openconnectcfg.LoadOptional(*configPath)
	if err != nil {
		return runOptions{}, 1, err
	}

	resolvedUsername, resolvedPassword, resolvedTOTP, err := resolveCredentials(*username, *password, *totpSecret, cfg.Auth, *dryRun)
	if err != nil {
		return runOptions{}, 1, err
	}

	resolvedMode := firstNonEmpty(*mode, cfg.DefaultMode, openconnect.ConnectModeFull)
	resolvedRoutes, resolvedVPNDomains := resolveSplitIncludeTargets(
		resolvedMode,
		cfg.SplitInclude,
		[]string(includeRoutes),
		splitCSV(*domainList),
	)
	resolvedVPNNameservers := resolveSplitIncludeNameservers(resolvedMode, cfg.SplitInclude)

	return runOptions{
		configPath:     *configPath,
		resolvedConfig: resolvedConfigPath,
		cacheDir:       resolveCacheDir(*cacheDir, cfg),
		server:         firstNonEmpty(*server, cfg.DefaultServer),
		profile:        firstNonEmpty(*profile, cfg.DefaultProfile),
		auth:           *auth,
		mode:           resolvedMode,
		username:       resolvedUsername,
		password:       resolvedPassword,
		totpSecret:     resolvedTOTP,
		vpnDomains:     resolvedVPNDomains,
		vpnNameservers: resolvedVPNNameservers,
		includeRoutes:  resolvedRoutes,
		dryRun:         *dryRun,
	}, 0, nil
}

func (a *App) executeRun(options runOptions, reconnect bool, commandName string) int {
	fmt.Fprintf(a.stdout, "config: %s\n", options.resolvedConfig)
	if !options.dryRun {
		fmt.Fprintf(a.stdout, "log_dir: %s\n", filepath.Join(options.cacheDir, "sessions"))
	}

	if reconnect {
		stopped, state, err := openconnect.Disconnect(options.cacheDir, 5*time.Second)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(a.stderr, "%s failed: %v\n", commandName, err)
			if stopped.LogPath != "" {
				fmt.Fprintf(a.stderr, "log=%s\n", stopped.LogPath)
			}
			return 1
		}
		switch state {
		case "stopped", "stopped_untracked", "stale", "cleared_starting":
			// no-op; reconnect continues with a fresh run
		}
	}

	homeDir, _ := os.UserHomeDir()
	result, err := openconnect.Connect(openconnect.ConnectOptions{
		Server:         options.server,
		Profile:        options.profile,
		Auth:           options.auth,
		Mode:           options.mode,
		IncludeRoutes:  options.includeRoutes,
		VPNDomains:     options.vpnDomains,
		VPNNameservers: options.vpnNameservers,
		Credentials: openconnect.Credentials{
			Username:   options.username,
			Password:   options.password,
			TOTPSecret: options.totpSecret,
		},
		ProfilePaths:   openconnect.DefaultProfileSearchPaths(homeDir),
		CacheDir:       options.cacheDir,
		ProgressWriter: a.stderr,
		DryRun:         options.dryRun,
	})
	if err != nil {
		fmt.Fprintf(a.stderr, "%s failed: %v\n", commandName, err)
		return 1
	}

	fmt.Fprintf(a.stdout, "mode: %s\n", result.Mode)
	fmt.Fprintf(a.stdout, "privileged_mode: %s\n", result.PrivilegedMode)
	fmt.Fprintf(a.stdout, "server: %s\n", result.Server)
	if result.ResolvedFrom != "" {
		fmt.Fprintf(a.stdout, "resolved_from: %s\n", result.ResolvedFrom)
	}
	if result.SessionID != "" {
		fmt.Fprintf(a.stdout, "session_id: %s\n", result.SessionID)
	}
	if result.Script != "" {
		fmt.Fprintf(a.stdout, "script: %s\n", result.Script)
	}
	fmt.Fprintf(a.stdout, "command: %s\n", strings.Join(result.Command, " "))
	if options.dryRun {
		fmt.Fprintln(a.stdout, "dry_run: true")
		if result.Mode == openconnect.ConnectModeFull {
			fmt.Fprintln(a.stdout, "warning: full mode will let openconnect/vpnc-script own default route and DNS")
		}
		return 0
	}
	fmt.Fprintf(a.stdout, "pid: %d\n", result.PID)
	if result.Interface != "" {
		fmt.Fprintf(a.stdout, "interface: %s\n", result.Interface)
	}
	if result.LogPath != "" {
		fmt.Fprintf(a.stdout, "log_file: %s\n", result.LogPath)
	}
	fmt.Fprintln(a.stdout, "use `openconnect-tun status` to inspect state and `openconnect-tun stop` to stop it")
	return 0
}

func (a *App) runStop(args []string) int {
	fs := flag.NewFlagSet("stop", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	configPath := fs.String("config", "", "Path to openconnect-tun config file")
	cacheDir := fs.String("cache-dir", "", "Override cache dir for session metadata and logs")
	timeout := fs.Duration("timeout", 5*time.Second, "How long to wait after SIGINT before failing")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, _, err := openconnectcfg.LoadOptional(*configPath)
	if err != nil {
		fmt.Fprintf(a.stderr, "stop failed: %v\n", err)
		return 1
	}
	stopped, state, err := openconnect.Disconnect(resolveCacheDir(*cacheDir, cfg), *timeout)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(a.stdout, "no current openconnect session file found")
		return 0
	}
	if err != nil {
		fmt.Fprintf(a.stderr, "disconnect failed: %v\n", err)
		if stopped.LogPath != "" {
			fmt.Fprintf(a.stderr, "log=%s\n", stopped.LogPath)
		}
		return 1
	}
	switch state {
	case "stopped":
		fmt.Fprintf(a.stdout, "stopped openconnect session %s (pid=%d)\n", stopped.ID, stopped.PID)
	case "stopped_untracked":
		fmt.Fprintf(a.stdout, "stopped untracked openconnect pid=%d\n", stopped.PID)
	case "stale":
		fmt.Fprintf(a.stdout, "cleared stale openconnect session %s (pid=%d)\n", stopped.ID, stopped.PID)
	case "cleared_starting":
		fmt.Fprintf(a.stdout, "cleared starting openconnect session %s\n", stopped.ID)
	default:
		fmt.Fprintf(a.stdout, "stop result=%s pid=%d\n", state, stopped.PID)
	}
	if stopped.LogPath != "" {
		fmt.Fprintf(a.stdout, "log=%s\n", stopped.LogPath)
	}
	return 0
}

func resolveCacheDir(flagValue string, cfg openconnectcfg.Config) string {
	if strings.TrimSpace(flagValue) != "" {
		return openconnect.ResolveCacheDir(flagValue)
	}
	if cacheDir := strings.TrimSpace(cfg.CacheDirOrDefault()); cacheDir != "" {
		return openconnect.ResolveCacheDir(cacheDir)
	}
	return openconnect.ResolveCacheDir("")
}

func resolveCredentials(username, password, totp string, authCfg openconnectcfg.AuthConfig, allowMissingSecrets bool) (string, string, string, error) {
	resolvedUsername := username
	resolvedPassword := password
	resolvedTOTP := totp

	var err error
	if strings.TrimSpace(resolvedUsername) == "" && authCfg.UsernameKeychainAccount != "" {
		resolvedUsername, err = keychainGet(authCfg.UsernameKeychainAccount)
		if err != nil {
			if allowMissingSecrets {
				resolvedUsername = ""
			} else {
				return "", "", "", fmt.Errorf("username keychain account %q: %w", authCfg.UsernameKeychainAccount, err)
			}
		}
	}
	resolvedUsername = firstNonEmpty(resolvedUsername, authCfg.Username)
	if resolvedPassword == "" && authCfg.PasswordKeychainAccount != "" {
		resolvedPassword, err = keychainGet(authCfg.PasswordKeychainAccount)
		if err != nil {
			if allowMissingSecrets {
				resolvedPassword = ""
			} else {
				return "", "", "", fmt.Errorf("password keychain account %q: %w", authCfg.PasswordKeychainAccount, err)
			}
		}
	}
	if resolvedTOTP == "" && authCfg.TOTPKeychainAccount != "" {
		resolvedTOTP, err = keychainGet(authCfg.TOTPKeychainAccount)
		if err != nil {
			if allowMissingSecrets {
				resolvedTOTP = ""
			} else {
				return "", "", "", fmt.Errorf("totp keychain account %q: %w", authCfg.TOTPKeychainAccount, err)
			}
		}
	}
	return resolvedUsername, resolvedPassword, resolvedTOTP, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func (a *App) runRoutes(args []string) int {
	fs := flag.NewFlagSet("routes", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	routes, err := openconnect.CurrentRoutes()
	if err != nil {
		fmt.Fprintf(a.stderr, "routes failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(a.stdout, "routes: %d\n", len(routes))
	for _, route := range routes {
		fmt.Fprintf(a.stdout, "- %s\n", route)
	}
	return 0
}

func (a *App) runProfiles(args []string) int {
	fs := flag.NewFlagSet("profiles", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	profiles, vpnBinary, err := openconnect.ListProfiles()
	if err != nil {
		fmt.Fprintf(a.stderr, "profiles failed: %v\n", err)
		return 1
	}
	if vpnBinary == "" {
		fmt.Fprintln(a.stdout, "vpn_binary: missing")
		return 0
	}

	fmt.Fprintf(a.stdout, "vpn_binary: %s\n", vpnBinary)
	fmt.Fprintf(a.stdout, "profiles: %d\n", len(profiles))
	for _, profile := range profiles {
		fmt.Fprintf(a.stdout, "- %s\n", profile.Name)
	}
	return 0
}

func (a *App) runInspectProfiles(args []string) int {
	fs := flag.NewFlagSet("inspect-profiles", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	dir := fs.String("dir", "", "Optional directory with AnyConnect XML profiles")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	paths := []string{}
	if *dir != "" {
		paths = append(paths, *dir)
	} else {
		homeDir, _ := os.UserHomeDir()
		paths = openconnect.DefaultProfileSearchPaths(homeDir)
	}

	profiles, err := openconnect.LoadDiskProfiles(paths)
	if err != nil {
		fmt.Fprintf(a.stderr, "inspect-profiles failed: %v\n", err)
		return 1
	}

	fmt.Fprintf(a.stdout, "sources: %s\n", strings.Join(paths, ", "))
	fmt.Fprintf(a.stdout, "profile_files: %d\n", len(profiles))
	for _, profile := range profiles {
		fmt.Fprintf(a.stdout, "- %s\n", profile.Path)
		fmt.Fprintf(a.stdout, "  host_entries: %d\n", len(profile.HostEntries))
		fmt.Fprintf(a.stdout, "  local_lan_access: %s\n", profile.LocalLanAccess)
		fmt.Fprintf(a.stdout, "  ppp_exclusion: %s\n", profile.PPPExclusion)
		fmt.Fprintf(a.stdout, "  enable_scripting: %s\n", profile.EnableScripting)
		fmt.Fprintf(a.stdout, "  proxy_settings: %s\n", profile.ProxySettings)
		for _, host := range profile.HostEntries {
			fmt.Fprintf(a.stdout, "  - %s | %s\n", host.Name, host.Address)
			if len(host.BackupServers) > 0 {
				fmt.Fprintf(a.stdout, "    backups: %s\n", strings.Join(host.BackupServers, ", "))
			}
		}
	}
	return 0
}

func (a *App) printUsage() {
	fmt.Fprintln(a.stdout, "openconnect-tun inspects Cisco AnyConnect / ASA profile state for bypass planning.")
	fmt.Fprintln(a.stdout)
	fmt.Fprintln(a.stdout, "Usage:")
	fmt.Fprintln(a.stdout, "  openconnect-tun start [--server host/path | --profile name] [--auth openconnect|aggregate|password] [--mode full|split-include] [--route cidr] [--vpn-domains a,b] [--dry-run]")
	fmt.Fprintln(a.stdout, "  openconnect-tun reconnect [--server host/path | --profile name] [--auth openconnect|aggregate|password] [--mode full|split-include] [--route cidr] [--vpn-domains a,b] [--dry-run]")
	fmt.Fprintln(a.stdout, "  openconnect-tun stop")
	fmt.Fprintln(a.stdout, "  openconnect-tun helper install|uninstall|status")
	fmt.Fprintln(a.stdout, "  openconnect-tun routes")
	fmt.Fprintln(a.stdout, "  openconnect-tun status")
	fmt.Fprintln(a.stdout, "  openconnect-tun profiles")
	fmt.Fprintln(a.stdout, "  openconnect-tun inspect-profiles [--dir path]")
	fmt.Fprintln(a.stdout)
	fmt.Fprintln(a.stdout, "Aliases:")
	fmt.Fprintln(a.stdout, "  run -> start")
	fmt.Fprintln(a.stdout, "  connect -> run")
	fmt.Fprintln(a.stdout, "  disconnect -> stop")
}

type multiValueFlag []string

func (f *multiValueFlag) String() string {
	return strings.Join(*f, ",")
}

func (f *multiValueFlag) Set(value string) error {
	*f = append(*f, strings.TrimSpace(value))
	return nil
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func resolveSplitIncludeTargets(mode string, cfg openconnectcfg.SplitIncludeConfig, cliRoutes []string, cliVPNDomains []string) ([]string, []string) {
	if mode != openconnect.ConnectModeSplitInclude {
		return nil, nil
	}
	return mergeNormalizedList(cfg.Routes, cliRoutes), mergeNormalizedList(cfg.VPNDomains, cliVPNDomains)
}

func resolveSplitIncludeNameservers(mode string, cfg openconnectcfg.SplitIncludeConfig) []string {
	if mode != openconnect.ConnectModeSplitInclude {
		return nil
	}
	return mergeNormalizedList(cfg.Nameservers, nil)
}

func mergeNormalizedList(base []string, extra []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(base)+len(extra))
	appendUnique := func(values []string) {
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
	}
	appendUnique(base)
	appendUnique(extra)
	if len(result) == 0 {
		return nil
	}
	return result
}

func currentSessionState(cacheDir string) (*openconnect.CurrentSession, string, bool, error) {
	current, err := openconnect.LoadCurrent(cacheDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, "none", false, nil
	}
	if err != nil {
		return nil, "unknown", false, err
	}

	alive, pid, err := openconnect.SessionAlive(current)
	if err != nil {
		return &current, "unknown", false, err
	}
	if current.PID <= 0 {
		return &current, "starting", false, nil
	}
	if pid > 0 {
		current.PID = pid
	}
	if alive {
		return &current, "active", true, nil
	}
	return &current, "stale", false, nil
}
