package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"multi-tun/desktop/internal/vless/config"
	"multi-tun/desktop/internal/vless/singbox"
	"multi-tun/desktop/internal/vless/subscription"
)

type App struct {
	stdout io.Writer
	stderr io.Writer
}

func New(stdout, stderr io.Writer) *App {
	return &App{
		stdout: stdout,
		stderr: stderr,
	}
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
	case "setup":
		return a.runSetup(args[1:])
	case "init":
		return a.runInit(args[1:])
	case "refresh":
		return a.runRefresh(args[1:])
	case "list":
		return a.runList(args[1:])
	case "set-current":
		return a.runSetCurrent(args[1:])
	case "start":
		return a.runStart(args[1:])
	case "run":
		return a.runRun(args[1:])
	case "reconnect":
		return a.runReconnect(args[1:])
	case "status":
		return a.runStatus(args[1:])
	case "diagnose":
		return a.runDiagnose(args[1:])
	case "stop":
		return a.runStop(args[1:])
	case "render":
		return a.runRender(args[1:])
	default:
		fmt.Fprintf(a.stderr, "unknown command %q\n\n", args[0])
		a.printUsage()
		return 2
	}
}

func (a *App) runSetCurrent(args []string) int {
	fs := flag.NewFlagSet("set-current", flag.ContinueOnError)
	fs.SetOutput(a.stderr)

	configPath := fs.String("config", "", "Path to config file")
	serverName := fs.String("server", "", "Configured VLESS server name")
	profileName := fs.String("profile", "", "Configured VLESS profile alias")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	selectionOptions, err := commandServerProfileSelection(*serverName, *profileName, "", fs.Args())
	if err != nil {
		fmt.Fprintf(a.stderr, "set-current failed: %v\n", err)
		return 2
	}

	effective, selection, resolvedPath, err := config.SetCurrent(*configPath, selectionOptions)
	if err != nil {
		fmt.Fprintf(a.stderr, "set-current failed: %v\n", err)
		return 1
	}

	fmt.Fprintf(a.stdout, "config: %s\n", resolvedPath)
	fmt.Fprintf(a.stdout, "current.server: %s\n", selection.Server)
	if selection.Profile != "" {
		fmt.Fprintf(a.stdout, "current.profile: %s\n", selection.Profile)
	}
	if effective.DefaultProfileSelector() != "" {
		fmt.Fprintf(a.stdout, "profile_selector: %s\n", effective.DefaultProfileSelector())
	}
	return 0
}

func (a *App) runSetup(args []string) int {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(a.stderr)

	configPath := fs.String("config", "", "Path to config file")
	sourceURL := fs.String("source-url", os.Getenv("DANCEVPN_SUBSCRIPTION_URL"), "VLESS source URL or literal vless:// URI")
	sourceMode := fs.String("source-mode", "", "Optional source mode override: proxy or direct")
	profileSelector := fs.String("profile", "", "Optional default profile selector by id, name, or substring")
	serverName := fs.String("server", "default", "Configured VLESS server name to create")
	configProfile := fs.String("config-profile", "default", "Configured VLESS profile alias to create")
	force := fs.Bool("force", false, "Overwrite config if it already exists")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	resolvedConfigPath, err := commandConfigPath(*configPath, fs.Args())
	if err != nil {
		fmt.Fprintf(a.stderr, "setup failed: %v\n", err)
		return 2
	}

	cfg, err := config.Setup(resolvedConfigPath, config.SetupOptions{
		SourceURL:       *sourceURL,
		SourceMode:      *sourceMode,
		ProfileSelector: *profileSelector,
		ServerName:      *serverName,
		ConfigProfile:   *configProfile,
	}, *force)
	if err != nil {
		fmt.Fprintf(a.stderr, "setup failed: %v\n", err)
		return 1
	}
	effective, selection, err := cfg.Effective(config.SelectionOptions{})
	if err != nil {
		fmt.Fprintf(a.stderr, "setup failed: %v\n", err)
		return 1
	}

	resolvedPath := config.ResolveInitPath(resolvedConfigPath)
	fmt.Fprintf(a.stdout, "configured %s\n", resolvedPath)
	fmt.Fprintf(a.stdout, "config: %s\n", resolvedPath)
	if selection.Server != "" {
		fmt.Fprintf(a.stdout, "server: %s\n", selection.Server)
	}
	if selection.Profile != "" {
		fmt.Fprintf(a.stdout, "config_profile: %s\n", selection.Profile)
	}
	fmt.Fprintf(a.stdout, "source_mode: %s\n", effective.SourceMode())
	if effective.DefaultProfileSelector() != "" {
		fmt.Fprintf(a.stdout, "default_profile_selector: %s\n", effective.DefaultProfileSelector())
	}
	if strings.Contains(effective.SourceURL(), "REPLACE_ME") {
		fmt.Fprintln(a.stdout, "source.url still has placeholder value; edit the file or rerun with --source-url")
	}
	return 0
}

func (a *App) runInit(args []string) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(a.stderr)

	configPath := fs.String("config", "", "Path to config file")
	subscriptionURL := fs.String("subscription-url", os.Getenv("DANCEVPN_SUBSCRIPTION_URL"), "Subscription URL to write into local config")
	force := fs.Bool("force", false, "Overwrite config if it already exists")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	resolvedConfigPath, err := commandConfigPath(*configPath, fs.Args())
	if err != nil {
		fmt.Fprintf(a.stderr, "init failed: %v\n", err)
		return 2
	}

	cfg, err := config.Init(resolvedConfigPath, *subscriptionURL, *force)
	if err != nil {
		fmt.Fprintf(a.stderr, "init failed: %v\n", err)
		return 1
	}
	effective, _, err := cfg.Effective(config.SelectionOptions{})
	if err != nil {
		fmt.Fprintf(a.stderr, "init failed: %v\n", err)
		return 1
	}

	fmt.Fprintf(a.stdout, "initialized %s\n", config.ResolveInitPath(resolvedConfigPath))
	if strings.Contains(effective.SourceURL(), "REPLACE_ME") {
		fmt.Fprintln(a.stdout, "source.url still has placeholder value; edit the file or rerun with --subscription-url")
	}
	return 0
}

func (a *App) runRefresh(args []string) int {
	fs := flag.NewFlagSet("refresh", flag.ContinueOnError)
	fs.SetOutput(a.stderr)

	configPath := fs.String("config", "", "Path to config file")
	serverName := fs.String("server", "", "Configured VLESS server name")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	selectionOptions, err := commandServerSelection(*serverName, fs.Args())
	if err != nil {
		fmt.Fprintf(a.stderr, "refresh failed: %v\n", err)
		return 2
	}

	cfg, selection, err := loadEffectiveConfig(*configPath, selectionOptions)
	if err != nil {
		fmt.Fprintf(a.stderr, "refresh failed: %v\n", err)
		return 1
	}

	snapshot, err := subscription.Refresh(context.Background(), cfg.SourceMode(), cfg.SourceURL(), cfg.CacheDir)
	if err != nil {
		fmt.Fprintf(a.stderr, "refresh failed: %v\n", err)
		return 1
	}

	if selection.Server != "" {
		fmt.Fprintf(a.stdout, "server: %s\n", selection.Server)
	}
	fmt.Fprintf(a.stdout, "refreshed %d profile(s) from %s\n", len(snapshot.Profiles), snapshot.SourceURL)
	fmt.Fprintf(a.stdout, "payload=%s cache=%s\n", snapshot.PayloadFormat, filepath.Join(cfg.CacheDir, "snapshot.json"))
	return 0
}

func (a *App) runList(args []string) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(a.stderr)

	configPath := fs.String("config", "", "Path to config file")
	serverName := fs.String("server", "", "Configured VLESS server name")
	refresh := fs.Bool("refresh", false, "Fetch subscription before listing cached profiles")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	selectionOptions, err := commandServerSelection(*serverName, fs.Args())
	if err != nil {
		fmt.Fprintf(a.stderr, "list failed: %v\n", err)
		return 2
	}

	cfg, selection, err := loadEffectiveConfig(*configPath, selectionOptions)
	if err != nil {
		fmt.Fprintf(a.stderr, "list failed: %v\n", err)
		return 1
	}

	snapshot, err := a.loadSnapshot(cfg, *refresh)
	if err != nil {
		fmt.Fprintf(a.stderr, "list failed: %v\n", err)
		return 1
	}

	if selection.Server != "" {
		fmt.Fprintf(a.stdout, "server: %s\n", selection.Server)
	}
	for idx, profile := range snapshot.Profiles {
		fmt.Fprintf(a.stdout, "%d. %s | %s | %s | %s\n", idx+1, profile.ID, profile.DisplayName(), profile.Endpoint(), profile.Network)
	}
	return 0
}

func (a *App) runRender(args []string) int {
	fs := flag.NewFlagSet("render", flag.ContinueOnError)
	fs.SetOutput(a.stderr)

	configPath := fs.String("config", "", "Path to config file")
	serverName := fs.String("server", "", "Configured VLESS server name")
	profileName := fs.String("profile", "", "Configured VLESS profile alias; in legacy flat configs this remains a profile selector")
	profileSelector := fs.String("selector", "", "Subscription profile selector by id, name, endpoint, or substring")
	outputPath := fs.String("output", "", "Override render.output_path")
	refresh := fs.Bool("refresh", false, "Fetch subscription before rendering")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	selectionOptions, err := commandServerProfileSelection(*serverName, *profileName, *profileSelector, fs.Args())
	if err != nil {
		fmt.Fprintf(a.stderr, "render failed: %v\n", err)
		return 2
	}

	cfg, selection, err := loadEffectiveConfig(*configPath, selectionOptions)
	if err != nil {
		fmt.Fprintf(a.stderr, "render failed: %v\n", err)
		return 1
	}

	snapshot, err := a.loadSnapshot(cfg, *refresh)
	if err != nil {
		fmt.Fprintf(a.stderr, "render failed: %v\n", err)
		return 1
	}

	profile, err := subscription.SelectProfile(snapshot.Profiles, cfg.DefaultProfileSelector())
	if err != nil {
		fmt.Fprintf(a.stderr, "render failed: %v\n", err)
		return 1
	}

	data, err := singbox.RenderWithOptions(cfg, profile, resolveRenderOptions(cfg.NetworkMode()))
	if err != nil {
		fmt.Fprintf(a.stderr, "render failed: %v\n", err)
		return 1
	}

	target := cfg.SingboxConfigPath()
	if *outputPath != "" {
		target = *outputPath
	}
	if err := singbox.Write(target, data); err != nil {
		fmt.Fprintf(a.stderr, "render failed: %v\n", err)
		return 1
	}

	if selection.Server != "" {
		fmt.Fprintf(a.stdout, "server: %s\n", selection.Server)
	}
	if selection.Profile != "" {
		fmt.Fprintf(a.stdout, "config_profile: %s\n", selection.Profile)
	}
	fmt.Fprintf(a.stdout, "rendered %s using profile %s (%s)\n", target, profile.DisplayName(), profile.ID)
	return 0
}

func (a *App) loadSnapshot(cfg config.ProjectConfig, refresh bool) (subscription.CacheSnapshot, error) {
	if refresh {
		return subscription.Refresh(context.Background(), cfg.SourceMode(), cfg.SourceURL(), cfg.CacheDir)
	}

	snapshot, err := subscription.LoadCache(cfg.CacheDir)
	if err == nil {
		return snapshot, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return subscription.CacheSnapshot{}, err
	}
	return subscription.Refresh(context.Background(), cfg.SourceMode(), cfg.SourceURL(), cfg.CacheDir)
}

func loadConfig(configPath string) (config.ProjectConfig, error) {
	cfg, err := config.Load(configPath)
	if err == nil {
		return cfg, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		if configPath == "" {
			return config.ProjectConfig{}, errors.New("no config found; run `vless-tun init` first or pass --config")
		}
		return config.ProjectConfig{}, fmt.Errorf("%s does not exist; run `vless-tun init --config %s` first", configPath, configPath)
	}
	return config.ProjectConfig{}, err
}

func loadEffectiveConfig(configPath string, options config.SelectionOptions) (config.ProjectConfig, config.EffectiveSelection, error) {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return config.ProjectConfig{}, config.EffectiveSelection{}, err
	}
	effective, selection, err := cfg.Effective(options)
	if err != nil {
		return config.ProjectConfig{}, config.EffectiveSelection{}, err
	}
	if err := effective.Validate(); err != nil {
		return config.ProjectConfig{}, config.EffectiveSelection{}, err
	}
	return effective, selection, nil
}

func commandConfigPath(flagValue string, args []string) (string, error) {
	if len(args) == 0 {
		return flagValue, nil
	}
	if len(args) > 1 {
		return "", fmt.Errorf("unexpected argument %q; pass flags before the config argument", args[1])
	}
	if strings.TrimSpace(flagValue) != "" {
		return "", errors.New("config path specified both with --config and positional argument")
	}
	return resolvePositionalConfigPath(args[0]), nil
}

type positionalSelection struct {
	Server  string
	Profile string
}

func commandServerSelection(serverFlag string, args []string) (config.SelectionOptions, error) {
	return commandSelection(serverFlag, "", "", args, false)
}

func commandServerProfileSelection(serverFlag, profileFlag, selectorFlag string, args []string) (config.SelectionOptions, error) {
	return commandSelection(serverFlag, profileFlag, selectorFlag, args, true)
}

func commandSelection(serverFlag, profileFlag, selectorFlag string, args []string, allowProfile bool) (config.SelectionOptions, error) {
	selection, err := parsePositionalSelection(args, allowProfile)
	if err != nil {
		return config.SelectionOptions{}, err
	}

	server := strings.TrimSpace(serverFlag)
	profile := strings.TrimSpace(profileFlag)
	if server != "" && selection.Server != "" {
		return config.SelectionOptions{}, errors.New("server specified both with --server and positional argument")
	}
	if profile != "" && selection.Profile != "" {
		return config.SelectionOptions{}, errors.New("profile specified both with --profile and positional argument")
	}

	if server == "" {
		server = selection.Server
	}
	if profile == "" {
		profile = selection.Profile
	}

	return config.SelectionOptions{
		Server:   server,
		Profile:  profile,
		Selector: strings.TrimSpace(selectorFlag),
	}, nil
}

func parsePositionalSelection(args []string, allowProfile bool) (positionalSelection, error) {
	maxArgs := 1
	expected := "server"
	if allowProfile {
		maxArgs = 2
		expected = "server and profile"
	}
	if len(args) > maxArgs {
		return positionalSelection{}, fmt.Errorf("unexpected argument %q; expected at most positional %s arguments, with flags before positionals", args[maxArgs], expected)
	}

	selection := positionalSelection{}
	if len(args) >= 1 {
		selection.Server = strings.TrimSpace(args[0])
	}
	if len(args) >= 2 {
		selection.Profile = strings.TrimSpace(args[1])
	}
	return selection, nil
}

func resolvePositionalConfigPath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}

	candidate := filepath.Join(filepath.Dir(config.DefaultPath()), path)
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	if filepath.Ext(path) == "" {
		return candidate + ".json"
	}
	return candidate
}

func (a *App) printUsage() {
	fmt.Fprintln(a.stdout, "vless-tun manages DenseVPN subscriptions and renders sing-box configs.")
	fmt.Fprintln(a.stdout)
	fmt.Fprintln(a.stdout, "Usage:")
	fmt.Fprintln(a.stdout, "  vless-tun setup [--config path | config] [--server name] [--config-profile name] [--source-url URL] [--source-mode proxy|direct] [--profile selector] [--force]")
	fmt.Fprintln(a.stdout, "  vless-tun init [--config path | config] [--subscription-url URL] [--force]")
	fmt.Fprintln(a.stdout, "  vless-tun refresh [--config path] [--server name | server]")
	fmt.Fprintln(a.stdout, "  vless-tun list [--config path] [--server name | server] [--refresh]")
	fmt.Fprintln(a.stdout, "  vless-tun set-current [--config path] [--server name | server [profile]] [--profile name]")
	fmt.Fprintln(a.stdout, "  vless-tun start [--config path] [--server name | server [profile]] [--profile name] [--selector selector] [--output path] [--refresh]")
	fmt.Fprintln(a.stdout, "  vless-tun reconnect [--config path] [--server name | server [profile]] [--profile name] [--selector selector] [--output path] [--refresh] [--timeout duration] [--force]")
	fmt.Fprintln(a.stdout, "  vless-tun status [--config path] [--server name | server [profile]] [--profile name] [--selector selector] [--refresh]")
	fmt.Fprintln(a.stdout, "  vless-tun diagnose [tunnel] [--config path]")
	fmt.Fprintln(a.stdout, "  vless-tun diagnose config [--config path] [--server name | server [profile]] [--profile name] [--selector selector]")
	fmt.Fprintln(a.stdout, "  vless-tun stop [--config path] [server] [--timeout duration] [--force]")
	fmt.Fprintln(a.stdout, "  vless-tun render [--config path] [--server name | server [profile]] [--profile name] [--selector selector] [--output path] [--refresh]")
	fmt.Fprintln(a.stdout)
	fmt.Fprintln(a.stdout, "Aliases:")
	fmt.Fprintln(a.stdout, "  run -> start")
	fmt.Fprintln(a.stdout)
	fmt.Fprintln(a.stdout, "Config:")
	fmt.Fprintln(a.stdout, "  With no config argument, vless-tun uses ~/.config/vless-tun/config.json.")
	fmt.Fprintln(a.stdout, "  Lifecycle command positionals override current.server/current.profile; reconnect, stop, and diagnose tunnel scan all configured session caches.")
	fmt.Fprintln(a.stdout, "  Use --config to choose a non-default config file.")
	fmt.Fprintln(a.stdout, "  setup/init still accept one positional config path for bootstrapping.")
}
