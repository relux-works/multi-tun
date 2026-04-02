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

	"multi-tun/internal/config"
	"multi-tun/internal/singbox"
	"multi-tun/internal/subscription"
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
	case "init":
		return a.runInit(args[1:])
	case "refresh":
		return a.runRefresh(args[1:])
	case "list":
		return a.runList(args[1:])
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

func (a *App) runInit(args []string) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(a.stderr)

	configPath := fs.String("config", "", "Path to config file")
	subscriptionURL := fs.String("subscription-url", os.Getenv("DANCEVPN_SUBSCRIPTION_URL"), "Subscription URL to write into local config")
	force := fs.Bool("force", false, "Overwrite config if it already exists")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := config.Init(*configPath, *subscriptionURL, *force)
	if err != nil {
		fmt.Fprintf(a.stderr, "init failed: %v\n", err)
		return 1
	}

	fmt.Fprintf(a.stdout, "initialized %s\n", config.ResolveInitPath(*configPath))
	if strings.Contains(cfg.SourceURL(), "REPLACE_ME") {
		fmt.Fprintln(a.stdout, "source.url still has placeholder value; edit the file or rerun with --subscription-url")
	}
	return 0
}

func (a *App) runRefresh(args []string) int {
	fs := flag.NewFlagSet("refresh", flag.ContinueOnError)
	fs.SetOutput(a.stderr)

	configPath := fs.String("config", "", "Path to config file")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(a.stderr, "refresh failed: %v\n", err)
		return 1
	}

	snapshot, err := subscription.Refresh(context.Background(), cfg.SourceMode(), cfg.SourceURL(), cfg.CacheDir)
	if err != nil {
		fmt.Fprintf(a.stderr, "refresh failed: %v\n", err)
		return 1
	}

	fmt.Fprintf(a.stdout, "refreshed %d profile(s) from %s\n", len(snapshot.Profiles), snapshot.SourceURL)
	fmt.Fprintf(a.stdout, "payload=%s cache=%s\n", snapshot.PayloadFormat, filepath.Join(cfg.CacheDir, "snapshot.json"))
	return 0
}

func (a *App) runList(args []string) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(a.stderr)

	configPath := fs.String("config", "", "Path to config file")
	refresh := fs.Bool("refresh", false, "Fetch subscription before listing cached profiles")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(a.stderr, "list failed: %v\n", err)
		return 1
	}

	snapshot, err := a.loadSnapshot(cfg, *refresh)
	if err != nil {
		fmt.Fprintf(a.stderr, "list failed: %v\n", err)
		return 1
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
	profileSelector := fs.String("profile", "", "Profile selector by id, name, or substring")
	outputPath := fs.String("output", "", "Override render.output_path")
	refresh := fs.Bool("refresh", false, "Fetch subscription before rendering")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(a.stderr, "render failed: %v\n", err)
		return 1
	}

	snapshot, err := a.loadSnapshot(cfg, *refresh)
	if err != nil {
		fmt.Fprintf(a.stderr, "render failed: %v\n", err)
		return 1
	}

	selector := *profileSelector
	if selector == "" {
		selector = cfg.DefaultProfileSelector()
	}

	profile, err := subscription.SelectProfile(snapshot.Profiles, selector)
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

func (a *App) printUsage() {
	fmt.Fprintln(a.stdout, "vless-tun manages DenseVPN subscriptions and renders sing-box configs.")
	fmt.Fprintln(a.stdout)
	fmt.Fprintln(a.stdout, "Usage:")
	fmt.Fprintln(a.stdout, "  vless-tun init [--config path] [--subscription-url URL] [--force]")
	fmt.Fprintln(a.stdout, "  vless-tun refresh [--config path]")
	fmt.Fprintln(a.stdout, "  vless-tun list [--config path] [--refresh]")
	fmt.Fprintln(a.stdout, "  vless-tun start [--config path] [--profile selector] [--output path] [--refresh]")
	fmt.Fprintln(a.stdout, "  vless-tun reconnect [--config path] [--profile selector] [--output path] [--refresh] [--timeout duration] [--force]")
	fmt.Fprintln(a.stdout, "  vless-tun status [--config path] [--refresh]")
	fmt.Fprintln(a.stdout, "  vless-tun diagnose [--config path]")
	fmt.Fprintln(a.stdout, "  vless-tun stop [--config path] [--timeout duration] [--force]")
	fmt.Fprintln(a.stdout, "  vless-tun render [--config path] [--profile selector] [--output path] [--refresh]")
	fmt.Fprintln(a.stdout)
	fmt.Fprintln(a.stdout, "Aliases:")
	fmt.Fprintln(a.stdout, "  run -> start")
}
