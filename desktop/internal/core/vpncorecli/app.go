package vpncorecli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"multi-tun/desktop/internal/core/vpncore"
)

type App struct {
	stdout io.Writer
	stderr io.Writer
}

var inspectServiceVPNCoreCLI = vpncore.InspectService

var (
	installServiceVPNCoreCLI = vpncore.InstallService
	installDigestVPNCoreCLI  = vpncore.InstallDigest
)

var lowercaseSHA256CLI = regexp.MustCompile(`^[0-9a-f]{64}$`)

func New(stdout, stderr io.Writer) *App {
	return &App{stdout: stdout, stderr: stderr}
}

func (a *App) Run(args []string) int {
	if len(args) == 0 {
		a.printUsage()
		return 2
	}

	switch args[0] {
	case "install-digest":
		return a.runInstallDigest(args[1:])
	case "install":
		return a.runInstall(args[1:])
	case "uninstall":
		return a.runUninstall(args[1:])
	case "status":
		return a.runStatus(args[1:])
	case "inspect-vless-url":
		return a.runInspectVLESSURL(args[1:])
	case "_daemon":
		return a.runDaemon(args[1:])
	case "help", "--help", "-h":
		a.printUsage()
		return 0
	default:
		fmt.Fprintf(a.stderr, "unknown command %q\n", args[0])
		a.printUsage()
		return 2
	}
}

func (a *App) runInstall(args []string) int {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	expectedDigest := fs.String("expect-sha256", "", "Expected vpn-core install digest")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(a.stderr, "install refuses positional arguments")
		return 2
	}
	if !lowercaseSHA256CLI.MatchString(*expectedDigest) {
		fmt.Fprintln(a.stderr, "install requires --expect-sha256 with exactly 64 lowercase hexadecimal characters")
		return 2
	}

	binaryPath, err := resolveExecutablePath()
	if err != nil {
		fmt.Fprintf(a.stderr, "install failed: %v\n", err)
		return 1
	}
	cfg := vpncore.DefaultServiceConfig()
	if err := installServiceVPNCoreCLI(cfg, binaryPath, os.Getuid(), os.Getgid(), *expectedDigest); err != nil {
		fmt.Fprintf(a.stderr, "install failed: %v\n", err)
		return 1
	}

	status, err := inspectServiceVPNCoreCLI(cfg)
	if err != nil {
		fmt.Fprintf(a.stderr, "install failed: %v\n", err)
		return 1
	}

	fmt.Fprintln(a.stdout, "installed vpn core")
	fmt.Fprintf(a.stdout, "socket: %s\n", status.SocketPath)
	fmt.Fprintf(a.stdout, "label: %s\n", status.Label)
	fmt.Fprintf(a.stdout, "plist: %s\n", status.PlistPath)
	if status.Compatibility != "" {
		fmt.Fprintf(a.stdout, "compatibility: %s\n", status.Compatibility)
	}
	return 0
}

func (a *App) runInstallDigest(args []string) int {
	fs := flag.NewFlagSet("install-digest", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(a.stderr, "install-digest refuses positional arguments")
		return 2
	}
	binaryPath, err := resolveExecutablePath()
	if err != nil {
		fmt.Fprintf(a.stderr, "install-digest failed: %v\n", err)
		return 1
	}
	digest, err := installDigestVPNCoreCLI(binaryPath)
	if err != nil {
		fmt.Fprintf(a.stderr, "install-digest failed: %v\n", err)
		return 1
	}
	fmt.Fprintln(a.stdout, digest)
	return 0
}

func (a *App) runUninstall(args []string) int {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg := vpncore.DefaultServiceConfig()
	if err := vpncore.UninstallService(cfg); err != nil {
		fmt.Fprintf(a.stderr, "uninstall failed: %v\n", err)
		return 1
	}
	fmt.Fprintln(a.stdout, "uninstalled vpn core")
	fmt.Fprintf(a.stdout, "socket: %s\n", cfg.SocketPath)
	fmt.Fprintf(a.stdout, "label: %s\n", cfg.Label)
	return 0
}

func (a *App) runStatus(args []string) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	status, err := inspectServiceVPNCoreCLI(vpncore.DefaultServiceConfig())
	if err != nil {
		fmt.Fprintf(a.stderr, "status failed: %v\n", err)
		return 1
	}

	fmt.Fprintf(a.stdout, "label: %s\n", status.Label)
	fmt.Fprintf(a.stdout, "plist: %s\n", status.PlistPath)
	fmt.Fprintf(a.stdout, "socket: %s\n", status.SocketPath)
	if status.Compatibility != "" {
		fmt.Fprintf(a.stdout, "compatibility: %s\n", status.Compatibility)
	}
	if status.Reachable {
		fmt.Fprintln(a.stdout, "state: reachable")
		fmt.Fprintf(a.stdout, "daemon_pid: %d\n", status.DaemonPID)
		if status.HelperSnapshot != nil {
			fmt.Fprintf(a.stdout, "active_requests: %s\n", vpncore.FormatRequestSnapshots(status.HelperSnapshot.ActiveRequests))
			fmt.Fprintf(a.stdout, "queued_requests: %s\n", vpncore.FormatRequestSnapshots(status.HelperSnapshot.QueuedRequests))
			fmt.Fprintf(a.stdout, "last_completed_request: %s\n", vpncore.FormatCompletedRequestSnapshot(status.HelperSnapshot.LastCompletedRequest))
		} else {
			fmt.Fprintln(a.stdout, "request_diagnostics: unavailable")
		}
	} else {
		fmt.Fprintln(a.stdout, "state: missing")
	}
	return 0
}

func (a *App) runDaemon(args []string) int {
	fs := flag.NewFlagSet("_daemon", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	cfg := vpncore.DefaultServiceConfig()
	socketPath := fs.String("socket", cfg.SocketPath, "VPN core socket path")
	clientUID := fs.Int("client-uid", os.Getuid(), "Client uid")
	clientGID := fs.Int("client-gid", os.Getgid(), "Client gid")
	binarySHA256 := fs.String("binary-sha256", "", "Installed vpn-core binary sha256")
	manifestSHA256 := fs.String("manifest-sha256", "", "Installed manifest sha256")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || !lowercaseSHA256CLI.MatchString(*binarySHA256) || !lowercaseSHA256CLI.MatchString(*manifestSHA256) {
		fmt.Fprintln(a.stderr, "daemon requires valid --binary-sha256 and --manifest-sha256 values and no positional arguments")
		return 2
	}
	cfg.SocketPath = *socketPath
	if err := vpncore.RunDaemon(cfg, *clientUID, *clientGID, *binarySHA256, *manifestSHA256); err != nil {
		fmt.Fprintf(a.stderr, "daemon failed: %v\n", err)
		return 1
	}
	return 0
}

func (a *App) printUsage() {
	fmt.Fprintln(a.stdout, "vpn-core manages the shared privileged VPN daemon used by openconnect-tun and vless-tun.")
	fmt.Fprintln(a.stdout)
	fmt.Fprintln(a.stdout, "Usage:")
	fmt.Fprintln(a.stdout, "  vpn-core install-digest")
	fmt.Fprintln(a.stdout, "  vpn-core install --expect-sha256 HEX")
	fmt.Fprintln(a.stdout, "  vpn-core uninstall")
	fmt.Fprintln(a.stdout, "  vpn-core status")
	fmt.Fprintln(a.stdout, "  vpn-core inspect-vless-url [--source-mode proxy|direct] [--insecure] [--host name] [--tls-server-name name] URL")
}

func resolveExecutablePath() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	if path == "" {
		return "", fmt.Errorf("empty executable path")
	}
	return path, nil
}
