package openconnectcli

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"multi-tun/internal/openconnect"
)

func (a *App) runHelper(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(a.stderr, "helper subcommand is required: install, uninstall, or status")
		return 2
	}

	switch args[0] {
	case "install":
		return a.runHelperInstall(args[1:])
	case "uninstall":
		return a.runHelperUninstall(args[1:])
	case "status":
		return a.runHelperStatus(args[1:])
	default:
		fmt.Fprintf(a.stderr, "unknown helper subcommand %q\n", args[0])
		return 2
	}
}

func (a *App) runHelperInstall(args []string) int {
	fs := flag.NewFlagSet("helper install", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	binaryPath, err := resolveVPNCoreExecutablePath()
	if err != nil {
		fmt.Fprintf(a.stderr, "helper install failed: %v\n", err)
		return 1
	}
	if err := openconnect.InstallPrivilegedHelper(binaryPath, os.Getuid(), os.Getgid()); err != nil {
		fmt.Fprintf(a.stderr, "helper install failed: %v\n", err)
		return 1
	}

	status, err := openconnect.InspectPrivilegedHelper(openconnect.DefaultPrivilegedHelperConfig())
	if err != nil {
		fmt.Fprintf(a.stderr, "helper install failed: %v\n", err)
		return 1
	}

	fmt.Fprintln(a.stdout, "installed shared vpn core")
	fmt.Fprintf(a.stdout, "socket: %s\n", status.SocketPath)
	fmt.Fprintf(a.stdout, "label: %s\n", status.Label)
	fmt.Fprintf(a.stdout, "plist: %s\n", status.PlistPath)
	if status.Compatibility != "" {
		fmt.Fprintf(a.stdout, "compatibility: %s\n", status.Compatibility)
	}
	fmt.Fprintln(a.stdout, "future `openconnect-tun start` and `vless-tun run` runs will prefer the shared core automatically before falling back to sudo")
	return 0
}

func (a *App) runHelperUninstall(args []string) int {
	fs := flag.NewFlagSet("helper uninstall", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := openconnect.UninstallPrivilegedHelper(); err != nil {
		fmt.Fprintf(a.stderr, "helper uninstall failed: %v\n", err)
		return 1
	}

	cfg := openconnect.DefaultPrivilegedHelperConfig()
	fmt.Fprintln(a.stdout, "uninstalled shared vpn core")
	fmt.Fprintf(a.stdout, "socket: %s\n", cfg.SocketPath)
	fmt.Fprintf(a.stdout, "label: %s\n", cfg.Label)
	return 0
}

func (a *App) runHelperStatus(args []string) int {
	fs := flag.NewFlagSet("helper status", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	status, err := openconnect.InspectPrivilegedHelper(openconnect.DefaultPrivilegedHelperConfig())
	if err != nil {
		fmt.Fprintf(a.stderr, "helper status failed: %v\n", err)
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
	} else {
		fmt.Fprintln(a.stdout, "state: missing")
	}
	return 0
}

func (a *App) runHelperDaemon(args []string) int {
	fs := flag.NewFlagSet("_helper-daemon", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	socketPath := fs.String("socket", openconnect.DefaultPrivilegedHelperConfig().SocketPath, "Helper socket path")
	clientUID := fs.Int("client-uid", os.Getuid(), "Client uid")
	clientGID := fs.Int("client-gid", os.Getgid(), "Client gid")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := openconnect.RunPrivilegedHelperDaemon(*socketPath, *clientUID, *clientGID); err != nil {
		fmt.Fprintf(a.stderr, "helper daemon failed: %v\n", err)
		return 1
	}
	return 0
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

func resolveVPNCoreExecutablePath() (string, error) {
	if path, err := exec.LookPath("vpn-core"); err == nil {
		if resolved, err := filepath.EvalSymlinks(path); err == nil {
			path = resolved
		}
		if path != "" {
			return path, nil
		}
	}
	return "", fmt.Errorf("vpn-core binary not found in PATH; run ./scripts/setup.sh first")
}
