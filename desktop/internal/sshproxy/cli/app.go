package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"multi-tun/desktop/internal/sshproxy/config"
	"multi-tun/desktop/internal/sshproxy/session"
)

type App struct {
	stdout io.Writer
	stderr io.Writer
}

func New(stdout io.Writer, stderr io.Writer) *App {
	return &App{stdout: stdout, stderr: stderr}
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
	case "start":
		return a.runStart(args[1:])
	case "status":
		return a.runStatus(args[1:])
	case "stop":
		return a.runStop(args[1:])
	default:
		fmt.Fprintf(a.stderr, "unknown command %q\n\n", args[0])
		a.printUsage()
		return 2
	}
}

func (a *App) runSetup(args []string) int {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	configPath := fs.String("config", "", "Path to config file")
	serverName := fs.String("server", "dedicated", "SSH proxy profile name")
	host := fs.String("host", "", "SSH host or ~/.ssh/config alias")
	account := fs.String("account", "", "Optional SSH account override")
	listenAddress := fs.String("listen-address", "127.0.0.1", "Local SOCKS bind IP")
	socksPort := fs.Int("socks-port", 1080, "Local SOCKS port")
	force := fs.Bool("force", false, "Overwrite an existing config")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 {
		fmt.Fprintln(a.stderr, "setup failed: no positional arguments are supported")
		return 2
	}
	_, writtenPath, err := config.Setup(*configPath, config.SetupOptions{
		ServerName:    *serverName,
		Host:          *host,
		Account:       *account,
		ListenAddress: *listenAddress,
		SocksPort:     *socksPort,
	}, *force)
	if err != nil {
		fmt.Fprintf(a.stderr, "setup failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(a.stdout, "config: %s\n", writtenPath)
	fmt.Fprintf(a.stdout, "current: %s\n", *serverName)
	return 0
}

func (a *App) runStart(args []string) int {
	fs := flag.NewFlagSet("start", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	configPath := fs.String("config", "", "Path to config file")
	serverName := fs.String("server", "", "Configured SSH proxy profile")
	timeout := fs.Duration("timeout", 15*time.Second, "How long to wait for the local SOCKS listener")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 {
		fmt.Fprintln(a.stderr, "start failed: no positional arguments are supported")
		return 2
	}
	server, err := loadServer(*configPath, *serverName)
	if err != nil {
		fmt.Fprintf(a.stderr, "start failed: %v\n", err)
		return 1
	}
	if current, err := session.Load(server.CacheDir); err == nil {
		if session.Alive(current.PID) {
			fmt.Fprintf(a.stderr, "start failed: ssh-proxy session %s is already running (pid=%d)\n", current.ID, current.PID)
			return 1
		}
		if err := session.Remove(server.CacheDir); err != nil {
			fmt.Fprintf(a.stderr, "start failed: remove stale session: %v\n", err)
			return 1
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(a.stderr, "start failed: read current session: %v\n", err)
		return 1
	}
	if err := ensurePortAvailable(server.ListenEndpoint()); err != nil {
		fmt.Fprintf(a.stderr, "start failed: %v\n", err)
		return 1
	}

	id := time.Now().UTC().Format("20060102T150405Z")
	logPath := session.LogPath(server.CacheDir, id)
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		fmt.Fprintf(a.stderr, "start failed: create log directory: %v\n", err)
		return 1
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		fmt.Fprintf(a.stderr, "start failed: open log: %v\n", err)
		return 1
	}
	cmd := exec.Command(server.SSHExecutable, server.SSHArgs()...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		fmt.Fprintf(a.stderr, "start failed: %v\n", err)
		return 1
	}
	_ = logFile.Close()
	if err := waitForListener(server.ListenEndpoint(), cmd.Process.Pid, *timeout); err != nil {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		fmt.Fprintf(a.stderr, "start failed: %v; log=%s\n", err, logPath)
		return 1
	}
	current := session.CurrentSession{
		ID:            id,
		PID:           cmd.Process.Pid,
		Server:        server.Name,
		Host:          server.Host,
		ListenAddress: server.ListenAddress,
		SocksPort:     server.SocksPort,
		StartedAt:     time.Now().UTC(),
		LogPath:       logPath,
	}
	if err := session.Save(server.CacheDir, current); err != nil {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		fmt.Fprintf(a.stderr, "start failed: save session: %v\n", err)
		return 1
	}
	fmt.Fprintf(a.stdout, "started ssh-proxy session %s\n", current.ID)
	fmt.Fprintf(a.stdout, "server: %s\n", current.Server)
	fmt.Fprintf(a.stdout, "host: %s\n", current.Host)
	fmt.Fprintf(a.stdout, "listen: %s\n", server.ListenEndpoint())
	fmt.Fprintf(a.stdout, "pid: %d\n", current.PID)
	fmt.Fprintf(a.stdout, "log: %s\n", current.LogPath)
	return 0
}

func (a *App) runStatus(args []string) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	configPath := fs.String("config", "", "Path to config file")
	serverName := fs.String("server", "", "Configured SSH proxy profile")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	server, err := loadServer(*configPath, *serverName)
	if err != nil {
		fmt.Fprintf(a.stderr, "status failed: %v\n", err)
		return 1
	}
	current, err := session.Load(server.CacheDir)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(a.stdout, "connection: down")
		fmt.Fprintf(a.stdout, "server: %s\n", server.Name)
		fmt.Fprintf(a.stdout, "listen: %s\n", server.ListenEndpoint())
		return 0
	}
	if err != nil {
		fmt.Fprintf(a.stderr, "status failed: %v\n", err)
		return 1
	}
	alive := session.Alive(current.PID)
	listening := alive && listenerReady(server.ListenEndpoint())
	state := "down"
	if listening {
		state = "up"
	} else if alive {
		state = "degraded"
	}
	fmt.Fprintf(a.stdout, "connection: %s\n", state)
	fmt.Fprintf(a.stdout, "session: %s\n", current.ID)
	fmt.Fprintf(a.stdout, "server: %s\n", current.Server)
	fmt.Fprintf(a.stdout, "host: %s\n", current.Host)
	fmt.Fprintf(a.stdout, "listen: %s\n", server.ListenEndpoint())
	fmt.Fprintf(a.stdout, "pid: %d\n", current.PID)
	fmt.Fprintf(a.stdout, "log: %s\n", current.LogPath)
	return 0
}

func (a *App) runStop(args []string) int {
	fs := flag.NewFlagSet("stop", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	configPath := fs.String("config", "", "Path to config file")
	serverName := fs.String("server", "", "Configured SSH proxy profile")
	timeout := fs.Duration("timeout", 5*time.Second, "How long to wait after SIGTERM")
	force := fs.Bool("force", false, "Escalate to SIGKILL after timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	server, err := loadServer(*configPath, *serverName)
	if err != nil {
		fmt.Fprintf(a.stderr, "stop failed: %v\n", err)
		return 1
	}
	current, err := session.Load(server.CacheDir)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(a.stdout, "no current session file found")
		return 0
	}
	if err != nil {
		fmt.Fprintf(a.stderr, "stop failed: %v\n", err)
		return 1
	}
	if !session.Alive(current.PID) {
		if err := session.Remove(server.CacheDir); err != nil {
			fmt.Fprintf(a.stderr, "stop failed: remove stale session: %v\n", err)
			return 1
		}
		fmt.Fprintf(a.stdout, "removed stale ssh-proxy session %s\n", current.ID)
		return 0
	}
	process, err := os.FindProcess(current.PID)
	if err != nil {
		fmt.Fprintf(a.stderr, "stop failed: %v\n", err)
		return 1
	}
	if err := process.Signal(syscall.SIGTERM); err != nil {
		fmt.Fprintf(a.stderr, "stop failed: signal session: %v\n", err)
		return 1
	}
	if err := waitForExit(current.PID, *timeout); err != nil {
		if !*force {
			fmt.Fprintf(a.stderr, "stop failed: %v; rerun with --force to send SIGKILL\n", err)
			return 1
		}
		if err := process.Kill(); err != nil {
			fmt.Fprintf(a.stderr, "stop failed: force kill: %v\n", err)
			return 1
		}
		if err := waitForExit(current.PID, time.Second); err != nil {
			fmt.Fprintf(a.stderr, "stop failed: %v\n", err)
			return 1
		}
	}
	if err := session.Remove(server.CacheDir); err != nil {
		fmt.Fprintf(a.stderr, "stop failed: remove session: %v\n", err)
		return 1
	}
	fmt.Fprintf(a.stdout, "stopped ssh-proxy session %s\n", current.ID)
	return 0
}

func loadServer(configPath string, serverName string) (config.ResolvedServer, error) {
	cfg, _, err := config.Load(configPath)
	if err != nil {
		return config.ResolvedServer{}, err
	}
	return cfg.Resolve(serverName)
}

func ensurePortAvailable(endpoint string) error {
	listener, err := net.Listen("tcp", endpoint)
	if err != nil {
		return fmt.Errorf("local SOCKS endpoint %s is unavailable: %w", endpoint, err)
	}
	return listener.Close()
}

func waitForListener(endpoint string, pid int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !session.Alive(pid) {
			return errors.New("ssh exited before the SOCKS listener became ready")
		}
		if listenerReady(endpoint) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("local SOCKS listener %s was not ready within %s", endpoint, timeout)
}

func listenerReady(endpoint string) bool {
	connection, err := net.DialTimeout("tcp", endpoint, 250*time.Millisecond)
	if err != nil {
		return false
	}
	return connection.Close() == nil
}

func waitForExit(pid int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !session.Alive(pid) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("ssh process %d did not stop within %s", pid, timeout)
}

func (a *App) printUsage() {
	fmt.Fprintln(a.stdout, "ssh-proxy manages local SSH dynamic SOCKS5 tunnels.")
	fmt.Fprintln(a.stdout)
	fmt.Fprintln(a.stdout, "Usage:")
	fmt.Fprintln(a.stdout, "  ssh-proxy setup --host ssh-alias [--server dedicated] [--account user] [--listen-address 127.0.0.1] [--socks-port 1080] [--force]")
	fmt.Fprintln(a.stdout, "  ssh-proxy start [--config path] [--server name] [--timeout duration]")
	fmt.Fprintln(a.stdout, "  ssh-proxy status [--config path] [--server name]")
	fmt.Fprintln(a.stdout, "  ssh-proxy stop [--config path] [--server name] [--timeout duration] [--force]")
	fmt.Fprintln(a.stdout)
	fmt.Fprintln(a.stdout, "With no --config, ssh-proxy uses ~/.config/ssh-proxy/config.json.")
}
