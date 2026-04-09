package ciscodumpcli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"multi-tun/desktop/internal/anyconnect/ciscodump"
)

type App struct {
	commandName string
	stdout      io.Writer
	stderr      io.Writer
}

func New(stdout, stderr io.Writer, argv0 string) *App {
	return &App{
		commandName: resolveCommandName(argv0),
		stdout:      stdout,
		stderr:      stderr,
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
	case "start":
		return a.runStart(args[1:])
	case "stop":
		return a.runStop(args[1:])
	case "status":
		return a.runStatus(args[1:])
	case "inspect":
		return a.runInspect(args[1:])
	case "__daemon":
		return a.runDaemon(args[1:])
	default:
		fmt.Fprintf(a.stderr, "unknown command %q\n\n", args[0])
		a.printUsage()
		return 2
	}
}

func (a *App) runStart(args []string) int {
	fs := flag.NewFlagSet("start", flag.ContinueOnError)
	fs.SetOutput(a.stderr)

	cacheDir := fs.String("cache-dir", "", "Override cache dir for session metadata and logs")
	interfaceName := fs.String("interface", "", "Capture interface expression, default pktap,all")
	filter := fs.String("filter", "", "tcpdump capture filter, default tcp or udp")
	tcpdumpBinary := fs.String("tcpdump-binary", "", "Explicit tcpdump binary path")
	noTcpdump := fs.Bool("no-tcpdump", false, "Disable packet capture and only snapshot Cisco logs/processes")
	noHostProbes := fs.Bool("no-host-probes", false, "Disable target host DNS/route/TCP/HTTPS probes")
	var probeHosts stringListFlag
	var probeNameservers stringListFlag
	fs.Var(&probeHosts, "probe-host", "Host to probe for DNS/route/TCP/HTTPS diagnostics (repeatable)")
	fs.Var(&probeNameservers, "probe-ns", "Nameserver to use for explicit dig probes (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	started, err := ciscodump.Start(*cacheDir, ciscodump.StartOptions{
		Interface:        *interfaceName,
		Filter:           *filter,
		TcpdumpBinary:    *tcpdumpBinary,
		NoTcpdump:        *noTcpdump,
		NoHostProbes:     *noHostProbes,
		ProbeHosts:       probeHosts.Values(),
		ProbeNameservers: probeNameservers.Values(),
	})
	if err != nil {
		fmt.Fprintf(a.stderr, "start failed: %v\n", err)
		return 1
	}

	fmt.Fprintf(a.stdout, "cache_dir: %s\n", ciscodump.ResolveCacheDir(*cacheDir))
	fmt.Fprintln(a.stdout, "session: active")
	fmt.Fprintf(a.stdout, "session_id: %s\n", started.ID)
	fmt.Fprintf(a.stdout, "started_at: %s\n", started.StartedAt.Format(time.RFC3339))
	fmt.Fprintf(a.stdout, "pid: %d\n", started.PID)
	fmt.Fprintf(a.stdout, "interface: %s\n", started.Interface)
	fmt.Fprintf(a.stdout, "filter: %s\n", started.Filter)
	fmt.Fprintf(a.stdout, "tcpdump: %s\n", enabledLabel(started.TcpdumpEnabled))
	if started.TcpdumpBackend != "" {
		fmt.Fprintf(a.stdout, "tcpdump_backend: %s\n", started.TcpdumpBackend)
	}
	if len(started.ProbeHosts) > 0 {
		fmt.Fprintf(a.stdout, "probe_hosts: %s\n", strings.Join(started.ProbeHosts, ", "))
	}
	if len(started.ProbeNameservers) > 0 {
		fmt.Fprintf(a.stdout, "probe_nameservers: %s\n", strings.Join(started.ProbeNameservers, ", "))
	}
	fmt.Fprintf(a.stdout, "log_file: %s\n", started.LogPath)
	fmt.Fprintf(a.stdout, "artifact_dir: %s\n", started.ArtifactDir)
	if started.PcapPath != "" {
		fmt.Fprintf(a.stdout, "pcap_file: %s\n", started.PcapPath)
	}
	if started.OCSCPcapPath != "" {
		fmt.Fprintf(a.stdout, "ocsc_pcap_file: %s\n", started.OCSCPcapPath)
	}
	fmt.Fprintf(a.stdout, "use `%s status` to inspect state and `%s stop` to stop it\n", a.commandName, a.commandName)
	return 0
}

func (a *App) runStop(args []string) int {
	fs := flag.NewFlagSet("stop", flag.ContinueOnError)
	fs.SetOutput(a.stderr)

	cacheDir := fs.String("cache-dir", "", "Override cache dir for session metadata and logs")
	timeout := fs.Duration("timeout", 10*time.Second, "How long to wait after SIGTERM before failing or forcing")
	force := fs.Bool("force", false, "Escalate from SIGTERM to SIGKILL if the dumper does not stop in time")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	stopped, state, err := ciscodump.Stop(*cacheDir, *force, *timeout)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(a.stdout, "no current %s session file found\n", a.commandName)
		return 0
	}
	if err != nil {
		fmt.Fprintf(a.stderr, "stop failed: %v\n", err)
		if stopped.LogPath != "" {
			fmt.Fprintf(a.stderr, "log=%s\n", stopped.LogPath)
		}
		return 1
	}

	switch state {
	case "stopped", "killed":
		fmt.Fprintf(a.stdout, "%s %s session %s (pid=%d)\n", state, a.commandName, stopped.ID, stopped.PID)
	case "stale":
		fmt.Fprintf(a.stdout, "cleared stale %s session %s (pid=%d)\n", a.commandName, stopped.ID, stopped.PID)
	default:
		fmt.Fprintf(a.stdout, "%s stop result=%s for session %s (pid=%d)\n", a.commandName, state, stopped.ID, stopped.PID)
	}
	fmt.Fprintf(a.stdout, "log=%s\n", stopped.LogPath)
	fmt.Fprintf(a.stdout, "artifact_dir=%s\n", stopped.ArtifactDir)
	if stopped.PcapPath != "" {
		fmt.Fprintf(a.stdout, "pcap_file=%s\n", stopped.PcapPath)
	}
	if stopped.OCSCPcapPath != "" {
		fmt.Fprintf(a.stdout, "ocsc_pcap_file=%s\n", stopped.OCSCPcapPath)
	}
	if stopped.OCSCFrameCount > 0 {
		fmt.Fprintf(a.stdout, "ocsc_frames=%d\n", stopped.OCSCFrameCount)
		fmt.Fprintf(a.stdout, "ocsc_interesting_frames=%d\n", stopped.OCSCInterestingFrameCount)
		fmt.Fprintf(a.stdout, "ocsc_timeline=%s\n", stopped.OCSCTimelinePath)
		fmt.Fprintf(a.stdout, "ocsc_summary=%s\n", stopped.OCSCSummaryPath)
	}
	return 0
}

func (a *App) runStatus(args []string) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(a.stderr)

	cacheDir := fs.String("cache-dir", "", "Override cache dir for session metadata and logs")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	resolvedCacheDir := ciscodump.ResolveCacheDir(*cacheDir)
	current, state, alive, err := currentSessionState(resolvedCacheDir)
	if err != nil {
		fmt.Fprintf(a.stderr, "status failed: %v\n", err)
		return 1
	}

	fmt.Fprintf(a.stdout, "cache_dir: %s\n", resolvedCacheDir)
	fmt.Fprintf(a.stdout, "session: %s\n", state)
	if current == nil {
		return 0
	}
	fmt.Fprintf(a.stdout, "session_id: %s\n", current.ID)
	fmt.Fprintf(a.stdout, "started_at: %s\n", current.StartedAt.Format(time.RFC3339))
	fmt.Fprintf(a.stdout, "pid: %d\n", current.PID)
	fmt.Fprintf(a.stdout, "interface: %s\n", current.Interface)
	fmt.Fprintf(a.stdout, "filter: %s\n", current.Filter)
	fmt.Fprintf(a.stdout, "tcpdump: %s\n", enabledLabel(current.TcpdumpEnabled))
	if current.TcpdumpBackend != "" {
		fmt.Fprintf(a.stdout, "tcpdump_backend: %s\n", current.TcpdumpBackend)
	}
	if len(current.ProbeHosts) > 0 {
		fmt.Fprintf(a.stdout, "probe_hosts: %s\n", strings.Join(current.ProbeHosts, ", "))
	}
	if len(current.ProbeNameservers) > 0 {
		fmt.Fprintf(a.stdout, "probe_nameservers: %s\n", strings.Join(current.ProbeNameservers, ", "))
	}
	if current.TcpdumpPID > 0 {
		fmt.Fprintf(a.stdout, "tcpdump_pid: %d\n", current.TcpdumpPID)
	}
	if current.OCSCTcpdumpPID > 0 {
		fmt.Fprintf(a.stdout, "ocsc_tcpdump_pid: %d\n", current.OCSCTcpdumpPID)
	}
	fmt.Fprintf(a.stdout, "log_file: %s\n", current.LogPath)
	fmt.Fprintf(a.stdout, "artifact_dir: %s\n", current.ArtifactDir)
	if current.PcapPath != "" {
		fmt.Fprintf(a.stdout, "pcap_file: %s\n", current.PcapPath)
	}
	if current.OCSCPcapPath != "" {
		fmt.Fprintf(a.stdout, "ocsc_pcap_file: %s\n", current.OCSCPcapPath)
	}
	if current.OCSCFrameCount > 0 {
		fmt.Fprintf(a.stdout, "ocsc_frames: %d\n", current.OCSCFrameCount)
		fmt.Fprintf(a.stdout, "ocsc_interesting_frames: %d\n", current.OCSCInterestingFrameCount)
		fmt.Fprintf(a.stdout, "ocsc_timeline: %s\n", current.OCSCTimelinePath)
		fmt.Fprintf(a.stdout, "ocsc_summary: %s\n", current.OCSCSummaryPath)
	}
	if !alive {
		if last := ciscodump.LastRelevantLogLine(current.LogPath); last != "" {
			fmt.Fprintf(a.stdout, "last_log_line: %s\n", last)
		}
	}
	return 0
}

func (a *App) runInspect(args []string) int {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.SetOutput(a.stderr)

	cacheDir := fs.String("cache-dir", "", "Override cache dir for session metadata and logs")
	sessionID := fs.String("session-id", "", "Analyze an existing session by id")
	artifactDir := fs.String("artifact-dir", "", "Analyze an existing artifact directory")
	pcapPath := fs.String("pcap", "", "Analyze an explicit pcap path")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	resolvedArtifactDir := *artifactDir
	if resolvedArtifactDir == "" && *sessionID != "" {
		resolvedArtifactDir = ciscodump.SessionArtifactDir(ciscodump.ResolveCacheDir(*cacheDir), *sessionID)
	}
	if resolvedArtifactDir == "" {
		fmt.Fprintln(a.stderr, "inspect failed: pass --artifact-dir or --session-id")
		return 2
	}

	artifacts, err := ciscodump.AnalyzeOCSCArtifactDir(resolvedArtifactDir, *pcapPath)
	if err != nil {
		fmt.Fprintf(a.stderr, "inspect failed: %v\n", err)
		return 1
	}

	fmt.Fprintf(a.stdout, "artifact_dir: %s\n", resolvedArtifactDir)
	if *pcapPath != "" {
		fmt.Fprintf(a.stdout, "pcap_file: %s\n", *pcapPath)
	}
	fmt.Fprintf(a.stdout, "ocsc_frames: %d\n", artifacts.FrameCount)
	fmt.Fprintf(a.stdout, "ocsc_interesting_frames: %d\n", artifacts.InterestingFrameCount)
	if artifacts.TimelinePath != "" {
		fmt.Fprintf(a.stdout, "ocsc_timeline: %s\n", artifacts.TimelinePath)
	}
	if artifacts.SummaryPath != "" {
		fmt.Fprintf(a.stdout, "ocsc_summary: %s\n", artifacts.SummaryPath)
	}
	return 0
}

func (a *App) runDaemon(args []string) int {
	fs := flag.NewFlagSet("__daemon", flag.ContinueOnError)
	fs.SetOutput(a.stderr)

	cacheDir := fs.String("cache-dir", "", "Resolved cache dir")
	sessionID := fs.String("session-id", "", "Session id")
	metadataPath := fs.String("metadata-path", "", "Metadata JSON path")
	artifactDir := fs.String("artifact-dir", "", "Artifact directory")
	pcapPath := fs.String("pcap-path", "", "PCAP output path")
	ocscPcapPath := fs.String("ocsc-pcap-path", "", "Loopback OCSC PCAP output path")
	interfaceName := fs.String("interface", "", "Capture interface")
	filter := fs.String("filter", "", "Capture filter")
	tcpdumpBinary := fs.String("tcpdump-binary", "", "tcpdump binary")
	noTcpdump := fs.Bool("no-tcpdump", false, "Disable tcpdump capture")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	err := ciscodump.RunDaemon(ciscodump.DaemonOptions{
		CacheDir:      *cacheDir,
		SessionID:     *sessionID,
		MetadataPath:  *metadataPath,
		ArtifactDir:   *artifactDir,
		PcapPath:      *pcapPath,
		OCSCPcapPath:  *ocscPcapPath,
		Interface:     *interfaceName,
		Filter:        *filter,
		TcpdumpBinary: *tcpdumpBinary,
		NoTcpdump:     *noTcpdump,
	})
	if err != nil {
		fmt.Fprintf(a.stderr, "daemon failed: %v\n", err)
		return 1
	}
	return 0
}

func (a *App) printUsage() {
	fmt.Fprintf(a.stdout, "%s captures tunnel-aware VPN diagnostics and packet artifacts around manual connect flows.\n", a.commandName)
	fmt.Fprintln(a.stdout)
	fmt.Fprintln(a.stdout, "Usage:")
	fmt.Fprintf(a.stdout, "  %s start [--cache-dir path] [--interface pktap,all] [--filter expr] [--tcpdump-binary path] [--no-tcpdump] [--no-host-probes] [--probe-host host] [--probe-ns ip]\n", a.commandName)
	fmt.Fprintf(a.stdout, "  %s status [--cache-dir path]\n", a.commandName)
	fmt.Fprintf(a.stdout, "  %s stop [--cache-dir path] [--timeout duration] [--force]\n", a.commandName)
	fmt.Fprintf(a.stdout, "  %s inspect [--cache-dir path] [--session-id id | --artifact-dir path] [--pcap path]\n", a.commandName)
}

func currentSessionState(cacheDir string) (*ciscodump.CurrentSession, string, bool, error) {
	current, err := ciscodump.LoadCurrent(cacheDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, "none", false, nil
	}
	if err != nil {
		return nil, "unknown", false, err
	}

	alive, pid, err := ciscodump.SessionAlive(current)
	if err != nil {
		return &current, "unknown", false, err
	}
	if pid > 0 {
		current.PID = pid
	}
	if alive {
		return &current, "active", true, nil
	}
	return &current, "stale", false, nil
}

func enabledLabel(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "disabled"
}

func resolveCommandName(argv0 string) string {
	name := strings.TrimSpace(filepath.Base(argv0))
	if name == "" || name == "." || name == string(filepath.Separator) {
		return "dump"
	}
	return name
}

type stringListFlag []string

func (s *stringListFlag) String() string {
	return strings.Join(*s, ",")
}

func (s *stringListFlag) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("value cannot be empty")
	}
	*s = append(*s, value)
	return nil
}

func (s *stringListFlag) Values() []string {
	if len(*s) == 0 {
		return nil
	}
	return append([]string(nil), (*s)...)
}
