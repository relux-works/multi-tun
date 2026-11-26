package session

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var (
	sidecarProcessListSession = func() ([]byte, error) {
		return execCommand("ps", "-axo", "pid=,ppid=,pgid=,command=").CombinedOutput()
	}
	sidecarProcessAliveSession = ProcessAlive
	sidecarSignalPIDSession    = func(pid int, signal syscall.Signal) error {
		err := syscall.Kill(pid, signal)
		if err == syscall.ESRCH {
			return nil
		}
		return err
	}
	sidecarSignalGroupSession = signalGroup
)

type sidecarProcess struct {
	PID     int
	PPID    int
	PGID    int
	Command string
}

type orphanSidecarTarget struct {
	Name           string
	ExecutableBase string
	ConfigPath     string
}

var psProcessLinePattern = regexp.MustCompile(`^\s*(\d+)\s+(\d+)\s+(\d+)\s+(.+?)\s*$`)

func cleanupOrphanSidecars(options []SidecarOptions, logFile io.Writer, timeout time.Duration) error {
	targets := orphanSidecarTargets(options)
	if len(targets) == 0 {
		return nil
	}

	writeSessionLog(logFile, logLevelInfo, "orphan_sidecar_cleanup_begin targets=%s\n", orphanSidecarTargetNames(targets))
	out, err := sidecarProcessListSession()
	if err != nil {
		return fmt.Errorf("list sidecar processes: %w", err)
	}

	// A process found here by a sidecar's executable and config path has no session record, so
	// nothing proves who owns it: another vless-tun session can share the config, or another program
	// can use it. Each one is reported with what can be observed now (orphanSidecarGuidance) and is
	// never signalled; the start refuses while any is found.
	processes := parseSidecarProcesses(out)
	var found []string
	seen := map[int]struct{}{}
	for _, target := range targets {
		for _, process := range processes {
			if process.PID == os.Getpid() {
				continue
			}
			if _, ok := seen[process.PID]; ok {
				continue
			}
			if !orphanSidecarMatches(target, process) {
				continue
			}
			seen[process.PID] = struct{}{}
			writeSessionLog(logFile, logLevelWarn, "orphan_sidecar_found name=%s pid=%d pgid=%d command=%s\n", target.Name, process.PID, process.PGID, process.Command)
			comm, started, identityErr := processIdentitySession(process.PID)
			found = append(found, orphanSidecarGuidance(target, process, comm, started, identityErr))
		}
	}
	if len(found) > 0 {
		return fmt.Errorf("%w:\n%s\nthen start again", errOrphanSidecarRunning, strings.Join(found, "\n"))
	}
	writeSessionLog(logFile, logLevelInfo, "orphan_sidecar_cleanup_done found=0\n")
	return nil
}

// psStartLayout is how `ps -o lstart` prints a start time in the C locale; the shown check pins
// LC_ALL=C and TZ=UTC0, and the recorded start is printed in the same form in UTC, so the two
// compare as text in any locale and time zone.
const psStartLayout = "Mon Jan _2 15:04:05 2006"

// orphanSidecarGuidance describes one process found by a sidecar's executable and config path and
// states only what the client observed. The start time comes from a kern.proc lookup of the PID,
// which reads whoever holds the PID at that moment, so it is shown only when the looked-up process
// name matches the executable in the listed command; otherwise the PID already belongs to another
// process and only that is said. The process may be another vless-tun session's sidecar (caches can
// share an Xray config) or another program, so no owner and no stop or kill command is named. The
// client itself signals nothing.
func orphanSidecarGuidance(target orphanSidecarTarget, process sidecarProcess, comm string, started time.Time, identityErr error) string {
	pid := process.PID
	head := fmt.Sprintf("leftover %s sidecar process: pid %d, config %s, command %s\n"+
		"  it may belong to another vless-tun session that uses the same Xray config, or to another program\n",
		target.Name, pid, target.ConfigPath, process.Command)
	if identityErr != nil || started.IsZero() {
		return head + fmt.Sprintf("  its start time could not be read, so `ps` cannot tell it from a later process that reuses pid %d;\n"+
			"  leave pid %d alone unless whoever owns it can confirm it is this process", pid, pid)
	}
	if listed := listedProcessName(process.Command); comm != listed {
		return head + fmt.Sprintf("  pid %d now belongs to another process (%q, not %q): the listed process is gone; leave pid %d alone", pid, comm, listed, pid)
	}
	shown := started.UTC().Format(psStartLayout)
	return head + fmt.Sprintf("  started:   %s UTC (%s)\n"+
		"  check it:  LC_ALL=C TZ=UTC0 ps -o pid,lstart,command -p %d\n"+
		"             a start time other than %s means the original is gone and pid %d was reused: leave that process alone\n"+
		"  stop it:   through the session or program that owns it\n"+
		"  confirm:   the original is gone once `ps` shows no process %d or one with another start time",
		shown, started.UTC().Format(time.RFC3339), pid, shown, pid, pid)
}

// listedProcessName is the process name kern.proc reports for the listed command's executable:
// its base name, cut to MAXCOMLEN (16) bytes.
func listedProcessName(command string) string {
	name := processCommandBase(command)
	if len(name) > 16 {
		name = name[:16]
	}
	return name
}

// errOrphanSidecarRunning marks a start refused because a process using a sidecar's executable and
// config path is already running and nothing proves it is a leftover of this client.
var errOrphanSidecarRunning = errors.New("a process using this sidecar's executable and config is already running and is not signalled")

func findRunningSidecar(option SidecarOptions) (sidecarProcess, bool, error) {
	targets := orphanSidecarTargets([]SidecarOptions{option})
	if len(targets) == 0 {
		return sidecarProcess{}, false, nil
	}
	out, err := sidecarProcessListSession()
	if err != nil {
		return sidecarProcess{}, false, fmt.Errorf("list sidecar processes: %w", err)
	}
	target := targets[0]
	for _, process := range parseSidecarProcesses(out) {
		if process.PID == os.Getpid() {
			continue
		}
		if orphanSidecarMatches(target, process) {
			return process, true, nil
		}
	}
	return sidecarProcess{}, false, nil
}

func orphanSidecarTargets(options []SidecarOptions) []orphanSidecarTarget {
	targets := make([]orphanSidecarTarget, 0, len(options))
	for _, option := range options {
		configPath := sidecarConfigPath(option.Args)
		if configPath == "" {
			continue
		}

		name := strings.TrimSpace(option.Name)
		if name == "" {
			name = "sidecar"
		}
		executableBase := filepath.Base(strings.TrimSpace(option.Executable))
		if executableBase == "." || executableBase == string(filepath.Separator) {
			executableBase = ""
		}

		targets = append(targets, orphanSidecarTarget{
			Name:           name,
			ExecutableBase: executableBase,
			ConfigPath:     configPath,
		})
	}
	return targets
}

func orphanSidecarTargetNames(targets []orphanSidecarTarget) string {
	names := make([]string, 0, len(targets))
	for _, target := range targets {
		names = append(names, target.Name+":"+target.ConfigPath)
	}
	return strings.Join(names, ",")
}

func sidecarConfigPath(args []string) string {
	for i, arg := range args {
		arg = strings.TrimSpace(arg)
		switch {
		case arg == "-c" || arg == "-config" || arg == "--config":
			if i+1 < len(args) {
				return strings.TrimSpace(args[i+1])
			}
		case strings.HasPrefix(arg, "-c="):
			return strings.TrimSpace(strings.TrimPrefix(arg, "-c="))
		case strings.HasPrefix(arg, "-config="):
			return strings.TrimSpace(strings.TrimPrefix(arg, "-config="))
		case strings.HasPrefix(arg, "--config="):
			return strings.TrimSpace(strings.TrimPrefix(arg, "--config="))
		}
	}
	return ""
}

func parseSidecarProcesses(out []byte) []sidecarProcess {
	var processes []sidecarProcess
	for _, line := range strings.Split(string(out), "\n") {
		match := psProcessLinePattern.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		pid, err := strconv.Atoi(match[1])
		if err != nil {
			continue
		}
		ppid, err := strconv.Atoi(match[2])
		if err != nil {
			continue
		}
		pgid, err := strconv.Atoi(match[3])
		if err != nil {
			continue
		}
		command := strings.TrimSpace(match[4])
		if command == "" {
			continue
		}
		processes = append(processes, sidecarProcess{
			PID:     pid,
			PPID:    ppid,
			PGID:    pgid,
			Command: command,
		})
	}
	return processes
}

func orphanSidecarMatches(target orphanSidecarTarget, process sidecarProcess) bool {
	if target.ConfigPath == "" || !strings.Contains(process.Command, target.ConfigPath) {
		return false
	}

	processBase := processCommandBase(process.Command)
	if processBase == "" {
		return false
	}
	if target.ExecutableBase != "" && processBase == target.ExecutableBase {
		return true
	}
	return processBase == target.Name
}

func processCommandBase(command string) string {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return ""
	}
	first := strings.Trim(fields[0], `"'`)
	base := filepath.Base(first)
	base = strings.Trim(base, "()")
	if base == "." || base == string(filepath.Separator) {
		return ""
	}
	return base
}
