package session

import (
	"fmt"
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

func cleanupOrphanSidecars(options []SidecarOptions, logFile *os.File, timeout time.Duration) error {
	targets := orphanSidecarTargets(options)
	if len(targets) == 0 {
		return nil
	}

	_, _ = fmt.Fprintf(logFile, "orphan_sidecar_cleanup_begin targets=%s\n", orphanSidecarTargetNames(targets))
	out, err := sidecarProcessListSession()
	if err != nil {
		return fmt.Errorf("list sidecar processes: %w", err)
	}

	processes := parseSidecarProcesses(out)
	killed := 0
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

			_, _ = fmt.Fprintf(logFile, "orphan_sidecar_cleanup_kill name=%s pid=%d pgid=%d command=%s\n", target.Name, process.PID, process.PGID, process.Command)
			if err := terminateOrphanSidecar(process, timeout); err != nil {
				return fmt.Errorf("stop orphan %s sidecar pid %d: %w", target.Name, process.PID, err)
			}
			seen[process.PID] = struct{}{}
			killed++
		}
	}
	_, _ = fmt.Fprintf(logFile, "orphan_sidecar_cleanup_done killed=%d\n", killed)
	return nil
}

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

func terminateOrphanSidecar(process sidecarProcess, timeout time.Duration) error {
	if err := signalOrphanSidecar(process, syscall.SIGTERM); err != nil {
		return err
	}
	if stopped, err := waitForSidecarProcessExit(process.PID, timeout); err != nil {
		return err
	} else if stopped {
		return nil
	}

	if err := signalOrphanSidecar(process, syscall.SIGKILL); err != nil {
		return err
	}
	if stopped, err := waitForSidecarProcessExit(process.PID, timeout); err != nil {
		return err
	} else if stopped {
		return nil
	}
	return fmt.Errorf("still alive after SIGKILL")
}

func signalOrphanSidecar(process sidecarProcess, signal syscall.Signal) error {
	if process.PGID == process.PID {
		err := sidecarSignalGroupSession(process.PID, signal)
		if err == nil {
			return nil
		}
		if err == syscall.EPERM {
			return sidecarSignalPIDSession(process.PID, signal)
		}
		return err
	}
	return sidecarSignalPIDSession(process.PID, signal)
}

func waitForSidecarProcessExit(pid int, timeout time.Duration) (bool, error) {
	deadline := time.Now().Add(timeout)
	for {
		alive, err := sidecarProcessAliveSession(pid)
		if err != nil {
			return false, err
		}
		if !alive {
			return true, nil
		}
		if time.Now().After(deadline) {
			return false, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
}
