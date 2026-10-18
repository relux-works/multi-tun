package vpncore

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

type LogOptions struct {
	MaxLines int
}

var execLookPathVPNCore = exec.LookPath

func Run(cfg ServiceConfig, command []string, stdinData, logPath string) error {
	return RunWithLogOptions(cfg, command, stdinData, logPath, LogOptions{})
}

func RunWithLogOptions(cfg ServiceConfig, command []string, stdinData, logPath string, options LogOptions) error {
	command, err := resolveClientCommand(command)
	if err != nil {
		return err
	}
	logFile, err := openClientLog(logPath)
	if err != nil {
		return err
	}
	defer logFile.Close()
	if _, err := callActiveWithLog(cfg, Request{
		Action:      "run",
		Command:     append([]string(nil), command...),
		Stdin:       stdinData,
		LogMaxLines: options.MaxLines,
	}, logFile); err != nil {
		if isUnavailable(err) {
			return fmt.Errorf("vpn core is unavailable; run `vpn-core install-digest`, then `vpn-core install --expect-sha256 HEX` once")
		}
		return err
	}
	return nil
}

func SpawnDetached(cfg ServiceConfig, command []string, stdinData, logPath string, setPGID bool) (int, error) {
	return SpawnDetachedWithLogOptions(cfg, command, stdinData, logPath, setPGID, LogOptions{})
}

func SpawnDetachedWithLogOptions(cfg ServiceConfig, command []string, stdinData, logPath string, setPGID bool, options LogOptions) (int, error) {
	command, err := resolveClientCommand(command)
	if err != nil {
		return 0, err
	}
	logFile, err := openClientLog(logPath)
	if err != nil {
		return 0, err
	}
	defer logFile.Close()
	response, err := callActiveWithLog(cfg, Request{
		Action:      "spawn",
		Command:     append([]string(nil), command...),
		Stdin:       stdinData,
		LogMaxLines: options.MaxLines,
		SetPGID:     setPGID,
	}, logFile)
	if err != nil {
		if isUnavailable(err) {
			return 0, fmt.Errorf("vpn core is unavailable; run `vpn-core install-digest`, then `vpn-core install --expect-sha256 HEX` once")
		}
		return 0, err
	}
	if response.PID <= 0 {
		return 0, fmt.Errorf("vpn core did not return child pid")
	}
	return response.PID, nil
}

func Signal(cfg ServiceConfig, pid int, signal string, group bool) error {
	if _, err := callActive(cfg, Request{
		Action: "signal",
		PID:    pid,
		Signal: signal,
		Group:  group,
	}); err != nil {
		if isUnavailable(err) {
			return fmt.Errorf("vpn core is unavailable; run `vpn-core install-digest`, then `vpn-core install --expect-sha256 HEX` once")
		}
		return err
	}
	return nil
}

func callActive(cfg ServiceConfig, request Request) (Response, error) {
	return callActiveWithLog(cfg, request, nil)
}

func callActiveWithLog(cfg ServiceConfig, request Request, logFile *os.File) (Response, error) {
	response, err := callWithTimeoutAndLog(cfg, request, rpcResponseTimeoutVPNCore, logFile)
	if err == nil || !isUnavailable(err) {
		return response, withRPCTimeoutSnapshot(cfg, request.Action, err)
	}
	return Response{}, err
}

func openClientLog(path string) (*os.File, error) {
	if path == "" {
		return nil, errors.New("log path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create client log directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open client log: %w", err)
	}
	return file, nil
}

func resolveClientCommand(command []string) ([]string, error) {
	if len(command) == 0 || command[0] == "" {
		return nil, errors.New("missing command")
	}
	resolved := append([]string(nil), command...)
	if !filepath.IsAbs(resolved[0]) {
		path, err := execLookPathVPNCore(resolved[0])
		if err != nil {
			return nil, fmt.Errorf("resolve command %q: %w", resolved[0], err)
		}
		absolute, err := filepath.Abs(path)
		if err != nil {
			return nil, fmt.Errorf("resolve absolute command path: %w", err)
		}
		resolved[0] = absolute
	}
	return resolved, nil
}

func withRPCTimeoutSnapshot(cfg ServiceConfig, action string, err error) error {
	if !isRPCTimeout(err) {
		return err
	}
	status, statusErr := inspectExactServiceWithTimeout(cfg, rpcTimeoutSnapshotTimeoutVPNCore)
	if statusErr != nil {
		return &RPCTimeoutError{
			Action:          action,
			ResponseTimeout: rpcResponseTimeoutVPNCore,
			cause:           err,
		}
	}
	return &RPCTimeoutError{
		Action:          action,
		ResponseTimeout: rpcResponseTimeoutVPNCore,
		Status:          &status,
		cause:           err,
	}
}
