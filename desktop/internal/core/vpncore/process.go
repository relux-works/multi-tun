package vpncore

import (
	"errors"
	"fmt"
)

type LogOptions struct {
	MaxLines int
}

func Run(cfg ServiceConfig, command []string, stdinData, logPath string) error {
	return RunWithLogOptions(cfg, command, stdinData, logPath, LogOptions{})
}

func RunWithLogOptions(cfg ServiceConfig, command []string, stdinData, logPath string, options LogOptions) error {
	if logPath == "" {
		return errors.New("log path is required")
	}
	if _, err := callActive(cfg, Request{
		Action:      "run",
		Command:     append([]string(nil), command...),
		Stdin:       stdinData,
		LogPath:     logPath,
		LogMaxLines: options.MaxLines,
	}); err != nil {
		if isUnavailable(err) {
			return fmt.Errorf("vpn core is unavailable; run `vpn-core install` once")
		}
		return err
	}
	return nil
}

func SpawnDetached(cfg ServiceConfig, command []string, stdinData, logPath string, setPGID bool) (int, error) {
	return SpawnDetachedWithLogOptions(cfg, command, stdinData, logPath, setPGID, LogOptions{})
}

func SpawnDetachedWithLogOptions(cfg ServiceConfig, command []string, stdinData, logPath string, setPGID bool, options LogOptions) (int, error) {
	if logPath == "" {
		return 0, errors.New("log path is required")
	}
	response, err := callActive(cfg, Request{
		Action:      "spawn",
		Command:     append([]string(nil), command...),
		Stdin:       stdinData,
		LogPath:     logPath,
		LogMaxLines: options.MaxLines,
		SetPGID:     setPGID,
	})
	if err != nil {
		if isUnavailable(err) {
			return 0, fmt.Errorf("vpn core is unavailable; run `vpn-core install` once")
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
			return fmt.Errorf("vpn core is unavailable; run `vpn-core install` once")
		}
		return err
	}
	return nil
}

func callActive(cfg ServiceConfig, request Request) (Response, error) {
	response, err := call(cfg, request)
	if err == nil || !isUnavailable(err) {
		return response, err
	}

	for _, compat := range compatibilityServiceConfigsVPNCore(cfg) {
		response, compatErr := call(compat.ServiceConfig, request)
		if compatErr == nil || !isUnavailable(compatErr) {
			return response, compatErr
		}
	}

	return Response{}, err
}
