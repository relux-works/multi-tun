package vpncore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type LogOptions struct {
	MaxLines int
}

func StartSingBox(cfg ServiceConfig, configJSON []byte, logPath string, setPGID bool, options LogOptions) (int, string, error) {
	logFile, err := openClientLog(logPath)
	if err != nil {
		return 0, "", err
	}
	defer logFile.Close()
	response, err := callPrimitiveOrLegacy(cfg, Request{Action: "proc.ensure", ProcEnsure: &ProcEnsureRequest{Kind: "sing-box", ConfigJSON: configJSON, LogMaxLines: options.MaxLines, SetPGID: setPGID}}, Request{
		Action:      "singbox.start",
		ConfigJSON:  append([]byte(nil), configJSON...),
		LogMaxLines: options.MaxLines,
		SetPGID:     setPGID,
	}, logFile)
	if err != nil {
		if isUnavailable(err) {
			return 0, "", fmt.Errorf("vpn core is unavailable; run `vpn-core install-digest`, then `vpn-core install --expect-sha256 HEX` once")
		}
		return 0, "", err
	}
	if response.PID <= 0 || response.Handle == "" {
		return 0, "", fmt.Errorf("vpn core did not return child pid and handle")
	}
	return response.PID, response.Handle, nil
}

// StartOpenConnect passes the client's already-open log descriptor over SCM_RIGHTS.
func StartOpenConnect(cfg ServiceConfig, req OpenConnectStartRequest, logPath string) (int, string, error) {
	logFile, err := openClientLog(logPath)
	if err != nil {
		return 0, "", err
	}
	defer logFile.Close()
	response, err := callPrimitiveOrLegacy(cfg, Request{Action: "proc.ensure", ProcEnsure: &ProcEnsureRequest{Kind: "openconnect", OpenConnect: &req, SetPGID: true}}, Request{Action: "openconnect.start", OpenConnect: &req}, logFile)
	if err != nil {
		// Older typed daemons reject the new JSON field before checking Action.
		// This exact explicit refusal proves no child was launched and is safe for
		// the automatic client's unsupported-action compatibility fallback.
		var refused *RefusedError
		if errors.As(err, &refused) && refused.Message == `json: unknown field "openconnect"` {
			return 0, "", &RefusedError{Message: `unsupported vpn core action "openconnect.start"`}
		}
		return 0, "", err
	}
	if response.PID <= 0 || response.Handle == "" {
		return 0, "", errors.New("vpn core did not return openconnect pid and handle")
	}
	return response.PID, response.Handle, nil
}

func Signal(cfg ServiceConfig, handle, signal string) (string, error) {
	response, err := callPrimitiveOrLegacy(cfg, Request{Action: "proc.stop", ProcStop: &ProcStopRequest{Handle: handle, Signal: signal}}, Request{
		Action: "signal",
		Handle: handle,
		Signal: signal,
	}, nil)
	if err != nil {
		if isUnavailable(err) {
			return "", fmt.Errorf("vpn core is unavailable; run `vpn-core install-digest`, then `vpn-core install --expect-sha256 HEX` once")
		}
		return "", err
	}
	return response.Path, nil
}

func RunSCUtil(cfg ServiceConfig, stdin string) error {
	_, err := callPrimitiveOrLegacy(cfg, Request{Action: "net.dns", NetDNS: &NetDNSRequest{Op: "scutil", Stdin: stdin}}, Request{Action: "dns.scutil", Stdin: stdin}, nil)
	return err
}

func RunNetworkSetup(cfg ServiceConfig, service string, servers []string) error {
	_, err := callPrimitiveOrLegacy(cfg, Request{Action: "net.dns", NetDNS: &NetDNSRequest{Op: "networksetup", Service: service, Servers: append([]string(nil), servers...)}}, Request{Action: "dns.networksetup", Service: service, Servers: append([]string(nil), servers...)}, nil)
	return err
}

func CleanupResolvers(cfg ServiceConfig) error {
	_, err := callPrimitiveOrLegacy(cfg, Request{Action: "net.dns", NetDNS: &NetDNSRequest{Op: "resolver_cleanup"}}, Request{Action: "resolver.cleanup"}, nil)
	return err
}

// ApplyFailClosed asks the helper to enforce the fail-closed anchor.
func ApplyFailClosed(cfg ServiceConfig, interfaces, table []string) error {
	_, err := callPrimitiveOrLegacy(cfg, Request{Action: "pf.anchor", PFAnchor: &PFAnchorRequest{Op: "apply", FailClosed: &FailClosedRequest{Interfaces: append([]string(nil), interfaces...), Table: append([]string(nil), table...)}}}, Request{Action: "failclosed.apply", FailClosed: &FailClosedRequest{
		Interfaces: append([]string(nil), interfaces...), Table: append([]string(nil), table...),
	}}, nil)
	return err
}

// ClearFailClosed removes the fail-closed anchor and keeps it off after reboot.
// It never touches the tunnel.
func ClearFailClosed(cfg ServiceConfig) error {
	_, err := callPrimitiveOrLegacy(cfg, Request{Action: "pf.anchor", PFAnchor: &PFAnchorRequest{Op: "clear"}}, Request{Action: "failclosed.clear"}, nil)
	return err
}

// FailClosedState reports the helper's fail-closed state without changing it.
func FailClosedState(cfg ServiceConfig) (FailClosedStatus, error) {
	response, err := callPrimitiveOrLegacy(cfg, Request{Action: "pf.anchor", PFAnchor: &PFAnchorRequest{Op: "status"}}, Request{Action: "failclosed.status"}, nil)
	if err != nil {
		return FailClosedStatus{}, err
	}
	if response.FailClosed == nil {
		return FailClosedStatus{}, errors.New("vpn core did not return fail-closed status")
	}
	return *response.FailClosed, nil
}

func StartTCPDump(cfg ServiceConfig, interfaceName string, filter []string, applePCAPNG, runAsUser bool) (int, string, error) {
	response, err := callPrimitiveOrLegacy(cfg, Request{Action: "proc.ensure", ProcEnsure: &ProcEnsureRequest{Kind: "tcpdump", Interface: interfaceName, Filter: append([]string(nil), filter...), ApplePCAPNG: applePCAPNG, RunAsUser: runAsUser}}, Request{Action: "tcpdump.start", Interface: interfaceName, Filter: append([]string(nil), filter...), ApplePCAPNG: applePCAPNG, RunAsUser: runAsUser}, nil)
	if err != nil {
		return 0, "", err
	}
	if response.PID <= 0 || response.Handle == "" {
		return 0, "", errors.New("vpn core did not return tcpdump pid and handle")
	}
	return response.PID, response.Handle, nil
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
