package vpncore

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const (
	rpcDialTimeoutVPNCore            = 2 * time.Second
	rpcTimeoutSnapshotTimeoutVPNCore = 750 * time.Millisecond
)

var rpcResponseTimeoutVPNCore = 5 * time.Second

type Request struct {
	Action      string   `json:"action"`
	Command     []string `json:"command,omitempty"`
	Stdin       string   `json:"stdin,omitempty"`
	LogPath     string   `json:"log_path,omitempty"`
	LogMaxLines int      `json:"log_max_lines,omitempty"`
	PID         int      `json:"pid,omitempty"`
	Signal      string   `json:"signal,omitempty"`
	Group       bool     `json:"group,omitempty"`
	SetPGID     bool     `json:"setpgid,omitempty"`
}

type Response struct {
	OK             bool            `json:"ok"`
	Error          string          `json:"error,omitempty"`
	DaemonPID      int             `json:"daemon_pid,omitempty"`
	PID            int             `json:"pid,omitempty"`
	HelperSnapshot *HelperSnapshot `json:"helper_snapshot,omitempty"`
}

func call(cfg ServiceConfig, request Request) (Response, error) {
	return callWithTimeout(cfg, request, rpcResponseTimeoutVPNCore)
}

func callWithTimeout(cfg ServiceConfig, request Request, timeout time.Duration) (Response, error) {
	if timeout <= 0 {
		timeout = rpcResponseTimeoutVPNCore
	}
	dialTimeout := minDuration(rpcDialTimeoutVPNCore, timeout)
	conn, err := net.DialTimeout("unix", cfg.SocketPath, dialTimeout)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return Response{}, err
	}
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return Response{}, err
	}

	var response Response
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		return Response{}, err
	}
	if !response.OK {
		return response, errors.New(response.Error)
	}
	return response, nil
}

// RPCTimeoutError preserves the network timeout while attaching a redacted
// helper status sampled through the existing ping request.
type RPCTimeoutError struct {
	Action          string
	ResponseTimeout time.Duration
	Status          *ServiceStatus
	cause           error
}

func (e *RPCTimeoutError) Error() string {
	return fmt.Sprintf(
		"vpn core rpc %s timed out after %s; helper snapshot: %s",
		safeRequestAction(e.Action),
		e.ResponseTimeout,
		formatTimeoutServiceStatus(e.Status),
	)
}

func (e *RPCTimeoutError) Unwrap() error {
	return e.cause
}

func (e *RPCTimeoutError) Timeout() bool {
	return true
}

func (e *RPCTimeoutError) Temporary() bool {
	return true
}

func isRPCTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}

func isUnavailable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	message := err.Error()
	return strings.Contains(message, "connect: no such file") ||
		strings.Contains(message, "connect: connection refused")
}
