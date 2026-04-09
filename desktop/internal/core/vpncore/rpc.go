package vpncore

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"time"
)

type Request struct {
	Action  string   `json:"action"`
	Command []string `json:"command,omitempty"`
	Stdin   string   `json:"stdin,omitempty"`
	LogPath string   `json:"log_path,omitempty"`
	PID     int      `json:"pid,omitempty"`
	Signal  string   `json:"signal,omitempty"`
	Group   bool     `json:"group,omitempty"`
	SetPGID bool     `json:"setpgid,omitempty"`
}

type Response struct {
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
	DaemonPID int    `json:"daemon_pid,omitempty"`
	PID       int    `json:"pid,omitempty"`
}

func call(cfg ServiceConfig, request Request) (Response, error) {
	conn, err := net.DialTimeout("unix", cfg.SocketPath, 2*time.Second)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
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
