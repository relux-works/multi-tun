package openconnect

import (
	"fmt"
	"io"
	"os"
	"strings"

	"multi-tun/internal/vpncore"
)

type PrivilegedHelperConfig = vpncore.ServiceConfig
type PrivilegedHelperStatus = vpncore.ServiceStatus

func DefaultPrivilegedHelperConfig() PrivilegedHelperConfig {
	return vpncore.DefaultServiceConfig()
}

func resolvePrivilegedMode(mode string) (string, PrivilegedHelperConfig, error) {
	cfg := DefaultPrivilegedHelperConfig()
	mode = strings.TrimSpace(mode)
	if mode == "" {
		mode = PrivilegedModeAuto
	}

	switch mode {
	case PrivilegedModeAuto:
		if os.Geteuid() == 0 {
			return PrivilegedModeDirect, cfg, nil
		}
		if helperAvailable(cfg) {
			return PrivilegedModeHelper, cfg, nil
		}
		return PrivilegedModeSudo, cfg, nil
	case PrivilegedModeSudo:
		if os.Geteuid() == 0 {
			return PrivilegedModeDirect, cfg, nil
		}
		return PrivilegedModeSudo, cfg, nil
	case PrivilegedModeDirect:
		return PrivilegedModeDirect, cfg, nil
	case PrivilegedModeHelper:
		if !helperAvailable(cfg) {
			return "", cfg, fmt.Errorf("vpn core is not reachable; run `vpn-core install` once")
		}
		return PrivilegedModeHelper, cfg, nil
	default:
		return "", cfg, fmt.Errorf("unsupported privileged mode %q", mode)
	}
}

func InspectPrivilegedHelper(cfg PrivilegedHelperConfig) (PrivilegedHelperStatus, error) {
	return vpncore.InspectService(cfg)
}

func InstallPrivilegedHelper(binaryPath string, clientUID, clientGID int) error {
	return vpncore.InstallService(DefaultPrivilegedHelperConfig(), binaryPath, clientUID, clientGID)
}

func UninstallPrivilegedHelper() error {
	return vpncore.UninstallService(DefaultPrivilegedHelperConfig())
}

func RunPrivilegedHelperDaemon(socketPath string, clientUID, clientGID int) error {
	cfg := DefaultPrivilegedHelperConfig()
	if strings.TrimSpace(socketPath) != "" {
		cfg.SocketPath = socketPath
	}
	return vpncore.RunDaemon(cfg, clientUID, clientGID)
}

func helperConnect(cfg PrivilegedHelperConfig, command []string, cookie, logPath string) error {
	return vpncore.Run(cfg, command, cookie+"\n", logPath)
}

func helperRun(cfg PrivilegedHelperConfig, command []string, stdinData, logPath string) error {
	return vpncore.Run(cfg, command, stdinData, logPath)
}

func helperSignal(cfg PrivilegedHelperConfig, pid int, signal string) error {
	return vpncore.Signal(cfg, pid, signal, false)
}

func shouldUseHelperSignal(mode string, helperSocketPath string) bool {
	switch strings.TrimSpace(mode) {
	case PrivilegedModeHelper:
		return true
	case "", PrivilegedModeAuto:
		return helperAvailable(defaultHelperConfigForSocket(helperSocketPath))
	default:
		return false
	}
}

func defaultHelperConfigForSocket(socketPath string) PrivilegedHelperConfig {
	cfg := DefaultPrivilegedHelperConfig()
	if strings.TrimSpace(socketPath) != "" {
		cfg.SocketPath = socketPath
	}
	return cfg
}

func currentLogPath(w io.Writer) string {
	file, ok := w.(*os.File)
	if !ok {
		return ""
	}
	return file.Name()
}

func helperAvailable(cfg PrivilegedHelperConfig) bool {
	return vpncore.Available(cfg)
}

func renderPrivilegedHelperPlist(cfg PrivilegedHelperConfig, binaryPath string, clientUID, clientGID int) []byte {
	return vpncore.RenderServicePlist(cfg, binaryPath, clientUID, clientGID)
}
