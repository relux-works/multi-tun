package openconnect

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"multi-tun/desktop/internal/core/vpncore"
)

type PrivilegedHelperConfig = vpncore.ServiceConfig
type PrivilegedHelperStatus = vpncore.ServiceStatus
type HelperSnapshot = vpncore.HelperSnapshot
type RequestSnapshot = vpncore.RequestSnapshot
type CompletedRequestSnapshot = vpncore.CompletedRequestSnapshot

var (
	vpnCoreCleanupResolversOpenConnect = vpncore.CleanupResolvers
	// Compatibility seams remain for existing client unit tests only. The
	// production functions fail closed; the daemon has no generic run action.
	vpnCoreRunOpenConnect = func(vpncore.ServiceConfig, []string, string, string) error {
		return errors.New("generic vpn-core run action was removed")
	}
	vpnCoreSignalOpenConnect = func(vpncore.ServiceConfig, int, string, bool) error {
		return errors.New("PID-based vpn-core signal action was removed")
	}
	vpnCoreAvailableOpenConnect = vpncore.Available
)

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
			return "", cfg, fmt.Errorf("vpn core is not reachable; run `vpn-core install-digest`, then `vpn-core install --expect-sha256 HEX` once")
		}
		// PR B removes generic root execution before PR C introduces the fully
		// typed openconnect.start action. Keep the CLI launch working through its
		// existing sudo lane, and use vpn-core only for typed resolver cleanup.
		return PrivilegedModeSudo, cfg, nil
	default:
		return "", cfg, fmt.Errorf("unsupported privileged mode %q", mode)
	}
}

func InspectPrivilegedHelper(cfg PrivilegedHelperConfig) (PrivilegedHelperStatus, error) {
	return vpncore.InspectService(cfg)
}

func InstallPrivilegedHelper(string, int, int) error {
	return errors.New("legacy helper install is disabled; run `vpn-core install-digest`, then `vpn-core install --expect-sha256 HEX`")
}

func UninstallPrivilegedHelper() error {
	return vpncore.UninstallService(DefaultPrivilegedHelperConfig())
}

func RunPrivilegedHelperDaemon(string, int, int) error {
	return errors.New("legacy helper daemon entrypoint is disabled; launch the installed vpn-core daemon")
}

func helperConnect(cfg PrivilegedHelperConfig, command []string, cookie, logPath string) error {
	return vpnCoreRunOpenConnect(cfg, command, cookie+"\n", logPath)
}

func isHelperRPCTimeout(err error) bool {
	var timeoutErr *vpncore.RPCTimeoutError
	return errors.As(err, &timeoutErr)
}

func helperSignal(cfg PrivilegedHelperConfig, pid int, signal string) error {
	return vpnCoreSignalOpenConnect(cfg, pid, signal, false)
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
	return vpnCoreAvailableOpenConnect(cfg)
}

func renderPrivilegedHelperPlist(cfg PrivilegedHelperConfig, binaryPath string, clientUID, clientGID int, binarySHA256, manifestSHA256 string) []byte {
	return vpncore.RenderServicePlist(cfg, binaryPath, clientUID, clientGID, binarySHA256, manifestSHA256)
}
