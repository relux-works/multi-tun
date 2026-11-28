package openconnect

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

var reconcileTunWaveOpenConnect = defaultReconcileTunWave
var reconcileLookPathOpenConnect = exec.LookPath
var reconcileExecutableOpenConnect = os.Executable
var reconcileCommandOpenConnect = exec.CommandContext

// Reconciliation is optional for standalone openconnect-tun installations.
func defaultReconcileTunWave(ctx context.Context, reason string) error {
	binary := resolveTunWaveForReconcile()
	if binary == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := reconcileCommandOpenConnect(ctx, binary, "reconcile", "--reason", reason)
	// No inherited terminal or captured output: reconciliation must not expose
	// credentials or wait forever for an inherited output pipe.
	cmd.WaitDelay = time.Second
	return cmd.Run()
}

func resolveTunWaveForReconcile() string {
	for _, name := range []string{"tun-wave", "vless-tun"} {
		if path, err := reconcileLookPathOpenConnect(name); err == nil {
			return path
		}
	}
	if executable, err := reconcileExecutableOpenConnect(); err == nil {
		for _, name := range []string{"tun-wave", "vless-tun", "../vless-tun/vless-tun"} {
			if path, err := reconcileLookPathOpenConnect(filepath.Join(filepath.Dir(executable), name)); err == nil {
				return path
			}
		}
	}
	return ""
}
