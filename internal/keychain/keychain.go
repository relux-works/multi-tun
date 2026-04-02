package keychain

import (
	"fmt"
	"os/exec"
	"strings"
)

const serviceName = "multi-tun"

type SetOptions struct {
	Label   string
	Kind    string
	Comment string
}

func Set(account, value string) error {
	return SetWithOptions(account, value, SetOptions{})
}

func SetWithOptions(account, value string, options SetOptions) error {
	if Exists(account) {
		if err := Delete(account); err != nil {
			return fmt.Errorf("keychain replace %q: %w", account, err)
		}
	}

	args := []string{
		"add-generic-password",
		"-a", account,
		"-s", serviceName,
	}
	if label := strings.TrimSpace(options.Label); label != "" {
		args = append(args, "-l", label)
	}
	if kind := strings.TrimSpace(options.Kind); kind != "" {
		args = append(args, "-D", kind)
	}
	if comment := strings.TrimSpace(options.Comment); comment != "" {
		args = append(args, "-j", comment)
	}
	args = append(args, "-w", value)

	cmd := exec.Command("security", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("keychain set %q: %w (%s)", account, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func Get(account string) (string, error) {
	cmd := exec.Command("security", "find-generic-password",
		"-a", account,
		"-s", serviceName,
		"-w",
	)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("keychain get %q: not found", account)
	}
	return strings.TrimSpace(string(out)), nil
}

func Delete(account string) error {
	cmd := exec.Command("security", "delete-generic-password",
		"-a", account,
		"-s", serviceName,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("keychain delete %q: %w (%s)", account, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func Exists(account string) bool {
	_, err := Get(account)
	return err == nil
}

func TunnelKey(tunnelName, key string) string {
	return tunnelName + "/" + key
}

func GetTunnelCred(tunnelName, key string) (string, error) {
	return Get(TunnelKey(tunnelName, key))
}

var AnyConnectKeys = []string{"username", "password", "totp_secret"}
