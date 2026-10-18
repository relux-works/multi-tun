package vpncore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"
)

const (
	manifestVersion          = 1
	launchctlForgetTimeout   = 10 * time.Second
	launchctlForgetPollDelay = 100 * time.Millisecond
)

var lowercaseSHA256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ManifestFile is intentionally extensible: PR B adds root-owned bin/ and
// libexec/ snapshots without changing the verification format.
type ManifestFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	Version int            `json:"version"`
	Files   []ManifestFile `json:"files"`
}

type installPackage struct {
	dir            string
	binaryPath     string
	manifestPath   string
	binarySHA256   string
	manifestSHA256 string
	digest         string
}

var (
	ensureSudoCredentialsVPNCore = ensureSudoCredentials
	runPrivilegedCommandVPNCore  = runPrivilegedCommand
	installSleepVPNCore          = time.Sleep
	installNowVPNCore            = time.Now
	installedOwnerUIDVPNCore     = installedOwnerUID
)

func InstallDigest(binaryPath string) (string, error) {
	pkg, err := prepareInstallPackage(binaryPath)
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(pkg.dir)
	return pkg.digest, nil
}

func InstallService(cfg ServiceConfig, binaryPath string, clientUID, clientGID int, expectedDigest string) error {
	if err := validateSHA256("expected install digest", expectedDigest); err != nil {
		return err
	}
	if cfg.HelperDir == "" {
		return errors.New("helper directory is required")
	}

	pkg, err := prepareInstallPackage(binaryPath)
	if err != nil {
		return err
	}
	defer os.RemoveAll(pkg.dir)
	if pkg.digest != expectedDigest {
		return fmt.Errorf("install digest mismatch: got %s, expected %s", pkg.digest, expectedDigest)
	}

	plistData := RenderServicePlist(cfg, cfg.BinaryPath(), clientUID, clientGID, pkg.binarySHA256, pkg.manifestSHA256)
	plistPath := filepath.Join(pkg.dir, "service.plist")
	if err := os.WriteFile(plistPath, plistData, 0o600); err != nil {
		return fmt.Errorf("write staged vpn core plist: %w", err)
	}

	// No authentication or privileged command is attempted until every digest
	// and argument has been validated above.
	if err := ensureSudoCredentialsVPNCore(); err != nil {
		return fmt.Errorf("sudo authentication: %w", err)
	}

	commands := []struct {
		label string
		args  []string
	}{
		{"create vpn core helper directory", []string{"install", "-d", "-o", "root", "-g", "wheel", "-m", "0755", cfg.HelperDir}},
		{"install vpn core binary", []string{"install", "-o", "root", "-g", "wheel", "-m", "0755", pkg.binaryPath, cfg.BinaryPath()}},
		{"install vpn core manifest", []string{"install", "-o", "root", "-g", "wheel", "-m", "0644", pkg.manifestPath, cfg.ManifestPath()}},
		{"install vpn core plist", []string{"install", "-o", "root", "-g", "wheel", "-m", "0644", plistPath, cfg.PlistPath}},
	}
	for _, command := range commands {
		if _, err := runPrivilegedCommandVPNCore(command.args[0], command.args[1:]...); err != nil {
			return fmt.Errorf("%s: %w", command.label, err)
		}
	}
	if err := verifyInstalledPackage(cfg, pkg, plistData); err != nil {
		_, _ = runPrivilegedCommandVPNCore("rm", "-f", cfg.BinaryPath(), cfg.ManifestPath(), cfg.PlistPath)
		return fmt.Errorf("installed vpn core package failed verification, nothing was bootstrapped: %w", err)
	}
	cleanupCompatibilityServices(cfg)

	_, _ = runPrivilegedCommandVPNCore("launchctl", "bootout", launchctlTarget(cfg.Label))
	deadline := installNowVPNCore().Add(launchctlForgetTimeout)
	for {
		if _, err := runPrivilegedCommandVPNCore("launchctl", "print", launchctlTarget(cfg.Label)); err != nil {
			break
		}
		if !installNowVPNCore().Before(deadline) {
			return fmt.Errorf("launchd did not forget %s within %s", cfg.Label, launchctlForgetTimeout)
		}
		installSleepVPNCore(launchctlForgetPollDelay)
	}
	if _, err := runPrivilegedCommandVPNCore("launchctl", "enable", launchctlTarget(cfg.Label)); err != nil {
		return fmt.Errorf("enable vpn core service: %w", err)
	}
	if _, err := runPrivilegedCommandVPNCore("launchctl", "bootstrap", "system", cfg.PlistPath); err != nil {
		return fmt.Errorf("bootstrap vpn core service: %w", err)
	}
	return nil
}

// verifyInstalledPackage re-reads the root-owned destinations before launchd
// sees them. The staged copies live in a user-writable temp directory, so a
// process running as the same user could swap them between hashing and the
// privileged copy; only the root-owned result is trusted.
func verifyInstalledPackage(cfg ServiceConfig, pkg installPackage, plistData []byte) error {
	for _, file := range []struct {
		path string
		want string
	}{
		{cfg.BinaryPath(), pkg.binarySHA256},
		{cfg.ManifestPath(), pkg.manifestSHA256},
	} {
		if err := requireRootOwnedRegularFile(file.path); err != nil {
			return err
		}
		got, err := hashFile(file.path)
		if err != nil {
			return err
		}
		if got != file.want {
			return fmt.Errorf("%s sha256 %s does not match staged %s", file.path, got, file.want)
		}
	}
	if err := requireRootOwnedRegularFile(cfg.PlistPath); err != nil {
		return err
	}
	installed, err := os.ReadFile(cfg.PlistPath)
	if err != nil {
		return fmt.Errorf("read installed plist: %w", err)
	}
	if !bytes.Equal(installed, plistData) {
		return fmt.Errorf("%s does not match the rendered plist", cfg.PlistPath)
	}
	return nil
}

func requireRootOwnedRegularFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect installed file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	uid, err := installedOwnerUIDVPNCore(path)
	if err != nil {
		return err
	}
	if uid != 0 {
		return fmt.Errorf("%s is owned by uid %d, want root", path, uid)
	}
	return nil
}

func installedOwnerUID(path string) (uint32, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("%s: owner unavailable", path)
	}
	return stat.Uid, nil
}

func prepareInstallPackage(binaryPath string) (installPackage, error) {
	if binaryPath == "" {
		return installPackage{}, errors.New("vpn core binary path is required")
	}
	dir, err := os.MkdirTemp("", "vpn-core-install-*")
	if err != nil {
		return installPackage{}, fmt.Errorf("create install staging directory: %w", err)
	}
	fail := func(err error) (installPackage, error) {
		_ = os.RemoveAll(dir)
		return installPackage{}, err
	}

	stagedBinary := filepath.Join(dir, "vpn-core")
	if err := copyRegularFile(binaryPath, stagedBinary, 0o700); err != nil {
		return fail(fmt.Errorf("stage vpn core binary: %w", err))
	}
	binarySHA, err := hashFile(stagedBinary)
	if err != nil {
		return fail(err)
	}
	manifest := Manifest{
		Version: manifestVersion,
		Files: []ManifestFile{{
			Path:   "vpn-core",
			SHA256: binarySHA,
		}},
	}
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fail(fmt.Errorf("encode vpn core manifest: %w", err))
	}
	manifestData = append(manifestData, '\n')
	manifestPath := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(manifestPath, manifestData, 0o600); err != nil {
		return fail(fmt.Errorf("write vpn core manifest: %w", err))
	}
	manifestSum := sha256.Sum256(manifestData)
	digestHash := sha256.New()
	binaryFile, err := os.Open(stagedBinary)
	if err != nil {
		return fail(err)
	}
	_, copyErr := io.Copy(digestHash, binaryFile)
	closeErr := binaryFile.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return fail(fmt.Errorf("hash vpn core install package: %w", err))
	}
	_, _ = digestHash.Write(manifestData)

	return installPackage{
		dir:            dir,
		binaryPath:     stagedBinary,
		manifestPath:   manifestPath,
		binarySHA256:   binarySHA,
		manifestSHA256: hex.EncodeToString(manifestSum[:]),
		digest:         hex.EncodeToString(digestHash.Sum(nil)),
	}, nil
}

func copyRegularFile(source, destination string, mode os.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", source)
	}
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, input)
	closeErr := output.Close()
	return errors.Join(copyErr, closeErr)
}

func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func validateSHA256(name, value string) error {
	if !lowercaseSHA256Pattern.MatchString(value) {
		return fmt.Errorf("%s must be exactly 64 lowercase hexadecimal characters", name)
	}
	return nil
}
