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
	"strings"

	"golang.org/x/sys/unix"
)

type ownerLookup func(path string, stat *unix.Stat_t) (uint32, error)

type verificationDependencies struct {
	executable func() (string, error)
	owner      ownerLookup
	checkACL   func(string) error
}

func productionVerificationDependencies() verificationDependencies {
	return verificationDependencies{
		executable: os.Executable,
		owner: func(_ string, stat *unix.Stat_t) (uint32, error) {
			return stat.Uid, nil
		},
		checkACL: checkWriteACL,
	}
}

func verifyDaemonInstallation(cfg ServiceConfig, binarySHA256, manifestSHA256 string, deps verificationDependencies) error {
	if err := validateSHA256("binary sha256", binarySHA256); err != nil {
		return err
	}
	if err := validateSHA256("manifest sha256", manifestSHA256); err != nil {
		return err
	}
	if cfg.HelperDir == "" {
		return errors.New("helper directory is required")
	}

	executable, err := deps.executable()
	if err != nil {
		return fmt.Errorf("resolve daemon executable: %w", err)
	}
	resolvedExecutable, err := filepath.EvalSymlinks(executable)
	if err != nil {
		return fmt.Errorf("resolve daemon executable symlinks: %w", err)
	}
	resolvedInstalled, err := filepath.EvalSymlinks(cfg.BinaryPath())
	if err != nil {
		return fmt.Errorf("resolve installed vpn core symlinks: %w", err)
	}
	if resolvedExecutable != resolvedInstalled {
		return fmt.Errorf("daemon executable %s is not installed helper %s", resolvedExecutable, resolvedInstalled)
	}

	binaryData, err := readVerifiedRegularFile(cfg.BinaryPath(), deps, false)
	if err != nil {
		return fmt.Errorf("verify vpn core binary: %w", err)
	}
	if got := sha256Hex(binaryData); got != binarySHA256 {
		return fmt.Errorf("vpn core binary sha256 mismatch: got %s, expected %s", got, binarySHA256)
	}
	manifestData, err := readVerifiedRegularFile(cfg.ManifestPath(), deps, false)
	if err != nil {
		return fmt.Errorf("verify vpn core manifest: %w", err)
	}
	if got := sha256Hex(manifestData); got != manifestSHA256 {
		return fmt.Errorf("vpn core manifest sha256 mismatch: got %s, expected %s", got, manifestSHA256)
	}

	manifest, err := decodeManifest(manifestData)
	if err != nil {
		return err
	}
	foundBinary := false
	seen := make(map[string]struct{}, len(manifest.Files))
	for _, entry := range manifest.Files {
		if err := validateSHA256("manifest entry sha256", entry.SHA256); err != nil {
			return fmt.Errorf("manifest entry %q: %w", entry.Path, err)
		}
		if entry.Path == "" || filepath.IsAbs(entry.Path) || filepath.Clean(entry.Path) != entry.Path || entry.Path == "." || strings.HasPrefix(entry.Path, ".."+string(filepath.Separator)) {
			return fmt.Errorf("manifest entry path %q is not a clean relative path", entry.Path)
		}
		if _, exists := seen[entry.Path]; exists {
			return fmt.Errorf("duplicate manifest entry %q", entry.Path)
		}
		seen[entry.Path] = struct{}{}
		if entry.Path == "vpn-core" {
			foundBinary = true
			if entry.SHA256 != binarySHA256 {
				return fmt.Errorf("manifest vpn-core sha256 does not match daemon binary sha256")
			}
		}
		data, err := readVerifiedRegularFile(filepath.Join(cfg.HelperDir, entry.Path), deps, false)
		if err != nil {
			return fmt.Errorf("verify manifest entry %q: %w", entry.Path, err)
		}
		if got := sha256Hex(data); got != entry.SHA256 {
			return fmt.Errorf("manifest entry %q sha256 mismatch: got %s, expected %s", entry.Path, got, entry.SHA256)
		}
	}
	if !foundBinary {
		return errors.New("manifest does not contain vpn-core")
	}
	if err := verifySecureDirectory(filepath.Dir(cfg.SocketPath), deps, true); err != nil {
		return fmt.Errorf("verify socket directory: %w", err)
	}
	return nil
}

func decodeManifest(data []byte) (Manifest, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode vpn core manifest: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return Manifest{}, fmt.Errorf("decode vpn core manifest: %w", err)
	}
	if manifest.Version != manifestVersion {
		return Manifest{}, fmt.Errorf("unsupported vpn core manifest version %d", manifest.Version)
	}
	if len(manifest.Files) == 0 {
		return Manifest{}, errors.New("vpn core manifest has no files")
	}
	return manifest, nil
}

func readVerifiedRegularFile(path string, deps verificationDependencies, allowStickyDirectory bool) ([]byte, error) {
	fd, stat, err := openSecurePath(path, false, deps, allowStickyDirectory)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("wrap verified file descriptor")
	}
	defer file.Close()
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if stat.Mode&0o022 != 0 {
		return nil, fmt.Errorf("%s is group/world-writable", path)
	}
	return io.ReadAll(file)
}

func verifySecureDirectory(path string, deps verificationDependencies, allowSticky bool) error {
	fd, _, err := openSecurePath(path, true, deps, allowSticky)
	if fd >= 0 {
		_ = unix.Close(fd)
	}
	return err
}

func openSecurePath(path string, wantDirectory bool, deps verificationDependencies, allowStickyFinalDirectory bool) (int, *unix.Stat_t, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) || clean == string(filepath.Separator) {
		return -1, nil, fmt.Errorf("path %q must be an absolute non-root path", path)
	}
	parts := strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator))
	currentFD, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, nil, err
	}
	currentPath := string(filepath.Separator)
	if err := verifyOpenedNode(currentPath, currentFD, true, false, deps); err != nil {
		_ = unix.Close(currentFD)
		return -1, nil, err
	}

	for index, part := range parts {
		final := index == len(parts)-1
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if !final || wantDirectory {
			flags |= unix.O_DIRECTORY
		}
		nextFD, openErr := unix.Openat(currentFD, part, flags, 0)
		_ = unix.Close(currentFD)
		if openErr != nil {
			return -1, nil, fmt.Errorf("open %s without following symlinks: %w", filepath.Join(currentPath, part), openErr)
		}
		currentFD = nextFD
		currentPath = filepath.Join(currentPath, part)
		isDirectory := !final || wantDirectory
		allowSticky := final && wantDirectory && allowStickyFinalDirectory
		if err := verifyOpenedNode(currentPath, currentFD, isDirectory, allowSticky, deps); err != nil {
			_ = unix.Close(currentFD)
			return -1, nil, err
		}
	}
	var stat unix.Stat_t
	if err := unix.Fstat(currentFD, &stat); err != nil {
		_ = unix.Close(currentFD)
		return -1, nil, err
	}
	return currentFD, &stat, nil
}

func verifyOpenedNode(path string, fd int, directory, allowSticky bool, deps verificationDependencies) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if directory && stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("%s is not a directory", path)
	}
	uid, err := deps.owner(path, &stat)
	if err != nil {
		return fmt.Errorf("lookup owner for %s: %w", path, err)
	}
	if uid != 0 {
		return fmt.Errorf("%s is owned by uid %d, want root", path, uid)
	}
	if stat.Mode&0o022 != 0 {
		sticky := stat.Mode&unix.S_ISVTX != 0
		if !directory || !allowSticky || !sticky {
			return fmt.Errorf("%s is group/world-writable", path)
		}
	}
	if err := deps.checkACL(path); err != nil {
		return fmt.Errorf("unsafe ACL on %s: %w", path, err)
	}
	return nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
