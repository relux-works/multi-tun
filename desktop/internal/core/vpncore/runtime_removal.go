package vpncore

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

var (
	runtimeRemovalLstatVPNCore       = unix.Lstat
	runtimeRenameatVPNCore           = unix.Renameat
	runtimeExecutableVPNCore         = os.Executable
	runtimeQuarantineEUIDVPNCore     = os.Geteuid
	runtimeQuarantineConfigVPNCore   = configuredRuntimeQuarantine
	runtimeQuarantineRandomVPNCore   = rand.Text
	runtimeQuarantineFchownVPNCore   = unix.Fchown
	runtimeQuarantineClearACLVPNCore = clearRuntimeQuarantineACL
	runtimeQuarantineDepsVPNCore     = productionVerificationDependencies
)

func removeServiceRuntimeDirectory(cfg ServiceConfig) error {
	path := cfg.RuntimeDir
	var expected unix.Stat_t
	if err := runtimeRemovalLstatVPNCore(path, &expected); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect runtime path %s: %w", path, err)
	}
	if expected.Mode&unix.S_IFMT == unix.S_IFLNK {
		if _, err := runPrivilegedCommandVPNCore("rm", "-f", path); err != nil {
			return fmt.Errorf("remove unexpected runtime symlink %s: %w", path, err)
		}
		return fmt.Errorf("unexpected runtime symlink %s was removed", path)
	}
	kind := map[uint32]string{
		unix.S_IFDIR: "directory", unix.S_IFREG: "regular file",
		unix.S_IFIFO: "named pipe", unix.S_IFSOCK: "socket",
		unix.S_IFCHR: "character device", unix.S_IFBLK: "block device",
	}[uint32(expected.Mode)&unix.S_IFMT]
	if kind == "" {
		kind = fmt.Sprintf("unknown (%#o)", expected.Mode&unix.S_IFMT)
	}
	deps := installVerificationDepsVPNCore()
	uid, err := deps.owner(path, &expected)
	if err != nil {
		return fmt.Errorf("inspect runtime path %s (type %s) owner: %w", path, kind, err)
	}
	if expected.Mode&unix.S_IFMT != unix.S_IFDIR || uid != 0 {
		return fmt.Errorf("unexpected runtime entry %s: type %s, owner uid %d; expected root-owned directory", path, kind, uid)
	}
	safeError := func(err error) error {
		return fmt.Errorf("runtime tree %s could not be removed safely: %w", path, err)
	}
	if cfg.HelperDir == "" {
		return safeError(errors.New("helper directory is required for quarantine"))
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return safeError(errors.New("runtime path must be a clean absolute non-root path"))
	}
	if err := verifyHelperRemovalParent(cfg.HelperDir, deps); err != nil {
		return safeError(err)
	}
	var sourceParent, quarantineParent unix.Stat_t
	if err := runtimeRemovalLstatVPNCore(filepath.Dir(path), &sourceParent); err != nil {
		return safeError(err)
	}
	if err := runtimeRemovalLstatVPNCore(filepath.Dir(filepath.Clean(cfg.HelperDir)), &quarantineParent); err != nil {
		return safeError(err)
	}
	if sourceParent.Mode&unix.S_IFMT != unix.S_IFDIR || quarantineParent.Mode&unix.S_IFMT != unix.S_IFDIR {
		return safeError(errors.New("quarantine and runtime parents must be real directories"))
	}
	if sourceParent.Dev != quarantineParent.Dev {
		return safeError(errors.New("quarantine and runtime parents are on different devices; rename only, never copy"))
	}
	executable, err := runtimeExecutableVPNCore()
	if err != nil {
		return safeError(fmt.Errorf("resolve quarantine executable: %w", err))
	}
	configured, expectedParent, err := runtimeQuarantineConfigVPNCore(cfg.Label)
	if err != nil {
		return safeError(err)
	}
	if configured.RuntimeDir != cfg.RuntimeDir || configured.HelperDir != cfg.HelperDir {
		return safeError(errors.New("caller runtime/helper config differs from configured service"))
	}
	if err := validateRuntimeQuarantineConfig(configured, expectedParent); err != nil {
		return safeError(err)
	}
	output, moveErr := runPrivilegedCommandVPNCore(executable, "_quarantine-runtime", cfg.Label,
		strconv.FormatUint(uint64(expected.Dev), 10), strconv.FormatUint(expected.Ino, 10))
	quarantine := strings.TrimSuffix(string(output), "\n")
	if !validRuntimeQuarantinePath(cfg, quarantine) {
		return safeError(fmt.Errorf("invalid printed quarantine path %q; quarantine retained: %w", quarantine, errors.Join(moveErr, errors.New("expected fresh quarantine name under helper parent"))))
	}
	destination := filepath.Join(quarantine, "runtime")
	// The pre-rename check cannot prevent substitution between fstatat and
	// renameat. Only this post-move identity check authorizes recursive removal.
	var found unix.Stat_t
	statErr := runtimeRemovalLstatVPNCore(destination, &found)
	if statErr == nil {
		foundUID, ownerErr := deps.owner(destination, &found)
		if ownerErr != nil || found.Mode&unix.S_IFMT != unix.S_IFDIR || foundUID != 0 || found.Dev != expected.Dev || found.Ino != expected.Ino {
			return safeError(fmt.Errorf("quarantined entry %s mismatch: expected dev=%d ino=%d type=directory uid=0; found dev=%d ino=%d type=%#o uid=%d (owner error: %v); original runtime tree may still exist under another name in %s; quarantine retained", destination, expected.Dev, expected.Ino, found.Dev, found.Ino, found.Mode&unix.S_IFMT, foundUID, ownerErr, filepath.Dir(path)))
		}
	}
	if moveErr != nil || statErr != nil {
		return safeError(fmt.Errorf("rename to quarantine %s failed; original runtime tree may still exist under another name in %s; quarantine retained: %w", quarantine, filepath.Dir(path), errors.Join(moveErr, statErr)))
	}
	if _, err := runPrivilegedCommandVPNCore("rm", "-rf", quarantine); err != nil {
		return safeError(fmt.Errorf("remove verified runtime quarantine %s: %w", quarantine, err))
	}
	if _, err := os.Lstat(quarantine); !errors.Is(err, os.ErrNotExist) {
		return safeError(fmt.Errorf("quarantine %s still exists or cannot be verified absent: %v", quarantine, err))
	}
	return nil
}

// configuredRuntimeQuarantine accepts only the shipped primary and compatibility labels.
func configuredRuntimeQuarantine(label string) (ServiceConfig, string, error) {
	primary := DefaultServiceConfig()
	if label == "" || label == primary.Label {
		return primary, filepath.Dir(defaultServiceRuntimeDir), nil
	}
	for _, compat := range compatibilityServiceConfigsVPNCore(primary) {
		if label == compat.Label {
			return compat.ServiceConfig, filepath.Dir(defaultServiceRuntimeDir), nil
		}
	}
	return ServiceConfig{}, "", fmt.Errorf("unknown runtime service label %q", label)
}

func validateRuntimeQuarantineConfig(cfg ServiceConfig, expectedParent string) error {
	if cfg.RuntimeDir == "" || cfg.HelperDir == "" {
		return errors.New("configured runtime and helper directories must be non-empty")
	}
	for _, path := range []string{cfg.RuntimeDir, cfg.HelperDir} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
			return fmt.Errorf("quarantine move requires clean absolute non-root paths: %q", path)
		}
	}
	if filepath.Dir(cfg.RuntimeDir) != expectedParent {
		return fmt.Errorf("configured runtime parent %q differs from expected %q", filepath.Dir(cfg.RuntimeDir), expectedParent)
	}
	return nil
}

func validRuntimeQuarantinePath(cfg ServiceConfig, path string) bool {
	if cfg.HelperDir == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Dir(path) != filepath.Dir(cfg.HelperDir) {
		return false
	}
	suffix, ok := strings.CutPrefix(filepath.Base(path), filepath.Base(cfg.HelperDir)+".uninstall-")
	if !ok || len(suffix) != 26 {
		return false
	}
	for _, char := range suffix {
		if !(char >= 'A' && char <= 'Z' || char >= '2' && char <= '7') {
			return false
		}
	}
	return true
}

// RunRuntimeQuarantineMove accepts only [known-label] device inode. Paths are
// derived from the service config; it never copies or recursively removes.
func RunRuntimeQuarantineMove(args []string, stdout io.Writer) error {
	if len(args) != 2 && len(args) != 3 {
		return errors.New("quarantine move requires [known-label] device inode; no path arguments")
	}
	label := ""
	if len(args) == 3 {
		label, args = args[0], args[1:]
	}
	device, err := strconv.ParseUint(args[0], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid runtime device: %w", err)
	}
	inode, err := strconv.ParseUint(args[1], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid runtime inode: %w", err)
	}
	cfg, expectedParent, err := runtimeQuarantineConfigVPNCore(label)
	if err != nil {
		return err
	}
	if err := validateRuntimeQuarantineConfig(cfg, expectedParent); err != nil {
		return err
	}
	if runtimeQuarantineEUIDVPNCore() != 0 {
		return errors.New("quarantine move requires root")
	}
	quarantine, moveErr := renameRuntimeToQuarantine(cfg, device, inode, runtimeQuarantineDepsVPNCore())
	// Return even a failed move's created quarantine so the caller can inspect
	// identity and retain evidence without guessing a path.
	if quarantine != "" {
		_, err = fmt.Fprintln(stdout, quarantine)
	}
	return errors.Join(moveErr, err)
}

func renameRuntimeToQuarantine(cfg ServiceConfig, device, inode uint64, deps verificationDependencies) (string, error) {
	source := cfg.RuntimeDir
	sourceFD, err := unix.Open(filepath.Dir(source), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", fmt.Errorf("open runtime parent: %w", err)
	}
	defer unix.Close(sourceFD)
	parentFD, parentStat, err := openSecurePath(filepath.Dir(cfg.HelperDir), true, deps, false)
	if err != nil {
		return "", fmt.Errorf("open quarantine parent: %w", err)
	}
	defer unix.Close(parentFD)
	var sourceParent unix.Stat_t
	if err := unix.Fstat(sourceFD, &sourceParent); err != nil {
		return "", err
	}
	if sourceParent.Dev != parentStat.Dev {
		return "", unix.EXDEV
	}
	quarantine := cfg.HelperDir + ".uninstall-" + runtimeQuarantineRandomVPNCore()
	if !validRuntimeQuarantinePath(cfg, quarantine) {
		return "", errors.New("invalid generated quarantine name")
	}
	// mkdirat has no reuse flag: EEXIST fails closed, including for symlinks.
	if err := unix.Mkdirat(parentFD, filepath.Base(quarantine), 0o711); err != nil {
		return "", fmt.Errorf("create exclusive quarantine: %w", err)
	}
	destFD, err := unix.Openat(parentFD, filepath.Base(quarantine), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return quarantine, err
	}
	defer unix.Close(destFD)
	if err := runtimeQuarantineFchownVPNCore(destFD, 0, 0); err != nil {
		return quarantine, fmt.Errorf("quarantine fchown root:wheel: %w", err)
	}
	if err := runtimeQuarantineClearACLVPNCore(destFD); err != nil {
		return quarantine, fmt.Errorf("clear quarantine ACL: %w", err)
	}
	if err := unix.Fchmod(destFD, 0o711); err != nil {
		return quarantine, err
	}
	var created unix.Stat_t
	if err := unix.Fstat(destFD, &created); err != nil {
		return quarantine, err
	}
	uid, ownerErr := deps.owner(quarantine, &created)
	gid, groupErr := deps.group(quarantine, &created)
	if ownerErr != nil || groupErr != nil || uid != 0 || gid != 0 || created.Mode&unix.S_IFMT != unix.S_IFDIR || created.Mode&0o7777 != 0o711 {
		return quarantine, fmt.Errorf("quarantine requires root:wheel directory mode 0711: uid=%d gid=%d mode=%#o: %v", uid, gid, created.Mode, errors.Join(ownerErr, groupErr))
	}
	if err := deps.checkACL(quarantine, destFD); err != nil {
		return quarantine, fmt.Errorf("unsafe ACL on quarantine: %w", err)
	}
	var child unix.Stat_t
	if err := unix.Fstatat(sourceFD, filepath.Base(source), &child, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return quarantine, fmt.Errorf("inspect runtime before rename: %w", err)
	}
	uid, err = deps.owner(source, &child)
	if err != nil || child.Mode&unix.S_IFMT != unix.S_IFDIR || uid != 0 || uint64(child.Dev) != device || child.Ino != inode {
		return quarantine, fmt.Errorf("runtime identity changed before rename: expected dev=%d ino=%d type=directory uid=0; found dev=%d ino=%d type=%#o uid=%d (owner error: %v)", device, inode, child.Dev, child.Ino, child.Mode&unix.S_IFMT, uid, err)
	}
	var existing unix.Stat_t
	if err := unix.Fstatat(destFD, "runtime", &existing, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, os.ErrNotExist) {
		return quarantine, fmt.Errorf("quarantine destination must be absent: %s (%v)", quarantine, err)
	}
	if err := runtimeRenameatVPNCore(sourceFD, filepath.Base(source), destFD, "runtime"); err != nil {
		return quarantine, fmt.Errorf("rename runtime (never copy): %w", err)
	}
	return quarantine, nil
}
