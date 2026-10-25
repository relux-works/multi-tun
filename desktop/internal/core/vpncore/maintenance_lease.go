package vpncore

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

const maintenanceLeaseFilename = "maintenance.lease"

type persistedMaintenanceLease struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Per-daemon dependencies let unprivileged fixtures exercise the real file I/O
// and validation without changing host ownership or running a service.
type maintenanceLeaseFiles struct {
	verification verificationDependencies
	chown        func(int, int, int) error
	sync         func(int) error
}

func productionMaintenanceLeaseFiles() maintenanceLeaseFiles {
	return maintenanceLeaseFiles{
		verification: productionVerificationDependencies(),
		chown:        unix.Fchown,
		sync:         unix.Fsync,
	}
}

// Open every ancestor without following symlinks, using the installation's
// root-ownership and ACL checks. Only the runtime parent uses the socket
// directory policy (root:wheel/daemon may be group-writable). All lease
// operations use the pinned directory.
func (d *serviceDaemon) openMaintenanceDirectory(create bool) (int, error) {
	path := d.cfg.RuntimeDir
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return -1, errors.New("maintenance requires an absolute runtime directory")
	}
	deps := d.leaseFiles.verification
	parent, _, err := openSecurePath(filepath.Dir(path), true, deps, true)
	if err != nil {
		return -1, err
	}
	defer unix.Close(parent)
	if create {
		if err := unix.Mkdirat(parent, filepath.Base(path), 0o711); err != nil && !errors.Is(err, unix.EEXIST) {
			return -1, err
		}
	}
	fd, err := unix.Openat(parent, filepath.Base(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	if err := verifyOpenedNode(path, fd, true, deps); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	var stat unix.Stat_t
	err = unix.Fstat(fd, &stat)
	if err == nil && stat.Mode&0o7777 != 0o711 {
		err = errors.New("maintenance runtime directory must have mode 0711")
	}
	if err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func (d *serviceDaemon) verifyMaintenanceFile(fd int) error {
	path := filepath.Join(d.cfg.RuntimeDir, maintenanceLeaseFilename)
	if err := verifyOpenedNode(path, fd, false, d.leaseFiles.verification); err != nil {
		return err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	gid, err := d.leaseFiles.verification.group(path, &stat)
	if err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o7777 != 0o600 || gid != 0 {
		return errors.New("maintenance lease must be a root:wheel regular file with mode 0600")
	}
	return nil
}

// Called under mutation. Rename is the last fallible operation: a failure leaves
// the old file and in-memory lease intact. No token enters logs or error text.
func (d *serviceDaemon) persistMaintenanceLease(token string, until time.Time) error {
	dir, err := d.openMaintenanceDirectory(true)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	name := ".maintenance-" + hex.EncodeToString(random[:])
	fd, err := unix.Openat(dir, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	defer unix.Unlinkat(dir, name, 0)
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	if err := unix.Fchmod(fd, 0o600); err != nil {
		return err
	}
	if err := d.leaseFiles.chown(fd, 0, 0); err != nil {
		return err
	}
	// A newly created file may inherit ACLs. Remove even read-only entries so
	// the ownership token is accessible only through root's file permissions.
	if err := clearRuntimeQuarantineACL(fd); err != nil {
		return err
	}
	if err := d.verifyMaintenanceFile(fd); err != nil {
		return err
	}
	data, err := json.Marshal(persistedMaintenanceLease{Token: token, ExpiresAt: until.UTC()})
	if err != nil {
		return err
	}
	if _, err := file.Write(append(data, '\n')); err != nil {
		return err
	}
	if err := d.leaseFiles.sync(fd); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return unix.Renameat(dir, name, dir, maintenanceLeaseFilename)
}

// Called under mutation. Unlink the entry, never a symlink target.
func (d *serviceDaemon) removeMaintenanceLease() error {
	dir, err := d.openMaintenanceDirectory(false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	err = unix.Unlinkat(dir, maintenanceLeaseFilename, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// Called under mutation only. Use one expiry observation for both admission and
// ownership checks, clearing both fields whenever it observes expiry, including
// when best-effort file cleanup fails.
func (d *serviceDaemon) drainActive() bool {
	if d.drainToken == "" {
		return false
	}
	if time.Now().Before(d.drainUntil) {
		return true
	}
	if err := d.removeMaintenanceLease(); err != nil {
		log.Printf("vpn core: remove expired maintenance lease: %v", err)
	}
	d.setMaintenanceState("", time.Time{})
	return false
}

// Run after self-verification and before publishing/listening on the socket.
func (d *serviceDaemon) restoreMaintenanceLease() {
	d.mutation.Lock()
	defer d.mutation.Unlock()
	dir, err := d.openMaintenanceDirectory(false)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		log.Printf("vpn core: ignore unsafe maintenance runtime directory: %v", err)
		return
	}
	defer unix.Close(dir)
	fd, err := unix.Openat(dir, maintenanceLeaseFilename, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		log.Printf("vpn core: ignore unreadable maintenance lease: %v", err)
		return
	}
	file := os.NewFile(uintptr(fd), maintenanceLeaseFilename)
	defer file.Close()
	if err := d.verifyMaintenanceFile(fd); err != nil {
		log.Printf("vpn core: ignore unsafe maintenance lease: %v", err)
		return
	}
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		log.Printf("vpn core: ignore unreadable maintenance lease: %v", err)
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var lease persistedMaintenanceLease
	decodeErr := decoder.Decode(&lease)
	_, offset := lease.ExpiresAt.Zone()
	now := time.Now()
	if len(data) > 4096 || decodeErr != nil || requireJSONEOF(decoder) != nil || !validMaintenanceToken(lease.Token) || offset != 0 || !lease.ExpiresAt.After(now) {
		// Never log the payload or decoder error, which could contain a token.
		log.Printf("vpn core: discard expired or malformed maintenance lease")
		if err := unix.Unlinkat(dir, maintenanceLeaseFilename, 0); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("vpn core: remove invalid maintenance lease: %v", err)
		}
		return
	}
	// Replacement has no shared monotonic clock. A large wall-clock change can
	// shorten or extend this lease across processes. Re-anchor the remaining
	// wall-clock duration to this instance's monotonic clock for all later checks.
	d.setMaintenanceState(lease.Token, now.Add(lease.ExpiresAt.Sub(now)))
}
