//go:build darwin

package processidentity

import (
	"bytes"
	"time"

	"golang.org/x/sys/unix"
)

// Read reports the command name (MAXCOMLEN-truncated) and start
// time of a live process, so a recorded PID can be matched against the
// process that actually holds it now.
func Read(pid int) (string, time.Time, error) {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return "", time.Time{}, err
	}
	comm := info.Proc.P_comm[:]
	if end := bytes.IndexByte(comm, 0); end >= 0 {
		comm = comm[:end]
	}
	start := time.Unix(info.Proc.P_starttime.Sec, int64(info.Proc.P_starttime.Usec)*1000)
	return string(comm), start, nil
}
