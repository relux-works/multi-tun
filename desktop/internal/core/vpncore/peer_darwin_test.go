//go:build darwin

package vpncore

import (
	"os"
	"testing"
)

func TestLocalPeerUIDReadsDarwinXucred(t *testing.T) {
	// This proves the production LOCAL_PEERCRED path reads an XUCRED_VERSION credential from a real local socket.
	server, _ := unixSocketPair(t)
	uid, err := localPeerUID(server)
	if err != nil {
		t.Fatalf("localPeerUID() error = %v", err)
	}
	if uid != uint32(os.Getuid()) {
		t.Fatalf("localPeerUID() = %d, want %d", uid, os.Getuid())
	}
}
