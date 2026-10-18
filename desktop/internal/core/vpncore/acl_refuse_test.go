//go:build !darwin || !cgo

package vpncore

import "testing"

func TestCheckWriteACLRefusesUnsupportedBuild(t *testing.T) {
	// This proves non-Darwin or non-cgo builds fail closed instead of silently skipping ACL verification.
	if err := checkWriteACL("ignored", -1); err == nil {
		t.Fatal("checkWriteACL() error = nil")
	}
}
