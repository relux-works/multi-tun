//go:build !darwin || !cgo

package vpncore

import "testing"

func TestCheckWriteACLRefusesUnsupportedBuild(t *testing.T) {
	// This proves non-Darwin or non-cgo builds fail closed instead of silently skipping ACL verification.
	if err := checkWriteACL("ignored", -1); err == nil {
		t.Fatal("checkWriteACL() error = nil")
	}
}

func TestRuntimeQuarantineClearACLRefusesUnsupportedBuild(t *testing.T) {
	// Unsupported builds refuse ACL clearing rather than claiming an unverified ACL-free quarantine.
	if err := clearRuntimeQuarantineACL(-1); err == nil {
		t.Fatal("ACL clearing unexpectedly available")
	}
}
