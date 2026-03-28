package config

import "testing"

func TestPrivilegedLaunchOrDefault(t *testing.T) {
	t.Parallel()

	cfg := RenderConfig{}
	got := cfg.PrivilegedLaunchOrDefault()
	if got.Mode != LaunchModeAuto {
		t.Fatalf("mode = %q, want %q", got.Mode, LaunchModeAuto)
	}
	if got.Label != defaultLaunchdLabel {
		t.Fatalf("label = %q, want %q", got.Label, defaultLaunchdLabel)
	}
	if got.PlistPath != defaultLaunchdPlistPath {
		t.Fatalf("plist_path = %q, want %q", got.PlistPath, defaultLaunchdPlistPath)
	}
}

func TestValidateRejectsUnknownPrivilegedLaunchMode(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.Render.Mode = RenderModeTun
	cfg.Render.PrivilegedLaunch = &PrivilegedLaunchConfig{Mode: "bogus"}

	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() returned nil error")
	}
}

func TestValidateAcceptsLaunchdPrivilegedLaunchMode(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.Render.Mode = RenderModeTun
	cfg.Render.PrivilegedLaunch = &PrivilegedLaunchConfig{Mode: LaunchModeLaunchd}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() returned error: %v", err)
	}
}

func TestValidateAcceptsHelperPrivilegedLaunchMode(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.Render.Mode = RenderModeTun
	cfg.Render.PrivilegedLaunch = &PrivilegedLaunchConfig{Mode: LaunchModeHelper}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() returned error: %v", err)
	}
}
