package subscription

import (
	"context"
	"testing"
)

func TestRefreshSupportsDirectSourceMode(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	sourceURL := "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=reality&type=tcp#demo"

	snapshot, err := Refresh(context.Background(), "direct", sourceURL, cacheDir)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if got, want := snapshot.SourceMode, "direct"; got != want {
		t.Fatalf("snapshot.SourceMode = %q, want %q", got, want)
	}
	if got, want := snapshot.SourceURL, sourceURL; got != want {
		t.Fatalf("snapshot.SourceURL = %q, want %q", got, want)
	}
	if got, want := snapshot.PayloadFormat, "direct"; got != want {
		t.Fatalf("snapshot.PayloadFormat = %q, want %q", got, want)
	}
	if len(snapshot.Profiles) != 1 {
		t.Fatalf("len(snapshot.Profiles) = %d, want 1", len(snapshot.Profiles))
	}
	if got, want := snapshot.Profiles[0].Host, "example.com"; got != want {
		t.Fatalf("snapshot.Profiles[0].Host = %q, want %q", got, want)
	}
}
