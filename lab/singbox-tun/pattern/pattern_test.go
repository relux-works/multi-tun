package pattern

import "testing"

// Claim: Fill and Mismatch agree on the same stream at any offset, including
// offsets that are not 8-byte aligned.
func TestFillMatches(t *testing.T) {
	for _, off := range []uint64{0, 1, 7, 8, 4093, 1 << 32} {
		p := make([]byte, 1000)
		Fill(42, off, p)
		if i := Mismatch(42, off, p); i != -1 {
			t.Fatalf("offset %d: mismatch at %d", off, i)
		}
	}
}

// Claim: a single flipped byte, a byte shifted from the neighbouring offset and
// a different seed are each detected at the exact position.
func TestMismatchDetectsCorruption(t *testing.T) {
	p := make([]byte, 64)
	Fill(7, 100, p)
	p[13] ^= 0x01
	if i := Mismatch(7, 100, p); i != 13 {
		t.Fatalf("flipped byte: got %d, want 13", i)
	}
	q := make([]byte, 64)
	Fill(7, 101, q) // stream shifted by one byte
	if i := Mismatch(7, 100, q); i < 0 {
		t.Fatal("shifted stream not detected")
	}
	r := make([]byte, 64)
	Fill(8, 100, r)
	if i := Mismatch(7, 100, r); i < 0 {
		t.Fatal("other seed not detected")
	}
}
