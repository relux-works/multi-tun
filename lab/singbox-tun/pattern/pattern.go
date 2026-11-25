// Package pattern produces the deterministic byte stream the sing-box TUN lab
// sends over TLS, so the client can prove every received byte is the byte the
// server wrote, independently of TLS record integrity.
package pattern

// Byte returns the stream byte at offset off for a stream seeded with seed.
func Byte(seed uint64, off uint64) byte {
	x := (off>>3 + 1) * 0x9E3779B97F4A7C15
	x ^= seed
	x ^= x >> 31
	x *= 0xBF58476D1CE4E5B9
	x ^= x >> 29
	return byte(x >> ((off & 7) * 8))
}

// Fill writes the stream bytes for [off, off+len(p)) into p.
func Fill(seed uint64, off uint64, p []byte) {
	for i := range p {
		p[i] = Byte(seed, off+uint64(i))
	}
}

// Mismatch returns the index of the first byte in p that differs from the
// stream at offset off, or -1 when all bytes match.
func Mismatch(seed uint64, off uint64, p []byte) int {
	for i := range p {
		if p[i] != Byte(seed, off+uint64(i)) {
			return i
		}
	}
	return -1
}
