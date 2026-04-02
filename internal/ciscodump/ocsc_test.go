package ciscodump

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExtractOCSCFrames_ParsesInterestingStrings(t *testing.T) {
	t.Parallel()

	payload := append(le32(4), le32(0)...)
	payload = append(payload, []byte("profile.xml\x00")...)
	payload = append(payload, []byte("Establishing VPN - Configuring system\x00")...)
	payload = append(payload, []byte("vpn-gw1.corp.example/outside\x00")...)
	payload = append(payload, []byte("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwuL0Tb6wxxQePXyCIFkEpQStMX78NlD7LARqgUlRtkw\x00")...)

	frameBytes := buildOCSCTestFrame(payload)
	frames := extractOCSCFrames(time.Unix(1711464570, 0).UTC(), 54763, 54764, frameBytes)
	if len(frames) != 1 {
		t.Fatalf("extractOCSCFrames() count = %d, want 1", len(frames))
	}

	frame := frames[0]
	if frame.HeaderLen != 26 || frame.PayloadLen != uint16(len(payload)) {
		t.Fatalf("frame header/payload len = %d/%d, want 26/%d", frame.HeaderLen, frame.PayloadLen, len(payload))
	}
	got := strings.Join(frame.Strings, " | ")
	for _, want := range []string{
		"profile.xml",
		"Establishing VPN - Configuring system",
		"vpn-gw1.corp.example/outside",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("frame.Strings missing %q in %q", want, got)
		}
	}
	if strings.Contains(got, "MFkwEwYHKoZIzj0") {
		t.Fatalf("frame.Strings should drop base64 blob, got %q", got)
	}
}

func TestAnalyzeOCSCArtifactDir_WritesSummaryAndTimeline(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	pcapPath := filepath.Join(tempDir, defaultOCSCPcapFileName)

	payload := append(le32(4), le32(0)...)
	payload = append(payload, []byte("Please enter the requested proxy credentials.\x00")...)
	payload = append(payload, []byte("https://vpn-gw-2.corp.example/outside\x00")...)
	payload = append(payload, []byte("DISPLAY\x00")...)

	frameBytes := buildOCSCTestFrame(payload)
	if err := os.WriteFile(pcapPath, buildTestPCAP(frameBytes, 54764, 54763), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	artifacts, err := AnalyzeOCSCArtifactDir(tempDir, pcapPath)
	if err != nil {
		t.Fatalf("AnalyzeOCSCArtifactDir() error = %v", err)
	}
	if artifacts.FrameCount != 1 {
		t.Fatalf("FrameCount = %d, want 1", artifacts.FrameCount)
	}
	if artifacts.InterestingFrameCount != 1 {
		t.Fatalf("InterestingFrameCount = %d, want 1", artifacts.InterestingFrameCount)
	}

	timeline, err := os.ReadFile(artifacts.TimelinePath)
	if err != nil {
		t.Fatalf("ReadFile(timeline) error = %v", err)
	}
	for _, want := range []string{
		"Please enter the requested proxy credentials",
		"https://vpn-gw-2.corp.example/outside",
		"DISPLAY",
	} {
		if !strings.Contains(string(timeline), want) {
			t.Fatalf("timeline missing %q in %q", want, string(timeline))
		}
	}

	summary, err := os.ReadFile(artifacts.SummaryPath)
	if err != nil {
		t.Fatalf("ReadFile(summary) error = %v", err)
	}
	if !strings.Contains(string(summary), "interesting_frames: 1") {
		t.Fatalf("summary missing interesting_frames count: %q", string(summary))
	}
}

func buildOCSCTestFrame(payload []byte) []byte {
	headerLen := 26
	result := make([]byte, headerLen+len(payload))
	copy(result[:4], ocscMagic)
	binary.LittleEndian.PutUint16(result[4:6], uint16(headerLen))
	binary.LittleEndian.PutUint16(result[6:8], uint16(len(payload)))
	copy(result[headerLen:], payload)
	return result
}

func buildTestPCAP(payload []byte, srcPort, dstPort uint16) []byte {
	packet := buildLoopbackTCPPacket(payload, srcPort, dstPort)
	var buf bytes.Buffer

	buf.Write([]byte{0xd4, 0xc3, 0xb2, 0xa1})
	_ = binary.Write(&buf, binary.LittleEndian, uint16(2))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(4))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(65535))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(pcapLinkTypeNull))

	_ = binary.Write(&buf, binary.LittleEndian, uint32(1711464570))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(941367))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(len(packet)))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(len(packet)))
	buf.Write(packet)
	return buf.Bytes()
}

func buildLoopbackTCPPacket(payload []byte, srcPort, dstPort uint16) []byte {
	packet := make([]byte, 4+20+20+len(payload))
	binary.LittleEndian.PutUint32(packet[:4], 2)

	ip := packet[4:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+20+len(payload)))
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], []byte{127, 0, 0, 1})
	copy(ip[16:20], []byte{127, 0, 0, 1})

	tcp := ip[20:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	tcp[12] = 0x50
	tcp[13] = 0x18
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	copy(tcp[20:], payload)
	return packet
}

func le32(value uint32) []byte {
	result := make([]byte, 4)
	binary.LittleEndian.PutUint32(result, value)
	return result
}
