package ciscodump

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	pcapLinkTypeNull = 0
	pcapLinkTypeLoop = 108

	ocscTimelineFileName = "ocsc-timeline.txt"
	ocscSummaryFileName  = "ocsc-summary.txt"
)

var (
	ocscMagic            = []byte("OCSC")
	interestingStatusCue = []string{
		"Establishing VPN",
		"proxy credentials",
		"profile.xml",
		"vpn-gw",
		"corp.example",
		"https://",
		"Activating VPN adapter",
		"Configuring system",
		"Examining system",
		"DISPLAY",
		"SSL",
		"gui",
		"undefined",
		"macOS",
		"local",
	}
)

type OCSCArtifacts struct {
	FrameCount            int
	InterestingFrameCount int
	TimelinePath          string
	SummaryPath           string
	UniqueStrings         []string
}

type ocscFrame struct {
	Timestamp  time.Time
	SrcPort    uint16
	DstPort    uint16
	HeaderLen  uint16
	PayloadLen uint16
	Metadata   []byte
	Payload    []byte
	Strings    []string
}

type tcpPayloadRecord struct {
	Timestamp time.Time
	SrcPort   uint16
	DstPort   uint16
	Payload   []byte
}

func AnalyzeOCSCArtifactDir(artifactDir, pcapPath string) (OCSCArtifacts, error) {
	artifactDir = strings.TrimSpace(artifactDir)
	pcapPath = strings.TrimSpace(pcapPath)
	if artifactDir == "" {
		return OCSCArtifacts{}, errors.New("artifact dir is required")
	}
	if pcapPath == "" {
		pcapPath = filepath.Join(artifactDir, defaultOCSCPcapFileName)
	}

	frames, err := analyzeOCSCPcap(pcapPath)
	if err != nil {
		return OCSCArtifacts{}, err
	}
	if len(frames) == 0 {
		return OCSCArtifacts{}, nil
	}

	interesting := make([]ocscFrame, 0, len(frames))
	uniqueStrings := map[string]int{}
	for _, frame := range frames {
		if len(frame.Strings) == 0 {
			continue
		}
		interesting = append(interesting, frame)
		for _, value := range frame.Strings {
			uniqueStrings[value]++
		}
	}

	timelinePath := filepath.Join(artifactDir, ocscTimelineFileName)
	if err := os.WriteFile(timelinePath, []byte(formatOCSCTimeline(interesting)), 0o644); err != nil {
		return OCSCArtifacts{}, err
	}

	summaryPath := filepath.Join(artifactDir, ocscSummaryFileName)
	summaryStrings := sortStringCounts(uniqueStrings)
	if err := os.WriteFile(summaryPath, []byte(formatOCSCSummary(frames, interesting, summaryStrings, pcapPath)), 0o644); err != nil {
		return OCSCArtifacts{}, err
	}

	return OCSCArtifacts{
		FrameCount:            len(frames),
		InterestingFrameCount: len(interesting),
		TimelinePath:          timelinePath,
		SummaryPath:           summaryPath,
		UniqueStrings:         summaryStrings,
	}, nil
}

func analyzeOCSCPcap(path string) ([]ocscFrame, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	order, nano, linkType, err := readPCAPGlobalHeader(file)
	if err != nil {
		return nil, err
	}
	if linkType != pcapLinkTypeNull && linkType != pcapLinkTypeLoop {
		return nil, fmt.Errorf("unsupported pcap linktype %d", linkType)
	}

	var frames []ocscFrame
	for {
		record, err := readPCAPPayloadRecord(file, order, nano, linkType)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		packetFrames := extractOCSCFrames(record.Timestamp, record.SrcPort, record.DstPort, record.Payload)
		frames = append(frames, packetFrames...)
	}
	return frames, nil
}

func readPCAPGlobalHeader(r io.Reader) (binary.ByteOrder, bool, uint32, error) {
	header := make([]byte, 24)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, false, 0, err
	}

	var order binary.ByteOrder
	var nano bool
	switch {
	case bytes.Equal(header[:4], []byte{0xd4, 0xc3, 0xb2, 0xa1}):
		order = binary.LittleEndian
	case bytes.Equal(header[:4], []byte{0xa1, 0xb2, 0xc3, 0xd4}):
		order = binary.BigEndian
	case bytes.Equal(header[:4], []byte{0x4d, 0x3c, 0xb2, 0xa1}):
		order = binary.LittleEndian
		nano = true
	case bytes.Equal(header[:4], []byte{0xa1, 0xb2, 0x3c, 0x4d}):
		order = binary.BigEndian
		nano = true
	default:
		return nil, false, 0, fmt.Errorf("unknown pcap magic %x", header[:4])
	}

	return order, nano, order.Uint32(header[20:24]), nil
}

func readPCAPPayloadRecord(r io.Reader, order binary.ByteOrder, nano bool, linkType uint32) (tcpPayloadRecord, error) {
	recordHeader := make([]byte, 16)
	if _, err := io.ReadFull(r, recordHeader); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return tcpPayloadRecord{}, io.EOF
		}
		return tcpPayloadRecord{}, err
	}

	tsSec := order.Uint32(recordHeader[0:4])
	tsFrac := order.Uint32(recordHeader[4:8])
	inclLen := order.Uint32(recordHeader[8:12])
	if inclLen == 0 {
		return tcpPayloadRecord{}, nil
	}
	packet := make([]byte, inclLen)
	if _, err := io.ReadFull(r, packet); err != nil {
		return tcpPayloadRecord{}, err
	}

	record, ok := parseLoopbackTCPRecord(packet, linkType)
	if !ok {
		return tcpPayloadRecord{}, nil
	}

	if nano {
		record.Timestamp = time.Unix(int64(tsSec), int64(tsFrac)).UTC()
	} else {
		record.Timestamp = time.Unix(int64(tsSec), int64(tsFrac)*int64(time.Microsecond)).UTC()
	}
	return record, nil
}

func parseLoopbackTCPRecord(packet []byte, linkType uint32) (tcpPayloadRecord, bool) {
	if len(packet) < 4 {
		return tcpPayloadRecord{}, false
	}

	var family uint32
	switch linkType {
	case pcapLinkTypeNull:
		family = binary.LittleEndian.Uint32(packet[:4])
	case pcapLinkTypeLoop:
		family = binary.BigEndian.Uint32(packet[:4])
	default:
		return tcpPayloadRecord{}, false
	}
	if family != 2 {
		return tcpPayloadRecord{}, false
	}

	ipPacket := packet[4:]
	if len(ipPacket) < 20 {
		return tcpPayloadRecord{}, false
	}
	version := ipPacket[0] >> 4
	if version != 4 {
		return tcpPayloadRecord{}, false
	}
	ihl := int(ipPacket[0]&0x0f) * 4
	if ihl < 20 || len(ipPacket) < ihl {
		return tcpPayloadRecord{}, false
	}
	if ipPacket[9] != 6 {
		return tcpPayloadRecord{}, false
	}
	totalLen := int(binary.BigEndian.Uint16(ipPacket[2:4]))
	if totalLen <= 0 || totalLen > len(ipPacket) {
		totalLen = len(ipPacket)
	}
	ipPayload := ipPacket[ihl:totalLen]
	if len(ipPayload) < 20 {
		return tcpPayloadRecord{}, false
	}
	dataOffset := int(ipPayload[12]>>4) * 4
	if dataOffset < 20 || len(ipPayload) < dataOffset {
		return tcpPayloadRecord{}, false
	}
	payload := ipPayload[dataOffset:]
	if len(payload) == 0 {
		return tcpPayloadRecord{}, false
	}

	return tcpPayloadRecord{
		SrcPort: binary.BigEndian.Uint16(ipPayload[0:2]),
		DstPort: binary.BigEndian.Uint16(ipPayload[2:4]),
		Payload: append([]byte(nil), payload...),
	}, true
}

func extractOCSCFrames(ts time.Time, srcPort, dstPort uint16, payload []byte) []ocscFrame {
	var frames []ocscFrame
	for offset := 0; offset+8 <= len(payload); {
		index := bytes.Index(payload[offset:], ocscMagic)
		if index < 0 {
			break
		}
		offset += index
		if offset+8 > len(payload) {
			break
		}
		headerLen := binary.LittleEndian.Uint16(payload[offset+4 : offset+6])
		bodyLen := binary.LittleEndian.Uint16(payload[offset+6 : offset+8])
		totalLen := int(headerLen) + int(bodyLen)
		if headerLen < 8 || totalLen <= 0 || offset+totalLen > len(payload) {
			break
		}

		frameBytes := payload[offset : offset+totalLen]
		frame := ocscFrame{
			Timestamp:  ts,
			SrcPort:    srcPort,
			DstPort:    dstPort,
			HeaderLen:  headerLen,
			PayloadLen: bodyLen,
			Metadata:   append([]byte(nil), frameBytes[8:headerLen]...),
			Payload:    append([]byte(nil), frameBytes[headerLen:]...),
		}
		frame.Strings = extractInterestingOCSCStrings(frame.Payload)
		frames = append(frames, frame)
		offset += totalLen
	}
	return frames
}

func extractInterestingOCSCStrings(payload []byte) []string {
	var stringsFound []string
	var buf []byte
	flush := func() {
		if len(buf) < 4 {
			buf = buf[:0]
			return
		}
		value := normalizeOCSCString(string(buf))
		if isInterestingOCSCString(value) {
			stringsFound = append(stringsFound, value)
		}
		buf = buf[:0]
	}

	for _, b := range payload {
		if b >= 0x20 && b <= 0x7e {
			buf = append(buf, b)
			continue
		}
		flush()
	}
	flush()
	return uniquePreserveOrder(stringsFound)
}

func normalizeOCSCString(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimLeft(value, ".,'()-+} ")
	value = strings.TrimRight(value, ". ")
	return value
}

func isInterestingOCSCString(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 4 {
		return false
	}
	if looksLikeBase64Blob(value) || looksLikeBinaryPlaceholder(value) {
		return false
	}
	for _, cue := range interestingStatusCue {
		if strings.Contains(value, cue) {
			return true
		}
	}
	hasLetter := false
	hasSignalPunct := false
	for _, r := range value {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z':
			hasLetter = true
		case strings.ContainsRune("./:-_ @", r):
			hasSignalPunct = true
		}
	}
	return hasLetter && hasSignalPunct
}

func looksLikeBase64Blob(value string) bool {
	if len(value) < 48 {
		return false
	}
	if strings.Contains(value, " ") || strings.Contains(value, "://") || strings.ContainsAny(value, ".:@_-") {
		return false
	}
	for _, r := range value {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '+', r == '/', r == '=':
		default:
			return false
		}
	}
	return true
}

func looksLikeBinaryPlaceholder(value string) bool {
	if strings.Count(value, ".") > len(value)/2 {
		return true
	}
	return strings.HasPrefix(value, "OCSC")
}

func uniquePreserveOrder(values []string) []string {
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func sortStringCounts(counts map[string]int) []string {
	type pair struct {
		value string
		count int
	}
	items := make([]pair, 0, len(counts))
	for value, count := range counts {
		items = append(items, pair{value: value, count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].count == items[j].count {
			return items[i].value < items[j].value
		}
		return items[i].count > items[j].count
	})

	result := make([]string, 0, len(items))
	for _, item := range items {
		result = append(result, fmt.Sprintf("%d x %s", item.count, item.value))
	}
	return result
}

func formatOCSCTimeline(frames []ocscFrame) string {
	var builder strings.Builder
	builder.WriteString("# OCSC timeline\n")
	if len(frames) == 0 {
		builder.WriteString("no OCSC frames with interesting strings\n")
		return builder.String()
	}
	for _, frame := range frames {
		builder.WriteString(fmt.Sprintf("%s %d->%d hdr=%d payload=%d\n",
			frame.Timestamp.Format(time.RFC3339Nano),
			frame.SrcPort,
			frame.DstPort,
			frame.HeaderLen,
			frame.PayloadLen,
		))
		builder.WriteString("strings: ")
		builder.WriteString(strings.Join(frame.Strings, " | "))
		builder.WriteString("\n\n")
	}
	return builder.String()
}

func formatOCSCSummary(frames, interesting []ocscFrame, uniqueStrings []string, pcapPath string) string {
	var builder strings.Builder
	builder.WriteString("# OCSC summary\n")
	builder.WriteString(fmt.Sprintf("pcap: %s\n", pcapPath))
	builder.WriteString(fmt.Sprintf("frames: %d\n", len(frames)))
	builder.WriteString(fmt.Sprintf("interesting_frames: %d\n", len(interesting)))
	builder.WriteString("\n")
	builder.WriteString("unique_strings:\n")
	if len(uniqueStrings) == 0 {
		builder.WriteString("- none\n")
		return builder.String()
	}
	for _, value := range uniqueStrings {
		builder.WriteString("- ")
		builder.WriteString(value)
		builder.WriteString("\n")
	}
	return builder.String()
}
