// Package ifaceaudit reports utun ownership from exact session claims.
// It never infers ownership from an address or address range.
package ifaceaudit

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Class string

const (
	ClassOwned      Class = "owned"
	ClassUnverified Class = "unverified"
	ClassUnknown    Class = "unknown"
	ClassSystem     Class = "system"
)

type Liveness string

const (
	LivenessAlive   Liveness = "alive"
	LivenessDead    Liveness = "dead"
	LivenessUnknown Liveness = "unknown"
)

const (
	EngineVLESS       = "vless-tun"
	EngineOpenConnect = "openconnect-tun"
)

type Interface struct {
	Name string   `json:"name"`
	IPv4 []string `json:"ipv4,omitempty"`
	IPv6 []string `json:"ipv6,omitempty"`
	Up   bool     `json:"up"`
}

type Claim struct {
	Engine    string   `json:"engine"`
	SessionID string   `json:"session_id,omitempty"`
	Interface string   `json:"interface"`
	Liveness  Liveness `json:"liveness"`
}

type Result struct {
	Name         string   `json:"name"`
	Class        Class    `json:"class"`
	Label        string   `json:"label,omitempty"`
	IPv4         []string `json:"ipv4,omitempty"`
	IPv6         []string `json:"ipv6,omitempty"`
	Up           bool     `json:"up"`
	DefaultRoute bool     `json:"default_route"`
	Claims       []Claim  `json:"claims,omitempty"`
	Warning      string   `json:"warning,omitempty"`
	Advice       []string `json:"advice,omitempty"`
}

type Report struct {
	Interfaces []Result `json:"interfaces"`
	Issues     []string `json:"issues,omitempty"`
}

var (
	interfaceHeaderPattern = regexp.MustCompile(`^([[:alnum:]_.-]+):\s+flags=[^<]*<([^>]*)>`)
	utunNamePattern        = regexp.MustCompile(`^utun[0-9]+$`)
	routeInterfacePattern  = regexp.MustCompile(`^[[:alpha:]][[:alnum:]_.-]*$`)
)

// ParseIfconfig parses the macOS ifconfig output and returns only utun blocks.
func ParseIfconfig(raw []byte) ([]Interface, error) {
	var interfaces []Interface
	var current *Interface
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
			if current != nil {
				interfaces = append(interfaces, *current)
				current = nil
			}
			matches := interfaceHeaderPattern.FindStringSubmatch(line)
			if matches == nil {
				if strings.HasPrefix(line, "utun") {
					return nil, fmt.Errorf("ifconfig line %d: malformed utun header", lineNumber)
				}
				continue
			}
			if !utunNamePattern.MatchString(matches[1]) {
				continue
			}
			current = &Interface{
				Name: matches[1],
				Up:   flagPresent(matches[2], "UP"),
			}
			continue
		}

		if current == nil {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "inet":
			address, err := parseIPv4Address(fields)
			if err != nil {
				return nil, fmt.Errorf("ifconfig line %d (%s): %w", lineNumber, current.Name, err)
			}
			current.IPv4 = append(current.IPv4, address)
		case "inet6":
			address, err := parseIPv6Address(fields)
			if err != nil {
				return nil, fmt.Errorf("ifconfig line %d (%s): %w", lineNumber, current.Name, err)
			}
			current.IPv6 = append(current.IPv6, address)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan ifconfig output: %w", err)
	}
	if current != nil {
		interfaces = append(interfaces, *current)
	}
	sort.Slice(interfaces, func(i, j int) bool {
		return utunIndex(interfaces[i].Name) < utunIndex(interfaces[j].Name)
	})
	return interfaces, nil
}

func parseIPv4Address(fields []string) (string, error) {
	if len(fields) < 2 {
		return "", fmt.Errorf("missing IPv4 address")
	}
	address := net.ParseIP(fields[1])
	if address == nil || address.To4() == nil {
		return "", fmt.Errorf("invalid IPv4 address %q", fields[1])
	}
	maskValue, ok := fieldAfter(fields, "netmask")
	if !ok {
		return address.To4().String(), nil
	}
	prefix, err := hexadecimalMaskPrefix(maskValue)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/%d", address.To4().String(), prefix), nil
}

func parseIPv6Address(fields []string) (string, error) {
	if len(fields) < 2 {
		return "", fmt.Errorf("missing IPv6 address")
	}
	rawAddress := fields[1]
	addressWithoutZone := rawAddress
	if zoneIndex := strings.LastIndex(addressWithoutZone, "%"); zoneIndex >= 0 {
		addressWithoutZone = addressWithoutZone[:zoneIndex]
	}
	address, err := netip.ParseAddr(addressWithoutZone)
	if err != nil || !address.Is6() {
		return "", fmt.Errorf("invalid IPv6 address %q", rawAddress)
	}
	prefixValue, ok := fieldAfter(fields, "prefixlen")
	if !ok {
		return "", fmt.Errorf("missing IPv6 prefix length")
	}
	prefix, err := strconv.Atoi(prefixValue)
	if err != nil || prefix < 0 || prefix > 128 {
		return "", fmt.Errorf("invalid IPv6 prefix length %q", prefixValue)
	}
	return fmt.Sprintf("%s/%d", rawAddress, prefix), nil
}

func hexadecimalMaskPrefix(value string) (int, error) {
	if !strings.HasPrefix(value, "0x") {
		return 0, fmt.Errorf("invalid IPv4 netmask %q", value)
	}
	parsed, err := strconv.ParseUint(strings.TrimPrefix(value, "0x"), 16, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid IPv4 netmask %q", value)
	}
	mask := net.IPMask{
		byte(parsed >> 24),
		byte(parsed >> 16),
		byte(parsed >> 8),
		byte(parsed),
	}
	ones, bits := mask.Size()
	if bits != 32 {
		return 0, fmt.Errorf("non-contiguous IPv4 netmask %q", value)
	}
	return ones, nil
}

func fieldAfter(fields []string, key string) (string, bool) {
	for index := 0; index+1 < len(fields); index++ {
		if fields[index] == key {
			return fields[index+1], true
		}
	}
	return "", false
}

func flagPresent(flags, want string) bool {
	for _, flag := range strings.Split(flags, ",") {
		if flag == want {
			return true
		}
	}
	return false
}

func utunIndex(name string) int {
	value, err := strconv.Atoi(strings.TrimPrefix(name, "utun"))
	if err != nil {
		return int(^uint(0) >> 1)
	}
	return value
}

// ParseDefaultRoutes parses macOS netstat -rn -f inet output. A paired 0/1
// and 128.0/1 route on one interface is treated as an IPv4 default route.
func ParseDefaultRoutes(raw []byte) (map[string]bool, error) {
	result := map[string]bool{}
	splitRoutes := map[string]uint8{}
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		destination, splitBit, relevant := routeDestination(fields[0])
		if !relevant {
			continue
		}
		if len(fields) < 4 {
			return nil, fmt.Errorf("route line %d (%s): missing interface", lineNumber, fields[0])
		}
		interfaceName := fields[3]
		if !routeInterfacePattern.MatchString(interfaceName) {
			return nil, fmt.Errorf("route line %d (%s): invalid interface %q", lineNumber, fields[0], interfaceName)
		}
		if destination == "default" {
			result[interfaceName] = true
			continue
		}
		splitRoutes[interfaceName] |= splitBit
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan route output: %w", err)
	}
	for interfaceName, bits := range splitRoutes {
		if bits == 3 {
			result[interfaceName] = true
		}
	}
	return result, nil
}

func routeDestination(value string) (destination string, splitBit uint8, relevant bool) {
	switch value {
	case "default", "0.0.0.0/0":
		return "default", 0, true
	case "0/1", "0.0.0.0/1":
		return "split", 1, true
	case "128.0/1", "128.0.0.0/1":
		return "split", 2, true
	default:
		return "", 0, false
	}
}

// Classify applies exact interface-name claims with the safety precedence
// alive > unknown > dead. It never inspects addresses to decide ownership.
func Classify(interfaces []Interface, claims []Claim, defaultRoutes map[string]bool) Report {
	claimsByInterface := map[string][]Claim{}
	for _, claim := range claims {
		claim.Interface = strings.TrimSpace(claim.Interface)
		if claim.Interface == "" {
			continue
		}
		claimsByInterface[claim.Interface] = append(claimsByInterface[claim.Interface], claim)
	}

	ordered := append([]Interface(nil), interfaces...)
	sort.Slice(ordered, func(i, j int) bool {
		return utunIndex(ordered[i].Name) < utunIndex(ordered[j].Name)
	})
	report := Report{Interfaces: make([]Result, 0, len(ordered))}
	for _, iface := range ordered {
		matched := append([]Claim(nil), claimsByInterface[iface.Name]...)
		sortClaims(matched)
		result := Result{
			Name:         iface.Name,
			IPv4:         append([]string(nil), iface.IPv4...),
			IPv6:         append([]string(nil), iface.IPv6...),
			Up:           iface.Up,
			DefaultRoute: defaultRoutes[iface.Name],
			Claims:       matched,
		}
		classifyResult(&result)
		report.Interfaces = append(report.Interfaces, result)
	}
	return report
}

func classifyResult(result *Result) {
	var alive, unknown, dead []Claim
	for _, claim := range result.Claims {
		switch claim.Liveness {
		case LivenessAlive:
			alive = append(alive, claim)
		case LivenessDead:
			dead = append(dead, claim)
		default:
			unknown = append(unknown, claim)
		}
	}

	switch {
	case len(alive) > 0:
		result.Class = ClassOwned
		result.Label = "owned by a live session"
	case len(unknown) > 0:
		result.Class = ClassUnverified
		result.Label = "claimed, but liveness could not be determined"
		result.Advice = statusCommandsForClaims(unknown)
	case len(dead) > 0:
		result.Class = ClassUnverified
		result.Label = "claimed by a dead session record; the interface name may since have been reused"
		result.Advice = statusCommandsForClaims(dead)
	case len(result.IPv4) > 0:
		result.Class = ClassUnknown
		result.Label = "not ours (another app or system)"
	default:
		result.Class = ClassSystem
		result.Label = "system utun (no IPv4 address)"
	}
}

func statusCommandsForClaims(claims []Claim) []string {
	seen := map[string]struct{}{}
	var commands []string
	for _, claim := range claims {
		var command string
		switch claim.Engine {
		case EngineVLESS:
			command = "vless-tun status"
		case EngineOpenConnect:
			command = "openconnect-tun status"
		}
		if command == "" {
			continue
		}
		if _, ok := seen[command]; ok {
			continue
		}
		seen[command] = struct{}{}
		commands = append(commands, command)
	}
	sort.Strings(commands)
	return commands
}

func sortClaims(claims []Claim) {
	sort.Slice(claims, func(i, j int) bool {
		left := claims[i].Engine + "\x00" + claims[i].SessionID + "\x00" + string(claims[i].Liveness)
		right := claims[j].Engine + "\x00" + claims[j].SessionID + "\x00" + string(claims[j].Liveness)
		return left < right
	})
}

// RenderText produces the human-readable read-only audit report.
func RenderText(report Report) string {
	var builder strings.Builder
	if len(report.Interfaces) == 0 {
		builder.WriteString("no utun interfaces found\n")
	}
	for _, result := range report.Interfaces {
		fmt.Fprintf(&builder, "%s: %s", result.Name, result.Class)
		if result.Label != "" {
			fmt.Fprintf(&builder, " — %s", result.Label)
		}
		builder.WriteByte('\n')
		if len(result.IPv4) > 0 {
			fmt.Fprintf(&builder, "  ipv4: %s\n", strings.Join(result.IPv4, ", "))
		}
		if result.Class != ClassSystem && len(result.IPv6) > 0 {
			fmt.Fprintf(&builder, "  ipv6: %s\n", strings.Join(result.IPv6, ", "))
		}
		for _, claim := range result.Claims {
			sessionID := claim.SessionID
			if sessionID == "" {
				sessionID = "unknown"
			}
			fmt.Fprintf(&builder, "  claim: engine=%s session=%s liveness=%s\n", claim.Engine, sessionID, claim.Liveness)
		}
		if result.DefaultRoute {
			builder.WriteString("  default_route: yes\n")
		}
		if result.Warning != "" {
			fmt.Fprintf(&builder, "  warning: %s\n", result.Warning)
		}
		for _, advice := range result.Advice {
			fmt.Fprintf(&builder, "  advice: %s\n", advice)
		}
	}
	for _, issue := range report.Issues {
		fmt.Fprintf(&builder, "issue: %s\n", issue)
	}
	return builder.String()
}
