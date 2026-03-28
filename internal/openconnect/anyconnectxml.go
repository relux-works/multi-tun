package openconnect

import (
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type HostEntry struct {
	Name          string
	Address       string
	BackupServers []string
}

type DiskProfile struct {
	Path                 string
	FileName             string
	LocalLanAccess       string
	PPPExclusion         string
	EnableScripting      string
	ProxySettings        string
	AllowManualHostInput string
	HostEntries          []HostEntry
}

type anyConnectProfileXML struct {
	XMLName              xml.Name `xml:"AnyConnectProfile"`
	ClientInitialization struct {
		LocalLanAccess       string `xml:"LocalLanAccess"`
		PPPExclusion         string `xml:"PPPExclusion"`
		EnableScripting      string `xml:"EnableScripting"`
		ProxySettings        string `xml:"ProxySettings"`
		AllowManualHostInput string `xml:"AllowManualHostInput"`
	} `xml:"ClientInitialization"`
	ServerList struct {
		HostEntries []struct {
			HostName         string `xml:"HostName"`
			HostAddress      string `xml:"HostAddress"`
			BackupServerList struct {
				HostAddresses []string `xml:"HostAddress"`
			} `xml:"BackupServerList"`
		} `xml:"HostEntry"`
	} `xml:"ServerList"`
}

func DefaultProfileSearchPaths(homeDir string) []string {
	paths := []string{
		"/opt/cisco/secureclient/vpn/profile",
		"/opt/cisco/anyconnect/profile",
	}
	if homeDir != "" {
		paths = append(paths, filepath.Join(homeDir, "Downloads", "cisco-anyconnect-profiles", "profiles"))
	}
	return paths
}

func DiscoverProfileFiles(paths []string) ([]string, error) {
	files := []string{}
	seen := map[string]struct{}{}
	for _, dir := range paths {
		if dir == "" {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if !strings.HasSuffix(strings.ToLower(entry.Name()), ".xml") {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			if _, ok := seen[path]; ok {
				continue
			}
			seen[path] = struct{}{}
			files = append(files, path)
		}
	}
	sort.Strings(files)
	return files, nil
}

func LoadDiskProfiles(paths []string) ([]DiskProfile, error) {
	files, err := DiscoverProfileFiles(paths)
	if err != nil {
		return nil, err
	}
	profiles := make([]DiskProfile, 0, len(files))
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		profile, err := ParseAnyConnectProfile(path, raw)
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, profile)
	}
	return profiles, nil
}

func ParseAnyConnectProfile(path string, raw []byte) (DiskProfile, error) {
	var parsed anyConnectProfileXML
	if err := xml.Unmarshal(raw, &parsed); err != nil {
		return DiskProfile{}, err
	}

	profile := DiskProfile{
		Path:                 path,
		FileName:             filepath.Base(path),
		LocalLanAccess:       normalizeXMLText(parsed.ClientInitialization.LocalLanAccess),
		PPPExclusion:         normalizeXMLText(parsed.ClientInitialization.PPPExclusion),
		EnableScripting:      normalizeXMLText(parsed.ClientInitialization.EnableScripting),
		ProxySettings:        normalizeXMLText(parsed.ClientInitialization.ProxySettings),
		AllowManualHostInput: normalizeXMLText(parsed.ClientInitialization.AllowManualHostInput),
		HostEntries:          make([]HostEntry, 0, len(parsed.ServerList.HostEntries)),
	}

	for _, host := range parsed.ServerList.HostEntries {
		backups := make([]string, 0, len(host.BackupServerList.HostAddresses))
		for _, backup := range host.BackupServerList.HostAddresses {
			backup = normalizeXMLText(backup)
			if backup != "" {
				backups = append(backups, backup)
			}
		}
		profile.HostEntries = append(profile.HostEntries, HostEntry{
			Name:          normalizeXMLText(host.HostName),
			Address:       normalizeXMLText(host.HostAddress),
			BackupServers: backups,
		})
	}

	return profile, nil
}

func normalizeXMLText(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Join(strings.Fields(value), " ")
	return value
}

func ResolveServerFromProfiles(paths []string, selector string) (HostEntry, error) {
	selector = normalizeProfileSelector(selector)
	if selector == "" {
		return HostEntry{}, errors.New("profile selector is required")
	}

	profiles, err := LoadDiskProfiles(paths)
	if err != nil {
		return HostEntry{}, err
	}

	exactMatches := []HostEntry{}
	containsMatches := []HostEntry{}
	exactSeen := map[string]struct{}{}
	containsSeen := map[string]struct{}{}
	for _, profile := range profiles {
		for _, host := range profile.HostEntries {
			name := normalizeProfileSelector(host.Name)
			address := strings.ToLower(strings.TrimSpace(host.Address))
			key := hostEntryKey(host)
			switch {
			case name == selector || address == selector:
				if _, ok := exactSeen[key]; !ok {
					exactSeen[key] = struct{}{}
					exactMatches = append(exactMatches, host)
				}
			case strings.Contains(name, selector) || strings.Contains(address, selector):
				if _, ok := containsSeen[key]; !ok {
					containsSeen[key] = struct{}{}
					containsMatches = append(containsMatches, host)
				}
			}
		}
	}

	switch {
	case len(exactMatches) == 1:
		return exactMatches[0], nil
	case len(exactMatches) > 1:
		return HostEntry{}, fmt.Errorf("profile selector %q matched multiple host entries: %s", selector, formatHostEntries(exactMatches))
	case len(containsMatches) == 1:
		return containsMatches[0], nil
	case len(containsMatches) > 1:
		return HostEntry{}, fmt.Errorf("profile selector %q matched multiple host entries: %s", selector, formatHostEntries(containsMatches))
	default:
		return HostEntry{}, fmt.Errorf("profile selector %q did not match any host entry", selector)
	}
}

func normalizeProfileSelector(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.TrimLeft(value, "0123456789. ")
	value = strings.Join(strings.Fields(value), " ")
	return value
}

func hostEntryKey(host HostEntry) string {
	return normalizeProfileSelector(host.Name) + "|" + strings.ToLower(strings.TrimSpace(host.Address))
}

func formatHostEntries(entries []HostEntry) string {
	formatted := make([]string, 0, len(entries))
	for _, entry := range entries {
		formatted = append(formatted, fmt.Sprintf("%s (%s)", entry.Name, entry.Address))
	}
	return strings.Join(formatted, ", ")
}
