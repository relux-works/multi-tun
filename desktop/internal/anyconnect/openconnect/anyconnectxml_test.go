package openconnect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseAnyConnectProfile(t *testing.T) {
	raw := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<AnyConnectProfile xmlns="http://schemas.xmlsoap.org/encoding/">
  <ClientInitialization>
    <ProxySettings>IgnoreProxy</ProxySettings>
    <LocalLanAccess UserControllable="false">true</LocalLanAccess>
    <PPPExclusion UserControllable="false">Disable
      <PPPExclusionServerIP UserControllable="false"></PPPExclusionServerIP>
    </PPPExclusion>
    <EnableScripting UserControllable="false">false</EnableScripting>
    <AllowManualHostInput>true</AllowManualHostInput>
  </ClientInitialization>
  <ServerList>
    <HostEntry>
      <HostName>1. MSK Base</HostName>
      <HostAddress>vpn-gw1.corp.example/dap</HostAddress>
      <BackupServerList>
        <HostAddress>vpn-gw2.corp.example/dap</HostAddress>
      </BackupServerList>
    </HostEntry>
  </ServerList>
</AnyConnectProfile>`)

	profile, err := ParseAnyConnectProfile("/tmp/cp_corp_inside_3.xml", raw)
	if err != nil {
		t.Fatalf("ParseAnyConnectProfile() error = %v", err)
	}
	if profile.FileName != "cp_corp_inside_3.xml" {
		t.Fatalf("FileName = %q", profile.FileName)
	}
	if profile.LocalLanAccess != "true" {
		t.Fatalf("LocalLanAccess = %q", profile.LocalLanAccess)
	}
	if profile.PPPExclusion != "Disable" {
		t.Fatalf("PPPExclusion = %q", profile.PPPExclusion)
	}
	if len(profile.HostEntries) != 1 {
		t.Fatalf("len(HostEntries) = %d", len(profile.HostEntries))
	}
	if profile.HostEntries[0].Address != "vpn-gw1.corp.example/dap" {
		t.Fatalf("Address = %q", profile.HostEntries[0].Address)
	}
}

func TestDiscoverProfileFiles(t *testing.T) {
	dir := t.TempDir()
	xmlPath := filepath.Join(dir, "cp_corp_inside_3.xml")
	txtPath := filepath.Join(dir, "notes.txt")

	if err := os.WriteFile(xmlPath, []byte("<AnyConnectProfile/>"), 0o644); err != nil {
		t.Fatalf("WriteFile xml: %v", err)
	}
	if err := os.WriteFile(txtPath, []byte("ignore"), 0o644); err != nil {
		t.Fatalf("WriteFile txt: %v", err)
	}

	files, err := DiscoverProfileFiles([]string{dir})
	if err != nil {
		t.Fatalf("DiscoverProfileFiles() error = %v", err)
	}
	if len(files) != 1 || files[0] != xmlPath {
		t.Fatalf("files = %#v", files)
	}
}

func TestResolveServerFromProfiles(t *testing.T) {
	dir := t.TempDir()
	xmlPath := filepath.Join(dir, "cp_corp_inside_3.xml")
	raw := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<AnyConnectProfile xmlns="http://schemas.xmlsoap.org/encoding/">
  <ServerList>
    <HostEntry>
      <HostName>5. Ural Outside extended</HostName>
      <HostAddress>vpn-gw2.corp.example/outside</HostAddress>
    </HostEntry>
  </ServerList>
</AnyConnectProfile>`)
	if err := os.WriteFile(xmlPath, raw, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	host, err := ResolveServerFromProfiles([]string{dir}, "Ural Outside extended")
	if err != nil {
		t.Fatalf("ResolveServerFromProfiles() error = %v", err)
	}
	if host.Address != "vpn-gw2.corp.example/outside" {
		t.Fatalf("Address = %q", host.Address)
	}
}

func TestResolveServerFromProfiles_DeduplicatesSameHostAcrossDirs(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()
	raw := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<AnyConnectProfile xmlns="http://schemas.xmlsoap.org/encoding/">
  <ServerList>
    <HostEntry>
      <HostName>5. Ural Outside extended</HostName>
      <HostAddress>vpn-gw2.corp.example/outside</HostAddress>
    </HostEntry>
  </ServerList>
</AnyConnectProfile>`)

	for _, dir := range []string{dirA, dirB} {
		if err := os.WriteFile(filepath.Join(dir, "cp_corp_inside_3.xml"), raw, 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	host, err := ResolveServerFromProfiles([]string{dirA, dirB}, "Ural Outside extended")
	if err != nil {
		t.Fatalf("ResolveServerFromProfiles() error = %v", err)
	}
	if host.Address != "vpn-gw2.corp.example/outside" {
		t.Fatalf("Address = %q", host.Address)
	}
}

func TestResolveServerFromProfiles_AmbiguousDistinctHosts(t *testing.T) {
	dir := t.TempDir()
	raw := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<AnyConnectProfile xmlns="http://schemas.xmlsoap.org/encoding/">
  <ServerList>
    <HostEntry>
      <HostName>MSK Outside extended</HostName>
      <HostAddress>vpn-gw1.corp.example/outside</HostAddress>
    </HostEntry>
    <HostEntry>
      <HostName>Ural Outside extended</HostName>
      <HostAddress>vpn-gw2.corp.example/outside</HostAddress>
    </HostEntry>
  </ServerList>
</AnyConnectProfile>`)
	if err := os.WriteFile(filepath.Join(dir, "cp_corp_inside_3.xml"), raw, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := ResolveServerFromProfiles([]string{dir}, "outside extended")
	if err == nil {
		t.Fatal("ResolveServerFromProfiles() error = nil, want ambiguity")
	}
	if got := err.Error(); got == "" || !strings.Contains(got, "matched multiple host entries") {
		t.Fatalf("error = %q", got)
	}
}
