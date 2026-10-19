package ifaceaudit

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"multi-tun/desktop/internal/anyconnect/openconnect"
	"multi-tun/desktop/internal/anyconnect/openconnectcfg"
	"multi-tun/desktop/internal/vless/config"
	"multi-tun/desktop/internal/vless/session"
)

type ClaimCollection struct {
	Claims []Claim
	Issues []string
}

var (
	resolveVLESSConfigPath = config.ResolveLoadPath
	loadVLESSConfig        = config.Load
	resolveVLESSCurrent    = session.ResolveCurrent
	checkVLESSSessionAlive = session.SessionAlive
	loadOpenConnectConfig  = openconnectcfg.LoadOptional
	loadOpenConnectCurrent = openconnect.LoadCurrent
	checkOpenConnectAlive  = openconnect.SessionAlive
)

// CollectClaims reads the same current-session records and invokes the same
// liveness functions used by the two engine status commands.
func CollectClaims() ClaimCollection {
	var collection ClaimCollection
	collectVLESSClaims(&collection)
	collectOpenConnectClaim(&collection)
	sort.Slice(collection.Claims, func(i, j int) bool {
		left := collection.Claims[i].Interface + "\x00" + collection.Claims[i].Engine + "\x00" + collection.Claims[i].SessionID
		right := collection.Claims[j].Interface + "\x00" + collection.Claims[j].Engine + "\x00" + collection.Claims[j].SessionID
		return left < right
	})
	sort.Strings(collection.Issues)
	return collection
}

func collectVLESSClaims(collection *ClaimCollection) {
	configPath, err := resolveVLESSConfigPath("")
	if err != nil {
		collection.Issues = append(collection.Issues, fmt.Sprintf("vless-tun configuration path: %v", err))
		return
	}

	cfg, err := loadVLESSConfig(configPath)
	if errors.Is(err, os.ErrNotExist) {
		cfg = config.DefaultForPath(configPath)
	} else if err != nil {
		collection.Issues = append(collection.Issues, fmt.Sprintf("vless-tun configuration: %v; rerun vless-tun status", err))
		return
	}

	for _, cacheDir := range vlessCacheDirs(cfg) {
		current, err := resolveVLESSCurrent(cacheDir, cfg.LaunchOrDefault())
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			collection.Issues = append(collection.Issues, fmt.Sprintf("vless-tun session state in %s: %v; rerun vless-tun status", cacheDir, err))
			continue
		}
		interfaceName := strings.TrimSpace(current.InterfaceName)
		if interfaceName == "" {
			collection.Issues = append(collection.Issues, fmt.Sprintf("vless-tun session %s has no recorded interface name (started by an older vless-tun); its interface is listed as not ours until the session is restarted", current.ID))
			continue
		}
		alive, _, aliveErr := checkVLESSSessionAlive(current)
		liveness := livenessFromCheck(alive, aliveErr)
		if aliveErr == nil && !alive && current.PID <= 0 {
			// A PID-less record may still represent a starting session. Keep it
			// unknown unless another liveness source positively reports it alive.
			liveness = LivenessUnknown
		}
		claim := Claim{
			Engine:    EngineVLESS,
			SessionID: current.ID,
			Interface: interfaceName,
			Liveness:  liveness,
		}
		collection.Claims = append(collection.Claims, claim)
		if aliveErr != nil {
			collection.Issues = append(collection.Issues, fmt.Sprintf("vless-tun session %s liveness: %v; rerun vless-tun status", current.ID, aliveErr))
		}
	}
}

func vlessCacheDirs(cfg config.ProjectConfig) []string {
	seen := map[string]struct{}{}
	var directories []string
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		directories = append(directories, value)
	}

	if len(cfg.Servers) == 0 {
		add(cfg.CacheDir)
	} else {
		for _, server := range cfg.Servers {
			if strings.TrimSpace(server.CacheDir) != "" {
				add(server.CacheDir)
			} else {
				add(cfg.CacheDir)
			}
		}
	}
	sort.Strings(directories)
	return directories
}

func collectOpenConnectClaim(collection *ClaimCollection) {
	cfg, _, err := loadOpenConnectConfig("")
	if err != nil {
		collection.Issues = append(collection.Issues, fmt.Sprintf("openconnect-tun configuration: %v; rerun openconnect-tun status", err))
		return
	}
	cacheDir := openconnect.ResolveCacheDir(cfg.CacheDirOrDefault())
	current, err := loadOpenConnectCurrent(cacheDir)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		collection.Issues = append(collection.Issues, fmt.Sprintf("openconnect-tun session state in %s: %v; rerun openconnect-tun status", cacheDir, err))
		return
	}
	interfaceName := strings.TrimSpace(current.Interface)
	if interfaceName == "" {
		collection.Issues = append(collection.Issues, fmt.Sprintf("openconnect-tun session %s has no recorded interface name; rerun openconnect-tun status", current.ID))
		return
	}

	alive, _, aliveErr := checkOpenConnectAlive(current)
	liveness := livenessFromCheck(alive, aliveErr)
	if aliveErr == nil && current.PID <= 0 {
		// Match openconnect-tun status: a PID-less current record is still
		// starting, so it is not safe to call it dead or suggest cleanup.
		liveness = LivenessUnknown
	}
	collection.Claims = append(collection.Claims, Claim{
		Engine:    EngineOpenConnect,
		SessionID: current.ID,
		Interface: interfaceName,
		Liveness:  liveness,
	})
	if aliveErr != nil {
		collection.Issues = append(collection.Issues, fmt.Sprintf("openconnect-tun session %s liveness: %v; rerun openconnect-tun status", current.ID, aliveErr))
	}
}

func livenessFromCheck(alive bool, err error) Liveness {
	if err != nil {
		return LivenessUnknown
	}
	if alive {
		return LivenessAlive
	}
	return LivenessDead
}
