package vpncore

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

type BinPinRequest struct {
	Op string `json:"op,omitempty"`
}

type PinnedBinaryStatus struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	SHA256   string `json:"sha256"`
	Verified bool   `json:"verified"`
	Drift    bool   `json:"drift"`
	Error    string `json:"error,omitempty"`
}

func (d *serviceDaemon) handleBinPin(req BinPinRequest) ([]PinnedBinaryStatus, error) {
	if req.Op != "" && req.Op != "status" && req.Op != "verify" {
		return nil, errors.New("unsupported bin.pin operation")
	}
	data, err := readVerifiedRegularFile(d.cfg.ManifestPath(), d.socketVerification)
	if err != nil {
		return nil, fmt.Errorf("read pinned manifest: %w", err)
	}
	manifest, err := decodeManifest(data)
	if err != nil {
		return nil, err
	}
	// Match the installation contract before joining any manifest paths.
	seen := make(map[string]bool)
	for _, entry := range manifest.Files {
		if entry.Path == "" || filepath.IsAbs(entry.Path) || filepath.Clean(entry.Path) != entry.Path || !filepath.IsLocal(entry.Path) || entry.Path == "." || seen[entry.Path] {
			return nil, errors.New("invalid or duplicate pinned manifest path")
		}
		if err := validateSHA256("pinned sha256", entry.SHA256); err != nil {
			return nil, err
		}
		seen[entry.Path] = true
	}
	drift, _ := ToolDrift(d.cfg)
	result := make([]PinnedBinaryStatus, 0, len(manifest.Files))
	for _, entry := range manifest.Files {
		status := PinnedBinaryStatus{Name: filepath.Base(entry.Path), Path: filepath.Join(d.cfg.HelperDir, entry.Path), SHA256: entry.SHA256}
		if req.Op == "verify" {
			binary, err := readVerifiedRegularFile(status.Path, d.socketVerification)
			if err != nil {
				status.Error = err.Error()
			} else if sha256Hex(binary) != entry.SHA256 {
				status.Error = "pinned binary sha256 mismatch"
				status.Drift = true
			} else {
				status.Verified = true
			}
		}
		for _, line := range drift {
			if strings.HasPrefix(line, "drift: "+status.Name+" ") {
				status.Drift = true
			}
		}
		result = append(result, status)
	}
	return result, nil
}
