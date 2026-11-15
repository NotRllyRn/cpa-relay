package relay

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"sort"
	"strings"
)

// credentialID is independent of tokens, workspace IDs and host runtime indexes.
// Physical paths never leave the exporter. Renaming a source is delete-and-add.
func credentialID(path string) string {
	sum := sha256.Sum256([]byte("cpa-relay/codex-source/v2\x00" + path))
	return hex.EncodeToString(sum[:])
}

func sourcePathValid(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && strings.TrimSpace(path) == path && !strings.ContainsRune(path, 0)
}

// discoverSources validates the entire physical Codex inventory before reads.
// Get resolves by index; even an unrelated index alias makes that read unsafe.
func discoverSources(entries []Entry) ([]Entry, error) {
	if entries == nil || len(entries) > 4096 {
		return nil, ErrExport
	}
	indexes := map[string]int{}
	paths := map[string]int{}
	for _, entry := range entries {
		indexes[entry.Index]++
		if entry.Path != "" {
			paths[entry.Path]++
		}
	}
	out := []Entry{}
	for _, entry := range entries {
		// An unclassified physical file may be a malformed Codex credential.
		// Do not silently treat it as an authoritative provider removal.
		if entry.UnknownProvider && !entry.RuntimeOnly {
			return nil, ErrExport
		}
		if !entry.Codex || entry.RuntimeOnly {
			continue
		}
		// Stock list preserves Path but trims Name; Get trims Path before reading.
		// Reject any path that Get would normalize rather than hash the wrong file.
		if entry.Index == "" || strings.TrimSpace(entry.Index) != entry.Index || indexes[entry.Index] != 1 ||
			!sourcePathValid(entry.Path) ||
			entry.Name == "" || strings.TrimSpace(filepath.Base(entry.Path)) != entry.Name || paths[entry.Path] != 1 {
			return nil, ErrExport
		}
		out = append(out, entry)
	}
	// This is a safety cap, never pagination/truncation, even for disabled sources.
	if len(out) > MaxAccounts {
		return nil, ErrExport
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func sameSources(a, b []Entry) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
