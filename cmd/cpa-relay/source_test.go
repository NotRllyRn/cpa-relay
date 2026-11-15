package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NotRllyRn/cpa-relay/internal/relay"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestHostSourceRequiresExactGetIdentity(t *testing.T) {
	entry := relay.Entry{Index: "index", Name: "a.json", Path: "/auth/a.json", Codex: true}
	for _, field := range []string{"ok", "index", "name", "path", "missing", "error"} {
		t.Run(field, func(t *testing.T) {
			s := hostSource{call: func(_ string, _ any, out any) error {
				response := pluginapi.HostAuthGetResponse{AuthIndex: entry.Index, Name: entry.Name, Path: entry.Path, JSON: json.RawMessage(`{"type":"codex"}`)}
				switch field {
				case "index":
					response.AuthIndex = "other"
				case "name":
					response.Name = "b.json"
				case "path":
					response.Path = "/auth/b.json"
				case "missing":
					response = pluginapi.HostAuthGetResponse{}
				case "error":
					return relay.ErrExport
				}
				return json.Unmarshal(encoded(response), out)
			}}
			_, err := s.Get(entry)
			if (err == nil) != (field == "ok") {
				t.Fatal("wrong Get identity result")
			}
		})
	}
}

func TestHostSourceDeletionProofUsesOnlyPhysicalAbsence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.json")
	s := hostSource{}
	if os.WriteFile(path, []byte(`not valid credential JSON`), 0600) != nil {
		t.Fatal("fixture")
	}
	if removed, err := s.Removed(path); err != nil || removed {
		t.Fatal("present malformed source became deleted")
	}
	if os.Remove(path) != nil {
		t.Fatal("fixture")
	}
	if removed, err := s.Removed(path); err != nil || !removed {
		t.Fatal("actual physical deletion rejected")
	}
	// A dangling symlink still exists and is not proof of deletion.
	if os.Symlink(filepath.Join(dir, "missing"), path) != nil {
		t.Fatal("fixture")
	}
	if removed, err := s.Removed(path); err != nil || removed {
		t.Fatal("symlink treated as absent")
	}
	if removed, err := s.Removed(filepath.Join(dir, "absent-parent", "a.json")); err == nil || removed {
		t.Fatal("inaccessible/missing parent became delete-all")
	}
}

func TestHostSourceListAndLegacySettingsFailClosed(t *testing.T) {
	for _, raw := range []string{`{}`, `{"files":null}`, `{"files":[{"auth_index":"a","type":"codex","provider":"other"}]}`} {
		s := hostSource{call: func(_ string, _ any, out any) error { return json.Unmarshal([]byte(raw), out) }}
		if _, err := s.List(); err == nil {
			t.Fatal("invalid List accepted")
		}
	}
	s := hostSource{call: func(_ string, _ any, out any) error { return json.Unmarshal([]byte(`{"files":[]}`), out) }}
	if entries, err := s.List(); err != nil || entries == nil || len(entries) != 0 {
		t.Fatal("valid empty inventory rejected")
	}
	a := &application{host: func(string, any, any) error { return relay.ErrExport }}
	a.handle("plugin.register", encoded(map[string]any{"schema_version": 10, "config_yaml": []byte(appConfig(t, "exporter") + "accounts: []\n")}))
	if a.state.Load() != "settings_migration_required" || a.current.Load() != nil {
		t.Fatal("legacy selection silently broadened")
	}
	meta := string(encoded(metadata()))
	if strings.Contains(meta, `"name":"accounts"`) || strings.Contains(meta, `"name":"source_files"`) {
		t.Fatal("removed selectors remain in UI")
	}
}
