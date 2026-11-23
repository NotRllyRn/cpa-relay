package main

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestCheckModelsRequiresExactRuntimeAndModelIdentity(t *testing.T) {
	for _, name := range []string{"ready", "empty", "unrelated", "wrong-id", "wrong-index", "wrong-provider", "duplicate-model-entry", "whitespace", "disabled", "unavailable", "status-error", "runtime-only", "wrong-path", "wrong-name", "empty-runtime-id", "duplicate-runtime", "models-error", "list-error"} {
		t.Run(name, func(t *testing.T) {
			path := "/fixture/auth/managed.json"
			f := pluginapi.HostAuthFileEntry{ID: "runtime-id", AuthIndex: "index", Provider: "codex", Name: "managed.json", Path: path, Status: "active"}
			m := pluginapi.HostAuthModels{ID: f.ID, AuthIndex: f.AuthIndex, Provider: "codex", Models: []string{"test-model"}}
			switch name {
			case "empty":
				m.Models = nil
			case "unrelated":
				m.ID = "other"
				m.AuthIndex = "other"
			case "wrong-id":
				m.ID = "other"
			case "wrong-index":
				m.AuthIndex = "other"
			case "wrong-provider":
				m.Provider = "other"
			case "whitespace":
				m.Models = []string{" "}
			case "disabled":
				f.Disabled = true
			case "unavailable":
				f.Unavailable = true
			case "status-error":
				f.Status = "error"
			case "runtime-only":
				f.RuntimeOnly = true
			case "wrong-path":
				f.Path = "/fixture/other/managed.json"
			case "wrong-name":
				f.Name = "other.json"
			case "empty-runtime-id":
				f.ID = ""
			}
			h := hostSource{call: func(method string, req, dst any) error {
				var result any
				switch method {
				case pluginabi.MethodHostAuthModels:
					if name == "models-error" {
						return errors.New("unavailable")
					}
					models := []pluginapi.HostAuthModels{m}
					if name == "duplicate-model-entry" {
						models = append(models, m)
					}
					result = pluginapi.HostAuthModelsResponse{Credentials: models}
				case pluginabi.MethodHostAuthList:
					if name == "list-error" {
						return errors.New("unavailable")
					}
					files := []pluginapi.HostAuthFileEntry{f}
					if name == "duplicate-runtime" {
						files = append(files, f)
					}
					result = map[string]any{"files": files}
				default:
					t.Fatal("unexpected method")
				}
				raw, _ := json.Marshal(result)
				return json.Unmarshal(raw, dst)
			}}
			ready, err := h.CheckModels([]string{path})
			if name == "ready" {
				if ready.Available != 1 || err != nil {
					t.Fatal("registered active model rejected")
				}
			} else if ready.Available > 0 {
				t.Fatal("unusable/mismatched route accepted")
			}
			if ready, _ := h.CheckModels([]string{path, "/fixture/auth/missing.json"}); ready.Available > 0 {
				t.Fatal("one registered credential masked another missing route")
			}
		})
	}
}

// Stock CPA retains raw error state after a transient cooldown. A pool with
// independently active accounts must not wait for that old error to clear.
func TestCheckModelsDoesNotLetOneFailedAccountBlockHealthyPool(t *testing.T) {
	paths := []string{"/fixture/auth/healthy.json", "/fixture/auth/failed.json"}
	files := []pluginapi.HostAuthFileEntry{
		{ID: "healthy", AuthIndex: "healthy-index", Name: "healthy.json", Path: paths[0], Provider: "codex", Status: "active"},
		{ID: "failed", AuthIndex: "failed-index", Name: "failed.json", Path: paths[1], Provider: "codex", Status: "error", Unavailable: true},
	}
	models := []pluginapi.HostAuthModels{
		{ID: "healthy", AuthIndex: "healthy-index", Provider: "codex", Models: []string{"test-model"}},
		{ID: "failed", AuthIndex: "failed-index", Provider: "codex", Models: []string{"test-model"}},
	}
	h := modelHost(t, files, models)
	if ready, err := h.CheckModels(paths); err != nil || ready.Available != 1 {
		t.Fatal("one failed account blocked an independently active registered account")
	}
}

func modelHost(t *testing.T, files []pluginapi.HostAuthFileEntry, models []pluginapi.HostAuthModels) hostSource {
	t.Helper()
	return hostSource{call: func(method string, req, dst any) error {
		var out any
		switch method {
		case pluginabi.MethodHostAuthList:
			out = map[string]any{"files": files}
		case pluginabi.MethodHostAuthModels:
			out = pluginapi.HostAuthModelsResponse{Credentials: models}
		default:
			t.Fatalf("unexpected method %s", method)
		}
		raw, err := json.Marshal(out)
		if err != nil {
			return err
		}
		return json.Unmarshal(raw, dst)
	}}
}

func TestCheckModelsPoolSafety(t *testing.T) {
	for _, name := range []string{"mixed-terminal", "mixed-elapsed-retry", "mixed-error-available", "all-error-elapsed-retry", "all-error-available", "active-unavailable-future", "disabled-flag", "disabled-status", "missing-models", "missing-runtime", "duplicate-id", "duplicate-index", "wrong-type"} {
		t.Run(name, func(t *testing.T) {
			paths := []string{"/fixture/auth/healthy.json", "/fixture/auth/failed.json"}
			files := []pluginapi.HostAuthFileEntry{
				{ID: "healthy", AuthIndex: "healthy-index", Name: "healthy.json", Path: paths[0], Provider: "codex", Status: "active"},
				{ID: "failed", AuthIndex: "failed-index", Name: "failed.json", Path: paths[1], Provider: "codex", Status: "error", Unavailable: true},
			}
			models := []pluginapi.HostAuthModels{
				{ID: "healthy", AuthIndex: "healthy-index", Provider: "codex", Models: []string{"test-model"}},
				{ID: "failed", AuthIndex: "failed-index", Provider: "codex", Models: []string{"test-model"}},
			}
			wantAvailable, wantReason := 1, "degraded"
			switch name {
			case "mixed-elapsed-retry":
				files[1].NextRetryAfter = time.Now().Add(-time.Hour)
			case "mixed-error-available":
				files[1].Unavailable = false
			case "all-error-elapsed-retry":
				files[0].Status, files[0].Unavailable = "error", true
				files[0].NextRetryAfter, files[1].NextRetryAfter = time.Now().Add(-time.Hour), time.Now().Add(-time.Hour)
				wantAvailable, wantReason = 0, "no_available_accounts"
			case "all-error-available":
				files[0].Status, files[1].Unavailable = "error", false
				wantAvailable, wantReason = 0, "no_available_accounts"
			case "active-unavailable-future":
				files[0].Unavailable = true
				files[0].NextRetryAfter = time.Now().Add(time.Hour)
				wantAvailable, wantReason = 0, "no_available_accounts"
			case "disabled-flag":
				files[1].Disabled = true
				wantAvailable, wantReason = 0, "runtime_disabled"
			case "disabled-status":
				files[1].Status = "disabled"
				wantAvailable, wantReason = 0, "runtime_disabled"
			case "missing-models":
				models[1].Models = nil
				wantAvailable, wantReason = 0, "models_pending"
			case "missing-runtime":
				files = files[:1]
				wantAvailable, wantReason = 0, "runtime_mismatch"
			case "duplicate-id":
				files[1].ID = files[0].ID
				models[1].ID = files[0].ID
				wantAvailable, wantReason = 0, "runtime_mismatch"
			case "duplicate-index":
				files[1].AuthIndex = files[0].AuthIndex
				wantAvailable, wantReason = 0, "runtime_mismatch"
			case "wrong-type":
				files[1].Type = "other"
				wantAvailable, wantReason = 0, "runtime_mismatch"
			}
			got, err := modelHost(t, files, models).CheckModels(paths)
			if err != nil || got.Available != wantAvailable || got.Reason != wantReason {
				t.Fatalf("got %+v, %v; want %d %s", got, err, wantAvailable, wantReason)
			}
		})
	}
}
