package main

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestModelsReadyRequiresExactActiveRuntimeAndModelIdentity(t *testing.T) {
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
			ready, err := h.ModelsReady([]string{path})
			if name == "ready" {
				if !ready || err != nil {
					t.Fatal("registered active model rejected")
				}
			} else if ready {
				t.Fatal("unusable/mismatched route accepted")
			}
			if ready, _ := h.ModelsReady([]string{path, "/fixture/auth/missing.json"}); ready {
				t.Fatal("one registered credential masked another missing route")
			}
		})
	}
}
