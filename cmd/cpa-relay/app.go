package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NotRllyRn/cpa-relay/internal/relay"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

type hostFunc func(string, any, any) error
type application struct {
	mu      sync.RWMutex
	engine  *relay.Engine
	current atomic.Pointer[relay.Engine]
	host    hostFunc
	state   atomic.Value // immutable string; status must not wait for callbacks
	fault   atomic.Bool
}

type hostSource struct{ call hostFunc }

func (s hostSource) List() ([]relay.Entry, error) {
	var out struct {
		Files []pluginapi.HostAuthFileEntry `json:"files"`
	}
	if err := s.call(pluginabi.MethodHostAuthList, struct{}{}, &out); err != nil {
		return nil, err
	}
	if out.Files == nil {
		return nil, relay.ErrExport
	}
	entries := make([]relay.Entry, 0, len(out.Files))
	for _, f := range out.Files {
		if (f.Type == "codex" && f.Provider != "" && f.Provider != "codex") || (f.Provider == "codex" && f.Type != "" && f.Type != "codex") {
			return nil, relay.ErrExport
		}
		entries = append(entries, relay.Entry{Index: f.AuthIndex, Name: f.Name, Path: f.Path, Codex: f.Type == "codex" || f.Provider == "codex", RuntimeOnly: f.RuntimeOnly, Disabled: f.Disabled, UnknownProvider: (f.Type == "" || f.Type == "unknown") && (f.Provider == "" || f.Provider == "unknown")})
	}
	return entries, nil
}
func (s hostSource) Removed(path string) (bool, error) {
	// CPA can remove malformed files from its runtime listing. Only physical
	// absence in an accessible parent proves deletion; no credential is read.
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil || !parent.IsDir() {
		return false, relay.ErrExport
	}
	_, err = os.Lstat(path)
	if os.IsNotExist(err) {
		return true, nil
	}
	if err != nil {
		return false, relay.ErrExport
	}
	return false, nil
}

func (s hostSource) Get(entry relay.Entry) ([]byte, error) {
	var out pluginapi.HostAuthGetResponse
	err := s.call(pluginabi.MethodHostAuthGet, pluginapi.HostAuthGetRequest{AuthIndex: entry.Index}, &out)
	if err != nil || out.AuthIndex != entry.Index || out.Name != entry.Name || out.Path != entry.Path {
		return nil, relay.ErrExport
	}
	return out.JSON, nil
}

func (s hostSource) Save(name string, raw []byte) (string, error) {
	var out pluginapi.HostAuthSaveResponse
	err := s.call(pluginabi.MethodHostAuthSave, pluginapi.HostAuthSaveRequest{Name: name, JSON: raw}, &out)
	return out.Path, err
}

// ModelsReady joins the manager-backed runtime identity to its model registry
// entry. A disk file, unrelated credential, or a disabled/error record is not
// evidence of an available route. Model registration does not prove inference.
func (s hostSource) ModelsReady(paths []string) (bool, error) {
	var models pluginapi.HostAuthModelsResponse
	if err := s.call(pluginabi.MethodHostAuthModels, pluginapi.HostAuthModelsRequest{}, &models); err != nil {
		return false, err
	}
	var files struct {
		Files []pluginapi.HostAuthFileEntry `json:"files"`
	}
	if err := s.call(pluginabi.MethodHostAuthList, struct{}{}, &files); err != nil {
		return false, err
	}
	if len(paths) == 0 {
		return false, nil
	}
	for _, path := range paths {
		var found *pluginapi.HostAuthFileEntry
		for i := range files.Files {
			f := &files.Files[i]
			if f.Path != path || f.Name != filepath.Base(path) {
				continue
			}
			if found != nil {
				return false, nil
			}
			found = f
		}
		f := found
		if f == nil || f.ID == "" || f.AuthIndex == "" || f.Provider != "codex" || f.RuntimeOnly || f.Disabled || f.Unavailable || f.Status != "active" {
			return false, nil
		}
		matched := 0
		for _, m := range models.Credentials {
			if m.AuthIndex != f.AuthIndex {
				continue
			}
			matched++
			if m.ID != f.ID || m.Provider != "codex" {
				return false, nil
			}
			usable := false
			for _, id := range m.Models {
				if strings.TrimSpace(id) != "" {
					usable = true
				}
			}
			if !usable {
				return false, nil
			}
		}
		if matched != 1 {
			return false, nil
		}
	}
	return true, nil
}

func success(v any) []byte {
	r, _ := json.Marshal(v)
	b, _ := json.Marshal(pluginabi.Envelope{OK: true, Result: r})
	return b
}
func failure() []byte {
	b, _ := pluginabi.NewErrorEnvelope("relay_error", "relay operation unavailable")
	return b
}

func (a *application) stop() error {
	a.current.Store(nil)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.engine != nil {
		if err := a.engine.Stop(); err != nil {
			a.state.Store("cleanup_failed")
			return err
		}
		a.engine = nil
	}
	a.current.Store(nil)
	a.state.Store("stopped")
	return nil
}

func (a *application) configure(raw []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.state.Store("settings_invalid")
	a.current.Store(nil)
	// Stop old workers and withdraw their inventory before changing authority.
	if a.engine != nil {
		if err := a.engine.Stop(); err != nil {
			a.state.Store("cleanup_failed")
			return
		}
		a.engine = nil
	}
	var req struct {
		ConfigYAML    []byte `json:"config_yaml"`
		SchemaVersion uint32 `json:"schema_version"`
	}
	if json.Unmarshal(raw, &req) != nil || req.SchemaVersion != pluginabi.SchemaVersion {
		return
	}
	c, secret, err := relay.ParseConfig(req.ConfigYAML)
	if err != nil {
		if err == relay.ErrLegacyConfig {
			a.state.Store("settings_migration_required")
		}
		return
	}
	if !c.Enabled {
		a.state.Store("disabled")
		return
	}
	e, err := relay.New(c, secret, hostSource{a.host})
	if err != nil {
		a.state.Store("storage_unavailable")
		return
	}
	a.engine = e
	a.current.Store(e)
	a.state.Store("configured")
	a.fault.Store(false)
}

func (a *application) handle(method string, raw []byte) []byte {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		a.configure(raw)
		// Keep the gate installed even for invalid settings. Never put a parser,
		// filesystem, URL, host error, or credential into the RPC error envelope.
		return success(metadata())
	case pluginabi.MethodPluginQuiesce, pluginabi.MethodPluginShutdown:
		if a.stop() != nil {
			return failure()
		}
		return success(struct{}{})
	case pluginabi.MethodManagementRegister:
		return success(struct {
			Routes    []pluginapi.ManagementRoute `json:"routes"`
			Resources []pluginapi.ResourceRoute   `json:"resources"`
		}{
			Routes:    []pluginapi.ManagementRoute{{Method: "GET", Path: "/cpa-relay/status"}, {Method: "POST", Path: "/cpa-relay/poll"}, {Method: "POST", Path: "/cpa-relay/drain"}},
			Resources: []pluginapi.ResourceRoute{{Path: "/status", Menu: "CPA Relay", Description: "Coarse relay readiness; configure through CPA plugin settings."}, {Path: "/ready"}, {Path: "/snapshot"}},
		})
	case pluginabi.MethodRequestInterceptBefore, pluginabi.MethodRequestInterceptAfter:
		e := a.current.Load()
		if a.fault.Load() || e == nil || e.Gate() {
			return success(pluginapi.RequestInterceptResponse{Terminate: true, StatusCode: 503, ResponseHeaders: http.Header{"Content-Type": {"application/json"}, "Cache-Control": {"no-store"}}, ResponseBody: []byte(`{"error":{"message":"relay not ready","type":"relay_not_ready"}}`)})
		}
		return success(pluginapi.RequestInterceptResponse{})
	case pluginabi.MethodManagementHandle:
		return a.management(raw)
	default:
		return failure()
	}
}

func response(status int, content string, body []byte) []byte {
	return success(pluginapi.ManagementResponse{StatusCode: status, Headers: http.Header{"Content-Type": {content}, "Cache-Control": {"no-store"}, "X-Content-Type-Options": {"nosniff"}, "Content-Security-Policy": {"default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"}, "Referrer-Policy": {"no-referrer"}}, Body: body})
}
func jsonResponse(status int, v any) []byte {
	b, _ := json.Marshal(v)
	return response(status, "application/json", b)
}

func (a *application) management(raw []byte) []byte {
	var req pluginapi.ManagementRequest
	if json.Unmarshal(raw, &req) != nil {
		return jsonResponse(400, map[string]string{"error": "invalid request"})
	}
	// Public probes must never wait for a reconfigure/host callback lock.
	if req.Method == "GET" && (req.Path == relay.ReadyPath || req.Path == "/v0/resource/plugins/cpa-relay/status") {
		e := a.current.Load()
		ready := e != nil && !a.fault.Load() && e.Ready()
		if req.Path == relay.ReadyPath {
			status := 503
			if ready {
				status = 200
			}
			return jsonResponse(status, map[string]bool{"ready": ready})
		}
		label := "NOT READY"
		if ready {
			label = "READY"
		}
		return response(200, "text/html; charset=utf-8", []byte(`<!doctype html><html lang="en"><meta charset="utf-8"><title>CPA Relay</title><h1>CPA Relay</h1><p>`+label+`</p><p>Reload to update. Use CPA plugin settings for role, endpoint and account selection. Authenticated controls: GET /v0/management/cpa-relay/status and POST /v0/management/cpa-relay/poll and /drain. Drain successfully before disabling or unloading.</p><p>Ingress must fail closed unless /v0/resource/plugins/cpa-relay/ready returns HTTP 200. Do not expose a direct bypass.</p></html>`))
	}
	// These paths are registered only with CPA's admin-authenticated management
	// router. Never register drain as a public resource.
	if req.Method == "POST" && req.Path == "/v0/management/cpa-relay/drain" {
		if a.stop() != nil {
			return jsonResponse(503, map[string]string{"state": "cleanup_failed"})
		}
		return jsonResponse(200, map[string]string{"state": "drained"})
	}
	if req.Method == "GET" && req.Path == "/v0/management/cpa-relay/status" {
		e := a.current.Load()
		if e == nil || a.fault.Load() {
			state := "unconfigured"
			if v := a.state.Load(); v != nil {
				state = v.(string)
			}
			return jsonResponse(200, map[string]any{"ready": false, "state": state})
		}
		return jsonResponse(200, e.Status())
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	e := a.engine
	switch {
	case req.Method == "GET" && req.Path == relay.SnapshotPath:
		// Authentication precedes role/status checks. Query-string credentials are
		// never supported; the receiver sends exactly one dedicated bearer header.
		if e == nil || !e.Authorized(req.Headers) {
			return jsonResponse(401, map[string]string{"error": "unauthorized"})
		}
		if len(req.Query) > 0 || a.fault.Load() {
			return jsonResponse(503, map[string]string{"error": "unavailable"})
		}
		raw, err := e.Export(time.Now())
		if err != nil {
			return jsonResponse(503, map[string]string{"error": "unavailable"})
		}
		return response(200, "application/json", raw)
	case req.Method == "POST" && req.Path == "/v0/management/cpa-relay/poll":
		if e == nil || a.fault.Load() {
			return jsonResponse(503, map[string]string{"state": "unavailable"})
		}
		if !e.Trigger() {
			return jsonResponse(409, map[string]string{"state": "poll_unavailable"})
		}
		return jsonResponse(202, map[string]string{"state": "poll_requested"})
	default:
		return jsonResponse(404, map[string]string{"error": "not found"})
	}
}

func metadata() any {
	fields := []pluginapi.ConfigField{
		{Name: "role", Type: pluginapi.ConfigFieldTypeEnum, EnumValues: []string{"exporter", "receiver"}, Description: "Required role. Exporter shares ALL current and future physical Codex credentials (maximum 128); no per-account selection. Invalid settings keep the gate closed."},
		{Name: "endpoint", Type: pluginapi.ConfigFieldTypeString, Description: "Receiver: direct primary HTTPS snapshot URL, never a failover hostname. No query or user info."},
		{Name: "secret_env", Type: pluginapi.ConfigFieldTypeString, Description: "Name of an environment variable containing 32+ random bytes encoded as unpadded base64url. Never put its value in settings."},
		{Name: "poll_seconds", Type: pluginapi.ConfigFieldTypeInteger, Default: 15, Description: "Receiver polling interval, 1–300 seconds."},
		{Name: "max_stale_seconds", Type: pluginapi.ConfigFieldTypeInteger, Default: 3600, Description: "Maximum original snapshot age; at least twice poll interval, at most 86400 seconds."},
		{Name: "expiry_skew_seconds", Type: pluginapi.ConfigFieldTypeInteger, Default: 60, Description: "Withdraw before the earlier explicit/JWT expiry, 5–600 seconds."},
		{Name: "state_dir", Type: pluginapi.ConfigFieldTypeString, Description: "Required absolute private 0700 state directory, outside CPA auth-dir."},
		{Name: "auth_dir", Type: pluginapi.ConfigFieldTypeString, Description: "Receiver only: exact absolute CPA auth-dir. Runtime updates require synchronous host save acknowledgements."},
		{Name: "receiver_id", Type: pluginapi.ConfigFieldTypeString, Description: "Receiver only: stable reserved filename namespace, lowercase letters/digits/hyphens, 1–32 characters."},
	}
	return struct {
		SchemaVersion uint32             `json:"schema_version"`
		Metadata      pluginapi.Metadata `json:"metadata"`
		Capabilities  map[string]bool    `json:"capabilities"`
	}{pluginabi.SchemaVersion, pluginapi.Metadata{Name: "cpa-relay", Version: "0.2.0", Author: "NotRllyRn", GitHubRepository: "https://github.com/NotRllyRn/cpa-relay", ConfigFields: fields}, map[string]bool{"management_api": true, "request_interceptor": true, "request_interceptor_omit_body_before": true, "request_interceptor_omit_body_after": true}}
}
