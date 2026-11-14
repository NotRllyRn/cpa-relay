package main

import (
	"encoding/json"
	"net/http"
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
	state   string
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
	entries := make([]relay.Entry, 0, len(out.Files))
	for _, f := range out.Files {
		entries = append(entries, relay.Entry{Index: f.AuthIndex, Codex: f.Type == "codex" || f.Provider == "codex", RuntimeOnly: f.RuntimeOnly, Disabled: f.Disabled})
	}
	return entries, nil
}
func (s hostSource) Get(index string) ([]byte, error) {
	var out pluginapi.HostAuthGetResponse
	err := s.call(pluginabi.MethodHostAuthGet, pluginapi.HostAuthGetRequest{AuthIndex: index}, &out)
	return out.JSON, err
}

func (s hostSource) Save(name string, raw []byte) (string, error) {
	var out pluginapi.HostAuthSaveResponse
	err := s.call(pluginabi.MethodHostAuthSave, pluginapi.HostAuthSaveRequest{Name: name, JSON: raw}, &out)
	return out.Path, err
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

func (a *application) stop() {
	a.current.Store(nil)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.engine != nil {
		_ = a.engine.Stop()
		a.engine = nil
	}
	a.current.Store(nil)
	a.state = "stopped"
}

func (a *application) configure(raw []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.state = "settings_invalid"
	a.current.Store(nil)
	// Stop old workers and withdraw their inventory before changing authority.
	if a.engine != nil {
		err := a.engine.Stop()
		a.engine = nil
		if err != nil {
			a.state = "cleanup_failed"
			return
		}
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
		return
	}
	if !c.Enabled {
		a.state = "disabled"
		return
	}
	e, err := relay.New(c, secret, hostSource{a.host})
	if err != nil {
		a.state = "storage_unavailable"
		return
	}
	a.engine = e
	a.current.Store(e)
	a.state = "configured"
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
		a.stop()
		return success(struct{}{})
	case pluginabi.MethodManagementRegister:
		return success(struct {
			Routes    []pluginapi.ManagementRoute `json:"routes"`
			Resources []pluginapi.ResourceRoute   `json:"resources"`
		}{
			Routes:    []pluginapi.ManagementRoute{{Method: "GET", Path: "/cpa-relay/status"}, {Method: "POST", Path: "/cpa-relay/poll"}},
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
		return response(200, "text/html; charset=utf-8", []byte(`<!doctype html><html lang="en"><meta charset="utf-8"><title>CPA Relay</title><h1>CPA Relay</h1><p>`+label+`</p><p>Reload to update. Use CPA plugin settings for role, endpoint and account selection. Authenticated controls: GET /v0/management/cpa-relay/status and POST /v0/management/cpa-relay/poll.</p><p>Ingress must fail closed unless /v0/resource/plugins/cpa-relay/ready returns HTTP 200. Do not expose a direct bypass.</p></html>`))
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
	case req.Method == "GET" && req.Path == "/v0/management/cpa-relay/status":
		if e == nil || a.fault.Load() {
			return jsonResponse(200, map[string]any{"ready": false, "state": a.state})
		}
		return jsonResponse(200, e.Status())
	case req.Method == "POST" && req.Path == "/v0/management/cpa-relay/poll":
		if e == nil || a.fault.Load() {
			return jsonResponse(503, map[string]string{"state": "unavailable"})
		}
		if !e.Trigger() {
			return jsonResponse(409, map[string]string{"state": "not_receiver"})
		}
		return jsonResponse(202, map[string]string{"state": "poll_requested"})
	default:
		return jsonResponse(404, map[string]string{"error": "not found"})
	}
}

func metadata() any {
	fields := []pluginapi.ConfigField{
		{Name: "role", Type: pluginapi.ConfigFieldTypeEnum, EnumValues: []string{"exporter", "receiver"}, Description: "Required role. Invalid settings keep the request gate closed."},
		{Name: "endpoint", Type: pluginapi.ConfigFieldTypeString, Description: "Receiver: direct primary HTTPS snapshot URL, never a failover hostname. No query or user info."},
		{Name: "secret_env", Type: pluginapi.ConfigFieldTypeString, Description: "Name of an environment variable containing 32+ random bytes encoded as unpadded base64url. Never put its value in settings."},
		{Name: "accounts", Type: pluginapi.ConfigFieldTypeArray, Default: []string{}, Description: "Required explicit Codex account_id allowlist on both roles; maximum 128."},
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
	}{pluginabi.SchemaVersion, pluginapi.Metadata{Name: "cpa-relay", Version: "0.1.0", Author: "NotRllyRn", GitHubRepository: "https://github.com/NotRllyRn/cpa-relay", ConfigFields: fields}, map[string]bool{"management_api": true, "request_interceptor": true, "request_interceptor_omit_body_before": true, "request_interceptor_omit_body_after": true}}
}
