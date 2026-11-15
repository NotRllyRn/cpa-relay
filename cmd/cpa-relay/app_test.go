package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NotRllyRn/cpa-relay/internal/relay"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func decodeResult(t *testing.T, raw []byte, dst any) {
	t.Helper()
	var env pluginabi.Envelope
	if json.Unmarshal(raw, &env) != nil || !env.OK || json.Unmarshal(env.Result, dst) != nil {
		t.Fatal("bad envelope")
	}
}
func encoded(v any) []byte { b, _ := json.Marshal(v); return b }
func registerRaw(config string) []byte {
	return encoded(map[string]any{"schema_version": pluginabi.SchemaVersion, "config_yaml": []byte(config)})
}
func appConfig(t *testing.T, role string) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("CPA_RELAY_TEST_BEARER", base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("x", 32))))
	config := fmt.Sprintf("enabled: true\nrole: %s\nsecret_env: CPA_RELAY_TEST_BEARER\nstate_dir: %s\n", role, filepath.Join(dir, "state"))
	if role == "receiver" {
		auth := filepath.Join(dir, "auth")
		os.Mkdir(auth, 0700)
		config += fmt.Sprintf("auth_dir: %s\nreceiver_id: secondary\nendpoint: https://127.0.0.1:1%s\n", auth, relay.SnapshotPath)
	}
	return config
}
func invoke(a *application, method, path string, headers http.Header) []byte {
	return a.handle(pluginabi.MethodManagementHandle, encoded(pluginapi.ManagementRequest{Method: method, Path: path, Headers: headers}))
}

func TestInvalidSettingsKeepCapabilitiesGateAndPublicReadiness(t *testing.T) {
	a := &application{}
	var metadata map[string]any
	decodeResult(t, a.handle(pluginabi.MethodPluginRegister, registerRaw("role: invalid\n")), &metadata)
	if metadata["schema_version"] != float64(pluginabi.SchemaVersion) {
		t.Fatal("SDK metadata mismatch")
	}
	caps := metadata["capabilities"].(map[string]any)
	if caps["request_interceptor"] != true {
		t.Fatal("gate missing")
	}
	for _, method := range []string{pluginabi.MethodRequestInterceptBefore, pluginabi.MethodRequestInterceptAfter} {
		var response pluginapi.RequestInterceptResponse
		decodeResult(t, a.handle(method, nil), &response)
		if !response.Terminate || response.StatusCode != 503 {
			t.Fatal("invalid settings failed open")
		}
	}
	var response pluginapi.ManagementResponse
	decodeResult(t, invoke(a, "GET", relay.ReadyPath, nil), &response)
	if response.StatusCode != 503 || string(response.Body) != "{\"ready\":false}" {
		t.Fatal("public probe not coarse")
	}
	if strings.Contains(string(response.Body), "acct-a") {
		t.Fatal("identifier leak")
	}
}

func TestExporterBridgeReadOnlyAndSecretFreeUI(t *testing.T) {
	config := appConfig(t, "exporter")
	var mu sync.Mutex
	var methods []string
	now := time.Now()
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, now.Add(time.Hour).Unix())))
	credential := map[string]any{"type": "codex", "account_id": "acct-a", "access_token": "e30." + payload + ".sig", "expired": now.Add(time.Hour).UTC().Format(time.RFC3339), "refresh_token": "DO-NOT-LEAK", "id_token": "DO-NOT-LEAK", "metadata": map[string]any{"secret": "DO-NOT-LEAK"}}
	physicalPath := "/example/auth/chosen.json"
	a := &application{host: func(method string, request any, dst any) error {
		mu.Lock()
		methods = append(methods, method)
		path := physicalPath
		mu.Unlock()
		switch method {
		case pluginabi.MethodHostAuthList:
			json.Unmarshal(encoded(map[string]any{"files": []any{pluginapi.HostAuthFileEntry{AuthIndex: "index", Name: "chosen.json", Path: path, Type: "codex"}, pluginapi.HostAuthFileEntry{AuthIndex: "other", Name: "other.json", Path: "/example/auth/other.json", Type: "other"}}}), dst)
		case pluginabi.MethodHostAuthGet:
			if request.(pluginapi.HostAuthGetRequest).AuthIndex != "index" {
				return errors.New("unselected source read")
			}
			json.Unmarshal(encoded(pluginapi.HostAuthGetResponse{AuthIndex: "index", Name: "chosen.json", Path: path, JSON: encoded(credential)}), dst)
		default:
			return errors.New("unexpected callback")
		}
		return nil
	}}
	a.handle(pluginabi.MethodPluginRegister, registerRaw(config))
	defer a.stop()
	secret := os.Getenv("CPA_RELAY_TEST_BEARER")
	var response pluginapi.ManagementResponse
	decodeResult(t, invoke(a, "GET", relay.SnapshotPath, nil), &response)
	if response.StatusCode != 401 {
		t.Fatal("unauthenticated export")
	}
	decodeResult(t, invoke(a, "GET", relay.SnapshotPath, http.Header{"Authorization": {"Bearer " + secret}}), &response)
	if response.StatusCode != 200 || strings.Contains(string(response.Body), "DO-NOT-LEAK") || strings.Contains(string(response.Body), "chosen.json") || strings.Contains(string(response.Body), "other.json") {
		t.Fatal("unsafe export")
	}
	for _, path := range []string{relay.ReadyPath, "/v0/resource/plugins/cpa-relay/status", "/v0/management/cpa-relay/status"} {
		decodeResult(t, invoke(a, "GET", path, nil), &response)
		body := string(response.Body)
		if strings.Contains(body, secret) || strings.Contains(body, "acct-a") || strings.Contains(body, "e30.") || strings.Contains(body, "DO-NOT-LEAK") || strings.Contains(body, "chosen.json") || strings.Contains(body, "other.json") {
			t.Fatal("UI/status leak")
		}
	}
	// Stock Get trims the path before reading: refuse a path it would alter.
	mu.Lock()
	physicalPath = "/example/auth/chosen.json "
	mu.Unlock()
	decodeResult(t, invoke(a, "GET", relay.SnapshotPath, http.Header{"Authorization": {"Bearer " + secret}}), &response)
	if response.StatusCode != 503 {
		t.Fatal("trimmed physical filename alias exported")
	}
	mu.Lock()
	defer mu.Unlock()
	gets := 0
	for _, method := range methods {
		if method == pluginabi.MethodHostAuthGet {
			gets++
		}
		if method == pluginabi.MethodHostAuthSave {
			t.Fatal("exporter wrote credentials")
		}
	}
	if gets != 1 {
		t.Fatal("physical filename alias was read")
	}
}

func TestReconfigureStopsWorkerAndReadinessNeverWaitsForLocks(t *testing.T) {
	a := &application{host: func(string, any, any) error { return errors.New("host unavailable") }}
	config := appConfig(t, "receiver")
	a.handle(pluginabi.MethodPluginRegister, registerRaw(config))
	a.mu.Lock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		var r pluginapi.ManagementResponse
		decodeResult(t, invoke(a, "GET", relay.ReadyPath, nil), &r)
		if r.StatusCode != 503 {
			t.Error("unready probe")
		}
		// Authenticated status is lock-free too, including during lifecycle work.
		invoke(a, "GET", "/v0/management/cpa-relay/status", nil)
		a.handle(pluginabi.MethodRequestInterceptBefore, nil)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("public readiness/gate blocked by lifecycle lock")
	}
	a.mu.Unlock()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 30; j++ {
				a.handle(pluginabi.MethodRequestInterceptBefore, nil)
				invoke(a, "GET", relay.ReadyPath, nil)
			}
		}()
	}
	a.handle(pluginabi.MethodPluginReconfigure, registerRaw(config))
	wg.Wait()
	a.stop()
	if a.current.Load() != nil {
		t.Fatal("stopped pointer published")
	}
}

func TestRoutesAndMetadataHaveNoSecretField(t *testing.T) {
	a := &application{}
	var routes struct {
		Routes    []pluginapi.ManagementRoute `json:"routes"`
		Resources []pluginapi.ResourceRoute   `json:"resources"`
	}
	decodeResult(t, a.handle(pluginabi.MethodManagementRegister, nil), &routes)
	if len(routes.Routes) != 3 || len(routes.Resources) != 3 {
		t.Fatal("missing control/menu routes")
	}
	b := string(encoded(metadata()))
	if strings.Contains(b, `"Name":"secret"`) {
		t.Fatal("inline secret setting exposed")
	}
	var response pluginapi.ManagementResponse
	decodeResult(t, invoke(a, "POST", relay.SnapshotPath, nil), &response)
	if response.StatusCode != 404 {
		t.Fatal("unsupported resource verb")
	}
}
