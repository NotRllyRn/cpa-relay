package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestDashboardCSPMatchesEmbeddedBytes(t *testing.T) {
	var response pluginapi.ManagementResponse
	decodeResult(t, invoke(&application{}, "GET", "/v0/resource/plugins/cpa-relay/status", nil), &response)
	if response.StatusCode != 200 || response.Headers.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatal("dashboard response missing")
	}
	for _, tag := range []string{"script", "style"} {
		matches := regexp.MustCompile("(?s)<"+tag+">(.*?)</"+tag+">").FindAllSubmatch(response.Body, -1)
		if len(matches) != 1 {
			t.Fatalf("expected exactly one %s", tag)
		}
		hash := sha256.Sum256(matches[0][1])
		want := tag + "-src 'sha256-" + base64.StdEncoding.EncodeToString(hash[:]) + "'"
		if !strings.Contains(response.Headers.Get("Content-Security-Policy"), want) {
			t.Fatalf("CSP does not authorize exact %s bytes", tag)
		}
	}
	for _, unsafe := range []string{"unsafe-inline", "unsafe-eval"} {
		if strings.Contains(response.Headers.Get("Content-Security-Policy"), unsafe) {
			t.Fatalf("unsafe policy: %s", unsafe)
		}
	}
	if regexp.MustCompile(`(?i)\s(?:style|on[a-z]+)\s*=`).Match(response.Body) {
		t.Fatal("inline style or handler")
	}
	for _, want := range []string{"connect-src 'self'", "frame-ancestors 'self'", "script-src-attr 'none'", "style-src-attr 'none'"} {
		if !strings.Contains(response.Headers.Get("Content-Security-Policy"), want) {
			t.Fatalf("missing policy %s", want)
		}
	}
	if response.Headers.Get("Referrer-Policy") != "no-referrer" || response.Headers.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("response protections missing")
	}
}

func TestDashboardIsStaticAndPrivateTelemetryIsProtectedRouteOnly(t *testing.T) {
	a := &application{}
	read := func(path string) pluginapi.ManagementResponse {
		t.Helper()
		var response pluginapi.ManagementResponse
		decodeResult(t, invoke(a, "GET", path, nil), &response)
		return response
	}
	before := read("/v0/resource/plugins/cpa-relay/status")
	a.state.Store("settings_migration_required")
	a.fault.Store(true)
	after := read("/v0/resource/plugins/cpa-relay/status")
	if !bytes.Equal(before.Body, after.Body) || !bytes.Equal(after.Body, dashboardHTML) {
		t.Fatal("public dashboard varies with private status")
	}
	if bytes.Contains(after.Body, []byte(`"last_error":`)) || bytes.Contains(after.Body, []byte("mockup")) || bytes.Contains(after.Body, []byte("__DASHBOARD_")) {
		t.Fatal("dashboard contains telemetry, demo hooks, or unresolved assets")
	}
	private := read("/v0/management/cpa-relay/status")
	var status map[string]any
	if json.Unmarshal(private.Body, &status) != nil || status["reason"] != "internal_error" {
		t.Fatal("protected diagnostics unavailable")
	}
	for _, path := range []string{"/v0/resource/plugins/cpa-relay/poll", "/v0/resource/plugins/cpa-relay/drain", "/v0/resource/plugins/cpa-relay/management/status"} {
		if read(path).StatusCode != 404 {
			t.Fatalf("public route exposed: %s", path)
		}
	}
}
