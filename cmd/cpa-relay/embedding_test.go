package main

import (
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestStatusAllowsOnlySameOriginEmbedding(t *testing.T) {
	a := &application{}
	for _, tc := range []struct{ path, ancestors string }{
		{"/v0/resource/plugins/cpa-relay/status", "'self'"},
		{"/v0/resource/plugins/cpa-relay/ready", "'none'"},
		{"/v0/resource/plugins/cpa-relay/snapshot", "'none'"},
		{"/v0/management/cpa-relay/status", "'none'"},
	} {
		var r pluginapi.ManagementResponse
		decodeResult(t, invoke(a, "GET", tc.path, nil), &r)
		csp := r.Headers.Get("Content-Security-Policy")
		want := "default-src 'none'; frame-ancestors " + tc.ancestors + "; base-uri 'none'; form-action 'none'"
		if csp != want {
			t.Fatalf("%s: unexpected policy %q", tc.path, csp)
		}
		if r.Headers.Get("Cache-Control") != "no-store" {
			t.Fatal("cache protection missing")
		}
		if tc.ancestors == "'self'" && strings.Contains(string(r.Body), "account selection") {
			t.Fatal("obsolete selection instructions")
		}
	}
}
