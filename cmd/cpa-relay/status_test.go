package main

import (
	"encoding/json"
	"testing"

	"github.com/NotRllyRn/cpa-relay/internal/relay"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestManagementStatusReportsFaultAndUnconfiguredReason(t *testing.T) {
	a := &application{}
	read := func() relay.Status {
		var response pluginapi.ManagementResponse
		decodeResult(t, invoke(a, "GET", "/v0/management/cpa-relay/status", nil), &response)
		var status relay.Status
		if response.StatusCode != 200 || json.Unmarshal(response.Body, &status) != nil {
			t.Fatal("invalid status response")
		}
		return status
	}
	empty := read()
	if empty.Ready || empty.Reason != "unconfigured" || empty.AvailableAccounts != 0 || empty.ModelCheckStartedAt != nil {
		t.Fatalf("invented unconfigured state: %+v", empty)
	}
	a.handle(pluginabi.MethodPluginRegister, registerRaw(appConfig(t, "exporter")))
	defer a.stop()
	if !read().Ready {
		t.Fatal("exporter not configured")
	}
	a.fault.Store(true)
	failed := read()
	if failed.Ready || failed.Reason != "internal_error" || failed.AvailableAccounts != 0 {
		t.Fatalf("application fault hidden: %+v", failed)
	}
}
