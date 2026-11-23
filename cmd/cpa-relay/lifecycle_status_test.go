package main

import (
	"encoding/json"
	"fmt"
	"github.com/NotRllyRn/cpa-relay/internal/relay"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"testing"
	"time"
)

func TestStatusDrainReasonWhileBlocked(t *testing.T) {
	a := &application{}
	a.handle(pluginabi.MethodPluginRegister, registerRaw(appConfig(t, "exporter")))
	a.mu.Lock()
	done := make(chan struct{})
	go func() { a.stop(); close(done) }()
	deadline := time.Now().Add(time.Second)
	for a.current.Load() != nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	var response pluginapi.ManagementResponse
	decodeResult(t, invoke(a, "GET", "/v0/management/cpa-relay/status", nil), &response)
	var got relay.Status
	err := json.Unmarshal(response.Body, &got)
	a.mu.Unlock()
	<-done
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("during drain: ready=%v state=%q reason=%q", got.Ready, got.State, got.Reason)
	if got.Ready || got.Reason != "stopping" {
		t.Errorf("drain transition not published")
	}
}

func TestStatusChangedReconfigureWhileExportBlocked(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	a := &application{host: func(string, any, any) error { close(entered); <-release; return fmt.Errorf("synthetic unavailable") }}
	config := appConfig(t, "exporter")
	a.handle(pluginabi.MethodPluginRegister, registerRaw(config))
	old := a.current.Load()
	exported := make(chan struct{})
	go func() { old.Export(time.Now()); close(exported) }()
	<-entered
	configured := make(chan struct{})
	go func() { a.configure(registerRaw(config+"max_stale_seconds: 7200\n"), true); close(configured) }()
	deadline := time.Now().Add(time.Second)
	for a.current.Load() != nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	var response pluginapi.ManagementResponse
	decodeResult(t, invoke(a, "GET", "/v0/management/cpa-relay/status", nil), &response)
	var got relay.Status
	err := json.Unmarshal(response.Body, &got)
	close(release)
	<-exported
	<-configured
	defer a.stop()
	if err != nil || got.Ready || got.Reason != "stopping" {
		t.Fatalf("changed configuration during blocked export: %+v, %v", got, err)
	}
}
