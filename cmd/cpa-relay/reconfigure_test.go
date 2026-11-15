package main

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/NotRllyRn/cpa-relay/internal/relay"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"gopkg.in/yaml.v3"
)

func TestEquivalentReconfigurePreservesInstanceAndFault(t *testing.T) {
	for _, role := range []string{"exporter", "receiver"} {
		t.Run(role, func(t *testing.T) {
			a := &application{host: func(string, any, any) error { return errors.New("host unavailable") }}
			defer a.stop()
			config := appConfig(t, role)
			a.handle(pluginabi.MethodPluginRegister, registerRaw(config))
			old := a.current.Load()
			if old == nil {
				t.Fatal("not configured")
			}
			c, _, err := relay.ParseConfig([]byte(config))
			if err != nil {
				t.Fatal(err)
			}
			canonical, err := yaml.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			for _, next := range []string{config, "# Formatting is not authority.\n" + config, string(canonical)} {
				a.handle(pluginabi.MethodPluginReconfigure, registerRaw(next))
				if a.current.Load() != old || a.engine != old {
					t.Fatal("equivalent config stopped/replaced engine")
				}
			}
			a.fault.Store(true)
			a.handle(pluginabi.MethodPluginReconfigure, registerRaw(config))
			var gate pluginapi.RequestInterceptResponse
			decodeResult(t, a.handle(pluginabi.MethodRequestInterceptBefore, nil), &gate)
			if a.current.Load() != old || !a.fault.Load() || !gate.Terminate {
				t.Fatal("unchanged reload cleared fault or revived admission")
			}
		})
	}
}

func TestChangedOrInvalidReconfigureStillDrains(t *testing.T) {
	for _, name := range []string{"endpoint", "state_dir", "auth_dir", "receiver_id", "secret_env", "secret_value", "timing", "disabled", "invalid", "schema", "malformed"} {
		t.Run(name, func(t *testing.T) {
			a := &application{host: func(string, any, any) error { return errors.New("host unavailable") }}
			defer a.stop()
			config := appConfig(t, "receiver")
			a.handle(pluginabi.MethodPluginRegister, registerRaw(config))
			old := a.current.Load()
			c, oldSecret, err := relay.ParseConfig([]byte(config))
			if err != nil || old == nil {
				t.Fatal("not configured")
			}
			switch name {
			case "endpoint":
				c.Endpoint = strings.Replace(c.Endpoint, ":1/", ":2/", 1)
			case "state_dir":
				c.StateDir = t.TempDir()
			case "auth_dir":
				c.AuthDir = t.TempDir()
			case "receiver_id":
				c.ReceiverID = "another"
			case "secret_env":
				c.SecretEnv = "CPA_RELAY_TEST_OTHER"
				t.Setenv(c.SecretEnv, oldSecret)
			case "secret_value":
				t.Setenv(c.SecretEnv, base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("y", 32))))
			case "timing":
				c.MaxStaleSeconds++
			case "disabled":
				c.Enabled = false
			case "invalid":
				c.Endpoint = "http://127.0.0.1:1" + relay.SnapshotPath
			}
			raw, _ := yaml.Marshal(c)
			req := registerRaw(string(raw))
			if name == "schema" {
				req = encoded(map[string]any{"schema_version": 0, "config_yaml": raw})
			}
			if name == "malformed" {
				req = []byte(`{"config_yaml":`)
			}
			a.handle(pluginabi.MethodPluginReconfigure, req)
			if a.current.Load() == old || old.Status().State != "stopped" || old.Ready() || !old.Gate() {
				t.Fatal("changed/invalid authority kept old engine live")
			}
			if name == "disabled" || name == "invalid" || name == "schema" || name == "malformed" {
				if a.current.Load() != nil {
					t.Fatal("invalid/disabled settings still published an engine")
				}
			}
		})
	}
}
