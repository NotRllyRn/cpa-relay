package main

import (
	"errors"
	"testing"

	"github.com/NotRllyRn/cpa-relay/internal/relay"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestUnchangedReconfigurePreservesExplicitDrain(t *testing.T) {
	for _, resume := range []string{"register", "changed config", "disable then enable"} {
		t.Run(resume, func(t *testing.T) {
			a := &application{host: func(string, any, any) error { return errors.New("host unavailable") }}
			defer a.stop()
			config := appConfig(t, "receiver")
			a.handle(pluginabi.MethodPluginRegister, registerRaw(config))
			old := a.current.Load()
			var response pluginapi.ManagementResponse
			decodeResult(t, invoke(a, "POST", "/v0/management/cpa-relay/drain", nil), &response)
			if response.StatusCode != 200 || old == nil || old.Status().State != "stopped" {
				t.Fatal("drain failed")
			}
			for i := 0; i < 3; i++ {
				a.handle(pluginabi.MethodPluginReconfigure, registerRaw(config))
				if a.engine != nil || a.current.Load() != nil || !a.drained || a.state.Load() != "stopped" {
					t.Fatal("same-config global reload undid explicit drain")
				}
			}
			switch resume {
			case "register":
				a.handle(pluginabi.MethodPluginRegister, registerRaw(config))
			case "changed config":
				a.handle(pluginabi.MethodPluginReconfigure, registerRaw(config+"priority: 1\n"))
			case "disable then enable":
				a.handle(pluginabi.MethodPluginReconfigure, registerRaw("enabled: false\n"+config[len("enabled: true\n"):]))
				a.handle(pluginabi.MethodPluginReconfigure, registerRaw(config))
			}
			if a.current.Load() == nil || a.current.Load() == old || a.drained || a.current.Load().Ready() || !a.current.Load().Gate() {
				t.Fatal("deliberate resume did not create a fresh closed receiver")
			}
			var probe pluginapi.ManagementResponse
			decodeResult(t, invoke(a, "GET", relay.ReadyPath, nil), &probe)
			if probe.StatusCode != 503 {
				t.Fatal("cold receiver authorized without live snapshot")
			}
		})
	}
}
