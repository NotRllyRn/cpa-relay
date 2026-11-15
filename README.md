# CPA Relay

A stock CPA v8.0.63 plugin that automatically discovers and relays **all physical Codex access tokens only**, including new logins on each sync. Choose exporter or receiver in plugin settings. It uses CPA's existing HTTPS listener, not another port or a CPA fork.

**First testable release, not production-validated.** Disable exporter request/body capture and put the receiver behind fail-closed readiness checks with no direct bypass. The plugin alone cannot guarantee fail-closed routing.

```sh
make check
```

Build target: Linux amd64, baseline CPU; match the deployment libc.

- [Setup, settings and required v1 migration](docs/setup.md)
- [Security and limitations](docs/security.md)
- [Checks and integration test plan](docs/testing.md)
