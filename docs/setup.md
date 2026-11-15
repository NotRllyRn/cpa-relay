# Setup

Read [security requirements](security.md) before enabling either role. Examples below are fragments to merge into separate CPA v8.0.63 configurations, not complete server configurations. Paths, hostnames and account IDs are fictional.

## Build and install

Requirements: Linux amd64, C compiler, Make, Go toolchain download access. `make` pins Go 1.26.10; dependencies are pinned in `go.mod`/`go.sum`, with no local replacements. Python 3 and OpenSSL are needed for the ABI test.

```sh
make check
```

This runs unit tests, race detection, vet, a native `c-shared` build and an HTTPS/native-callback smoke test. Install only `dist/cpa-relay.so` in the existing CPA plugin directory. Keep that exact filename: CPA derives the plugin ID and resource URLs from it. The generated C header is not needed by CPA.

`GOAMD64=v1` and baseline C flags avoid requiring AVX/x86-64-v2. This does **not** make libc portable: build on the oldest compatible libc used by your hosts, or inside the matching deployment image. A glibc build is not a musl build. CPU/libc compatibility and the real CPA binary must be tested before rollout. No other OS/architecture is claimed supported.

Before installation or config changes, back up the existing plugin, CPA config and relay state outside this repository with restricted permissions. This repository does not install or restart anything automatically.

## Prepare both processes

1. Obtain the Codex `account_id` values from the primary's credentials through a secure local/admin workflow. Select accounts explicitly on **both** roles; an empty selection is invalid. Do not use credential filenames, emails or auth indexes as selectors.
2. Generate a dedicated secret locally, for example with Python's `secrets.token_urlsafe(32)`. Put its value in a protected service/container environment on both processes as `CPA_RELAY_BEARER`. Do not put it in YAML, shell history, URLs, browser fields or this repository. The accepted encoding is unpadded base64url representing 32–128 bytes. Randomness cannot be measured by the plugin; the operator must generate it securely.
3. Start CPA with that environment already set. Native Go plugins read the process startup environment; changing an external environment file does not update a running process. Rotation requires coordinated process restarts. A secret is shared only by the intended primary/receiver pair.
4. Provision explicit absolute state directories, owned by CPA's Unix user, mode `0700`. They must not contain symlinked path components. Ancestors must be owned by root or the CPA user and not be group/world writable (root-owned sticky directories such as `/tmp` are allowed). Receiver auth-dir must already exist, be owned by the same Unix user and not be group/world writable. The two directories may not contain each other. Do not put exporter state inside its CPA auth-dir either.
5. Require a valid HTTPS certificate on the primary's existing listener. System trust roots are used; a private CA must be installed in the receiver's trust store **before startup**. No insecure-TLS switch, HTTP endpoint, ambient HTTP proxy, or redirect is supported.

## Exporter

**Mandatory logging prerequisite:** resource routes are not exempt from CPA request logging. Before enabling this role, set `observability.logs.request-log: false`. For the stock pinned server, also use `server.commercial-mode: true` and restart CPA: that omits its request-logging middleware, including error-only capture. This has a host-wide observability cost. Disable equivalent request/response body and authorization capture in every proxy, gateway, APM and log forwarder. See [why both settings matter](security.md#logging-is-a-deployment-requirement).

```yaml
config-version: 8
server:
  commercial-mode: true
  tls:
    enable: true
    cert: /etc/example-cpa/tls/cert.pem
    key: /etc/example-cpa/tls/key.pem
observability:
  logs:
    request-log: false
plugins:
  enabled: true
  dir: /opt/example-cpa/plugins
  configs:
    cpa-relay:
      enabled: true
      priority: 100
      role: exporter
      secret_env: CPA_RELAY_BEARER
      accounts: [acct-example-a]
      state_dir: /var/lib/example-relay/exporter
```

The authenticated endpoint is `GET /v0/resource/plugins/cpa-relay/snapshot`, on the existing primary HTTPS listener. Its only authentication is one `Authorization: Bearer <dedicated relay secret>` header. Do not use a CPA management key. Restrict network access to intended receivers as well.

The exporter calls only `host.auth.list` and `host.auth.get`. It never saves, refreshes or deletes credentials. It reads Codex physical sources and emits only selected account IDs. Unknown source fields are discarded. Duplicate-free JSON structure and an unambiguous `account_id` are checked first; clearly unselected sources are then skipped before interpreting their token/optional fields. Ambiguous identity, read errors, duplicate selected IDs or malformed selected credentials make the export fail as a whole. Expired selected accounts are omitted from a successful full snapshot; disabling or deselecting one propagates removal. A successful empty snapshot is valid, but cannot make a receiver ready.

## Receiver

Use the **direct primary endpoint**, never the public failover hostname or the receiver itself. Reusing a failover hostname can loop the relay or change its trust authority. Do not put a broad primary management key on the receiver.

```yaml
config-version: 8
oauth:
  auth-dir: /var/lib/example-cpa/auth
plugins:
  enabled: true
  dir: /opt/example-cpa/plugins
  configs:
    cpa-relay:
      enabled: true
      priority: 100
      role: receiver
      endpoint: https://primary.example.invalid/v0/resource/plugins/cpa-relay/snapshot
      secret_env: CPA_RELAY_BEARER
      accounts: [acct-example-a]
      auth_dir: /var/lib/example-cpa/auth
      state_dir: /var/lib/example-relay/receiver
      receiver_id: secondary
      poll_seconds: 15
      max_stale_seconds: 3600
      expiry_skew_seconds: 60
```

`auth_dir` **must exactly match the resolved absolute `oauth.auth-dir` used by CPA**. The host does not expose that configuration to this plugin. Disabled staging saves check the returned host path before enabling credentials; a mismatch keeps readiness closed. Fix the setting rather than bypassing that check.

Reserve `cpa-relay-<receiver_id>-<sha256(account_id)>.json` for this receiver. Never log in, add refresh material, enable SIWC, or manually replace normal credentials in this namespace. Existing files outside the durable ownership inventory are refused, not adopted or removed. Keep ordinary credentials in other files. Do not share this namespace across processes. A hidden namespace lock file also lives in auth-dir.

### Settings

Settings are described by CPA `ConfigFields` and can be changed through its normal plugin settings UI. Invalid/missing settings retain the installed request gate in an unready state; they do not start a worker. Host-disabled, unloaded or fused plugins are different: CPA skips their gate, so external readiness enforcement is mandatory.

| Field | Requirement/default |
| --- | --- |
| `role` | Required: `exporter` or `receiver` |
| `secret_env` | Required environment variable **name**, never its value |
| `accounts` | Required unique array, 1–128 account IDs; letters/digits/underscore/hyphen, first character alphanumeric, maximum 128 characters each |
| `state_dir` | Required absolute private directory, not symlinked |
| `endpoint` | Receiver only; exact HTTPS snapshot path, no user info, query or fragment |
| `auth_dir` | Receiver only; absolute, exact CPA auth-dir |
| `receiver_id` | Receiver only; stable 1–32 lowercase alphanumeric/hyphen characters, first alphanumeric |
| `poll_seconds` | 15; range 1–300 |
| `max_stale_seconds` | 3600; at least twice poll interval, at most 86400 |
| `expiry_skew_seconds` | 60; range 5–600 |

CPA also supplies its standard `enabled` and `priority` fields. Other settings are rejected. Source endpoint, role, auth-dir and receiver namespace are bound to the state file. To change that authority/namespace, stop the old role and verify cleanup, keep its private state for rollback, and provision a **new empty state directory**. Account selection and timing settings can change in place while preserving the replay watermark. Do not delete state to work around an error.

## Status, control and ingress

- Menu resource: `GET /v0/resource/plugins/cpa-relay/status` shows coarse readiness only. Reload to update; there is no secret/token input in this page.
- Public probe: `GET /v0/resource/plugins/cpa-relay/ready` returns only `{"ready":true}` with HTTP 200, otherwise `{"ready":false}` with HTTP 503. No account IDs, endpoints or secrets are returned.
- Local authenticated CPA management route: `GET /v0/management/cpa-relay/status` returns role, coarse state, count, original generation time and last-attempt code, never tokens or selectors.
- Local authenticated management control: `POST /v0/management/cpa-relay/poll` coalesces a receiver poll request (202). It is not a successful-sync acknowledgement. Exporter or terminated-worker use returns 409; a fully drained/unconfigured application returns 503.
- Local authenticated lifecycle control: `POST /v0/management/cpa-relay/drain` closes admission, cancels/joins workers and synchronously disables/removes managed credentials. **Require HTTP 200 with `{"state":"drained"}` before disabling/unloading the plugin.** A 503 means cleanup is incomplete; keep ingress denied and retry. This is not a public resource. These management routes use existing CPA admin authentication; the receiver worker never uses that key.

**Configure the failover ingress to deny receiver traffic unless the receiver probe returns HTTP 200. Missing routes, 404, 5xx, timeouts, TLS errors and unavailable health state must all deny traffic. Do not cache a successful probe indefinitely. Restrict direct listener access so clients cannot bypass ingress.** Active health polling has a detection interval; choose it deliberately. For stronger admission, use a per-request readiness decision and deny on any error. Verify the failure behavior with the plugin disabled and unloaded, not just with an expired snapshot.

The receiver starts closed on **every start/reconfigure**. It first synchronously disables/removes its old managed records, then requires a strictly newer live snapshot. Recoverable startup withdrawal errors retry with exponential backoff from one to fifteen seconds, with admission closed. Integrity quarantine is not retried automatically, and poll requests are rejected if the worker has terminated. A fresh cache is never sufficient to authorize startup. Restarting during a primary outage therefore blocks service even if the cache has unexpired access tokens. This is intentional.

During normal operation a failed fetch or rejected replay retains the previous accepted state **only until its original deadline**. A valid newer snapshot is a full replacement; it may remove selected accounts. The deadline is the earliest of generation plus max-stale and each active token's explicit/JWT expiry minus skew. Admission also requires every active managed path to match an active, enabled, available Codex runtime record with at least one model registered through `host.auth.models`. Save acknowledgement or disk presence alone is insufficient. A one-second worker rechecks registration; observations expire after three seconds even if a callback stalls. Missing/error model observations keep the gate closed and retry without rewriting otherwise valid credentials. This is registration readiness, **not** proof of upstream inference, quota or every requested model. The public probe, authenticated status and request interceptor do not wait for disk or host callbacks. Background cleanup runs independently of slow HTTP fetches. No setting extends a cached generation's age.

## Drain before disable, unload, updates or rollback

1. Deny receiver ingress and serialize configuration changes with this operation.
2. While the plugin is still enabled and its host callbacks are available, POST to the authenticated `/v0/management/cpa-relay/drain` route. Require HTTP 200 and `state: drained`; also verify readiness is non-200 and managed runtime records/files are disabled/removed. Do not treat a timeout or 503 as success.
3. Only after that handshake, disable/unload the plugin, replace it, or stop CPA. Drain does not disable the host plugin setting: its installed gate stays closed until reconfigured.
4. For rollback, restore the backed-up plugin/config/private state together with original ownership/permissions, restart, and require a newer live snapshot before admitting traffic.

A failed drain/quiesce retains its engine, ownership inventory and store locks; retrying drain performs the outstanding disable callbacks. Reconfigure cannot discard that obligation. **Stock CPA v8.0.63 closes callback availability before native shutdown on disable/unload**, so shutdown alone cannot guarantee acknowledged cleanup. Abrupt disable/fuse/crash must be contained by external ingress; old files or disabled tombstones may remain. A resident failed-cleanup library may retain ownership locks until the CPA process exits, so recovery can require a controlled full process restart, not merely re-enabling the plugin. Keep ingress denied, preserve private state, and inspect only the reserved namespace. Never remove unrelated auth files.
