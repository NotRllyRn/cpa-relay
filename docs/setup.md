# Setup

Read [security requirements](security.md) before enabling either role. These are fragments for separate stock CPA v8.0.63 configurations, not complete server configurations. All paths and hostnames are fictional. Existing installations must follow the [v1 migration](#migrate-from-v1-explicit-selection) before replacing the binary.

## Build and install

Requirements: Linux amd64, C compiler, Make, Go toolchain download access. `make` pins Go 1.26.10; dependencies are pinned in `go.mod`/`go.sum`. Python 3 and OpenSSL are needed for the ABI test.

```sh
make check
make stock-smoke # optional isolated Docker integration; synthetic credentials only
```

Install only `dist/cpa-relay.so` in the existing CPA plugin directory. Keep that exact filename: CPA derives its plugin ID and resource URLs from it. The generated C header is not needed. No command in this repository installs or restarts production services.

Baseline `GOAMD64=v1` avoids AVX/x86-64-v2 requirements, but does not make libc portable. Build against the deployment libc (glibc and musl builds are not interchangeable). Test CPU/libc compatibility and the real CPA binary before rollout. No other OS/architecture is claimed supported.

Before installation or config changes, back up plugin, CPA config and private relay state outside the repository with restricted permissions and original ownership/modes. Record exact restore commands for that deployment.

## Prepare both processes

1. Authorize distribution of **all physical Codex credentials** on this primary, including credentials added later. There is no per-account or per-file selector. A workspace `account_id` is not a login identity; multiple logins sharing it are supported. Use a separate primary instance if some Codex credentials must not be shared.
2. Generate a dedicated secret locally, for example with Python's `secrets.token_urlsafe(32)`. Put it in the protected process startup environment as `CPA_RELAY_BEARER` on both roles. Never put the value in YAML, shell history, URLs, browser fields or the repository. The accepted encoding is unpadded base64url representing 32–128 bytes; the operator must generate it securely.
3. Start CPA with that environment already set. Native Go plugins snapshot the startup environment. External environment-file changes do not update a running process; rotate with coordinated process restarts. Share the secret only with intended receivers.
4. Provision explicit absolute state directories owned by CPA's Unix user, mode `0700`, with no symlinked components. Ancestors must be owned by root or that user and not group/world writable (root-owned sticky `/tmp` is allowed). Receiver auth-dir must already exist, be owned by the same user and not group/world writable. Auth-dir and state-dir must not contain each other. Do not put exporter state inside its auth-dir either.
5. Require valid primary HTTPS and install any private CA into the receiver trust store **before startup**. There is no insecure TLS, HTTP, proxy or redirect option.

## Exporter

**Mandatory logging prerequisite:** set `observability.logs.request-log: false` and `server.commercial-mode: true`, then restart CPA. The latter omits stock request-logging middleware, including error-only capture, at a host-wide observability cost. Disable body/authorization capture in every proxy, APM and log forwarder too. See [logging requirements](security.md#logging-is-a-deployment-requirement).

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
      state_dir: /var/lib/example-relay/exporter-v2
```

`GET /v0/resource/plugins/cpa-relay/snapshot` uses the existing primary HTTPS listener. It requires exactly one `Authorization: Bearer <dedicated relay secret>` header, not a CPA management key. Restrict network access to intended receivers.

Every sync lists physical Codex records, reads their JSON using `host.auth.get`, then lists again. Runtime-only and known other-provider records are not exported or read. Duplicate paths/indexes, inconsistent list/get identities, malformed active credentials, failed callbacks or a changing inventory fail the **whole** export with 503. Unknown-provider physical entries also fail closed because they may be malformed Codex records. Nothing is truncated: limits are 128 discovered physical Codex sources (including disabled/expired ones), 4096 total host entries and a bounded 2 MiB response. Over a limit, repair/reduce the inventory; do not expect a partial snapshot.

Only an access-token allowlist is projected: `credential_id`, `type`, `account_id`, `access_token`, `expired`, `disabled`, optional `email` and `plan_type`. No refresh/ID token, last-refresh, SIWC, proxy settings or arbitrary metadata is copied. Explicitly disabled Codex entries are omitted even with unusable token fields, provided their JSON and Codex type are valid. Well-formed expired tokens are omitted. Malformed active token/identity/expiry fields fail the whole export, rather than silently withdrawing an account. A valid empty/all-disabled inventory is authoritative, removes receiver credentials and cannot make it ready.

### Stable source identity and safe removal

Protocol v2 identifies a credential by lowercase hex `SHA256("cpa-relay/codex-source/v2" || NUL || host physical Path)`; `NUL` is one zero byte. The exact, absolute, clean host-reported path is hashed without trimming/normalizing it. Stock CPA trims display `Name` and resolves Get by auth index; the adapter validates index/name/path responses and rejects aliases/duplicates. Basename whitespace inside a path remains distinct when the host can represent it consistently. The ID does not depend on access/refresh tokens, email, workspace or the runtime auth index. Tokens refreshed at the same path replace the same relay record; unchanged projections do not rewrite receiver files. **Rename/move is delete-and-add**, including changing the mounted auth-dir path. Two physical copies are two identities even if their contents match. No filename/path is sent on the wire or in public status. Hashes are pseudonymous identifiers, not protection against guessed paths.

CPA can omit a malformed file entirely from its runtime list. The exporter therefore durably remembers paths from its last successful inventory in **private** state. Before treating a missing entry as deleted, it uses read-only filesystem metadata (`stat`/`lstat`, never direct credential reads) to prove the old file is absent and its parent still accessible. A still-present/unknown/inaccessible omitted source fails export, including across restarts. Repair it or physically delete it; do not erase state to bypass the guard. Conversion to another provider at the same path also requires a confirmed deletion first. This guard concerns previously discovered sources: an unlisted new malformed file has never been exported. Discovery still trusts CPA's host metadata, not an independent directory crawler or inode pinning against a local admin. Concurrent host/file changes are not a filesystem transaction; subsequent syncs converge.

## Receiver

Use the **direct primary endpoint**, never the public failover hostname or the receiver itself. That would risk loops or change trust authority. No primary management key belongs on the receiver.

```yaml
config-version: 8
oauth:
  auth-dir: /var/lib/example-cpa/auth
plugins:
  enabled: true
  dir: /opt/example-cpa/plugins
  configs:
    cpa-relay:
      enabled: false # enable through management only after CPA's initial scan
      priority: 100
      role: receiver
      endpoint: https://primary.example.invalid/v0/resource/plugins/cpa-relay/snapshot
      secret_env: CPA_RELAY_BEARER
      auth_dir: /var/lib/example-cpa/auth
      state_dir: /var/lib/example-relay/receiver-v2
      receiver_id: secondary
      poll_seconds: 15
      max_stale_seconds: 3600
      expiry_skew_seconds: 60
```

`auth_dir` must exactly match CPA's resolved absolute `oauth.auth-dir`; disabled staging verifies the host's save path before enabling credentials. Reserve `cpa-relay-<receiver_id>-<sha256(credential_id)>.json`. Never log in, add renewal/SIWC material or manually replace files in this namespace. Existing files outside durable ownership are refused, not adopted/deleted. Keep unrelated credentials elsewhere; do not share the namespace across processes. A hidden auth-dir namespace lock is also used.

### Receiver process startup

Stock CPA v8.0.63 can race its initial auth-directory scan against plugin saves/model registration. This host race is **not fixed** by the relay. Keep receiver ingress denied throughout startup; a disabled plugin has no interception gate.

1. Start the receiver CPA process with `plugins.configs.cpa-relay.enabled: false` (global `plugins.enabled` stays true), as above. Before planned restarts, first successfully drain the enabled receiver, then stage this disabled startup setting; never disable an undrained live receiver to follow this sequence.
2. Wait for CPA's initial auth-directory scan to finish and its authenticated management API to become available. Confirm scan completion in local startup diagnostics; a reachable API or fixed sleep alone is not proof.
3. Using local CPA management authentication, send `PATCH /v0/management/plugins/cpa-relay/enabled` with JSON `{"enabled":true}`. This is not authenticated with the relay export bearer. Require a newer live snapshot, the expected credential count, registered models for every active record and HTTP 200 readiness before admitting traffic. Management enable may persist `enabled: true`; stage the disabled startup setting again after a successful drain before the next process start.

### Settings

CPA `ConfigFields` describes the settings UI. Invalid settings retain the installed gate unready with no worker. Host-disabled/unloaded/fused plugins are different: CPA skips their gate, so external ingress checks are mandatory.

| Field | Requirement/default |
| --- | --- |
| `role` | Required: `exporter` or `receiver` |
| `secret_env` | Required environment variable **name**, not its value |
| `state_dir` | Required absolute private directory, not symlinked |
| `endpoint` | Receiver only; exact HTTPS snapshot path, no user info/query/fragment |
| `auth_dir` | Receiver only; exact absolute CPA auth-dir |
| `receiver_id` | Receiver only; stable 1–32 lowercase alphanumeric/hyphen characters, first alphanumeric |
| `poll_seconds` | 15; range 1–300 |
| `max_stale_seconds` | 3600; at least twice poll interval, at most 86400 |
| `expiry_skew_seconds` | 60; range 5–600 |

CPA also supplies standard `enabled`/`priority`. Other settings are rejected. Source endpoint, role, auth-dir and receiver namespace are bound to state. To change them, cleanly drain the old role, preserve its state and use a new empty private state directory. Timing changes retain replay protection. Do not delete state to work around errors.

## Migrate from v1 explicit selection

This is an intentional protocol, state and authorization break, not an in-place auto-upgrade. Protocol/cache v1 and v1 ownership keys are rejected; there is no v1 fallback or adoption. **The old one-file receiver inventory must be drained by the old binary before replacement.** New naming cannot clean up that old ownership safely by inference.

1. Keep the running installation unchanged until the maintenance window and explicit all-Codex authorization. Deny receiver ingress; prevent concurrent config updates. Back up both old binaries/configs/private state and the receiver's owned auth files with original ownership/modes in a restricted directory outside the repo. These backups contain bearer credentials.
2. While the **old receiver binary is still enabled with working callbacks and its original config/state**, call authenticated `POST /v0/management/cpa-relay/drain`. Require HTTP 200 and `state: drained`. Verify readiness is non-200, old inventory `managed` is empty, and every formerly owned file is gone/runtime-disabled. A 503/timeout is **not** success; retain old state/binary and retry. Never just remove the state directory or disable first.
3. Only after verified drain, stop CPA safely and retain a separate post-drain old-state copy for rollback. Back up/stop the exporter too. Replace both binaries together; mixed v1/v2 peers cannot sync. Preserve the old private directories unchanged.
4. Explicitly remove the old `accounts` and `source_files` keys from **both** configs, including empty/null values. Their presence returns `settings_migration_required`; removing them is the operator's authorization to export all current and future Codex credentials. They no longer appear in the UI. Provision **new empty** mode-0700 v2 state directories on both roles. Keep the same auth-dir/receiver ID only after the old namespace is confirmed drained. Do not point the new binary at v1 cache or try editing its version/binding.
5. Start the exporter, then start the receiver **process with its relay plugin disabled** (`plugins.configs.cpa-relay.enabled: false`; global plugins remain enabled). Wait for CPA's initial auth-directory scan to complete, then enable the plugin using authenticated `PATCH /v0/management/plugins/cpa-relay/enabled` with `{"enabled":true}`, following [receiver process startup](#receiver-process-startup). Require a newer authenticated live v2 snapshot, correct expected credential count, receiver readiness and registered models for every active record. Recheck logging and ingress fail-closed behavior. Only then admit traffic. Do not copy real snapshot bodies into logs/reports.
6. Rollback: deny ingress and drain the **new** receiver successfully while its callbacks still work. Stop CPA; restore old binaries/configs and paired **post-drain** old state with original permissions. Restart exporter then receiver using the same [disabled-plugin startup sequence](#receiver-process-startup); retain the restored v1 authority/selection/state settings. After the initial scan, enable through management and require a newer live v1 snapshot, registered models and readiness before admitting traffic. A pre-drain backup has outstanding ownership obligations; never silently discard them. If a drain fails, keep ingress denied and the matching state/binary available for recovery.

## Status, control and ingress

- Menu: `GET /v0/resource/plugins/cpa-relay/status` shows coarse readiness.
- Public probe: `GET /v0/resource/plugins/cpa-relay/ready` returns only `{"ready":true}`/HTTP 200, otherwise false/503; no identifiers or secrets.
- Authenticated local CPA management: `GET /v0/management/cpa-relay/status` gives safe readiness reasons, synchronized/available counts, model-check duration/lease, original freshness and sync/error times; see the [status contract](status.md). `POST .../poll` coalesces a poll (202, not sync acknowledgement); exporter/quarantined/terminated-worker returns 409, drained/unconfigured returns 503.
- Authenticated `POST /v0/management/cpa-relay/drain` closes admission, cancels/joins workers and disables/removes managed records. Require HTTP 200 with `{"state":"drained"}` **before** disable/unload/replacement. A 503 means retain ownership and retry. These controls use existing local admin authentication, never the export bearer.

**Deny receiver traffic unless its probe returns 200. Missing routes, 404/5xx, errors, timeouts and missing health state must deny; prevent direct listener bypass.** Choose the health detection interval deliberately or use per-request checks. Test disabled/unloaded plugins, not just stale tokens. The plugin alone cannot enforce this boundary.

Every receiver cold start, new registration or genuine settings change is closed: withdraw old owned records, then require a strictly newer live snapshot. Recoverable startup cleanup retries from one to fifteen seconds. Integrity quarantine cannot resume fetching/admission automatically. Cached tokens never authorize startup; restart during a primary outage intentionally blocks service.

Stock CPA reconfigures all plugins when another plugin's settings change. If Relay's **validated effective settings and resolved environment secret are unchanged**, `plugin.reconfigure` is a no-op: it preserves the same workers, original generation/deadline, replay watermark and any fault/quarantine/drained state. YAML formatting and explicit default values do not count as settings changes. During a primary outage, an already-ready receiver can therefore use only its **remaining original** bounded availability; reloads never rejuvenate cache or make an unready receiver healthy. Changed/disabled/invalid settings, changed resolved secrets, registration and process restarts still follow the closed lifecycle; invalid updates do not keep the prior configuration serving.

Failed fetch/invalid snapshot/replay retains the previous accepted state **only until its original deadline**; nothing extends it. A newer valid snapshot fully replaces membership. The deadline is the earliest of generation plus max-stale and every active explicit/JWT expiry minus skew. Admission also requires exact enabled runtime identities and registered models for **every** active managed path, plus at least one raw active/available candidate. Historical errors on other records do not veto that candidate; an all-error pool remains closed because the stock ABI cannot safely infer eligibility from elapsed retries. See [readiness semantics and limitations](status.md). Save acknowledgement/disk presence is not enough. A one-second worker audits files/models; model observations expire after three seconds even if callbacks stall. Missing model publication keeps the gate closed and retries without rewriting unchanged credentials. Registration is not proof of inference, quota or every requested model. Ready/status/interception do not wait for disk/callback locks; cleanup is independent of HTTP fetches.

## Drain before disable, unload, updates or rollback

Deny ingress, serialize configuration changes, then call authenticated drain while the plugin is enabled and callbacks work. Require 200/`drained`, non-200 readiness and removed/disabled owned files/runtime before disabling, unloading, replacing or stopping CPA. An identical global reconfigure also preserves the explicit drained latch, even with a healthy primary. To deliberately resume, disable then re-enable through CPA management, start a new registration/process, or apply a genuine validated settings change. Every receiver resume requires a newer live snapshot and runtime/model confirmation; there is no cached resume or extra resume endpoint.

Failed drain/quiesce retains engine, inventory and locks so retries perform real disable callbacks. **Stock CPA v8.0.63 closes callbacks before native shutdown on disable/unload**; shutdown alone cannot guarantee withdrawal. Abrupt disable/fuse/crash can leave files/tombstones and require a controlled full process restart to release resident-library locks. Keep ingress denied, preserve private state and inspect only the reserved namespace; never remove unrelated auth files.
