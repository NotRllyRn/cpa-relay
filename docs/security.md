# Security model and limits

This is an access-token distribution tool, not an OAuth login/refresh service or a security boundary against a compromised CPA process. Only use it for accounts you are authorized to share. A relayed access token remains a bearer credential until expiry. Revocation/removal cannot claw back a token already copied elsewhere.

## Logging is a deployment requirement

**Do not enable the exporter with request/response body capture enabled.** CPA v8.0.63 excludes `/v0/management` from global request logging, but **does not exclude `/v0/resource/plugins/...`**. `Cache-Control: no-store` does not stop server logging.

Required on the exporter:

```yaml
server:
  commercial-mode: true
observability:
  logs:
    request-log: false
```

Restart after changing middleware settings. In the pinned stock source, `internal/api/server.go` installs `RequestLoggingMiddleware` only when commercial mode is false. Request-log false alone still permits error-only logging; commercial mode avoids that middleware entirely. This disables host-wide request-log observability. Also prohibit body/header capture by reverse proxies, TLS terminators, APM, debug traces, packet decryptors and log forwarding. Ordinary access logs must not contain authorization values or sensitive query data. Use no secret-bearing query strings.

The stock plugin API exposes no authoritative logging configuration check, so the plugin cannot enforce or attest to these settings. Test logging with generated canaries in an isolated environment before using a real token. If you cannot control the complete capture path, do not deploy this exporter.

## Trust and protocol

- Export authentication uses exactly one dedicated high-entropy bearer header and constant-time hash comparison. Settings contain only its environment variable name. Both roles reject weakly sized/invalid encodings, but cannot prove randomness. Do not share an admin key with the relay.
- Receiver transport requires HTTPS with normal chain/hostname verification and TLS 1.2 or later. It does not honor ambient proxy variables, follow redirects, accept compressed response bodies, or provide a skip-verification option. The primary endpoint is an explicit trust decision; DNS and CA trust must be secured independently.
- Protocol v1 is a bounded full snapshot: version, integer generation, UTC/RFC3339 generation time, and account array. Generation is the exporter's Unix nanosecond timestamp. Timestamp and generation must agree. Timestamps more than five seconds ahead or at/past max age are rejected. Keep clocks synchronized. Future/clock rollback errors must not be bypassed by erasing watermarks.
- Both roles explicitly select accounts. A source record is projected into only `type`, `access_token`, `account_id`, `expired`, optional `email`, optional `plan_type`, and `disabled`. Only `type: codex` is supported. `refresh_token`, `id_token`, `last_refresh`, nested SIWC, proxy settings and arbitrary metadata are never relayed.
- Receiver JSON parsing rejects unknown fields, duplicate keys/IDs, deep nesting, oversized responses, unselected/unsafe IDs and invalid tokens. Limit: 128 accounts, 2 MiB HTTP body, 16 KiB token, 16 KiB response headers. Requests have a 10-second overall timeout, with shorter dial/TLS/header limits. One fetch runs at a time; manual polls are coalesced.
- Both explicit expiry and JWT `exp` are required. The earlier wins, minus configured skew. The optional JWT account-ID claim must agree when present. JWT payload parsing only **shortens validity**; it is not signature validation or proof of account ownership. Authenticity depends on the chosen primary and verified TLS. Opaque access tokens are deliberately unsupported.
- A generation must be strictly greater than the persisted receiver watermark. An identical retry is rejected, including after restart. Every successful exporter request mints a newer timestamp and durably advances its own watermark before responding. Rollback of an external backup can roll back that protection; this is not a hardware-backed anti-rollback mechanism.

## Storage and reconciliation

`state.json` is an atomic, fsynced, mode-0600 private cache plus replay watermark and write-ahead ownership inventory. It contains access tokens; back it up and destroy it as a secret. Snapshots retain their original generation times on disk. Cache corruption, binding mismatch, wrong permissions, symlinked paths and competing state/namespace locks fail closed.

The receiver uses computed hashed names, never a source-supplied filename. It refuses pre-existing files not in its durable inventory. It changes only its reserved namespace and does not delete ordinary CPA auth files. Different source authority/role/namespace/path settings require a new state directory after clean shutdown. Account allowlist changes retain the watermark.

Reconciliation is deliberately conservative:

1. Close request admission before persisting or applying a new snapshot.
2. Persist the accepted generation and union ownership inventory before new files can exist.
3. Reject unexpected fields/refresh/SIWC material in owned files. Never adopt ordinary login credentials or merge their metadata into a relay snapshot.
4. For added/changed/removed records, stage sanitized disabled tombstones atomically; call `host.auth.save` and require its synchronous runtime acknowledgement. Verify the returned host path and resulting file contents. Unchanged, previously acknowledged records are audited without rewriting them.
5. Only then unlink removed/disabled owned files. Apply active replacements through sanitized staging plus acknowledged host saves, not watcher-only writes.
6. Verify all resulting owned files and persist the final inventory. Require `host.auth.models` registration plus an active, enabled, available manager record for **every** active managed path before opening admission. `host.auth.save` only acknowledges manager register/update; it does not register models. Missing model publication keeps admission closed and retries without rewriting credentials. A failed write, host callback or integrity check never makes the receiver ready. Best-effort synchronous disabling contains partial updates.

Host saves are **not a cross-file transaction**: stock CPA writes a physical file and then updates runtime state. A post-save disk audit detects contamination and keeps admission closed. A separate one-second worker audits accepted files, rechecks per-account runtime/model registration, and withdraws stale/expired state even while HTTP fetches are slow. Model observations have a three-second lease; a stalled callback cannot hold admission open beyond that lease. Ready/gate paths independently check that lease and the original conservative deadline without waiting for worker locks. Registration is necessary routing evidence, not a successful provider request, scheduler-wide transaction, model-specific quota check or promise of uninterrupted availability; asynchronous host changes have an observation window. Host callbacks can still delay physical cleanup; ingress must deny on missing/failed readiness, not assume deletion was instantaneous.

Keep the namespace private to this plugin. Another same-user/admin writer, a queued watcher update, or an already-running request can race CPA persistence after a check. Periodic audits detect disk changes, but this is not an atomic barrier against every concurrent CPA watcher/runtime action or a compromised local administrator. Do not put refresh credentials in the namespace; CPA persistence may merge refresh/SIWC material from disk. No refresh flow is implemented. A dedicated receiver instance/auth-dir with no unrelated credentials is the simplest deployment to reason about.

At every cold start/reconfigure, old managed records must be synchronously disabled and removed before fetching. Recoverable cleanup errors retry with bounded exponential backoff (one to fifteen seconds); integrity quarantine terminates the worker and rejects polls. **Cached state never authorizes startup.** Primary unavailability during restart therefore means unready, even if cached tokens are unexpired. Live fetch failures during an existing session retain the old state only until its original freshness/expiry boundary. A valid empty or all-disabled snapshot removes managed credentials and remains unready.

## Lifecycle and failure boundary

The adapter uses stock C ABI v1 and the SDK/schema from pinned CPA v8.0.63 (schema 10). Native host context is instance-scoped; `host.auth.list/get/save/models` do not require a request-scoped callback ID. The receiver retains no temporary callback ID. Reconfigure, drain, quiesce and shutdown cancel HTTP/retry work and **join both workers**. Only successful withdrawal releases storage ownership. Failed withdrawal retains its sanitized error, inventory, engine and locks; repeated Stop/drain retries real disable callbacks, and quiesce reports failure. Only one serialized reconciliation owns mutable state. Public readiness, authenticated status and interception do not wait for lifecycle/host callback locks.

**Drain before stock disable/unload.** Authenticated `POST /v0/management/cpa-relay/drain` is the cleanup handshake while callbacks are still available. Require HTTP 200 with `state: drained` and keep ingress denied. Stock v8.0.63 marks the callback instance closed before invoking native shutdown, so shutdown after host disable/unload cannot acknowledge runtime withdrawal. A failed-cleanup resident library can retain namespace locks until CPA exits; full process restart may be needed for recovery. Abrupt disable, fuse, crash and power loss remain external-ingress failure cases, not successful drains. See the [operator sequence](setup.md#drain-before-disable-unload-updates-or-rollback).

The native ABI provides no cancellation hook for an in-progress synchronous host callback; the pinned `host.auth.models` implementation ignores its context. Retry waits/HTTP are cancellable, model observations expire and status stays responsive, but joining a callback can still wait on CPA locks. Spawning a detached callback to claim bounded shutdown would be unsafe. Keep storage healthy, allow lifecycle completion, and treat stalled or missing readiness as unready.

Go panics at RPC boundaries and workers are contained and return generic failure state; raw errors, URLs, credentials and identifiers are not emitted by this plugin. Native memory faults can still kill **the entire CPA process**. CPA can skip disabled, unloaded, fused or failed interceptors, which is fail-open without an external gate. In-flight requests are not revoked by changing readiness, and established streams/WebSockets are not forcibly disconnected. This release validates normal/stream interception through mocks; full CPA protocol coverage is not certified.

**External ingress must deny missing readiness, non-200 responses, timeouts and errors, and prevent all direct bypass.** Health polling has a detection window; the plugin cannot promise a global fail-closed invariant on its own. The primary/exporter readiness endpoint only reports that its configured role is running; it is not proof that selected accounts exist. Route failover using the receiver's readiness, never the exporter's.
