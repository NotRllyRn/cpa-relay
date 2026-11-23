# Readiness and status

**Known limit:** a pool whose every runtime record retains raw `error` stays unready, even after transient cooldowns expire. Stock CPA v8.0.63's plugin API does not expose enough scheduler state to distinguish that condition from rejected access tokens. An elapsed retry timestamp is not admission evidence. Recovery needs a genuinely active runtime record, normally after a changed credential is synchronized; repeated polling of unchanged credentials does not reset errors. Do not clear private state to bypass this check.

## Admission

Receiver readiness requires a fresh authenticated snapshot, intact installed credentials, exact enabled runtime/model identities for **every** active managed path, and at least one raw `status: active`, `unavailable: false` runtime candidate. Disabled flags or disabled status, identity mismatches, duplicate IDs/indexes and missing models keep the entire gate closed. Historical errors on other records do not veto an independently active candidate. Those error records are never counted available; the relay does not reset their errors or retry deadlines.

This is conservative pool admission, not a provider inference test. CPA still enforces rejected tokens, model-specific cooldowns and quotas when scheduling requests. A qualified runtime candidate does not prove every requested model or available quota. The pinned API exposes raw auth status; its management auth-files view derives effective availability separately and may display different values.

The original snapshot age, every active credential's expiry minus skew, replay protection, integrity auditing and withdrawal requirements still apply to the entire inventory. One-second audits renew model observations for at most three seconds from each check's **start**. A slow or blocked callback cannot extend that lease. No observation timeout was increased.

## Authenticated JSON

`GET /v0/management/cpa-relay/status` uses CPA management authentication. It returns fixed codes, counts and UTC timestamps. It never returns credential/account/model identifiers, paths, URLs, tokens or raw error messages. Public `/ready` remains only `{"ready":true}` with HTTP 200, otherwise `{"ready":false}` with HTTP 503.

| Field | Meaning |
| --- | --- |
| `role`, `ready`, `state` | Configured role, current admission result, coarse lifecycle state. |
| `reason` | Current admission reason; see codes below. |
| `last_attempt` | Latest operation result. A failed fetch can coexist with readiness until the original deadline. |
| `accounts` | Receiver: same as `synchronized_accounts`. Exporter: active records in its last emitted snapshot. |
| `synchronized_accounts` | Receiver active snapshot records successfully installed and audited; remains nonzero while models are pending, and becomes zero when reconciliation is invalidated or records are withdrawn. Exporter: zero. |
| `available_accounts` | Receiver raw active/available candidates from a complete successful runtime/model observation. Zero when admission is closed, the observation expires, or any required identity/model check fails. Exporter: zero. |
| `generated_at`, `snapshot_age_seconds` | Original snapshot generation time and its current age, clamped to zero for allowed future clock tolerance. Cached startup data can expose these fields but never authorizes startup. |
| `fresh_until` | Earlier of original generation plus maximum stale age and every active expiry minus skew. Uses the same boundary as admission. |
| `model_check_started_at` | Latest check start, published before native callbacks. |
| `model_check_completed_at`, `model_check_duration_ms` | Last completed check's finish and total duration, including both host callbacks. A newer start than completion means a check is in progress. |
| `model_check_valid_until` | Last successful observation's lease deadline. Retained after later failures; compare with current readiness/reason, not by itself. |
| `last_sync_at` | Last successfully installed/audited live snapshot on receivers; last emitted snapshot on exporters. Fetch failures/replays do not advance it. |
| `last_error`, `last_error_at` | Last failed-operation code and time, retained after recovery. Separate from the current admission reason. |

Unknown/unobserved optional fields are omitted. Polling status is read-only and never waits for disk, reconciliation or callback locks. Diagnostics describe the latest published observation; they are not a scheduler transaction. A stopped/unconfigured/invalid-settings response keeps the same basic JSON shape with zero counts and no invented observations.

Compatibility: older versions returned `accounts: 0` whenever the receiver was unready, even after a complete successful synchronization. It now reports synchronized membership independently of runtime availability; use `ready` and `available_accounts` for admission.

| Reason | Meaning |
| --- | --- |
| `ready`, `degraded` | All required identities/models match and all/some records are qualified candidates. Both can be ready. |
| `no_available_accounts` | No raw active/available candidate, or empty inventory. Includes the all-error limitation above. |
| `runtime_mismatch`, `runtime_disabled`, `models_pending` | Identity/model publication or enabled-state requirement failed. |
| `models_failed`, `model_check_slow`, `model_check_expired` | Host observation failed, took at least three seconds, or its lease elapsed. |
| `snapshot_stale`, `credential_expired` | Original freshness or token deadline elapsed. |
| `starting`, `synchronizing`, `stopping`, `stopped`, `exporter` | Lifecycle/role state. |
| `fetch_failed`, `replay_rejected`, `apply_failed`, `integrity_failed`, `cleanup_failed`, `internal_error` | Fixed safe operation/fault codes. `last_error` can also be `export_failed`. |

Invalid settings/storage and disabled/unconfigured instances report their existing fixed lifecycle state as `reason`. Consumers should display a safe fallback for unknown codes.

## Reproduce the upstream distinction

```sh
sh tests/stock_readiness_repro.sh
```

This optional check creates an isolated temporary Go module, downloads the pinned CPA dependencies, and runs its real manager/selector with synthetic credentials. It moves recorded retry deadlines through the real manager's `Update` API to simulate elapsed time. It verifies retained raw errors, clone-only listing, transient 429/502 eligibility, a later rejected 401 with the same readiness tuple, a mixed healthy pool, and replacement-token recovery. It makes no network inference request and requires no running CPA or Docker. The relay module's dependencies are unchanged.

That reproduction establishes the upstream behavior, not the precise cause of a particular deployment's readiness failure. Production confirmation needs a measured observation through the actual plugin ABI; management's effective-status view alone is insufficient.
