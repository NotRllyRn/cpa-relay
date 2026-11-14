# Checks and first integration test

## Automated checks

Run on Linux amd64 with Python 3, OpenSSL and a C compiler:

```sh
make check
```

The Makefile selects Go 1.26.10, baseline amd64 and cgo. CI runs the same command on Ubuntu 24.04, then checks formatting and dependency tidiness. A local CI definition is not evidence that a remote CI run has passed.

Coverage includes:

- Fixed-schema projection: no refresh token, ID token, nested metadata or arbitrary source fields can escape.
- Dedicated bearer authentication, duplicate authorization headers, explicit account selection, empty/disabled state and secret-free public/admin status.
- Duplicate/unknown/deep/oversized JSON, unsafe IDs, replay/future/stale timestamps, explicit expiry, conservative JWT expiry/account binding, wrong protocol/provider and malformed HTTP.
- Redirect refusal/no bearer forwarding, untrusted TLS rejection, cancellation and response bounds.
- Durable original cache age and watermark, restart requiring a newer live snapshot, failed fetch preserving fresh credentials, successful full-snapshot removal and expiry withdrawal.
- Ownership collision refusal, symlinks, private paths/cache, locks, partial writes, contamination and concurrent callback persistence changes.
- Synchronous runtime acknowledgements for additions/removals, failed runtime update keeping admission closed, physical deletion only after runtime disable acknowledgement, and unchanged credentials avoiding runtime churn.
- Reconfigure/cancel/join, callback-in-progress shutdown, race detection, lock-independent public readiness/interception and expired-deadline admission.
- `tests/abi_smoke.py` loads the **built shared object** with `ctypes`, supplies actual C ABI host callbacks, uses a temporary trusted HTTPS server and invokes real plugin RPC envelopes. It checks background native-thread saves, sanitization, authentication, failure retention, removal, replay, buffer ownership and lifecycle. All credentials are generated fake JWTs; no provider call is made.

The ABI test is a **mock CPA host**, not the CPA server. Go unit tests are also not proof of real provider or full protocol support. The implementation was developed against the pinned released SDK and source contract. Real CPA watcher integration, a real Codex request, proxy/ingress enforcement, target libc/CPU and installed host logging remain operator integration checks.

An optional parser fuzz pass is:

```sh
GOTOOLCHAIN=go1.26.10 go test ./internal/relay -run '^$' -fuzz FuzzSanitize -fuzztime=30s
```

## Exact isolated CPA integration plan

Use two disposable CPA **v8.0.63** instances, matching the intended CPU/libc and service UID. Do not use production instances or real tokens for leak/failure tests. Keep the primary/receiver ports bound to loopback or an isolated private test network. Save restricted rollback copies of both configurations and state first.

1. **Load and ABI:** build with `make check`, record compiler/libc, install `dist/cpa-relay.so`, and start each stock CPA process. Verify metadata version 0.1.0, role/settings fields, menu and protected routes are registered. Missing/invalid settings must leave the installed gate unready with a 503. Stop if loading fuses or crashes CPA.
2. **Logging prerequisite:** set exporter `observability.logs.request-log: false` and `server.commercial-mode: true`, then restart. Disable capture in every proxy/APM. Put distinct generated canaries in fake access/refresh/ID tokens and nested SIWC metadata. Exercise authorized success, unauthorized export, upstream failure and disconnected clients. Search all host/proxy/forwarded logs, traces and temporary captures for those canaries and the relay bearer using a local script that prints only pass/fail (never paste tokens into commands or reports). No token may appear. Verify settings contain only the environment variable name. Do not proceed if capture cannot be excluded.
3. **TLS/auth:** configure the direct primary HTTPS endpoint with a trusted certificate. Missing/wrong/duplicate bearer headers must not export. Bad hostname, untrusted certificate, plain HTTP, user-info/query/fragment URLs and redirects must not make the receiver ready; verify a redirect destination receives no request/header. Disable any gateway compression on the snapshot route, because compressed bodies are deliberately rejected.
4. **Selection/projection:** create two fake Codex auth files on the primary, selecting just one ID on both sides. Fetch locally with the dedicated secret supplied without shell history or output capture. Inspect only field names: fixed allowed keys, one selected ID, no refresh/ID token/last-refresh/SIWC/proxy metadata. Duplicate the selected account in another file and confirm the entire export fails rather than choosing one arbitrarily.
5. **Host runtime vs disk:** verify a receiver save registers/enables its managed entry immediately through the host runtime API, not only by eventual watcher observation. Change the selected access token; until synchronous host save succeeds, public readiness must be non-200 and both normal and streaming interception must return 503. Confirm runtime uses the new token before readiness returns. Never print token values in reports.
6. **Removal and write failures:** deselect/disable/remove a selected source and accept a newer snapshot. Confirm the receiver saves a sanitized disabled tombstone, runtime is disabled **before** physical unlink, and an unrelated manual file remains untouched. Make a test save/runtime operation fail (test harness or controlled auth-dir fault); readiness must never become true, including after partial writes. Restore permissions before cleanup. A corrupt/invalid/failed fetched snapshot must not remove a still-fresh accepted credential.
7. **Freshness/replay/restart:** use a short but valid test stale interval. Stop export responses and observe the exact original generation/expiry deadline: readiness and normal/stream requests must reject at that boundary; cleanup must disable/remove owned records. Retrying old snapshots must not extend it. Restart while the primary is blocked: even a formerly fresh cache must remain unready. Unblock the primary and require a strictly newer live snapshot. Restart the exporter and verify its generation still increases. Test both JWT-earlier and explicit-expiry-earlier cases with generated tokens.
8. **Ownership/contamination:** pre-create a colliding computed filename that is not in the inventory; it must neither be adopted nor deleted. In an already owned test record, inject a fake `refresh_token` or SIWC field during a save; readiness must remain/turn unready and the field must never be adopted into a live relay snapshot. Test a concurrent persistence update and verify post-save/audit failure closes admission. Use an isolated instance: local admin writers are not an adversarial security boundary.
9. **Lifecycle:** while an HTTPS fetch is slow and separately while a host save is pending, reconfigure the endpoint/settings, quiesce and stop. HTTP must be canceled; callbacks must finish before state locks/context are released. No old worker may write afterward. Public readiness and interception must remain responsive and deny throughout. A genuinely blocked synchronous native callback cannot be canceled by this API; keep ingress closed until the host recovers.
10. **Ingress is the real failure boundary:** explicitly disable, fuse, unload and rename the plugin in the disposable receiver; also stop CPA and make the readiness request time out. Check that ingress denies missing/non-200/error/timeout probes, does not keep serving on cached success, and that clients cannot reach the listener directly. Verify all intended client protocols separately, including normal/SSE chat and any Responses, WebSocket, realtime or other endpoints actually used. Established requests/streams are not revoked by a new readiness failure. Do not infer protocol coverage from one chat test.
11. **Optional real-provider check:** only after steps 1–10 pass, with explicit authorization, use one dedicated test Codex account on the primary and one ordinary plus one streaming model request through receiver ingress. Confirm no refresh/ID token reaches the receiver. Record only status/model/result counts, not credentials or payload captures. This step is intentionally **not** part of automated checks or claimed complete here.
12. **Rollback rehearsal:** deny ingress; quiesce/stop the receiver; verify its runtime records are disabled and reserved files removed. Restore the paired private state/config/plugin backup with original permissions, restart, and require a newer live snapshot before admitting traffic. Record exact paths/commands for the real deployment separately; none are installed or executed by this repository.

Keep the ingress denied if any required check fails. There is no automatic production deployment, plugin updater, credential refresh loop, new listener, or CPA fork in this repository.
