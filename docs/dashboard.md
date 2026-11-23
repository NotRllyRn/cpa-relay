# Relay dashboard

Open **CPA Relay** in CPA's plugin resource menu, or open
`/v0/resource/plugins/cpa-relay/status` on the CPA origin. The public page is a
static shell. Enter the **CPA management key** to read private diagnostics.
Use HTTPS; plain HTTP is accepted only on loopback for disposable tests.

The key stays in this page's memory. **Disconnect**, page exit, or a 401/403 clears
the key, status, and pending reads. The password field clears on submit. This is
CPA's full management credential, not a scoped dashboard token. Parent dashboard
logout has no supported bridge to this page; use Disconnect before leaving a
shared session. No key is read from parent storage or saved by this dashboard.

**Refresh status** reads diagnostics; it does not trigger synchronization.
Automatic reads run every five seconds after connection. Pause stops automatic
reads, and hidden tabs pause them. Relay synchronization runs independently.
Authentication failures stop all reads until another explicit login.

Readiness is the backend decision at the last successful read. A three-second
runtime observation lease and the snapshot deadline are separate. An elapsed
browser deadline marks observations historical; it cannot prove current closure
because backend checks may have renewed independently. After 15 seconds without
a successful read, current status is unknown. Counts are conservative runtime
candidates, not provider inference or quota guarantees. Recorded errors remain
historical; readiness does not prove fetch recovery.

The exporter shows its latest exported inventory. It cannot observe receiver
receipt or health. See [status fields and limits](status.md).

## Local browser checks

Build with `make build`, then use an installed Playwright module and Chromium:

```sh
PLAYWRIGHT_MODULE=/path/to/playwright/index.mjs \
  timeout 180s node tests/dashboard_browser.mjs dist/cpa-relay.so /tmp/relay-ui-check
```

Set `CHROMIUM` if Chromium is not `/usr/bin/chromium`. Without
`PLAYWRIGHT_MODULE`, the runner imports `playwright` normally. It serves HTML and
headers extracted through the real C ABI on a disposable loopback fixture, uses
synthetic management status, writes screenshots/results, and closes its browser
and server. This checks browser behavior, not stock CPA authentication or a
production installation. `make stock-smoke` separately checks stock CPA routes.
