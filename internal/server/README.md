# Local HTTP core

`server.New(Config)` returns an `http.Handler`; the concrete `*Server` also exposes `Close() error` to flush/close the database after HTTP shutdown.

Frontend build inputs are `internal/server/assets/console.html` and `internal/server/assets/csp.txt`. Both are embedded at compile time. `server.Assets()` returns their contents. `Config.HTML` and `Config.CSP` can explicitly override them together.

CLI environment:
- `API_KEYS_JSON`: required JSON array of `{id,sha256,scopes,accounts}`. Hashes are lowercase SHA-256; bearer tokens are never persisted.
- `STATE_KEY_HEX`: required 64-character AES-256 key.
- `DATA_DIR`: default `./data` (encrypted `state.db`, mode 0600, new directory mode 0700).
- `BIND`: default `127.0.0.1:8892`.
- `CONSOLE_HTML_FILE`: optional external frontend; requires `CONSOLE_CSP`.

The sole storage dependency is pinned bbolt. Each account state and each intent are independently AES-256-GCM encrypted using the existing base64 envelope (`12-byte nonce || ciphertext || 16-byte tag`) and AAD `steam-worker:v1:<slug>`. State, intent and rate counter updates commit atomically in one durable transaction. Upstream calls never hold a bbolt transaction or a global network mutex. Account deletion keeps encrypted journal tombstones; replay cannot recreate/deletions cannot repeat an earlier effect.

An in-flight intent is durable before the operation runs. Restart, panic, canceled execution or an uncertain upstream error never retries the same intent. Context state mutations and cookies are saved on errors. Typed API errors with zero transport requests are replayable rejections; other mutating failures return `outcome_unknown`. Results over 16 KiB are not retained in the intent. The HTTP request cap is 128 KiB. State encryption does not enforce the TS 120000-character storage cap because discarding post-upstream state would violate uncertainty durability.

Encrypted export/import uses the original `{state: ...}` payload and account-bound AAD; session/guard field names are not rewritten. Export includes **no intent journal or rate history**. Envelope compatibility is not proof of business-state compatibility or live authentication. Legacy business state must be audited separately before use. Local records are explicitly `steam-go-v1`; local intent digests are domain-separated `steam-go-journal-v1`, not TS canonical digests. There is no automatic legacy journal migration. Never treat importing a state export as migrating effect history; rotate client idempotency namespaces only after an explicit migration review.

No real Steam effects are required for core tests. Run only bounded synthetic tests: `GOMAXPROCS=2 go test -p=1 ./internal/server` and bounded build `GOMAXPROCS=2 go build -p=1 ./cmd/steam-server`. No pytest, race detector, fuzzing or live account actions.
