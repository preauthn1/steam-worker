# Steam Worker — TypeScript rewrite contract

Project root: the repository directory. Pure TypeScript Cloudflare Worker. **No Python, no Pyodide, no aiohttp.**
Reason for rewrite: Python Workers exceeded the Free plan's hard 10 ms CPU limit (`CpuLimitExceeded`, ~25% of
requests). The TS build must stay small and cheap per request. Budget target: **p95 CPU < 5 ms for public reads**.

## Hard rules for every agent
- **pytest is forbidden** in any form (including wrappers). Do not run vitest's full workerd pool either.
  Verification: `npx tsc --noEmit`, plus small scoped `node --test` files compiled/run with `npx tsx --test <file>`.
- No real credentials, account names, domains, account IDs, or chat details in code, tests, docs, or commit text.
  Use `example.com` and visibly synthetic values. The repository will be published publicly.
- No Cloudflare or GitHub writes. The parent agent deploys and publishes.
- Dependencies: avoid them. Hand-write the small protobuf codec and RSA. Every dependency adds bundle size and CPU.
- Never log secrets, tokens, cookies, passwords, auth codes, request bodies, or exception text containing them.

## Directory layout
```
src/index.ts          Worker fetch entry + Durable Object exports (core agent)
src/http.ts           routing, auth, body limits, safe JSON replies (core agent)
src/vault.ts          AES-256-GCM via Web Crypto (core agent)
src/account.ts        SteamAccount DO: encrypted state, mutation journal, rate limit (core agent)
src/directory.ts      AccountDirectory DO (core agent)
src/console.ts        HTML console (core agent)
src/steam/            protocol + operations (steam agent)
  transport.ts        fetch transport: host allowlist, manual redirects, cookie jar, deadlines, body cap
  protobuf.ts         minimal varint/length-delimited codec
  rsa.ts              RSA PKCS#1 v1.5 encrypt with BigInt (password login)
  guard.ts            Steam Guard TOTP codes + confirmation keys (HMAC-SHA1 via Web Crypto)
  session.ts          IAuthenticationService login: credentials, QR, code, poll, refresh, cookies
  ops/*.ts            operation families
  registry.ts         immutable operation registry
test/*.test.ts        node:test unit tests
```

## API (unchanged from the Python version — existing smoke scripts must still pass)
- `GET /` console HTML; `GET /health` → `{"ok":true}`.
- `GET /v1/operations` → `{"operations":[...]}` (read scope).
- `GET /v1/accounts` → admin: `{"accounts":[...]}` filtered by principal allowlist.
- `PUT /v1/accounts/{slug}` create, `GET` info, `DELETE` delete — `{"exists":bool,"version":n}`.
- `POST /v1/accounts/{slug}/import` body `{"state":{...}}` or `{"envelope":"..."}`; `POST .../export` → `{"format":"steam-worker-state-v1","envelope":"..."}`.
- `POST /v1/accounts/{slug}/operations/{name}` body `{"arguments":{...}}` → `{"result":...}`.
- Slug regex `[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}`. Unknown route 404, wrong method 405.
- Errors: `{"error":{"code":"snake_case"}}` only. Never raw exception text.

## Auth (unchanged)
- Secret `API_KEYS_JSON`: `[{"id":slug,"sha256":"<64 hex>","scopes":["read"|"write"|"admin"],"accounts":["slug"|"*"]}]`.
- `Authorization: Bearer <32..512 chars>`; compare SHA-256 digest in constant time.
- Invalid/missing config → 503 `configuration_missing`. Bad token → 401. Scope → 403 `scope_denied`. Account → 403 `account_denied`.
- `admin` implies all scopes. `"*"` account wildcard only honored for admin.
- Account management (create/delete/import/export/list) requires admin.
- Mutations require `X-Confirm-Write: true` (else 428) and `Idempotency-Key` `[A-Za-z0-9_-]{16,128}` (else 400).

## Storage compatibility (MUST stay byte-compatible with existing encrypted data)
- Secret `STATE_KEY_HEX`: 64 hex chars → AES-256-GCM key.
- Envelope: base64(nonce[12] ‖ ciphertext‖tag[16]); AAD = UTF-8 `"steam-worker:v1:" + accountSlug`; plaintext = compact JSON.
- DO storage keys: `account-v1` = record `{exists,state,journal:{},version,rate:{minute,count}}`;
  `intent:<sha256 hex>` = one journal entry each.
- Journal slot = sha256(principalId + "\0" + idempotencyKey). Digest = sha256(JSON [operation, args] with sorted keys).
  Statuses: prepared → in_flight → succeeded | unknown | rejected. Same key + different digest → 409 `idempotency_conflict`.
  `unknown`/`prepared`/`in_flight` replay → 409 `outcome_unknown`. Results > 16 KiB stored as `result_omitted`.
- Zero upstream requests before failure ⇒ record `rejected` with the error, not `unknown`.
- Rate limit: 30 operations/minute/account, persisted.
- Replayed create/delete must report CURRENT existence; directory records current existence, not requested action.

## Operation interface (core ⇄ steam)
```ts
export interface OperationSpec {
  name: string; scope: 'read' | 'write' | 'admin'; mutating: boolean;
  description: string; schema: JSONSchema;       // additionalProperties:false
  run(ctx: OpContext, args: Record<string, unknown>): Promise<unknown>;
}
export interface OpContext {
  state: AccountState;            // mutable; persisted encrypted after run (also on failure)
  transport: SteamTransport;      // fresh per operation; exposes requestCount
  scope: 'read' | 'write' | 'admin';  // EFFECTIVE caller privilege
}
export class OpError extends Error { constructor(public status: number, public code: string) }
export const OPERATIONS: ReadonlyMap<string, OperationSpec>;
export function describeOperations(): readonly object[];   // cached
export function validateArgs(spec, args): Record<string, unknown>; // throws OpError(400,'invalid_arguments')
```
- `mutating && scope==='read'` is invalid. `public.*` operations need no Steam session.
- uint64 IDs are decimal strings in JSON in and out. Prices are integer minor units.

## Security invariants to preserve (from the earlier review)
1. Confirmations: write callers may only act on types 2 (trade), 3 (market listing), 12 (market purchase), 13 (refund).
   Types 5, 6, 9 and unknown require admin. `accept_all`, `deny_all`, `confirm_api_key_request` are admin-scoped.
2. Pending login: only a complete upstream challenge (request_id + client_id) is resumable. Failed startup must not
   poison later operations. Persist `new_client_id` rotation. Never persist the password.
3. Outbound hosts allowlist: steamcommunity.com, store.steampowered.com, login.steampowered.com,
   help.steampowered.com, api.steampowered.com — HTTPS port 443 only, revalidated on every redirect; strip
   Cookie/Authorization cross-host; refuse cross-origin 307/308 with a body.
4. Responses never contain access/refresh tokens, cookies, shared/identity secrets, revocation codes, passwords.
   Export only as encrypted envelope.
5. Bounded everything: 25 s per upstream request, 40 upstream requests per operation, 8 MB response cap
   (streamed), 128 KiB request body cap, pagination bounded and cursor must advance.
