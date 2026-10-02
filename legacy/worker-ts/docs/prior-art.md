# Prior-art survey (2026-10-02) — do not reinvent; port and cite

Searched GitHub (repo search API) and npm. **No existing project provides a Steam login/Guard/trade
library that runs unmodified on Cloudflare Workers.** Every candidate depends on Node built-ins.

| Project | Fit for Workers | Why | Use as |
|---|---|---|---|
| DoctorMcKay/node-steam-session 1.9.4 (MIT, TypeScript, ~22k/week) | **No, as-is** | `require('crypto'/'https'/'zlib'/'os'/'events')`, `socks-proxy-agent`, runtime `protobufjs` reflecting a 576 KB JSON schema at load (CPU cost), WebSocket CM transport | **Primary reference** for the WebAPI login flow: request fields, platform types, poll/rotation, finalize/transfer, refresh |
| DoctorMcKay/node-steam-totp 2.1.2 (MIT, 0 deps) | **No, as-is** | Node `crypto` HMAC + `https` time query | Algorithm reference for TOTP code alphabet and confirmation key (~60 lines to port to Web Crypto) |
| DoctorMcKay/node-steamcommunity 3.50 (MIT) | No | `request`, `cheerio`, `xml2js`, Node streams | Endpoint/parameter reference for trade offers, confirmations, inventory |
| somespecialone/aiosteampy 1.0.0b16 (MIT, Python) | No (Python) | Pyodide exceeds Free CPU | Already-reviewed behavioural reference; keep its fixes for known upstream bugs |
| xDimGG/node-steamapi (`steamapi-cloudflare-workers` fork) | Partial | Only public Web API key queries, 12 downloads/week, no auth/trade | Not used |
| mmspring13/steam-2fa-node | No | 0 stars, Node | Not used |
| candyboyz/browserify-steam-session | No | Abandoned browserify shim, no stars | Not used |

## Decision
Write a small Workers-native TypeScript implementation, porting logic (not code wholesale) from the
MIT references above with attribution in NOTICE. Keep it cheap:

- Hand-written protobuf for the ~10 IAuthenticationService/ITwoFactorService messages actually used,
  instead of protobufjs + a 576 KB reflected schema.
- Web Crypto for HMAC-SHA1/SHA256 and AES-GCM; BigInt for RSA PKCS#1 v1.5 (password encryption only).
- `fetch` only. No WebSocket CM transport, no proxy agents.

Wire-level facts to take from node-steam-session (cite file names in code comments):
- WebAPI transport: `POST https://api.steampowered.com/I<Service>Service/<Method>/v1` with
  `input_protobuf_encoded` (base64) form field; response body is protobuf, EResult in `x-eresult` header.
- Login: GetPasswordRSAPublicKey → BeginAuthSessionViaCredentials (or ViaQR) →
  UpdateAuthSessionWithSteamGuardCode → PollAuthSessionStatus (honour new_client_id) →
  finalizelogin + transfer for web cookies; GenerateAccessTokenForApp for refresh.
