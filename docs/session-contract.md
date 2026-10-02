# Session integration contract

`state.session.cookies` is an array of plain objects `{name:string,value:string,domain:string,path:string,hostOnly:boolean,secure:boolean,expires:number|null}`. `expires` is Unix seconds (null = session cookie).

Import `CookieJar` from `src/steam/cookies.ts`. API: `constructor(cookies?:unknown)`, `header(url:URL|string):string`, `export():Json`, `setFromHeaders(url:URL|string, headers:Headers):void`, `set(cookie):void`.

`state.session`: `steam_id`, `access_token`, `refresh_token`, `session_id`, `cookies`, `platform` (`web` or `mobile`), `account_name`, `access_expires_at`, `refresh_expires_at`. Authenticated consumers must use CookieJar.header for trusted HTTPS Steam destinations, never concatenate cookie values themselves. Tokens/secrets remain encrypted state and never operation results.

`state.guard`: `shared_secret`, `identity_secret`, optional `device_id`, `revocation_code` (never returned).

All session operation responses expose `ready_for_web` (not `cookies_ready`) to survive core redaction. `expires_at` and CookieJar `expires` are Unix seconds. Exact transfer host allowlist additionally includes upstream constants `checkout.steampowered.com` and `steam.tv`; there are no wildcard destinations.

Session operation names: `session.credentials`, `session.qr`, `session.code`, `session.poll`, `session.cookies`, `session.refresh`, `session.cancel`, `session.status`, `guard.configure`. Code/poll/cancel require `login_handle`, bound to the currently complete pending challenge.
