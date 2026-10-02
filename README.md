# Steam Worker

A dependency-free TypeScript Cloudflare Worker adapter for a small, security-focused subset of Steam HTTP functionality.

It is designed for the Workers Free CPU limit:

- no Python/Pyodide runtime;
- no reflected protobuf schema or `protobufjs`;
- Workers `fetch` and Web Crypto only;
- encrypted account state in SQLite-backed Durable Objects;
- scoped bearer-token authorization and idempotency protection for writes.

> **Status:** early, intentionally limited. This is **not** a drop-in replacement for `aiosteampy` and must not be described as one. See [coverage](docs/coverage.md).

## Implemented operations

- `public.server_time` — Steam server time, as a decimal string
- `public.market.get_price_overview` — public price overview

The Worker also exposes account create/delete/import/export primitives, an encrypted Durable Object store, and a small browser console. It does not yet implement credential login, inventory, trading, market writes, or Steam Guard confirmations.

## Security model

- Configure `API_KEYS_JSON` as a Worker secret containing only SHA-256 bearer-token hashes, scopes, and permitted account slugs.
- Configure `STATE_KEY_HEX` as a Worker secret with exactly 32 random bytes encoded as 64 hexadecimal characters.
- Account state is AES-256-GCM encrypted. The envelope is compatible with the earlier Python implementation: base64 of `nonce(12) || ciphertext || tag(16)`, with AAD `steam-worker:v1:<account-slug>`.
- Mutating routes require both `X-Confirm-Write: true` and an `Idempotency-Key`.
- The Worker never logs passwords, tokens, cookies, Steam Guard secrets, or raw upstream exceptions.
- Outbound requests are restricted to the Steam hosts required by implemented operations. Responses are capped at 8 MB, requests at 40 per operation, and redirects are manually restricted.

## Deploy

```sh
npm install
npx wrangler secret put API_KEYS_JSON
npx wrangler secret put STATE_KEY_HEX
npx wrangler deploy
```

Example (use generated values; do not put plaintext bearer tokens in the JSON):

```json
[
  {
    "id": "operator",
    "sha256": "64-lowercase-hex-characters-for-the-token-hash",
    "scopes": ["admin"],
    "accounts": ["*"]
  }
]
```

The deployment uses SQLite-backed Durable Objects, supported on Workers Free. Use your own custom domain and keep operational hostnames, tokens, and account identifiers out of source control.

## Verification

```sh
npx tsc --noEmit
npx tsx --test test/core.test.ts test/steam.test.ts
npx wrangler deploy --dry-run
```

Tests are deterministic and use fake Steam transports; they never contact Steam or require credentials.

## License and attribution

MIT. Steam protocol behavior was independently implemented using publicly documented behavior and informed by the MIT-licensed projects listed in [docs/prior-art.md]. See [NOTICE](NOTICE).
