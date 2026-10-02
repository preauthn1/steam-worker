# Steam Worker

<!-- impeccable:product-schema 1 -->

## Platform
web

## Product Purpose
Operate account-scoped Steam API workflows through a lightweight Worker console: select an account, sign in when supported, inspect inventory and prices, and deliberately review trading, market and confirmation actions.

## Operating Context
Desktop and mobile have equal priority. The console consumes the authenticated `/v1/operations` registry rather than inventing backend capabilities. Account operations use `/v1/accounts/:slug/operations/:name` with `{arguments}`.

## Capabilities and Constraints
- Zero-dependency browser UI with system fonts; no third-party requests or QR services.
- API bearer token lives only in page memory. Password inputs clear when submitted. Secret response fields must not be displayed.
- Every mutation requires a second confirmation dialog with visible amount, item and recipient summary and a mandatory checkbox.
- Each intentional write uses a new idempotency key. Only an explicit retry may reuse a key; mutations are never retried automatically.
- Login challenges render locally as QR using the MIT Project Nayuki encoder, with a validated challenge link fallback. Login handles and bounded, cancellable polling are supported; session-write polling requires an explicit batch authorization.
- Unsupported backend features are labeled unavailable, not simulated.

## Brand Commitments
The user chose a Steam tribute: navy, blue-grey and bright blue, professional and operational rather than promotional. This is an independent console, not an official Steam application.

## Product Principles
Make account scope unmistakable. Show risk before dispatch. Preserve secret boundaries. Derive capabilities from the registry. Give phone operators the same controls as desktop operators.

## Accessibility & Inclusion
Keyboard-operable forms and navigation, visible focus, labeled inputs, live request status, native confirmation dialog, reduced-motion support and responsive layouts.

## Evidence on Hand
Registry schemas and local source are authoritative. No live credentials, fabricated accounts, balances, trades, prices or deployment claims are used.
