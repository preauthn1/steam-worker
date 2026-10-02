# Steam Worker

<!-- impeccable:product-schema 1 -->

## Platform
web

## Product Purpose
Approve the QR login shown by the desktop Steam client, from a browser, without a phone. The console is password-protected with an owner-chosen password and contains nothing else.

## Operating Context
Desktop and mobile have equal priority. The frontend language is Simplified Chinese; exact API operation names and field identifiers remain unchanged for interoperability. The console consumes the authenticated `/v1/operations` registry rather than inventing backend capabilities. Account operations use `/v1/accounts/:slug/operations/:name` with `{arguments}`.

## Capabilities and Constraints
- Zero-dependency browser UI with system fonts; no third-party requests or QR services.
- API bearer token lives only in page memory. Password inputs clear when submitted. Secret response fields must not be displayed.
- Every mutation requires a second confirmation dialog with visible amount, item and recipient summary and a mandatory checkbox.
- Each intentional write uses a new idempotency key. Only an explicit retry may reuse a key; mutations are never retried automatically.
- QR decoding happens locally (BarcodeDetector, vendored MIT jsQR fallback); captured frames never leave the browser.
- Console access uses an owner-chosen password (PBKDF2 hash on disk, short-lived in-memory sessions); setting it requires an admin API key.
- Unsupported backend features are labeled unavailable, not simulated.

## Brand Commitments
The user chose a Steam tribute: navy, blue-grey and bright blue, professional and operational rather than promotional. This is an independent console, not an official Steam application.

## Product Principles
Make account scope unmistakable. Show risk before dispatch. Preserve secret boundaries. Derive capabilities from the registry. Give phone operators the same controls as desktop operators.

## Accessibility & Inclusion
Keyboard-operable forms and navigation, visible focus, labeled inputs, live request status, native confirmation dialog, reduced-motion support and responsive layouts.

## Evidence on Hand
Registry schemas and local source are authoritative. No live credentials, fabricated accounts, balances, trades, prices or deployment claims are used.
