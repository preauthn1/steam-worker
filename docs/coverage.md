# Operation coverage

This project deliberately reports coverage by operation, rather than implying that an HTTP transport alone makes the upstream SDK available.

## Implemented and tested

- `public.server_time`
  - Protobuf request and response are hand-written.
  - Verified against a canned service response and production-read smoke call.
- `public.market.get_price_overview`
  - Sends the documented public GET request.
  - Preserves Steam's localized price strings and returns best-effort integer minor units.
  - Uses `median_price` for the median (not `lowest_price`).
  - Tested with a fake Steam response. A production probe reached Steam but received an upstream `429`; this is reported to callers and is not treated as a Worker CPU fault.

## Deliberately not implemented yet

- Session lifecycle: QR login, credential login, Steam Guard-code submission, polling, refresh, cookie acquisition, token import/cancel.
- Account-authenticated inventory, wallet, notification, market, trade-offer, API-key, profile, and confirmation actions.
- Public inventory, profile, and the remaining public-market queries.
- Steam Guard confirmation approval/denial.

These are excluded because a secure implementation needs complete per-endpoint protocol tests and, for mutations, a test account with explicit authorization. They are not represented by placeholder success responses.

## API behavior outside this list

Unknown operation names return `404 operation_not_found`. No generic endpoint forwarding exists: accepting arbitrary Steam URLs would defeat the outbound host and request-budget controls.
