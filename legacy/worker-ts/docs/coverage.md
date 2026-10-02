# Operation coverage

Implemented registry families:

- Public: `public.server_time`, `public.market.get_price_overview`.
- Login: `session.credentials`, `session.qr`, `session.code`, `session.poll`, `session.cookies`, `session.refresh`, `session.cancel`, `session.status`.
- Guard configuration: `guard.configure` (admin-only, secrets encrypted).
- Wallet and inventory: `wallet.info`, `inventory.get` (single bounded page).
- Market: `market.get_user_listings`, `market.place_sell_listing`, `market.cancel_sell_listing`, `market.place_buy_order`, `market.cancel_buy_order`, `market.buy_listing`, `market.get_buy_order_status`.
- Trade offers: `trade.get`, `trade.get_multiple`, `trade.send`, `trade.accept`, `trade.decline`, `trade.cancel`.
- Confirmations: `confirmations.get_all`, `confirmations.accept`, `confirmations.deny`, `confirmations.send_multiple`, `confirmations.accept_all`, `confirmations.deny_all`.

The authoritative arguments, required fields and privileges are published by `GET /v1/operations`; the browser renders that catalog. This adapter uses explicit JSON DTOs, not Python SDK object serialization.

## Money and write protection

Prices, fees and totals are integer minor units, not floating point currency values. Market spending/selling requires an explicit currency matching a preceding trusted `wallet.info` read. Sell uses `to_receive`; buy-listing uses explicit `subtotal` and `fee`. There are no automatic fee guesses, financial retries or confirmation approvals. Pending mobile/email confirmation is returned as such.

Mutations require explicit write authorization and an idempotency key. The browser shows operation/account/amount/items/recipient and requires an acknowledgment before a write. Login polling is separately authorized and bounded; it is not financial retry automation.

Confirmation types are refetched from Steam before acting. Only supported financial types are processed; unknown and account-security types fail closed. Bulk confirmation operations additionally require admin scope.

## Verification limits

Deterministic protocol tests use synthetic responses, not real Steam credentials or financial transactions. Passing these tests proves code behavior and wire construction against the reviewed upstream references; it does not prove that every operation succeeds for every live account, regional currency, Steam policy, account restriction or upstream version.

Real-account password/QR approval, inventory access, actual buying/selling/trading and actual confirmation approval have not been executed during development. No real account credentials are required to run the test suite.

Unsupported SDK features remain intentionally absent, including full profile/notification management and other public-market APIs. Unknown operation names return `404 operation_not_found`; no generic arbitrary-URL forwarding exists.
