# Steam Worker console design

One task, one screen: approve the QR login shown by the desktop Steam client. The console is an Operate surface; everything that is not this task has been removed from the browser UI (the HTTP API is unchanged).

## Flow
1. **Setup** (first visit, no password stored): admin API key + chosen password → saved as PBKDF2-SHA256 (210k iterations) in `DATA_DIR/console-password.json`, then signed in.
2. **Lock**: password → short-lived in-memory session token (12 h, `sess_` prefix). 10 failures / 15 min lock out. Logout and password change revoke sessions.
3. **Approve**: share the Steam window → continuous local QR decode (BarcodeDetector, jsQR fallback) → `session.qr_inspect` → device review → `session.qr_approve`. Expired/rotated codes are remembered and skipped; scanning continues until success. Paste-link and screenshot upload are the fallback, and the primary path on touch devices.

## Visual world
Steam tribute, night-room use: deep navy ground with a soft blue glow from the top, raised slate cards, one bright-blue primary action per view, green only for success, red only for refusal/errors.

| Token | Value | Role |
|---|---|---|
| bg | #0e141b | Page |
| surface / raise | #18232f / #1e2b39 | Cards / secondary buttons |
| inset | #0b1118 | Inputs, capture stage |
| line / line2 | #2a3a4b / #36495d | Borders |
| text / soft / mute | #e8eff6 / #c3d1de / #a1b4c6 | Text tiers |
| blue | #66c0f4 | Focus, selection, scan reticle |
| action | #1a7fc0 → #2593d9 | Primary gradient |
| ok / err / warn | #8fd17a / #ff9e8f / #f0c674 | Status |

System CJK sans stack, base 15px, titles 22–27px, 10px card radius, 6px control radius, ≥44px controls, 600px column.

## Motion
One authored moment per state: scan sweep + pulsing dot while searching, review panel rises in, success check draws itself. All disabled under `prefers-reduced-motion`.

## Constraints
No external requests, fonts or frameworks; inline SVG icons; strict hash-only CSP (unpadded sha256, no inline `style=` attributes). Token/password never touch storage.
