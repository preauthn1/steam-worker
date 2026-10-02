# Steam Worker console design

The user-approved identity is an independent Steam tribute, applied to an Operate surface. System fonts and embedded assets keep the browser and Worker dependency-free.

## Color tokens
| Token | Value | Role |
|---|---|---|
| bg | #171d25 | Navy-grey page |
| shell | #101822 | Masthead and account rail |
| panel | #202e3d | Challenge and protected review |
| inset | #121d29 | Inputs and response inspector |
| line | #3c5269 | Control and section boundaries |
| text | #edf3f9 | Primary text |
| muted | #b7c8d9 | Supporting copy |
| blue | #66c0f4 | Links, focus and selection |
| action | #1774ae | Primary buttons |
| danger | #ffb7a9 | Errors |
| ok | #b4dfa1 | Completed requests |

## Typography and spacing
System UI sans-serif; monospace only for JSON/data. Base 15px, masthead 20px, workbench title 28px desktop / 25px phone, subsection 18px. Supporting text is 12–13px. Body measure caps at 72ch. Major padding 28–32px desktop and 16–24px phone, field gap 18px, working-column gap 28px. Corner radius 2–4px; controls have at least 44px height.

## Structure and responsive rules
The persistent shell houses connection and account context. At desktop widths a 248px account rail accompanies operation editor and response inspector. At 1050px the inspector stacks; at 700px the rail stacks above the canvas, connection controls wrap, and workflow navigation becomes a fully visible two-row, three-column grid. No action disappears on phone. At 1600px content spacing expands instead of inventing more panels.

## Interaction language

All user-facing navigation, labels, descriptions, statuses, errors and write-review copy use Simplified Chinese (`zh-CN`). API identifiers and upstream JSON remain unchanged; localized human-readable labels accompany technical field names. Third-party QR algorithm/license text is not translated.
One bright-blue primary action per task. Native form validity, schema-derived fields, multiline JSON textarea for array/object arguments, optional omission and server capability truth. All response text uses textContent; authentication output is restricted and secret-shaped fields are recursively hidden. Mutations freeze their target and arguments before a native dialog with amount/subtotal/fees/receive/currency, items and recipient; a reset acknowledgement gates dispatch. Cancel and Escape do not send a request. Exact-key retry is explicit and excludes sensitive bodies.

Login challenge QR is black on white, rendered locally to canvas using the bundled MIT Project Nayuki encoder; the quiet zone is four modules. Polling is capped at 20 requests, cancellable, paced by bounded server intervals and only session polling may be explicitly authorized as a write batch. Each poll uses a fresh idempotency key; errors stop the batch.

## Browser details and accessibility
Bright-blue 3px visible keyboard focus, themed selection/caret/scrollbars, tabular data, semantic headings, skip link, labeled controls and atomic polite request status. Native dialog provides focus protection; Cancel receives initial focus. Only modal entry animates, and only without reduced-motion preference. Empty, denied-list-access, busy, error, disconnected and unsupported-capability states use actionable copy.

## Assets and verification
No shipping raster images, external fonts, frameworks or third-party requests. QR source: Project Nayuki QR-Code-generator `typescript-javascript/qrcodegen.ts`, MIT, fetched from the public upstream repository and transpiled into a browser-only string retaining full license. It is a reference implementation, not a claim of independent security certification.

Nine focused single-process node:test checks passed for CSP byte hashes, no persistence/HTML sinks, responsive/a11y anchors, confirmation gating and cancel, write/retry headers, JSON assets, secret scrub/URL allowlist, deterministic QR, and bounded polling. Inline JavaScript syntax checked. Parent's initial desktop1440/mobile390 browser batch reported no document overflow, JS errors or storage persistence, and working trade JSON/review; mobile navigation was then changed to a visible two-row grid. Final browser confirmation and visual verdict belong to the parent. No deployment or live credentials used.
