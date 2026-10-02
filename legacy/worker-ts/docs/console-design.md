# Console surface

Mode: Operate. Scope: `src/console.ts`; independent Steam-inspired account console.

## Direction contract
THESIS: A Steam-library-style workbench, not a dashboard of fabricated metrics. Account scope and request consequences lead.

OWN-WORLD: Solid navy shell, blue-grey working surfaces, square-edged inset inputs, crisp bright-blue actions and a persistent account rail. System UI typography is a budget and operating-mode commitment.

STORY: Connect a memory-only API token, choose an account, inspect supported capabilities, fill schema-driven arguments, then review any write in a protected second step.

FIRST VIEWPORT: Compact masthead above a connection strip; a narrow account rail beside a large workflow canvas. The canvas has horizontal capability navigation, an operation list, generated fields and an adjacent result inspector. Phone layout stacks the connection, accounts and canvas without dropping actions.

FORM: User-pinned Steam tribute; code-led implementation within the delegated five-file boundary. No further concept interview: the parent completed approval. Signature interaction is the transaction review with explicit account, amounts, items, recipient and acknowledgement.

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance

## Behavioral contract
- Registry is capability truth. Missing login/inventory/trade/market/confirmation operations render honest unavailable states; advanced exposes all operations.
- The MIT Project Nayuki reference QR implementation is embedded in console.ts with its license. Validated Steam challenge URLs encode to local canvas modules with a four-module quiet zone. No service, remote image or frame receives a challenge. A link is available for accessible fallback.
- Poll only the catalog-declared session.poll operation, using the login handle, 3–30 second interval, at most 20 attempts. Mutating session polling requires a separate modal authorizing that bounded batch, with a fresh key per request and no individual failed-request retry. Stop button, disconnect, account changes and any manual operation cancel polling. Each poll is serialized and cancellable.
- Dialog resets checkbox for every opening, freezes target and arguments, and closes/cancels without dispatch. Sensitive writes cannot be explicitly retried because credential payloads are not retained.
- General responses are recursively scrubbed; authentication results expose only safe status information and dedicated validated challenge handling, not raw authentication JSON.

## Verification handoff
Static syntax/type/CSP checks only in the delegated build; runtime tests and browser preview are intentionally not run. Parent must obtain consent for bounded browser verification at desktop and phone sizes, check contrast, focus return, write cancellation, schema fields, challenge-link flow and polling cancellation. No whole-surface visual verdict is claimed yet. No raster assets ship.
