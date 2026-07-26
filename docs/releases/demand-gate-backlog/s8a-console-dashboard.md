# DEMAND-GATE-BACKLOG · S8a · Console dashboard — flow-graph/trend charts, object flag, waiting-for-reply state

> **Phase document** — the maintainable source of truth for THIS session's status. Master index:
> [DEMAND-GATE-BACKLOG-MULTISESSION-PLAN](../DEMAND-GATE-BACKLOG-MULTISESSION-PLAN.md). Reconciles/supersedes the plan-11 lane(s) for these items.

| | |
|---|---|
| **Session** | `S8a` |
| **Wave** | 6 |
| **Status** | **○ Not started** |
| **Effort** | XL |
| **Backlog items** | #76 · #131 · #136 |
| **Build order** | #76 → #131 → #136 |
| **ADR(s)** | amend ADR 0065 — ADR 0065 amendment — historical trend charts + status-colored by-name data-flow graph (CSP 'self', no channel/route object); amend ADR 0007 — ADR 0007 amendment — console-settable connection flag + flagged-only filter (scoped to TOML-managed; builds the first console→connections.toml write seam); (decision note) Per-message 'waiting for reply' outbound display state + cosmetic display delay |
| **Store schema / 3-backend** | No |
| **Parallel-safe** | No |
| **Branch** | `claude/s8a-console-dashboard` |
| **Depends on** | None |

## Items

| Item | Title | Status |
|---|---|---|
| #76 | Historical-metrics charting + status-colored data-flow graph | ○ open |
| #131 | Object flagging + Flagged Objects filter | ○ open |
| #136 | 'Waiting for Reply' per-message connection state + display delay | ○ open |

## Owned files / seams

- `messagefoundry/api/metrics.py (in-memory ring sampled from existing counts — reuse the ~1s /ws/stats sampler), api/app.py (history + graph-edges endpoints), api/models.py (ConnectionRow)`
- `messagefoundry/config/wiring.py (Registry edges for the graph; InboundConnection/OutboundConnection flag; waiting_display_delay), config/models.py (Destination.waiting_display_delay — HOTSPOT shared with S2/S3a/S3b, all different waves)`
- `messagefoundry/config/connections_edit.py + connections_file.py (_INBOUND_KEYS/_OUTBOUND_KEYS + the NEW console→connections.toml write seam — NOT wired to the console today; keep the key-schema parity test green)`
- `messagefoundry/transports/mllp.py (side-band waiting-for-reply window around the ACK read — no delivery-path change) — HOTSPOT shared with S5 #117 (different waves)`
- `messagefoundry_webconsole/pages/connections.py + pages/monitoring.py + static/app.js/app.css (inline-SVG charts, flow graph, flag/filter, waiting status) — app.js HOTSPOT shared with S7b/S8b`
- `messagefoundry_webconsole/routes/connection_writes.py (flag toggle — the new console write path)`

## Notes, PHI & gotchas

EFFORT INFLATED L→XL: #131/#136 require building the FIRST console→connections.toml write seam. connections_edit.py (ADR 0007 write path) is wired ONLY into the CLI — there is NO console→connections.toml write path today (ADR 0007 is Proposed/'Built: Not yet'), so a console-settable flag/delay must build that seam first, not merely add a key. SCOPE FORK (record in the 0007 amendment): scope #131/#136 to TOML-managed connections ONLY (keeps store_schema=false). A flag on a CODE-FIRST connection has no TOML home; the universal-flag branch needs a NEW name-keyed annotation table across all 3 backends — if the owner chooses it, S8a becomes STORE-SERIALIZED and MUST join store_serialization_order (after S8b). #136 waiting_display_delay is a new PERSISTED config field (not purely runtime) and rides the same unbuilt console-write seam if console-editable. #136 × #117 (S5) INTERACTION: waiting-for-reply is INAPPLICABLE when the ACK read is skipped (no-ack mode) — render it only on ACK-waiting outbounds. All three items are aggregate/metadata only — no message body. #76 INVARIANT TRIPWIRE: render the by-name graph from Registry edges — do NOT construct a 'channel'/route bundling object (CLAUDE.md §1); graph-edges endpoint stays read-only in api/, no pipeline/ import. CSP script-src 'self' → inline SVG / first-party JS only, no chart-lib CDN; keep the first slice an in-memory ring (durable table would flip store_schema true).

## Claim & Definition of Done

- **Claim first (mandatory):** in this worktree, `pwsh -NoProfile -File scripts\coord\alloc.ps1 -Kind adr -Title "<title>"`
  for each ADR, then **commit the `🚧` claim banner** on every item above in `docs/BACKLOG.md`
  (e.g. `> 🚧 **Status — in progress (lane \`dg-s8a\`, branch \`claude/s8a-console-dashboard\`).**`), in its OWN commit,
  BEFORE writing code. The finishing PR flips each `🚧 → ✅` with the PR ref.
- **Ratify the ADR before writing the code it governs.** Add the ADR index row (`docs/adr/README.md`) in the same commit as the ADR file.
- **Verification bar (in order):** `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest`
  (`QT_QPA_PLATFORM=offscreen` for Qt/harness) → `messagefoundry check`. New behavior gets a test.
- **3-backend / store:** no store edits.
- Every PR: `git merge main` first; **no `Co-Authored-By: Claude` trailer** (CLA bot fails on it); carry `BACKLOG #N`.
  **Pushes / PRs / merges need owner approval.**

---
_Generated 2026-07-17 from the ultracode plan workflow. Master: [DEMAND-GATE-BACKLOG-MULTISESSION-PLAN](../DEMAND-GATE-BACKLOG-MULTISESSION-PLAN.md)._
