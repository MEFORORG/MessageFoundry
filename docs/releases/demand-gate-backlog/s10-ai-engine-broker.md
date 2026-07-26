# DEMAND-GATE-BACKLOG · S10 · Engine-brokered AI assistance (XL / speculative / demand-gated)

> **Phase document** — the maintainable source of truth for THIS session's status. Master index:
> [DEMAND-GATE-BACKLOG-MULTISESSION-PLAN](../DEMAND-GATE-BACKLOG-MULTISESSION-PLAN.md). Reconciles/supersedes the plan-11 lane(s) for these items.

| | |
|---|---|
| **Session** | `S10` |
| **Wave** | 5 |
| **Status** | **○ Not started** |
| **Effort** | XL |
| **Backlog items** | #95 |
| **Build order** | #95 |
| **ADR(s)** | NEW — Engine-brokered AI assistance — customer-managed / self-hosted LLM egress with per-use audit |
| **Store schema / 3-backend** | No |
| **Parallel-safe** | Yes |
| **Branch** | `feat/s10-ai-engine-broker` |
| **Depends on** | None |

## Items

| Item | Title | Status |
|---|---|---|
| #95 | Engine-brokered AI assistance | ○ open |

## Owned files / seams

- `messagefoundry/api/app.py (NEW authenticated POST /ai/chat gated by AI_ASSIST; RE-RESOLVE resolve_effective_policy SERVER-side; record_audit per use — disjoint route, shares api/app.py with S8b in wave 5), api/models.py (AiChatRequest/Response)`
- `new broker HTTP client in transports/ (reuse rest.py hardened _NO_REDIRECT_OPENER + _redact_url, off the event loop — mirror smart.py; MUST NOT import api/)`
- `messagefoundry/config/settings.py (consume AiSettings provider/model/baa_attested/endpoint; add broker credential env-key to _SECRET_SETTING_KEYS), config/ai_policy.py (optional managed_endpoint AiMode)`
- `ide/src/chat.ts (flip managed → engine-broker call; keep code_only context)`

## Notes, PHI & gotchas

NEW egress/upload surface. MVP boundary UNCHANGED: code_only context regardless of mode (never message bodies). phi scope reachable ONLY under managed_claude_baa + BAA + zero-data-retention — never merely because an endpoint is on-prem/self-hosted. Server (not IDE) is the sole enforcement point. Prompt/response payloads + provider keys NEVER logged — only PHI-safe metadata in the audit detail. Per-use audit reuses the existing hash-chained audit_log (no schema change — do NOT add a bespoke ai_egress table). OWNER/DEMAND-GATED (P3, V5/D6, ADR-FIRST) — build only on explicit customer/owner demand. No new dep (reuse httpx>=0.27 base dep or rest.py opener; a vendor SDK = separate DEP-1 vet). VERIFIER SSRF caveat: [egress].allowed_http is opt-in PERMISSIVE-WHEN-EMPTY (unrestricted unless deny_by_default=true) — the broker must enforce endpoint membership itself + no-redirect opener. If managed_endpoint AiMode is added, keep it OUT of resolve_effective_policy's phi-granting branch. New authenticated POST → confirm CSRF/session coverage. Provider call off the event loop (asyncio.to_thread), MVP may be non-streaming.

## Claim & Definition of Done

- **Claim first (mandatory):** in this worktree, `pwsh -NoProfile -File scripts\coord\alloc.ps1 -Kind adr -Title "<title>"`
  for each ADR, then **commit the `🚧` claim banner** on every item above in `docs/BACKLOG.md`
  (e.g. `> 🚧 **Status — in progress (lane \`dg-s10\`, branch \`feat/s10-ai-engine-broker\`).**`), in its OWN commit,
  BEFORE writing code. The finishing PR flips each `🚧 → ✅` with the PR ref.
- **Ratify the ADR before writing the code it governs.** Add the ADR index row (`docs/adr/README.md`) in the same commit as the ADR file.
- **Verification bar (in order):** `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest`
  (`QT_QPA_PLATFORM=offscreen` for Qt/harness) → `messagefoundry check`. New behavior gets a test.
- **3-backend / store:** no store edits.
- Every PR: `git merge main` first; **no `Co-Authored-By: Claude` trailer** (CLA bot fails on it); carry `BACKLOG #N`.
  **Pushes / PRs / merges need owner approval.**

---
_Generated 2026-07-17 from the ultracode plan workflow. Master: [DEMAND-GATE-BACKLOG-MULTISESSION-PLAN](../DEMAND-GATE-BACKLOG-MULTISESSION-PLAN.md)._
