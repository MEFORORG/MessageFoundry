# PLAN-13 — Owner decisions & ratification checklist

> Companion to [MULTISESSION-PLAN-13](../MULTISESSION-PLAN-13.md). **Nothing here is code** — it is owner sign-off. Two
> kinds of action gate the plan: decisions that unblock/close a specific session (§A/§B), and ratifications the
> `docs-ledger-reconcile` session needs before it may flip four banners (§B). §C are scope calls with no schedule
> pressure. §D is informational (already shipped/dead — the ledger session flips them on evidence).

## A. Decisions that gate a build session

| # | Decision | Gates | Note |
|---|---|---|---|
| **#245/#246** | Approve push of branch `asvs-wp245` → PR → merge to `main`; **ratify the already-produced 2026-07-17 re-score (`597d6eb9`)** as verdict-of-record — do **NOT** re-run it. | `auth-245-reconcile-flip` (W1) | The build is **done** on `asvs-wp245` (a clean descendant of `origin/main`). Do **not** merge this session's `claude/asvs-drive-to-pass` line (superseded). |
| **#207 bytes/msg** | Choose which proxy to publish: **copies/msg** (backend-named) · **measured bytes/msg** (db-growth-delta ÷ acked) · **per-backend estimate**. | `harness-207-bytes-per-msg` (W2) | Any *byte* figure reverses a prior recorded refusal → the session **allocates a fresh ADR at build** (`alloc.ps1`) pinning the proxy + caveats. |

## B. Ratifications for `docs-ledger-reconcile` (flip only if ratified; else the session annotates "pending owner ratification" + cites the superseding ADR)

| # | Proposed close | Evidence |
|---|---|---|
| **#210** | ⛔ **WITHDRAWN** — SQL tempdb table-var rewrite (table vars retained by design) | THROUGHPUT-STATUS 2026-07-12; ADR 0107 / 0114 |
| **#217** | ⛔ **DECLINED** — group-commit / durable-write lever measured-dead | ADRs 0069 / 0099 / 0107 / 0114 |
| **#212** | ✅ **close** — `fifo_claim_batch` stays default OFF | ADR 0107 sized it ~+4.7% (< the +8% bar) |
| **#211** | ✅ **close** — claim-mode lane-sweep is characterization-only | ADR 0114 (pooled default settled); off the critical path |

## C. Scope calls (not scheduled — decide when you want them)

- **#91 free-threading A/B** — fund the campaign or shelve it. Likely a paper NO-GO (ADR 0053 desk-Amdahl ~+6–7%; ADR 0107
  found the single-engine wall "both FT-immune") and needs unavailable inputs (a real high-transform-CPU hot feed, a
  genuine GIL-on cp314 control + cp314t, a concurrent-commit SQL Server rig, enterprise NVMe-PLP). Spin up the harness-91
  sessions **only** on a GO.
- **#223 server-DB DR seed** — build option (a) the full engine-driven store seed that makes DR vintage engine-verifiable
  (~4–5d; re-opens the #52 DBA-delegation boundary; extends ADR 0049), **or** keep the recorded risk-acceptance + the
  shipped `[dr].restore_token`.
- **#231 Steps "Block" grouping** — pick a decorative-grouping representation (leading candidate: `# region` / `# endregion`
  native folding) or declare out-of-scope. Zero runtime behavior either way; the ADR 0106 revisit-trigger is now met.
- **#208 part B** — schedule the self-hosted whole-box CPU reconciliation (per-PID sum vs engine p95 88.4% / max 91.9% on
  the per_lane 28/s rig) to formally admit a CPU verdict. Off-repo measurement + ratification; **#208 stays 🔢-open** until
  then (part A / #220 ships in W1).
- **#246** — confirm the delegated-residual register fold-in (already committed on `asvs-wp245`, `410349fd`) is ratified as
  it merges with #245 — no separate engine work.

## D. Banner-rot the ledger session flips on evidence (informational — already shipped/dead)

✅ **Shipped but still 🔢-open:** #209, #213 (PR #952 / ADR 0084) · #227 (PR #1008) · #218 (PR #868) · #215 (Phase 5
DECLINING) · #221 (ADR 0100 / PR #886) · #222 (ADR 0076 + 0103/0106/0108) · #239 (tray ADR 0113 / PR #1084-#1088) · #48
(base #595 + L1 #794). **ADR 0106** doc-status → *Accepted* (palette shipped #1013/#1022). Full evidence table:
MULTISESSION-PLAN-13 §E.

---
_Authored 2026-07-17. This is a decision aid, not a status source — per-item build state stays authoritative in
`docs/BACKLOG.md` banners + `CHANGELOG.md`._
