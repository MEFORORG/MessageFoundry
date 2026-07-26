# Plan-12 phase documents — dir index

**Progress: 10 / 10 sessions complete — PLAN-12 EXECUTED (2026-07-16)** (1 of the 10 is optional). Master index (waves, contention matrix, shared
rules, verdict-corrections register): [MULTISESSION-PLAN-12](../MULTISESSION-PLAN-12.md).

| Wave | Phase doc | Items | Status |
|---|---|---|---|
| 1 | [w01-docs-230-errata](w01-docs-230-errata.md) | #230 (P1/4) | ✅ Done (2026-07-16) — committed; **merge FIRST** (PR via coordinator) |
| 1 | [w01-store-235-port](w01-store-235-port.md) | #235 (P1/3) | ✅ Complete (2026-07-16 — flag stays False; T-SQL proof is W2) |
| 1 | [w01-config-234-writer](w01-config-234-writer.md) | #234 (P1+P2/4) | ✅ Complete (2026-07-16) |
| 1 | [w01-ide-238-setup](w01-ide-238-setup.md) | #238 (all) | ✅ Complete (2026-07-16, IDE v0.0.32) |
| 2 | [w02-ide-230-autocomplete](w02-ide-230-autocomplete.md) | #230 (P2+P3/4) | ✅ Complete (2026-07-16, IDE v0.0.33) |
| 2 | [w02-engine-230-dryrun-parity](w02-engine-230-dryrun-parity.md) | #230 (P4, **optional**) | ✅ Complete (2026-07-16 — #230 flips ✅) |
| 2 | [w02-store-235-ci-tests](w02-store-235-ci-tests.md) | #235 (P2/3) | ✅ Complete (2026-07-16 — CI legs on its PR = the W3 gate) |
| 3 | [w03-store-235-flip](w03-store-235-flip.md) | #235 (P3/3) | ✅ Complete (2026-07-16 — #235 flips ✅; gate was green on PR #1078) |
| 3 | [w03-ide-234-merge-fix](w03-ide-234-merge-fix.md) | #234 (P3/4) | ✅ Complete (2026-07-16, IDE v0.0.34) |
| 4 | [w04-docs-234-closeout](w04-docs-234-closeout.md) | #234 (P4/4) | ✅ Complete (2026-07-16 — #234 flips ✅; #240/#241 filed) |

## How to maintain

- One session lands → edit **its phase doc** (Status field + Items table) and flip the status cell **here**. Never
  rewrite the master's roster — it gets dated progress blockquotes only.
- Per-item build state stays authoritative in `docs/BACKLOG.md` banners + `CHANGELOG.md`; phase docs track *session*
  progress and point at merged PRs.
- Shared rules (verify order, trailer rule, ide-leg manual hold, ledger/allocation rules) live in the
  [master §D](../MULTISESSION-PLAN-12.md#d-coordination-rules--gotchas) — phase docs restate them per-session but the
  master wins on conflict.
