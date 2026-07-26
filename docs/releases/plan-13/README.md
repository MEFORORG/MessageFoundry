# Plan-13 phase documents — dir index

**Progress: 8 / 10 merged, 1 in progress, 1 done-in-lane — updated 2026-07-20** (was: AUTHORED 2026-07-17).
Master index (waves, contention matrix, shared rules, banner-rot register, coverage):
[MULTISESSION-PLAN-13](../MULTISESSION-PLAN-13.md). **Owner sign-off needed to dispatch:**
[OWNER-DECISIONS](OWNER-DECISIONS.md).

| Wave | Phase doc | Items | Status |
|---|---|---|---|
| 1 | [docs-ledger-reconcile](docs-ledger-reconcile.md) | banner-rot (no build item) | ✅ MERGED — PR [#1096](https://github.com/MEFORORG/MessageFoundry/pull/1096) |
| 1 | [store-241-atrest-hardening](store-241-atrest-hardening.md) | #241 F1+F2 | ✅ MERGED — PR [#1131](https://github.com/MEFORORG/MessageFoundry/pull/1131) |
| 1 | [verify-241-snapshot-thread](verify-241-snapshot-thread.md) | #241 F3 | ✅ MERGED — PR [#1132](https://github.com/MEFORORG/MessageFoundry/pull/1132) |
| 1 | [config-240-editor-writers](config-240-editor-writers.md) | #240 a+b | ✅ MERGED — PR [#1126](https://github.com/MEFORORG/MessageFoundry/pull/1126) |
| 1 | [harness-208-220-cpu-collector](harness-208-220-cpu-collector.md) | #208 A + #220 | ✅ MERGED — PR [#1125](https://github.com/MEFORORG/MessageFoundry/pull/1125) (#208 part B = off-repo measurement, still open) |
| 1 | [harness-229-a4b-strand-guard](harness-229-a4b-strand-guard.md) | #229 | ✅ MERGED — PR [#1129](https://github.com/MEFORORG/MessageFoundry/pull/1129) |
| 1 | [harness-207-txn-per-msg](harness-207-txn-per-msg.md) | #207 loose end 1 | ✅ MERGED — PR [#1130](https://github.com/MEFORORG/MessageFoundry/pull/1130) |
| 1 | [auth-245-reconcile-flip](auth-245-reconcile-flip.md) | #245 + #246 | ✅ DONE — #245 ✅ via PRs [#1093](https://github.com/MEFORORG/MessageFoundry/pull/1093)/[#1098](https://github.com/MEFORORG/MessageFoundry/pull/1098); #246 banner flipped in the `plan13-owner-calls` ledger lane |
| 2 | [harness-207-bytes-per-msg](harness-207-bytes-per-msg.md) | #207 loose end 2 | 🚧 In progress (sibling lane; owner bytes decision + new ADR) |
| 2 | [ide-240-wizard-collision](ide-240-wizard-collision.md) | #240 c | ✅ MERGED — PR [#1133](https://github.com/MEFORORG/MessageFoundry/pull/1133) |

## How to maintain

- One session lands → edit **its phase doc** (Status field + Items table) and flip the status cell **here**. Never
  rewrite the master's roster — it gets dated progress blockquotes only.
- Per-item build state stays authoritative in `docs/BACKLOG.md` banners + `CHANGELOG.md`; phase docs track *session*
  progress and point at merged PRs.
- Shared rules (verify order, trailer rule, ide-leg manual hold, ledger/allocation rules) live in the
  [master §D](../MULTISESSION-PLAN-13.md#d-coordination-rules--gotchas) — phase docs restate them per-session but the
  master wins on conflict.
