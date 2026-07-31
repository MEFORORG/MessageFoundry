# DEMAND-GATE-BACKLOG — per-session phase documents

Split per session so **status is maintained one session at a time**. Master (waves, store-serialization, hotspot matrix, ADR ledger, cross-cutting risks): [DEMAND-GATE-BACKLOG-MULTISESSION-PLAN](../DEMAND-GATE-BACKLOG-MULTISESSION-PLAN.md).

**Progress:** 13 lanes merged (S11/S6/S9/S1a/S2/S5/S3a/S7b/S3b/S1b/S8b/S10/S8a) · **2 in progress (`dg-s4`, `dg-s7a`)** · 0 not started.

| Wave | Session | Items | Effort | Store | Status |
|---|---|---|---|---|---|
| 2 | [S1a](s1a-alert-notifier.md) | #146 · #138 · #145 · #144 | L | no | ✅ Merged to main |
| 4 | [S1b](s1b-alert-store.md) | #143 · #81 | XL | yes | ✅ Merged to main |
| 2 | [S2](s2-outbound-forward-proxy.md) | #112 · #128 · #127 | L | no | ✅ Merged to main |
| 3 | [S3a](s3a-file-disposition.md) | #114 · #142 | L | yes | ✅ Merged to main |
| 4 | [S3b](s3b-file-alt-credential.md) | #111 | L | no | ✅ Merged to main |
| 1 | [S4](s4-compression-cron.md) | #172 · #160 | L | no | 🚧 In progress (`dg-s4`, ADR 0123, ADR 0011) |
| 2 | [S5](s5-outbound-keepalive-nowait-ack.md) | #117 · #97 | M | no | ✅ Merged to main |
| 1 | [S6](s6-db-soap-breadth.md) | #67 · #69 | L | no | ✅ Merged to main |
| 6 | [S7a](s7a-log-maintenance-infra.md) | #121 · #122 | L | no | 🚧 In progress (`dg-s7a`, ADR 0137) |
| 3 | [S7b](s7b-logging-surfaces.md) | #171 · #124 | M | no | ✅ Merged to main |
| 6 | [S8a](s8a-console-dashboard.md) | #76 · #131 · #136 | XL | no | ✅ Merged to main |
| 5 | [S8b](s8b-upload-search.md) | #125 · #126 · #151 | XL | yes | ✅ Merged to main |
| 1 | [S9](s9-testbench-hex-and-collections.md) | #84 · #168 | L | no | ✅ Merged to main |
| 5 | [S10](s10-ai-engine-broker.md) | #95 | XL | no | ✅ Merged to main |
| 1 | [S11](backlog-73-fips-attestation.md) | #73 | S | no | ✅ Merged to main |

## How to maintain

- **A session starts →** in its own worktree: `alloc.ps1` its ADR number(s), then commit the `🚧` claim banner on each item in `docs/BACKLOG.md` (own commit, before code), then flip this table's Status to `🚧 In progress (branch …)`.
- **A session lands →** edit its phase doc Status + this cell to `✅`, and the finishing PR flips each item's backlog banner `🚧 → ✅` with the PR ref.
- **Per-item build state is authoritative in `docs/BACKLOG.md`** (the `✅/⛔/🪦/🔢/🚧` banner); these docs track *session* progress.
- Respect the **wave order** and the **store-serialization order** (S3a → S1b → S8b) for any concurrent work.

_Method: coordinator + one worker subagent per session in its own worktree (`scripts/worktree/new.ps1 -Name dg-<lane>`); workers build + verify + local-commit; the owner opens and approves every PR._
