# MULTISESSION-PLAN-11 — per-session phase documents

Split out of the monolithic [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md) on 2026-07-11 so that **status is maintained one session at a time**: when a session's items land, edit **only that session's phase doc** (and the status cell in the table below). The master file keeps the shared material — wave sequencing (§B), the contention matrix (§C), coordination rules (§D), the ADR/overlap reconciliation (§E), and coverage (§F).

**Progress (reconciled 2026-07-11 against `origin/main` @ 08f0b0c):** 2 complete · 8 partially built · 19 not started · 1 deferred. Both PLAN-10-deferred ADR-Accepted items (#150, #134) have shipped. **2026-07-12:** appended a gated final **Wave 19** (`ad-lab-integration-validation`) collecting the AD/domain-lab-gated items (#98, #99 smoke, #187 Kerberos residual) + the real-environment testing of the built/in-flight chunk — runs last, after the AD lab is provisioned.

| Wave | Phase doc | Items | Status |
|---|---|---|---|
| 1 | [mllp-tcp-outbound-delivery](w01-mllp-tcp-outbound-delivery.md) | #82 · #97 · #117 · #136 | ○ Not started |
| 1 | [log-retention-lifecycle](w01-log-retention-lifecycle.md) | #120 · #122 · #179 | 🚧 Partially built |
| 1 | [config-reachability-analysis](w01-config-reachability-analysis.md) | #176 · #152 | ✅ Complete |
| 1 | [asvs-l3-scorecard-docs](w01-asvs-l3-scorecard-docs.md) | #191 · #205 | ○ Not started |
| 2 | [per-message-metadata-bag](w02-per-message-metadata-bag.md) | #150 · #169 | 🚧 Partially built |
| 2 | [auth-secure-defaults-decisions](w02-auth-secure-defaults-decisions.md) | #189 · #193 · #203 · #98 | 🚧 Partially built |
| 2 | [ide-code-sets-editors](w02-ide-code-sets-editors.md) | #161 · #162 · #175 | 🚧 Partially built |
| 3 | [hl7-parsing-serialization](w03-hl7-parsing-serialization.md) | #107 · #108 · #89 | 🚧 Partially built |
| 3 | [message-replay-resend](w03-message-replay-resend.md) | #123 · #153 | ○ Not started |
| 4 | [http-outbound-connectors](w04-http-outbound-connectors.md) | #112 · #127 · #68 | 🚧 #68 shipped (#970); #112/#127 dropped |
| 4 | [auth-audit-rotation-rbac](w04-auth-audit-rotation-rbac.md) | #195 · #177 | ✅ Complete (#177 #971) |
| 5 | [streaming-large-payloads](w05-streaming-large-payloads.md) | #149 | ○ Not started |
| 5 | [console-display-flags-theme](w05-console-display-flags-theme.md) | #137 · #164 · #133 · #131 | ○ Not started |
| 6 | [connector-store-backend-breadth](w06-connector-store-backend-breadth.md) | #66 · #160 · #45 | 🚧 #66+#45 shipped (#969); #160 dropped |
| 6 | [ide-test-bench](w06-ide-test-bench.md) | #84 · #167 · #168 · #132 | ○ Not started |
| 7 | [connection-lifecycle-scheduling](w07-connection-lifecycle-scheduling.md) | #109 · #147 | ✅ Complete (#966, ADR 0095) |
| 7 | [log-uploaded-files-console](w07-log-uploaded-files-console.md) | #125 · #126 | ○ Not started |
| 8 | [tls-pki-security](w08-tls-pki-security.md) | #200 · #99 · #129 | 🚧 Partially built (#129 ✅ #965/ADR 0094; #99 partial; #200 tail #954) |
| 9 | [crypto-integrity-hardening](w09-crypto-integrity-hardening.md) | #190 | 🚧 Partially built |
| 10 | [audit-log-viewer](w10-audit-log-viewer.md) | #170 · #171 | 🚧 Partially built (#170 ✅ #964; #171 deferred) |
| 11 | [alert-escalation-recipients-templates](w11-alert-escalation-recipients-templates.md) | #81 · #146 · #138 | ○ Not started |
| 12 | [alert-events-mute-actions](w12-alert-events-mute-actions.md) | #144 · #143 | ○ Not started |
| 13 | [alert-test-saturation-kpi](w13-alert-test-saturation-kpi.md) | #118 · #93 | ○ Not started |
| 14 | [cluster-ha-dr-alerts](w14-cluster-ha-dr-alerts.md) | #101 · #145 | ✅ Complete (#101 #977, ADR 0096; #145→P10) |
| 15 | [shared-named-queues](w15-shared-named-queues.md) | #130 | ○ Not started |
| 15 | [ai-assist-broker](w15-ai-assist-broker.md) | #95 | ○ Not started |
| 16 | [handler-sandbox-isolation](w16-handler-sandbox-isolation.md) | #197 | ✅ Complete |
| 16 | [log-search-presets-export](w16-log-search-presets-export.md) | #151 · #124 | ○ Not started |
| 17 | [hl7-batch-envelope](w17-hl7-batch-envelope.md) | #134 | ↪️ Deferred (session removed) |
| 18 | [file-ftp-transports](w18-file-ftp-transports.md) | #114 · #142 · #111 · #172 | ○ Not started |
| **19** | [ad-lab-integration-validation](w19-ad-lab-integration-validation.md) | #98 · #99(e) · #187-Kerberos · #224 · #127 · #65 + integration validation of the built chunk | ○ Not started — **GATED** (AD lab + chunk merged) |

## How to maintain

- **One session lands →** edit its phase doc's **Status** + **Items** table, then flip the status cell above. Nothing else needs touching.
- **Per-item build state stays authoritative in `docs/BACKLOG.md`** (the ✅/⛔/🪦/🚧 banner) + `CHANGELOG.md`; these phase docs track *session* progress and point at the merged PRs.
- Shared coordination rules, the hotspot contention matrix, and cross-session/cross-plan dependencies are in the [master index](../MULTISESSION-PLAN-11.md) — read it before dispatching a wave.

_Method: Coordinator + one worker subagent per session in its own worktree (`scripts/worktree/new.ps1 -Name plan11-<lane>`); workers build + verify + local-commit; the owner opens and approves every PR._
