# MessageFoundry -- Multisession Execution Plan 11 (2026-07-10)

> 📁 **Split into per-session phase documents (2026-07-11): [`plan-11/`](plan-11/README.md).** Each build session now has its own maintainable doc under `docs/releases/plan-11/` — **when a session's items land, update only its phase doc** (and the status cell in the [dir index](plan-11/README.md)), not this file. This master stays the **shared index**: wave sequencing (§B), the contention matrix (§C), coordination rules (§D), the ADR/overlap reconciliation (§E), and coverage (§F). The §A roster below is an at-a-glance summary; the phase docs are authoritative for per-session status.

**Grouping the 71 owner-selected backlog items into 30 parallel-safe, single-subsystem build sessions across 18 waves so that no two sessions in the same wave ever co-own a file.** Six items (`#82 #118 #144 #145 #150 #134`) are already scheduled in [MULTISESSION-PLAN-10](MULTISESSION-PLAN-10.md) and are **deferred to it** (see §E.c), leaving **65 items built here across 29 sessions**. A **Start here** dispatch set — the immediately-actionable Wave-1/2 work — is called out below.

This batch is the 71 demand-gated / scheduled backlog items the owner chose to plan in one pass. They are partitioned into single-subsystem sessions and serialized by wave against the concentrated hotspots (`config/settings.py`, `config/models.py`, `config/wiring.py`, `pipeline/wiring_runner.py`, `pipeline/alerts.py`, the store triad, `api/app.py`/`api/models.py`, the TLS/crypto files, and `__main__.py`) — each held to at most one owner per wave, verified against the analysis records' *touched* files, not just declared ownership. Method: **Coordinator + one worker subagent per session in its own worktree (`scripts/worktree/new.ps1 -Name plan11-<lane>`); workers build + verify + local-commit; the owner opens and approves every PR.** Status: **IN PROGRESS** — dispatch has begun; **see the progress callout below.**

> **Progress since this plan was written — updated 2026-07-11** (git-verified against `origin/main`, which has advanced to `08f0b0c` / #922; per-item ✅ banner + `CHANGELOG.md` remain authoritative). Several planned sessions have already landed, mostly carried by the PLAN-9 ASVS waves and by the two PLAN-10 deferrals actually shipping:
>
> - **Complete:** `handler-sandbox-isolation` (W16) — **#197 ✅ shipped** (ADR 0087, PR #917). `config-reachability-analysis` (W1) — **#176 + #152 core ✅ merged** (PR #919; per-item banner-flip still pending).
> - **Partially built:** `log-retention-lifecycle` (W1) — **#120 ✅** (#922, auto-delete app logs after N days); #122/#179 remain. `auth-secure-defaults-decisions` (W2) — **#189 ✅** (#898) + **#193 ✅** (#902) + **#203 ✅** (#920, opt-in delegated-identity precondition + delegation-boundary doc); only **#98 remains**. `ide-code-sets-editors` (W2) — **#161 + #175 ✅** (#921, TypeScript editor polish); #162 remains. `auth-audit-rotation-rbac` (W4) — **#195 ✅** both halves (#902 #195a / #904 #195b); #177 remains. `tls-pki-security` (W8) — **#200 🚧 partial** (ADR 0083 mTLS-identity + fail-closed off-loopback gate, #906/#911); #99/#129 remain. `crypto-integrity-hardening` (W9) — **#190 🚧 partial** (GCM rekey counter + keyed audit chain, #899); JWS signing remains.
> - **Deferrals resolved by shipping:** the two ADR-Accepted PLAN-10 items have now **actually landed** — **#150 ✅** metadata bag (ADR 0081, #894) and **#134 ✅** outbound batch (ADR 0082, #900). This **unblocks the two PLAN-11 sessions that gated on the bag: #169 (W2) and #167 (W6) can now build on the shipped `SetMeta` bag.** (The four remaining PLAN-10 deferrals — #82 SENDER, #118/#144/#145 ALERTS-OPS — were not observed merged as of this update.)
> - **Already reflected below:** #89 (W3 residual) landed in PLAN-9 Wave 1 (#891); no change.
> - **ADR numbering:** next-free is now **0089** (0081–0088 are all Accepted/merged), superseding §E.a's stale "~0083".

> The verifier flagged the single log-search/console session (effort 20) as oversized; it is split here into `log-uploaded-files-console` (#125+#126, Wave 7) and `log-search-presets-export` (#151+#124, Wave 16), which share `api/app.py`/`api/models.py`/`console/widgets.py`/webconsole search and therefore must not run in the same wave.

---

## Start here — immediately actionable (Wave 1–2, no upstream dependency)

The lowest-gating work to dispatch on day one: Wave-1/2 items with **no cross-session or cross-plan dependency and no new-engine-seam ADR**. Nine items across four sessions — a coordinator can open these worktrees first. **(Update 2026-07-11: #120, #176, #152, #161, #175, #193, and #203 have all since shipped — 7 of the 9 start-here items are done; only the two owner-decisions #191/#205 remain.)**

| Item | Session (wave) | V/D | Gate | What |
|---|---|---|---|---|
| ~~#120~~ ✅ | log-retention-lifecycle (W1) | 5/2 | none | Auto-delete application log files after N days — **merged #922** |
| ~~#176~~ ✅ | config-reachability-analysis (W1) | 4/3 | none | Unused-object / dead-config detection — **core merged #919** |
| ~~#152~~ ✅ | config-reachability-analysis (W1) | 4/5 | none | Reverse-dependency / impact analysis — **core merged #919** (shared reverse-reachability index) |
| ~~#161~~ ✅ | ide-code-sets-editors (W2) | 4/2 | none | Code-set editor in-grid row search — **merged #921** |
| ~~#175~~ ✅ | ide-code-sets-editors (W2) | 4/2 | none | Clone-a-connection editor action — **merged #921** |
| ~~#193~~ ✅ | auth-secure-defaults-decisions (W2) | 5/3 | none | Anti-automation pacing floor — **merged #902** (reused the 2.4.1 rate-limiter seam) |
| ~~#203~~ ✅ | auth-secure-defaults-decisions (W2) | 5/3 | doc | Delegated-identity / device-posture precondition — **merged #920** |
| **#191** | asvs-l3-scorecard-docs (W1) | 2/1 | **decision** | Exercise the SMART/OAuth outbound path or scope it out — **zero code** |
| **#205** | asvs-l3-scorecard-docs (W1) | 2/1 | **decision** | Sign the ASVS L3 risk-acceptance record — **zero code** |

- The two **decisions** (#191, #205) are owner calls, not builds — resolve them first; they close out the `asvs-l3-scorecard-docs` session.
- Pairing is forced by shared files: #176+#152 (reverse-reachability index) = one session; #161+#175 (IDE editor `.ts`) = one session; #193+#203 ride the auth-defaults session while its **ADR-gated** siblings #189/#98 wait.
- **Not** start-here: everything deferred to PLAN-10 (§E.c). The mllp-tcp items (#97/#117/#136) and per-message-history (#169) only become available once PLAN-10's SENDER and METADATA lanes land.

---

## A. Session roster

| Wave | Session | Items | Effort | Owns (files / seams) | Notes |
|---|---|---|---|---|---|
| 1 | mllp-tcp-outbound-delivery | ~~#82~~→P10 · #97, #117, #136 | 13 | `transports/mllp.py`, `transports/tcp.py`, `transports/x12.py`, `config/models.py`, `api/app.py`, `api/models.py`, `console/status.py`, `console/connections.py` | needs_adr (#117 delivery-confirmation contract). All four contend on `mllp.py`; owns the W1 `config/models.py`+`api/app.py` slot. |
| 1 | log-retention-lifecycle 🚧 | ~~#120~~ ✅ · #122, #179 | 15 | `pipeline/retention.py`, `logging_setup.py`, `config/settings.py`, `pipeline/alerts.py`, store triad (`store.py`/`base.py`/`sqlserver.py`/`postgres.py`), `pipeline/engine.py` | needs_adr (#179 copy-then-purge). store-schema/3-backend (#179 archive). **#120 ✅ shipped (#922, auto-delete app logs after N days); remaining = #122 + #179.** Sole W1 owner of `alerts.py`+settings+store-triad; may also take `wiring_runner.py` for the #122 connection-stop hook (no W1 sibling touches it). |
| 1 | config-reachability-analysis ✅ | #176, #152 | 10 | `checks.py`, `config/wiring.py`, `config/reachability.py`, `config/codeset_edit.py`, `ide/src/graphTree.ts`, `ide/src/connectionEditor.ts`, `ide/src/codeSetEditor.ts` | **CORE MERGED #919** (reverse-reachability index — dead-config advisory + referrers). #176 is a strict subset of #152; shared reverse-reachability index. Owned W1 `config/wiring.py` + IDE editor slot. |
| 1 | asvs-l3-scorecard-docs | #191, #205 | 2 | `docs/security/ASVS-L3-*`, `docs/SECURITY.md`, `docs/BACKLOG.md` | Zero code (owner decisions #191 scope-out, #205 risk-acceptance). Sole W1 owner of the ASVS scorecard + `docs/SECURITY.md`. |
| 2 | per-message-metadata-bag | ~~#150~~ ✅ shipped · #169 | 5 | `store` triad, `api/app.py`, `api/models.py`, `console/search.py`, webconsole messages | **#150 ✅ SHIPPED (ADR 0081, `SetMeta`, PR #894) — the bag dependency is now satisfied.** Builds #169 (append-history) **on the shipped bag**; #167 (W6) likewise now unblocked. |
| 2 | auth-secure-defaults-decisions 🚧 | ~~#189~~ ✅ · ~~#193~~ ✅ · ~~#203~~ ✅ · #98 | 12 | `config/settings.py`, `config/models.py`, `api/approvals.py`, `api/security.py`, `auth/service.py`, `auth/ldap.py`, `webconsole/routes/sso.py`, `docs/SECURITY.md`, `docs/security/*` | needs_adr (#189 default-flip, #98 EPA). **#189 ✅ (#898, dual-control warn gate + 2.2.1/2.2.3 signed deviation) + #193 ✅ (#902) + #203 ✅ (#920, opt-in delegated-identity precondition) shipped; remaining = #98 (Kerberos EPA) only.** Owns W2 settings+models+`docs/SECURITY.md`. |
| 2 | ide-code-sets-editors 🚧 | ~~#161~~ ✅ · #162 · ~~#175~~ ✅ | 9 | `ide/src/codeSetEditor.ts`, `ide/src/codesetsTree.ts`, `ide/src/connectionEditor.ts`, `ide/src/connectionsTree.ts`, `__main__.py`, `config/code_sets.py`, `config/codeset_edit.py`, `config/reference.py`, `pipeline/reference_sync.py` | needs_adr (#162 amends ADR 0033). **#161 + #175 ✅ shipped (#921, TypeScript editor polish); remaining = #162 (unmapped-value policy).** Owns W2 `__main__.py`; waved off W1 config-reachability + W5 console-display which also touch the editor `.ts`. |
| 3 | hl7-parsing-serialization | #107, #108, #89 | 8 | `parsing/message.py`, `parsing/_builtin_hl7.py`, `parsing/peek.py`, `parsing/validate.py`, `config/models.py`, `config/wiring.py`, `pipeline/wiring_runner.py`, `transports/mllp.py` | needs_adr (#107 parsing-contract). **#89 already merged (PLAN-9 W1) — residual only.** Owns W3 `wiring_runner.py`+models+`mllp.py`+wiring slot. |
| 3 | message-replay-resend | #123, #153 | 12 | store triad, `pipeline/engine.py`, `api/app.py`, `api/models.py`, `console/search.py`, `console/client.py`, webconsole messages/search | needs_adr (control-plane redirect). 3-backend replay signature. #153 builds on #123 (intra-session). Owns W3 store-triad slot (disjoint from hl7-parsing). |
| 4 | http-outbound-connectors | #112, #127, #68 | 14 | `transports/rest.py`, `soap.py`, `fhir.py`, `smart.py`, `dicomweb.py`, `config/models.py`, `config/wiring.py`, `pipeline/wiring_runner.py`, `store/store.py`, `store/postgres.py`, `store/sqlserver.py` | needs_adr (#68 per-message carry). store-schema/3-backend (#68). #127 depends on #112 (intra-session). Owns W4 store-triad+models+`wiring_runner.py`. |
| 4 | auth-audit-rotation-rbac 🚧 | ~~#195~~ ✅ · #177 | 8 | `api/security.py`, `auth/service.py`, `config/settings.py`, `store/crypto.py`, `store/keyprovider.py`, `pipeline/leader_tasks.py`, `pipeline/cert_expiry.py`, `api/auth_routes.py`, `api/auth_models.py`, `api/models.py`, `auth/identity.py`, `console/users_page.py`, `__main__.py` | needs_adr (#195 rotation policy). **#195 ✅ both halves shipped via PLAN-9 W2 (#195a authorization-grant audit twin #902 + #195b secret-rotation reminder #904); remaining = #177 (effective-permission inspector).** Waved off #190 (`crypto.py`, W9) + #197 (`crypto.py`, W16). Owns W4 settings+security+service+`__main__.py`. |
| 5 | streaming-large-payloads | #149 | 9 | `transports/mllp.py`, `store/store.py`, `store/sqlserver.py`, `store/base.py`, `store/postgres.py`, `pipeline/wiring_runner.py`, `config/settings.py`, `parsing/split.py` | needs_adr (touches ACK-on-receipt + reliability invariant). store-schema/3-backend chunked BLOB. Runs effectively alone in W5. |
| 5 | console-display-flags-theme | #137, #164, #133, #131 | 12 | `console/shell.py`, `console/widgets.py`, `console/theme.py`, `console/connections.py`, `config/models.py`, `api/models.py`, `api/app.py`, `webconsole/pages/connections.py`, `ide/src/connectionEditor.ts` | Presentation-only. #131/#133 both add display fields to `config/models.py`+`api/models.py` (co-located). File-disjoint from streaming in W5. |
| 6 | connector-store-backend-breadth | #66, #160, #45 | 12 | `transports/database.py`, `transports/timer.py`, `store/sqlserver.py`, `config/models.py`, `config/settings.py`, `pyproject.toml`, `requirements.lock`, `docs/CONNECTIONS.md`, `docs/CONFIGURATION.md` | Dep-adding (#66 drivers, #160 croniter) — verify deps before adding. Owns W6 pyproject/lock+settings+`sqlserver.py`. |
| 6 | ide-test-bench | #84, #167, #168, #132 | 12 | `ide/src/hl7diff.ts`, `testBench.ts`, `traceView.ts`, `testBenchCollections.ts`, `ide/package.json`, `console/widgets.py`, `parsing/binary.py`, `pipeline/dryrun.py`, `api/app.py`, `__main__.py`, `checks.py` | **#167 depends on the per-message-metadata bag — dependency now SATISFIED (#150/ADR 0081 shipped #894); still sequence to W6 for `__main__.py`/`api/app.py` contention.** Owns W6 `__main__.py`+`dryrun.py`+`api/app.py`. |
| 7 | connection-lifecycle-scheduling | #109, #147 | 11 | `pipeline/stage_dispatcher.py`, `transports/remotefile.py`, `config/settings.py`, `transports/base.py`, `config/wiring.py`, `pipeline/wiring_runner.py`, `config/connections_file.py`, `console/connections.py`, `console/client.py` | needs_adr (new RegistryRunner lifecycle seam). Owns W7 settings+wiring+`wiring_runner.py`, disjoint from the W7 log-uploaded session. |
| 7 | log-uploaded-files-console | #125, #126 | 10 | `api/app.py`, `api/models.py`, `auth/permissions.py`, `console/shell.py`, `console/widgets.py`, `console/event_log_page.py`, `parsing/split.py`, `webconsole/mount.py`, `webconsole/pages/messages.py`, `webconsole/routes/search.py` | needs_adr (#125 where uploaded logs live). **#126 hard-depends on #125 (intra-session).** Split half A of the oversized log-search session; disjoint from connection-lifecycle in W7. |
| 8 | tls-pki-security 🚧 | #200 (part), #99, #129 | 17 | `api/app.py`, `api/tls.py`, `api/security.py`, `config/settings.py`, `config/tls_policy.py`, `config/models.py`, `__main__.py`, `transports/{mllp,remotefile,rest,fhir,soap,dicom}.py`, `scripts/service/install-service.ps1`, `webconsole/` | needs_adr (#200 fail-closed contract). **#200 🚧 partially built (ADR 0083 mTLS client-cert identity + #200 fail-closed off-loopback Posture-B gate, #906/#911); remaining #200 transport-refusal tail + #99 (AD/gMSA hardening) + #129 (Allow-Expired relaxation).** Solo in W8 to hold `api/tls.py`+`tls_policy.py`; waved before crypto-integrity which also touches them. |
| 9 | crypto-integrity-hardening 🚧 | #190 (part) | 8 | `store/crypto.py`, `store/base.py`, `store/store.py`, `store/postgres.py`, `store/sqlserver.py`, `store/keyprovider.py`, `transports/signing.py`, `config/settings.py`, `config/tls_policy.py`, `api/tls.py` | needs_adr. store-schema/3-backend. **#190 🚧 partially built — GCM rekey counter + HMAC-keyed audit chain shipped (#899); JWS signing remains.** Solo W9; isolated from tls-pki (W8) and the W4 `crypto.py` owner. |
| 10 | audit-log-viewer | #170, #171 | 10 | store triad, `api/auth_routes.py`, `api/auth_models.py`, `api/_ui_seam.py`, `api/app.py`, `api/models.py`, `logging_setup.py`, `config/settings.py`, `support/bundle.py`, `console/event_log_page.py`, `console/client.py`, `console/shell.py`, `console/log_viewer_page.py`, `webconsole/{pages,routes}/{audit,monitoring}.py` | 3-backend `list_audit` filter query. Additive, no ACK/engine seam. Solo W10. |
| 11 | alert-escalation-recipients-templates | #81, #146, #138 | 13 | `pipeline/alerts.py`, `pipeline/alert_sinks.py`, `config/settings.py`, `store/store.py`, `store/sqlserver.py`, `store/base.py`, `store/postgres.py`, `api/app.py`, `api/models.py`, `console/alerts_page.py` | needs_adr (#81 escalation state machine). store-schema/3-backend (#81 `alert_instance`; add `postgres.py`). First of four serialized alert waves. |
| 12 | alert-events-mute-actions | ~~#144~~→P10 · #143 | 6 | `config/settings.py`, `pipeline/alerts.py`, `pipeline/alert_sinks.py`, `pipeline/wiring_runner.py`, `api/app.py`, `api/models.py`, store triad, `console/alerts_page.py`, `console/client.py`, `webconsole/pages/monitoring.py` | needs_adr (#144 lifecycle seam). store-schema/3-backend (#143 `suspend_until`). Second alert wave; solo W12. |
| 13 | alert-test-saturation-kpi | ~~#118~~→P10 · #93 | 8 | `api/app.py`, `api/models.py`, `pipeline/alert_sinks.py`, `pipeline/alerts.py`, `config/settings.py`, `pipeline/wiring_runner.py`, `store/store.py`, `store/pool_metrics.py`, `api/metrics.py`, `console/status.py`, `console/alerts_page.py`, `webconsole/` | needs_adr (#93 saturation dimension vs declined ADR 0014). Third alert wave; solo W13. |
| 14 | cluster-ha-dr-alerts | #101 · ~~#145~~→P10 | 5 | `config/settings.py`, `pipeline/cluster.py`, `pipeline/cluster_sqlserver.py`, `api/app.py`, `api/models.py`, `pipeline/alerts.py`, `pipeline/alert_sinks.py`, `pipeline/dr.py` | needs_adr (#145 AlertSink protocol method; #101 lease-race). Both edit `cluster*.py`. Fourth/final alert wave; solo W14. |
| 15 | shared-named-queues | #130 | 9 | store triad, `config/wiring.py`, `config/models.py`, `pipeline/wiring_runner.py` | needs_adr. store-schema/3-backend; preserves per-lane FIFO, not a channel element. Owns W15 store-triad+wiring, disjoint from ai-assist. |
| 15 | ai-assist-broker | #95 | 7 | `api/app.py`, `api/models.py`, `config/settings.py`, `config/ai_policy.py`, `transports/ai_broker.py`, `auth/permissions.py`, `ide/src/{chat,aiPolicy,engineClient}.ts`, `docs/AI.md` | needs_adr (design forks). Verify any new SDK dep. Contends only on api/config hotspots → paired with shared-queues (store/wiring) in W15. |
| 16 | handler-sandbox-isolation ✅ | ~~#197~~ ✅ | 9 | `pipeline/wiring_runner.py`, `pipeline/dryrun.py`, `config/wiring.py`, `store/crypto.py`, `config/settings.py`, `docs/THREAT-MODEL.md` | **SHIPPED 2026-07-10 (ADR 0087, PR #917)** — opt-in `[sandbox]` per-inbound subprocess isolation (`mode=off` default, byte-identical; `mode=subprocess` persistent worker child). Closes the WP-L3-17 (ASVS 15.2.5) residual. Session complete. |
| 16 | log-search-presets-export | #151, #124 | 10 | store triad, `api/app.py`, `api/models.py`, `api/security.py`, `console/search.py`, `console/widgets.py`, `webconsole/routes/search.py`, `webconsole/pages/messages.py` | needs_adr (#151 preset table). store-schema/3-backend (#151). PHI-heavy mass export (#124) — keep per-view audit. Split half B; W16 is the earliest store-triad-clean slot after W7; file-disjoint from handler-sandbox. |
| ~~17~~ | ~~hl7-batch-envelope~~ → **PLAN-10 BATCH (deferred)** | ~~#134~~ | — | — | **Entire session deferred to PLAN-10's BATCH lane (ADR 0082 Accepted); W17 vacated (§E.c).** |
| 18 | file-ftp-transports | #114, #142, #111, #172 | 17 | `transports/file.py`, `transports/remotefile.py`, `pipeline/wiring_runner.py`, store triad, `config/models.py`, `config/settings.py`, `parsing/compress.py`, `pyproject.toml`, `requirements.lock`, `docs/CONNECTIONS.md` | needs_adr (#142 processed-file ledger, #111 SMB dep). store-schema/3-backend (#142). Every item edits `file.py`; own final wave — file+store+settings+pyproject all hot. |
| **19** | **ad-lab-integration-validation** (final, GATED) | #98, #99(e), #187-Kerberos, #224, #127, #65 + integration validation of the built chunk | 13 | `scripts/service/install-service.ps1`, `auth/ldap.py`, `auth/service.py`, `api/security.py`, `api/tls.py`, `docs/OFF-LOOPBACK-DEPLOYMENT.md`, `docs/security/KERBEROS-EPA-SPIKE-RUNBOOK.md`, `docs/adr/0079-*`, new `tests/integration/` + `harness/` | **Appended 2026-07-12.** Everything that can't finish in the ruff/mypy/pytest loop — needs a live AD domain rig and/or real-backend integration env. Gated on (1) the AD lab provisioned + (2) the go-live-readiness chunk (Sessions A/B/C) merged. #187 Kerberos residual moves ADR 0079 Proposed→Accepted on a green run. See the [phase doc](plan-11/w19-ad-lab-integration-validation.md). |

---

## B. Waves & sequencing

**Wave 1 (4 sessions)** — file-disjoint roots with no cross-session dependency: MLLP/TCP transport polish (owns `mllp.py`/models/api), retention+log lifecycle (owns settings+store-triad+`alerts.py` — **#120 ✅ merged #922; #122/#179 remain**), reverse-reachability analysis (owns `checks.py`/`wiring.py`/IDE graph — **✅ core merged #919**), and the zero-code ASVS scorecard decisions (owns the ASVS docs + `SECURITY.md`). Nothing here shares a file.

**Wave 2** — the metadata bag is **already shipped** (#150/ADR 0081, #894), so #169 here and #167 (W6) no longer gate on it; alongside those the auth secure-default decisions (owns W2 `config/settings.py`+`config/models.py` — **#189/#193/#203 ✅ shipped, only #98 remains**) and the IDE code-set editors (owns `__main__.py` + the editor `.ts`, waved off W1's IDE-graph touch — **#161/#175 ✅ merged #921, #162 remains**).

**Wave 3** — HL7 decode/serialize seam and the store-replay seam, split so one owns `wiring_runner.py`+models and the other owns the store triad.

**Wave 4** — HTTP-outbound proxy/header seam (owns store triad + `wiring_runner.py` this wave) with the auth audit/rotation surface (owns settings+security+service). Their file sets are disjoint.

**Wave 5** — the streaming big-bet runs effectively alone (it touches `mllp`/store/`wiring_runner`/settings, the invariant-bearing hotspots); only the file-disjoint presentation session (console display flags + theme) shares the wave.

**Wave 6** — connector/store-backend breadth (owns pyproject/lock+`sqlserver.py`) with the IDE Test Bench cluster, which **waits until W6 because #167 requires the W2 metadata bag**.

**Wave 7** — runner-lifecycle scheduling (owns settings+wiring+`wiring_runner.py`) and the uploaded-logs console page (owns `api/app.py`+webconsole search); disjoint.

**Waves 8–14 (mostly solo)** — the TLS/PKI trio (W8, **#200 🚧 partially built via ADR 0083, #906/#911**) and the crypto-integrity item (W9, **#190 🚧 partially built #899**) are serialized because they share `api/tls.py`/`tls_policy.py`/`crypto.py`; the audit-log viewer (W10); then the four alert-cluster waves (W11–W14) are held one-per-wave because `alerts.py`/`alert_sinks.py`/`config/settings.py` `AlertRule` are co-touched by every alert item.

**Wave 15** — the shared-named-queue store big-bet (owns store triad + `wiring.py` + `wiring_runner.py`) paired with the AI broker (api/config/ide only), which is file-disjoint.

**Wave 16** — handler sandbox isolation (owns `wiring_runner.py`/`crypto.py` — **✅ shipped #917, ADR 0087**) with the split-off log-search presets + PHI export session; W16 is the first store-triad-and-api-clean slot after W7, so the two split halves never share a wave.

**Wave 17** — ~~outbound batch-envelope big-bet~~ **deferred to PLAN-10 BATCH (§E.c); W17 is vacated and the W18 file/FTP cluster may advance into it.**

**Wave 18** — the file/FTP transport cluster last, because all four items edit `transports/file.py` and the ledger touches the store triad + pyproject.

**Wave 19 (final, GATED — appended 2026-07-12)** — the AD/domain-lab & integration-validation wave. It gathers the work that **cannot finish in the ruff/mypy/pytest loop**: the AD-domain-gated items (**#98** Kerberos EPA spike + SSO smoke, **#99(e)** end-to-end gMSA/Kerberos/reverse-proxy smoke, **#187** Kerberos IdP-session-lifetime residual → ADR 0079), the Windows-service-smoke item **#224** (least-priv virtual account — not domain-gated; reconcile with #99(b)), the AD-adjacent NTLM/Negotiate items **#127/#65**, and the **real-environment testing of the built or in-flight chunk** (#129 real expired-cert handshake; #170 on the SQL Server + Postgres legs; #109/#147 against a real FTP/SFTP server + a clock-driven soak; and a real pass over the prior security tails #200/#190/#123/#153). It runs **last**, gated on the AD lab being provisioned and on the go-live-readiness chunk merging. **The lab is a superset** — provisioning #99(e)'s rig (DC + AD CS + gMSA + domain-joined engine + domain-joined client + IIS/ARR proxy, plus an optional 2-node SQL AlwaysOn AG) clears #98 and #187's Kerberos tail and confirms the shipped gMSA/integrated-SQL/DPAPI/LDAPS paths (#43/#44/#100) in one stand-up.

The metadata bag (#150) **has now shipped** (ADR 0081, PR #894), so its two PLAN-11 dependents — **#169 (W2) and #167 (W6) — are unblocked** and no longer wait on a PLAN-10 lane. No other cross-session hard dependency remains.

---

## C. Contention matrix

Each hotspot file is held to **one owner per wave** (later waves may re-own it — that is the serialization). No two sessions listed for the *same* wave exist.

| Hotspot file | Owner by wave (W#:session) |
|---|---|
| `config/settings.py` | W1 log-retention · W2 auth-secure-defaults · W4 auth-audit-rotation · W5 streaming · W6 connector-store-breadth · W7 connection-lifecycle · W8 tls-pki · W9 crypto-integrity · W10 audit-log-viewer · W11 alert-escalation · W12 alert-events-mute · W13 alert-test-saturation · W14 cluster-ha-dr · W15 ai-assist · W16 handler-sandbox · W18 file-ftp |
| `config/models.py` | W1 mllp-tcp · W2 auth-secure-defaults · W3 hl7-parsing · W4 http-outbound · W5 console-display · W6 connector-store-breadth · W8 tls-pki · W15 shared-queues · W17 hl7-batch · W18 file-ftp |
| `config/wiring.py` | W1 config-reachability · W2 per-message-metadata · W3 hl7-parsing · W4 http-outbound · W7 connection-lifecycle · W15 shared-queues · W16 handler-sandbox |
| `pipeline/wiring_runner.py` | W1 log-retention (opt.) · W2 per-message-metadata · W3 hl7-parsing · W4 http-outbound · W5 streaming · W7 connection-lifecycle · W12 alert-events-mute · W13 alert-test-saturation · W15 shared-queues · W16 handler-sandbox · W17 hl7-batch · W18 file-ftp |
| `pipeline/alerts.py` | W1 log-retention (#122) · W11 alert-escalation · W12 alert-events-mute · W13 alert-test-saturation · W14 cluster-ha-dr |
| `store/store.py` (+ `base`/`sqlserver`/`postgres`) | W1 log-retention · W2 per-message-metadata · W3 message-replay · W4 http-outbound · W5 streaming · W6 connector-store-breadth (`sqlserver`) · W9 crypto-integrity · W10 audit-log-viewer · W11 alert-escalation · W12 alert-events-mute · W13 alert-test-saturation · W15 shared-queues · W16 log-search-presets · W17 hl7-batch · W18 file-ftp |
| `store/sqlserver.py` | (subset of the store-triad row above; one owner per wave) |
| `api/app.py` | W1 mllp-tcp (#136) · W2 per-message-metadata · W3 message-replay · W5 console-display · W6 ide-test-bench · W7 log-uploaded-files · W8 tls-pki · W10 audit-log-viewer · W11 alert-escalation · W12 alert-events-mute · W13 alert-test-saturation · W14 cluster-ha-dr · W15 ai-assist · W16 log-search-presets |
| `api/models.py` | W1 mllp-tcp · W2 per-message-metadata · W3 message-replay · W5 console-display · W10 audit-log-viewer · W11 alert-escalation · W12 alert-events-mute · W13 alert-test-saturation · W14 cluster-ha-dr · W15 ai-assist · W16 log-search-presets (+ W7 log-uploaded-files) |
| `console/shell.py` (main window) | W5 console-display · W7 log-uploaded-files · W10 audit-log-viewer |
| `ide/` (`*.ts`) | W1 config-reachability (graph/editors) · W2 ide-code-sets · W5 console-display (`connectionEditor.ts`) · W6 ide-test-bench · W15 ai-assist |

---

## D. Coordination rules & gotchas

- **One worktree / branch / `.venv` per session** — `scripts/worktree/new.ps1 -Name plan11-<lane>`; never share a working tree.
- **Every PR must `git merge main` first** — the CI gate hangs otherwise (branches predating the CI-gate roll-up must merge `main` or hang).
- **NO `Co-Authored-By: Claude` trailer** — the CLA bot fails on it.
- **The finishing PR carries `BACKLOG #N`** and flips that item's banner to done.
- **3-backend tests (SQLite + Postgres + SQL Server; SQL Server is the win2025 CI leg) for any store-schema touch** — required for #179, #123, #68, #149, #151, #81, #143, #130, #142, #134, #190.
- **The forbidden-content leak-gate token is a 3-place edit** — keep all three in sync or the scan job fails closed.
- **Verify order:** `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest` (`QT_QPA_PLATFORM=offscreen` for console tests).
- **New engine seams need an ADR ratified FIRST** — do not write code ahead of the ADR for the needs_adr sessions.
- **Do not weaken the at-least-once / strict-FIFO / ACK-after-ingress invariant** — most acute for streaming (#149), batch-envelope (#134), fire-and-forget (#117), shared queues (#130), and the file ledger (#142).

---

## E. Decisions, ADRs & overlaps

**(a) Sessions needing an ADR ratified before code.** mllp-tcp-outbound-delivery (#117), log-retention-lifecycle (#179), per-message-metadata-bag, auth-secure-defaults-decisions (#189, #98), ide-code-sets-editors (#162), hl7-parsing-serialization (#107), message-replay-resend, http-outbound-connectors (#68), auth-audit-rotation-rbac (#195), streaming-large-payloads, connection-lifecycle-scheduling, tls-pki-security (#200), crypto-integrity-hardening, the four alert waves (#81/#144/#143/#145/#101/#93), shared-named-queues, ai-assist-broker, handler-sandbox-isolation, hl7-batch-envelope, and file-ftp-transports (#142/#111). ADR numbers churn across sessions — **recompute the next-free number before merge**: as of 2026-07-11 the ceiling on `origin/main` is **0088** (next-free **0089**; 0081–0088 all Accepted/merged, including 0081 metadata-bag, 0082 batch, 0083 mTLS-identity, 0087 sandbox).

**(b) Near-zero-code decision items (owner calls, not builds).** **#191** — exercise the built SMART/OAuth outbound path or scope it out (a scoping call). **#205** — sign the risk-acceptance record for the four ASVS L3 residuals; the residuals stay Partial/Fail, only ownership changes. **#203** — if it resolves to a documented precondition/delegation boundary rather than a start-time check, it too is a doc/decision, not a build. These ship no runnable code; land them as scorecard/`SECURITY.md` edits, not engineering.

**(c) Reconciliation with MULTISESSION-PLAN-10 — 6 items deferred (do not double-build).** All six overlap items owned a PLAN-10 lane rather than a PLAN-11 build. **Update 2026-07-11: #150 and #134 have now actually shipped** (verified against `origin/main`); #82/#118/#144/#145 were not observed merged yet. Still never open two PRs against the same `BACKLOG #N`:

| Item | PLAN-10 lane | Status (2026-07-11) | Effect on PLAN-11 |
|---|---|---|---|
| #82 | SENDER (owns the ACK-matching fix + `mllp.py`) | not yet merged | `mllp-tcp-outbound-delivery` drops #82 → builds #97/#117/#136 and **rebases on PLAN-10 SENDER** |
| #118 | ALERTS-OPS | not yet merged | `alert-test-saturation-kpi` (W13) drops #118 → builds **#93 only** |
| #144 | ALERTS-OPS | not yet merged | `alert-events-mute-actions` (W12) drops #144 → builds **#143 only** |
| #145 | ALERTS-OPS | not yet merged | `cluster-ha-dr-alerts` (W14) drops #145 → builds **#101 only** |
| #150 | METADATA (ADR 0081) | **✅ SHIPPED #894** | `per-message-metadata-bag` (W2) builds **#169 on the shipped bag**; #167 (W6) **unblocked** |
| #134 | BATCH (ADR 0082) | **✅ SHIPPED #900** | `hl7-batch-envelope` (W17) stays **entirely deferred** — session removed, W17 vacated (delivered by #900) |

**Net:** PLAN-11 builds **65 items in 29 sessions**; the batch session is gone, and **#167 (W6) + #169 (W2) are now unblocked** by the shipped #150 bag. Of the 65 PLAN-11 items, **as of 2026-07-11: ~11 built** (#89, #120, #161, #175, #176, #152-core, #189, #193, #195, #197, #203) **+ 2 partial** (#200, #190).

**Live-worktree caution.** ~18 worktrees are active as of this update (was ~26). Every session must **re-check in-flight file ownership before starting** (`git worktree list`, `gh pr list --state all`, `git log origin/main`) — a parallel session may already own or have merged a hotspot file this plan assigns. (`origin/main` has advanced to `#919` since this plan was written.)

---

## F. Coverage appendix

Every one of the 71 items mapped to its session (id — session):

- #82 — mllp-tcp-outbound-delivery · **→ PLAN-10 (SENDER), deferred**
- #97 — mllp-tcp-outbound-delivery
- #117 — mllp-tcp-outbound-delivery
- #136 — mllp-tcp-outbound-delivery
- #120 — log-retention-lifecycle · **✅ merged #922**
- #122 — log-retention-lifecycle
- #179 — log-retention-lifecycle
- #176 — config-reachability-analysis · **✅ core merged #919**
- #152 — config-reachability-analysis · **✅ core merged #919**
- #191 — asvs-l3-scorecard-docs
- #205 — asvs-l3-scorecard-docs
- #150 — per-message-metadata-bag · **→ PLAN-10 (METADATA) · ✅ SHIPPED #894 (ADR 0081)**
- #169 — per-message-metadata-bag
- #189 — auth-secure-defaults-decisions · **✅ shipped #898**
- #193 — auth-secure-defaults-decisions · **✅ shipped #902**
- #203 — auth-secure-defaults-decisions · **✅ merged #920**
- #98 — auth-secure-defaults-decisions
- #161 — ide-code-sets-editors · **✅ merged #921**
- #162 — ide-code-sets-editors
- #175 — ide-code-sets-editors · **✅ merged #921**
- #107 — hl7-parsing-serialization
- #108 — hl7-parsing-serialization
- #89 — hl7-parsing-serialization · **✅ merged #891 (PLAN-9 W1)**
- #123 — message-replay-resend
- #153 — message-replay-resend
- #112 — http-outbound-connectors
- #127 — http-outbound-connectors
- #68 — http-outbound-connectors
- #195 — auth-audit-rotation-rbac · **✅ shipped #902/#904**
- #177 — auth-audit-rotation-rbac
- #149 — streaming-large-payloads
- #137 — console-display-flags-theme
- #164 — console-display-flags-theme
- #133 — console-display-flags-theme
- #131 — console-display-flags-theme
- #66 — connector-store-backend-breadth
- #160 — connector-store-backend-breadth
- #45 — connector-store-backend-breadth
- #84 — ide-test-bench
- #167 — ide-test-bench
- #168 — ide-test-bench
- #132 — ide-test-bench
- #109 — connection-lifecycle-scheduling
- #147 — connection-lifecycle-scheduling
- #125 — log-uploaded-files-console
- #126 — log-uploaded-files-console
- #200 — tls-pki-security · **🚧 partial #906/#911 (ADR 0083)**
- #99 — tls-pki-security
- #129 — tls-pki-security
- #190 — crypto-integrity-hardening · **🚧 partial #899**
- #170 — audit-log-viewer
- #171 — audit-log-viewer
- #81 — alert-escalation-recipients-templates
- #146 — alert-escalation-recipients-templates
- #138 — alert-escalation-recipients-templates
- #144 — alert-events-mute-actions · **→ PLAN-10 (ALERTS-OPS), deferred**
- #143 — alert-events-mute-actions
- #118 — alert-test-saturation-kpi · **→ PLAN-10 (ALERTS-OPS), deferred**
- #93 — alert-test-saturation-kpi
- #101 — cluster-ha-dr-alerts
- #145 — cluster-ha-dr-alerts · **→ PLAN-10 (ALERTS-OPS), deferred**
- #130 — shared-named-queues
- #95 — ai-assist-broker
- #197 — handler-sandbox-isolation · **✅ shipped #917 (ADR 0087)**
- #151 — log-search-presets-export
- #124 — log-search-presets-export
- #134 — hl7-batch-envelope · **→ PLAN-10 (BATCH) · ✅ SHIPPED #900 (ADR 0082)**
- #114 — file-ftp-transports
- #142 — file-ftp-transports
- #111 — file-ftp-transports
- #172 — file-ftp-transports

**Coverage: 71/71** — **65 built in PLAN-11 · 6 deferred to PLAN-10** (#82 SENDER · #118/#144/#145 ALERTS-OPS · #150 METADATA · #134 BATCH). **Progress as of 2026-07-11: of the 65 PLAN-11 items, ~11 built (#89, #120, #161, #175, #176, #152-core, #189, #193, #195, #197, #203) + 2 partial (#200, #190); both deferred ADR-Accepted items (#150, #134) have shipped.**
