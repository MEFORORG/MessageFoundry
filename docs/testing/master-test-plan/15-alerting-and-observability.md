[← Master Test Plan index](../MASTER-TEST-PLAN.md) · *Part II — Subsystem chapters*

---

## 14. Alerting & Observability

**ID prefix:** `ALERT` · **Surface:** engine + web console + IDE + CLI + infra
· **Primary risk:** the alert vocabulary, its operator-routable set, and its emit sites are bound by
convention only — so a signal can exist, fire, and still be unroutable, unclearable, or leak free text
off-box, and nothing in CI notices.

### 14.1 Scope & objectives

**In scope — Alerting.** The ADR 0014 rules engine (`AlertRuleSet.decide` matcher, first-match-wins,
per-rule severity/transport-subset/cooldown/suppress, `mute`, `recipients`, `id`, `control_action`/
`control_target`, `escalate` tiers, `schedule`, `content_label`) and its five amendments; the
`AlertSink` Protocol ([`pipeline/alerts.py:27`](../../../messagefoundry/pipeline/alerts.py) — **20** public
methods) + its `LoggingAlertSink` fallback (same file, `:231`, the same 20) and the **separate**
`NotifierAlertSink` ([`pipeline/alert_sinks.py:578`](../../../messagefoundry/pipeline/alert_sinks.py) — a
different class: 35 defs, 27 public = those 20 emit methods + `content_match` + six sink-lifecycle
methods; do not conflate its count with the Protocol's);
the **18**-member operator-routable set `_ALERT_EVENT_TYPES`
([`config/settings.py:2499-2526`](../../../messagefoundry/config/settings.py) — `lane_stuck` (`:2515`)
and `rcsi_off_degraded` (`:2516`) **are** members, see 14.2); the webhook and SMTP
transports and their failure behaviour; ADR 0127 email templates; ADR 0044 durable
`alert_instance` ack/mute(suspend)/resume/resolve lifecycle and auto-resolve inverses; ADR 0128
control actions; the emit sites in `wiring_runner.py`, `stage_dispatcher.py`, `cert_expiry.py`,
`secret_rotation.py`, `update_check.py`, `gcm_invocations.py`, `retention.py`, `dr_backup.py`,
`dr.py`, `cluster.py`, `cluster_sqlserver.py`, `integrity.py`, `engine.py`, `reference_sync.py`,
`state_convergence.py`; `POST /alerts/test-email`; `GET /alerts/rules`; the
`messagefoundry alert list|add|remove` CLI + [`config/alerts_edit.py`](../../../messagefoundry/config/alerts_edit.py);
the web console `/ui/alerts` page + nav bell; the VS Code alert editor
([`ide/src/alertEditor.ts`](../../../ide/src/alertEditor.ts)); alert-storm behaviour; alert delivery across a
failover; and **PHI leakage in alert payloads (metadata-only by contract)**.

**In scope — Observability.** Prometheus `GET /metrics` and the OpenTelemetry seam
([`api/metrics.py`](../../../messagefoundry/api/metrics.py)) — **`/metrics` label cardinality and scrape cost
are owned here** (ALERT-40 / ALERT-61; the API chapter's `API-54` is a pointer row to them, no separate
work scoped there); `GET /stats`, `GET /metrics/history`,
`GET /graph/edges`, `POST /statistics/reset` and the `/ws/stats` socket; stdlib logging
([`logging_setup.py`](../../../messagefoundry/logging_setup.py)) — the three PHI filters, levels, JSON format,
syslog UDP/TCP/TLS off-box forwarding, NSSM capture + `AppRotateBytes` rotation; runtime verbosity
(`GET`/`PATCH /logging/level`) and the redacted `GET /logs/tail` (ADR 0130); the support bundle
([`support/bundle.py`](../../../messagefoundry/support/bundle.py), [`support/redact.py`](../../../messagefoundry/support/redact.py));
Windows crash-dump suppression ([`crashdump.py`](../../../messagefoundry/crashdump.py), ADR 0152); the
`connection_event` log (ADR 0021 §7); the cluster observability API (ADR 0008); and the
cross-cutting question **can an operator actually detect each failure mode the other chapters
inject**.

**ID convention (plan-wide).** A bare `ALERT-nn` / `G-nn` in this chapter is **this plan's own row**.
Every reference to another document's ID carries a prefix: **`FCP:`** for a
[`docs/testing/FEATURE-COVERAGE-PLAN.md`](../FEATURE-COVERAGE-PLAN.md) gap ID and **`W25:`**
for a WIN2025 plan/matrix test ID. The collision is real, not hypothetical: FEATURE-COVERAGE-PLAN §19
has its own `FCP:ALERT-1..FCP:ALERT-24` (different subjects from ours) and the WIN2025 matrix has a
`W25:G4` that is not this chapter's G4 risk.

**Explicitly NOT in scope here.**

| Area | Owner — cite, do not restate |
|---|---|
| The 24-row subsystem coverage-gap audit `FCP:ALERT-1..FCP:ALERT-24` (six dimensions, per-feature verdicts) | [`docs/testing/FEATURE-COVERAGE-PLAN.md` §19, lines 1300-1341](../FEATURE-COVERAGE-PLAN.md) — this chapter **supersedes four stale rows** (see 14.2) and otherwise inherits it |
| The PHI posture of every log/alert stream (14 rows: format, sink, ACL, retention, PHI class) | [`docs/PHI.md` §7 "Logging inventory (16.1.1 / 16.2.3)", rows 1-14](../../PHI.md) — CI-guarded by `tests/test_phi_logging_inventory.py` |
| Windows Server 2025 host/service-identity acceptance (NSSM install, gMSA, ACLs, reboot autostart) | [`docs/testing/WIN2025-TEST-PLAN.md`](../WIN2025-TEST-PLAN.md) + [`WIN2025-TEST-MATRIX.md`](../WIN2025-TEST-MATRIX.md). **Note:** the whole WIN2025 estate contains exactly one alerting row — matrix row `W25:G4` "/cluster observability + alerts + dead-letters page", claimed ONCE, `Coverage.PYTEST`, delegated to `tests/test_cluster.py` + `tests/test_alert_rules.py` ([`harness/acceptance/matrix.py:454-462`](../../../harness/acceptance/matrix.py)). The WIN2025 plan itself has **zero** occurrences of "alert". The host-side alerting rows below are therefore **new**, not duplicates |
| On-box deployment acceptance (`messagefoundry verify` host/store/smoke/manual/federation sections) | [`docs/testing/VERIFY.md`](../VERIFY.md) — it has no alerting or logging section; nothing here duplicates it |
| Load generation mechanics, profiles, governor, SLO verdicts | [`docs/LOAD-TESTING.md`](../../LOAD-TESTING.md) — this chapter only *consumes* the `connscale` / `sustained-overload` profiles |
| Cluster leadership/lease/failover mechanics themselves | the HA/DR chapter — here only the **alerting behaviour across** a leadership move |
| ADR 0020 raw-frame Protocol Data / Protocol Text capture | **declined** — ADR 0020 is "Superseded (raw-frame scope) 2026-07-13"; the metadata subset shipped as the ADR 0021 §7 `connection_event` log. The supersede decision is already carried in FEATURE-COVERAGE-PLAN `FCP:ALERT-22`/`FCP:MLLP-22` (lines 371/400/537). No test rows |

**Objective.** Prove three things: (1) an operator can be **told** about every failure the product
can suffer, (2) the telling is **routable, suppressible and clearable** by rule and by hand, and
(3) nothing in the telling carries PHI off the box.

### 14.2 Already covered — do not re-test

| Evidence | What it proves |
|---|---|
| `tests/test_alert_rules.py` (422 lines, ~28 cases) | `AlertRuleSet` matcher: event-type / connection glob / `min_depth` / `min_oldest_seconds` / AND-conjunction / first-match-wins / case-sensitive glob; severity tag; transport subset; `[]` suppression; cooldown override; factory fail-loud on an unconfigured transport; model validation. Lines 357/370/381/395 pin `lane_stuck`, `rcsi_off_degraded` and `bootstrap_admin_expiring` as rule-targetable end to end |
| `tests/test_alert_sinks.py` (342 lines, 22 cases) | Fan-out to every transport; one failing transport does not starve the others; re-alert throttle; suspend / resume / window-expiry; per-rule mute; the no-message-body payload assertion; webhook JSON POST; SMTP send; SMTP allowlist refusal; `notifier_from_settings` variants; webhook URL length bound |
| `tests/test_alert_state.py` (548 lines) | ADR 0044 lifecycle: first-fire open, refire dedupe on the throttle key, ack / resolve / reopen, auto-resolve on an inverse, `count_open_by_connection`, `reason` encrypted at rest, purge resolved-only, `escalation_tier` persisted monotonic, suspend/resume durable, side-observer never pins a disposition, a state-write failure never raises, three-backend method + column parity |
| `tests/test_alert_escalation.py` (211 lines) | ADR 0133 AC-1..AC-4: occurrence escalation, highest-satisfied-tier wins, schedule-aware `decide`, `content_label` routing, `content_match` PHI-free payload, `content_match` re-emit idempotence — **all at the sink, none through a Handler** (see gap G2) |
| `tests/test_alert_templates.py` (261 lines) | ADR 0127: renderer values `==` `_ALERT_TEMPLATE_VARS`; unknown / attribute / index / format-spec / empty placeholders rejected fail-closed; escaped braces literal; HTML value escaping; subject CRLF header-injection strip; `rule_id` reaches email but not the webhook |
| `tests/test_alert_recipients.py` (168 lines) | #146: `decide` carries the override; it reaches `EmailTransport`; it NEVER reaches the webhook payload; empty `[]` rejected at config load; `None` = global `email_to` |
| `tests/test_alert_control.py` (190 lines) | #144 / ADR 0128: action whitelist, default vs explicit target, throttled with the notification, fires even when the notification is suppressed, never raises, no-callback no-op, callback maps to `RegistryRunner` restart |
| `tests/test_alert_failover.py` (386 lines) | #145: leadership/DR events rule-targetable; inverses are NOT alert types; `_AUTO_RESOLVE` pairs; `LoggingAlertSink` transitions; fan-out; inverses do not notify but do auto-resolve; `DbCoordinator` acquired-once / lost-on-takeover / self-fence / clean-release; `SqlServerCoordinator` lockstep; `DrCoordinator` activate/release |
| `tests/test_api_alerts.py` (292 lines) | `/alerts/active` + ack + resolve + suspend + resume round-trips; `alerts_active` open count; `monitoring:diagnose` gate; per-channel scope; out-of-scope refusal with no mutation |
| `tests/test_alerts_rules_api.py` (255 lines) | `GET /alerts/rules` view shape; never leaks SMTP password / recipients / webhook URL; defaults when unset; `monitoring:read` gate; lifespan plumbs `alerts_settings` |
| `tests/test_alerts_test_email.py` (304 lines) | #118: PHI-free success; scrubbed failure (not a 500); not-configured refusal; host-outside-allowlist clean failure; recipient override; `service:configure` gate; metadata-only `alert_test_email` audit row |
| `tests/test_alerts_edit.py` (217 lines) | TOML editor: add / list / remove-by-index; an invalid rule is not persisted; comments + siblings survive; byte-stable rollback on a failed add; unknown-key rejection; the #234 (above the published #231 baseline) schema-drift parity guard `set(_RULE_FIELDS) == set(AlertRule.model_fields)` at `:153` plus its falsifiability check at `:160` |
| `tests/test_asvs_phase0.py:158-190` | Webhook egress hardening: non-`http(s)` scheme rejected; plaintext `http` refused by default; allowed under `MEFOR_ALLOW_INSECURE_TLS`; host outside `webhook_allowed_hosts` refused inside `_post`; `_NoRedirectHandler` refuses a 3xx |
| `tests/test_saturation.py` (8 cases) | `SaturationDetector` purity: fires on a sustained rising backlog, NOT on a bursty-but-draining lane, not before the window primes; flat/dip suppression; bounded window; reset; `sustain_samples` floor |
| `tests/test_cert_expiry.py` (17+ cases) | `CertExpiryRunner`: healthy / near / expired / boundary; missing + unparseable skipped; one bad cert does not block others; registry enumeration including client certs with distinct labels; disabled at `warn_days=0`; logging + notifier sink emit |
| `tests/test_secret_rotation*.py` (4 modules) | Reminder emission, warn window + boundary, deny-by-default tracking, notifier event, server-backend rotation metadata |
| `tests/test_update_check.py` | ADR 0026: version compare; alert only on a newer pinned version; no-pinned no-alert; settings validation; `update_available` membership in `_ALERT_EVENT_TYPES`; PHI-free payload; immediate first pass |
| `tests/test_postgres_store.py:3367-3436` + `tests/test_sqlserver_store.py:3392+` | **FEATURE-COVERAGE-PLAN `FCP:ALERT-19` is CLOSED**: `alert_instance` upsert / dedup / ack / get / resolve / reopen / `resolve_for` / `count_open` / purge executed **live** on real Postgres and real SQL Server — not a DDL string-parse |
| `tests/test_phi_logging_inventory.py` (762 lines) | `docs/PHI.md` §7 parity **derived from code**: every `_ALERT_EVENT_TYPES` member named (`:424`); auto-resolve inverses described accurately including the dead `connection_started` key (`:436`); `LoggingAlertSink` no-ops disclosed (`:683`); every alert broadcast transport has a row (`:597`); support-bundle stream inventoried (`:616`); `connection_event` vocabulary derived from emit sites (`:361`); log sinks == the documented set (`:580`) |
| `tests/test_metrics_exporter.py` (365 lines) | Parseable Prometheus exposition; never leaks PHI; latency histogram cumulative + negative clamp; `gather_snapshot` aggregates; pool saturation emit/absent; store cost counters; `monitoring:read` gate; the OTel seam records without PHI |
| `tests/test_logging.py` (784 lines) | Single stdout handler; idempotent config; uvicorn routing; hl7 PHI-logger silencing; `RedactionFilter` over message + chained traceback + `stack_info` + bare field runs; prod-DEBUG refusal; JSON formatter one-object-per-line + redaction; off-box forwarder wiring; TLS syslog context / CA / client-cert + unreachable-collector tolerance; SNTP offset + fail-closed time-sync gate |
| `tests/test_logging_surfaces.py` (258 lines) | #171 / ADR 0130: `set_runtime_level`; `GET`/`PATCH /logging/level` with audit + 400 on a bad level + `monitoring:diagnose` gate; `/logs/tail` redaction + `logs_view` audit + pagination-from-the-end + graceful degrade + `logs:view` gate |
| `tests/test_support_bundle.py` (236 lines) | Bundle members; manifest/version; real status models; config summary counts-only; broken-config error member; redacted log tail; HL7 segment + `MEFOR_*` + name/DOB redaction; store-path basename/backend-only redaction |
| `tests/test_crashdump_suppression.py` (120 lines) | ADR 0152: never raises; no-op off Windows; error mode ORed not replaced; WER flags set; residual names machine policy; claims nothing about ASVS 11.7.1; memory-lock probe honesty |
| `tests/test_diagnostics.py` (53 lines) | `log_note` redacts every value by default, reveals only under the dev flag, a bad template never raises; checkpoint logs segment ids not field values |
| `tests/test_metrics_history_graph.py`, `test_host_metrics.py`, `test_load_metrics.py`, `test_stats_reset.py`, `test_ws_stats_revalidation.py` | Metrics-history ring dedupe/bounds + endpoint; `/graph/edges`; host gauges present + absent-psutil; load histogram/rate/correlator maths; per-connection stats reset + RBAC/scope/audit; `/ws/stats` revoked / disabled-session prompt close |
| `tests/test_connection_event_{emit,store,api,scope,outbound}.py` (883 lines) | ADR 0021 §7 `connection_event` log: emit vocabulary, store round-trip, `/events` + `/connections/{name}/events`, per-channel scope, outbound `connection_lost`/`restored` |
| `tests/test_cluster*.py` (5 modules) | ADR 0008 `/cluster/status` + `/cluster/nodes`; leadership lease + self-fence; live failover on both server backends |
| `tests/test_security_notify.py` (88 lines) | Per-user security-event SMTP notifier: factory with/without SMTP; emails the affected user; skips no-email users; swallows a send failure |
| `packaging/messagefoundry-webconsole/tests/test_webui.py:1325-1410`, `:896-916`, `:1551` | `/ui/alerts` renders for an operator; requires `monitoring:diagnose`; redirects unauthenticated; a hostile alert `reason` is escaped not live markup; the nav alerts bell is present and ordered; the ack POST path pattern |
| `.github/workflows/ci.yml` jobs `test` (`:41`), `sqlserver-store` (`:483`), `postgres-store` (`:732`), `windows-service-smoke` (`:1081-1259`), `ide` (`:263`) | The full pytest suite including every `tests/test_alert*.py` and the webconsole suite; mypy strict over `messagefoundry` + `messagefoundry_webconsole` (`:194`); the live-backend legs that execute the ADR 0044 lifecycle; NSSM install reaching Running + serving `/health` + MLLP with `service.out.log`/`service.err.log` captured and uploaded; the `@vscode/test-electron` + mocha harness on ubuntu + windows |

**Done — do not re-plan.** The **rules matcher**, **template renderer**, **per-rule recipients**,
**control-action dispatch**, **escalation-tier arithmetic**, **schedule gating**, **ADR 0044 durable
lifecycle on all three backends**, **webhook egress hardening**, **alert-state PHI-at-rest
encryption**, **the alert-rule TOML editor's schema-drift guard**, **`/alerts/*` RBAC + per-channel
scope**, **`/metrics` PHI-free exposition**, **the three logging PHI filters**, **`/logs/tail`
redaction + audit**, and **crash-dump suppression** are all covered by execution, not by inspection.
Nothing below re-asserts them.

**Four FEATURE-COVERAGE-PLAN §19 rows are superseded as of 2026-07-29** (re-verified against the
tree; carry the correction here, leave that document as a historical artifact):

| Stale row | Re-verified status |
|---|---|
| `FCP:ALERT-4` (line 483: webhook http/SSRF/3xx refusal "partial", P3) | **CLOSED** by `tests/test_asvs_phase0.py:158-190` |
| `FCP:ALERT-12` (lines 431/1319/1341: `lane_stuck` + `rcsi_off_degraded` "absent from `_ALERT_EVENT_TYPES`", P0) | **CLOSED** — both are members at [`settings.py:2515-2516`](../../../messagefoundry/config/settings.py) with rule-targetable tests at `test_alert_rules.py:357/370/395`. The auditor note at line 11 and its `settings.py:1755` line reference are stale (the constant is now at `:2499`) |
| `FCP:ALERT-19` (line 438: three-backend parity "structural only", P1) | **CLOSED** by live execution on both server backends |
| `FCP:ALERT-24` (line 1331) | Cites `tests/test_console_alerts.py`, which **no longer exists**; the PySide6 console is retired. The live surface is `/ui/alerts`, covered by the webconsole suite |

`FCP:ALERT-3` (queue-full drop path), `FCP:ALERT-5` (Vault→SMTP password), `FCP:ALERT-9`/`FCP:ALERT-10`
(runner emit sites) remain **open** and are carried forward below as this plan's ALERT-19, ALERT-22,
ALERT-13 and ALERT-11.

### 14.3 Risk analysis

| Risk | Failure mode | Blast radius | Detected today? | Priority |
|---|---|---|---|---|
| **G1 — three alert vocabularies bound only by convention** | An emit site's `type` literal, `_ALERT_EVENT_TYPES`, and the `AlertSink` Protocol / `LoggingAlertSink` / `NotifierAlertSink` method sets drift. A type absent from the routable set can never be escalated, routed, suppressed or muted by any operator rule; a method present only on `NotifierAlertSink` raises `AttributeError` on the logging fallback | Every deployment. Drift has fired **twice** already: `lane_stuck` + `rcsi_off_degraded` once shipped unroutable — **both are members today** ([`settings.py:2515-2516`](../../../messagefoundry/config/settings.py)), rule-targetable end to end at `test_alert_rules.py:357/370/395`, so the only live drift is that no guard stops the next one; `content_match` is **still** divergent (only on `NotifierAlertSink` at [`alert_sinks.py:676`](../../../messagefoundry/pipeline/alert_sinks.py), absent from the Protocol and the fallback). Note the non-obvious third form: `AlertSink.saturation_rising()` emits type `"saturation"` — method name ≠ event type, so a naive guard would false-fail | **No.** No guard exists in either direction | **P0** |
| **G2 — `content_match` has no Handler-reachable surface** | ADR 0133 AC-3 says "WHEN a Handler emits a `content_match`" — but there is no export in `messagefoundry/__init__.py` (unlike `db_lookup`/`fhir_lookup` at lines 32-33/150/153), no injected sink on a Handler context, and no dry-run path. Every test calls `sink.content_match(...)` directly | The differentiating Corepoint "Action Point" parity capability is unusable in practice; the PHI-free-by-contract guarantee has never been exercised through real Handler code | **No** — AC-3/AC-4 pass at the sink so nothing fails | **P0** |
| **G3 — `connection_started` is mapped but emitted nowhere** | `_AUTO_RESOLVE["connection_started"] = "connection_stopped"` ([`alert_sinks.py:100`](../../../messagefoundry/pipeline/alert_sinks.py)) but a repo-wide search finds **no emit site**. A lane that STOPs on an internal error and is later restarted (by hand or by a #144 `control_action`) leaves its `alert_instance` permanently `open` | `alerts_active` on the connections dashboard stays non-zero forever; `/alerts/active` accumulates; the nav bell's `list_active_alerts(limit=200)` ([`webconsole/routes/status.py:166`](../../../messagefoundry_webconsole/routes/status.py)) saturates. Textbook alert fatigue — the operator learns to ignore the list and the next real stop is missed | **Partially** — `tests/test_phi_logging_inventory.py:439` *documents* the dead key; nothing asserts the operator consequence | **P0** |
| **G4 — CLOSED by #323 (2026-08-02). The alert/security-notify SMTP hop is VERIFIED.** This row asserted the hop was encrypted but unauthenticated and that `docs/PHI.md` and `docs/BACKLOG.md` contradicted each other about it. **Both halves are false at HEAD** and were already false when this plan was written (BACKLOG #1100). | `send_plain_email` builds an explicit verifying context via `tls_policy.build_smtp_tls_context()` and passes it — `smtp.starttls(context=tls_context)` ([`alert_sinks.py:430-431`](../../../messagefoundry/pipeline/alert_sinks.py)), whose comment reads *"context= is REQUIRED (#323): starttls()'s own default verifies NOTHING"*. The `CERT_NONE`/`check_hostname=False` text at `:387-388` is a **historical note about the fixed defect**, not the current posture — reading it as current is the mistake this row made. | — | **Yes.** `docs/PHI.md` row 11 states the verifying posture and records the pre-#323 state explicitly as history; `tests/test_alert_smtp_tls.py` exists with 21 tests. The documents agree with the code and with each other. | **CLOSED** |
| **G5 — `[alerts]` is startup-only** | `app.state.alerts_settings` is assigned only at app construction ([`api/app.py:1120`](../../../messagefoundry/api/app.py)) and lifespan startup (`:5485`). `POST /config/reload` (`:2741`) re-runs the `--config` graph, never the service-settings TOML | An operator adds a suppression rule mid-incident via the IDE or `messagefoundry alert add`; the IDE re-lists from the **file** and shows it; `/alerts/rules` still shows the **startup** set; the running notifier keeps paging until a restart. The requirement is documented only in `alerts_edit.py:19-21` and the CLI docstring — nowhere an operator looks | **No** | **P0** |
| **G6 — IDE alert editor offers 4 of the 18 event types and 7 of the 15 fields** | [`ide/src/alertEditor.ts:13-19`](../../../ide/src/alertEditor.ts) offers a 5-entry dropdown — `any` plus only `connection_stopped`/`queue_buildup`/`storage_threshold`/`cert_expiry`; `:25-32` supports only `event_type`/`connection`/`min_depth`/`min_oldest_seconds`/`severity`/`transports`/`cooldown_seconds` (7 of the 15 `AlertRule` fields). `ide/src/test/suite/` has **no** alert test file (35 suites, none for the alert editor) | An operator on the supported GUI authoring path cannot rule on **14 of the 18** signals, nor set `id`, `recipients`, `mute`, `escalate`, `schedule`, `content_label`, `control_action`, `control_target` | **No** — the `ide` CI leg runs and tests nothing here | **P1** |
| **G7 — no end-to-end drive of the runner's buildup / stall / saturation emit sites** | `_maybe_alert_buildup` (`:5401`), `_maybe_alert_saturation` (`:5444`), `_maybe_alert_stall` (`:5511`) in `wiring_runner.py`. Only the pure `SaturationDetector` and the **engine-shard** non-owned-lane watchdog are tested | These are the three alerts an operator relies on to notice a stalled or drowning feed. Threshold resolution, the `_outbound_paused` suppression guard, the per-`(stage,lane)` `_BUILDUP_REALERT_SECONDS` throttle and the `pending_depth` read could all break silently | **No** — FEATURE-COVERAGE-PLAN `FCP:ALERT-10` flagged it and it is still open | **P1** |
| **G8 — the alert-storm bound is untested** | `_MAX_QUEUE = 1000` with drop-with-warning ([`alert_sinks.py:126-131`](../../../messagefoundry/pipeline/alert_sinks.py)). With a wedged webhook (a hung POST inside the 10 s timeout) and a large estate, a burst silently exceeds the bound and the excess is dropped with only a `WARNING` — there is **no dropped-alert counter or metric** | The operator sees neither the alerts nor a countable drop signal. A regression that lowers the bound, blocks the drain loop, or turns the drop into a *stall* on the emitting delivery worker is invisible | **No** — `tests/test_communications_inventory.py:372` pins `_MAX_QUEUE` as documentation only | **P1** |
| **G9 — post-failover / post-restart re-page volume is unbounded and untested** | `_last_sent` (throttle) and `_occurrences` (escalation counter) are per-node, in-memory and **not** primed from the store — only `_suspended` is (`prime_suspensions`, `:873`) | On an HA leadership move, a DR promotion, or an ordinary restart, the new node re-pages **every** open condition at once and every escalation tier resets to base, so a long-running critical drops back to warning. ADR 0014 §4 (lines 91-92, 117) records this as accepted — but nothing bounds it and nothing tests it | **No** | **P1** |
| **G10 — no boundary assertion that every emit site's `detail`/`reason` is PHI-scrubbed** | `docs/PHI.md` row 10: the webhook carries this free text "`safe_exc()`-scrubbed at the emit sites, but **not** re-run through `safe_text` on this path". The scrub is a convention across ~20 scattered call sites | One new emit site passing `str(exc)` instead of `safe_exc(exc)` sends an HL7 fragment straight off-box to a third-party webhook (Slack/Teams/PagerDuty) — no store, no ACL, no audit. **Silent**: the `alert_instance.reason` IS `safe_text`'d at the store, so an at-rest test passes while the wire payload leaks | **No** | **P1** |
| **G11 — outbound saturation blind spot** | `_maybe_alert_saturation` is reached only from `_maybe_alert_buildup`, which runs on the delivery-failure/retry tick — a **healthy-but-behind** outbound (delivering successfully while its backlog climbs) is never sampled. ADR 0014 amendment records it as the "BACKLOG #93 residual" | The single most common real overload — a downstream that is slow but not failing — produces no saturation page, while an operator who opted in believes they are covered | **No** — the known non-coverage is documented but not pinned, so a refactor could widen or narrow it unnoticed | **P1** |
| **G12 — four periodic alert runners are not leader-gated** | `cert_expiry.py`, `secret_rotation.py`, `update_check.py`, `gcm_invocations.py` have no `is_leader()` call; only `retention.py:357/:380` does. `gcm_invocations.py:28-29` documents its non-gating *for block refill*, which is a different question from the alert | In an N-node active-passive cluster each node independently observes the **same cluster-wide facts** (a cert file, the DEK rotation age, the installed version, the shared DEK invocation count) and pages every cooldown — N duplicate pages per condition, plus N `alert_instance` upserts contending on `ux_alert_instance_open`. ADR 0014 §4's per-node reasoning covers *lane* events, not these | **No** | **P1** |
| **G13 — `support/redact.py` has no adversarial corpus test** | `tests/test_support_bundle.py:93-234` asserts ~7 shapes. The module is a small `re` pass plus the shared `messagefoundry.redaction.redact`; its stated residual is the single-token identifier | The support bundle is the **one** stream designed to leave the box, and `docs/PHI.md` row 14 records it carries **no RBAC, no audit row, no retention** — the operator emails it to a third party. A missed residual is an unlogged, uncontrolled PHI disclosure | **No** — the residual is stated but never measured | **P1** |
| **G14 — no cross-surface alert-rule parity check** | Three views of one rule set: `/alerts/rules` (startup `app.state`), the IDE editor list (the TOML **file**), and `/ui/alerts` (rendering `/alerts/rules`). During the restart window they disagree **by construction** (G5) | An operator confirming "the suppression rule is in place" in the IDE while the engine still pages is a real incident-time failure. Nothing detects or signals the divergence | **No** | **P1** |
| **G15 — an alert-triggered `control_action` writes no audit row** | `_dispatch_control` ([`alert_sinks.py:1039`](../../../messagefoundry/pipeline/alert_sinks.py)) fires the injected callback and only logs on failure; `_alert_control` at [`api/app.py:5469`](../../../messagefoundry/api/app.py) has no `record_audit` | A rule can restart a production inbound or outbound automatically with **no** entry in the tamper-evident audit chain. Every other connection-control path in the API is audited | **No** | **P2** |
| **G16 — never-resolved `alert_instance` rows grow without bound** | Retention purges **RESOLVED** rows only (`docs/PHI.md` row 8: "an open or acknowledged condition is never aged out from under an operator"). With G3, open `connection_stopped` rows accumulate permanently | The `ux_alert_instance_open` partial unique index and every `/alerts/active` read carry them forever; the nav bell caps at 200 so the count silently understates | **No** — no growth or soak test | **P2** |
| **G17 — OpenTelemetry export is smoke-only** | `tests/test_metrics_exporter.py:345` records against an in-process provider. No OTLP collector round-trip; no CI leg exercises the `[otel]` extra present **or** absent (the guarded-import `RuntimeError` at [`api/metrics.py:463-465`](../../../messagefoundry/api/metrics.py)) | `[otel]` is an advertised capability (`docs/FEATURE-MAP.md:159`). A broken export or a wrong resource/attribute set regresses silently while the default Prometheus path keeps passing | **No** | **P2** |
| **G18 — NSSM log rotation is never asserted** | `scripts/service/install-service.ps1:456-458` sets `AppRotateFiles 1` / `AppRotateOnline 1` / `AppRotateBytes 10485760`; the `windows-service-smoke` leg only captures and uploads the logs (`ci.yml:1239-1259`) | The app log is the **sole** sink for PHI.md stream 1 (the engine installs no file handler) and the source of `/logs/tail` and the support bundle. If rotation stops, the volume fills or the tail becomes unusable — precisely during an incident | **No** — `[retention].app_log_days` deletion and `app_log_compress_days` gzip are unit-tested but never on a real Windows service | **P2** |
| **G19 — `/metrics` has no cardinality or scrape-cost bound** | `gather_snapshot` does per-scrape store reads; exporter tests use a handful of connections | A 200+ connection estate on a 15 s Prometheus scrape adds measurable store load, and an unbounded label set (connection × destination × status) can blow up a TSDB | **No** | **P2** |
| **G20 — off-box log forwarding has no live-collector round-trip** | `tests/test_logging.py:371-660` covers handler construction, TLS context, CA anchoring, client cert and unreachable-collector tolerance — nothing asserts a record **arrives**, correctly framed, at a collector | This is the SIEM evidence path (`docs/PHI.md` rows 3/4). An RFC 5425 length-prefix or framing regression means audit rows silently never reach the SIEM while the engine reports nothing wrong | **No** | **P2** |
| **G21 — the notifier is constructed only on the `serve` path** | `notifier_from_settings` is called once, in the `create_serve_app` lifespan ([`api/app.py:5316-5318`](../../../messagefoundry/api/app.py)). Any other engine path (embedded `Engine`, `messagefoundry check`, dryrun, most tests) silently runs on `LoggingAlertSink` | A future deployment mode or a lifespan reorder would leave a production engine with no webhook/email notifier and only `WARNING` log lines | **No** — nothing asserts the runner's sink identity after a `serve` lifespan | **P2** |
| **G22 — no bounded-latency assertion that a new alert reaches an operator surface** | The nav bell + `/ui/alerts` are poll-driven (`/ui/nav-status` ~every 15 s, [`webconsole/routes/status.py:128`](../../../messagefoundry_webconsole/routes/status.py)); `/ws/stats` pushes queue counts, **not** alerts | An operator watching the console can be a poll interval behind a stopped connection with no indication the view is stale | **No** — the webconsole tests assert rendering and RBAC, not freshness | **P2** |
| **G23 — three ledger/catalog documents lie about this area** | `docs/FEATURE-MAP.md` §9 lists 8 rows and omits ADR 0044 alert state, escalation, templates, per-rule recipients, control actions, **16 of the 18** event types (§9 names only `connection_stopped` and `queue_buildup`), the support bundle, crashdump suppression, the `connection_event` log, `/logs/tail`, `/metrics/history` and host metrics; §10 is still titled "Surfaces — Admin Console (PySide6)" with an Alerts page row at `:172`, and `:131` asserts "The PySide6 desktop console stays (additive)" though `messagefoundry/console/` does not exist. `docs/BACKLOG.md` #171 (lines 5768-5780) still banners DEMAND-GATE and states "there is no runtime/per-area verbosity control and no interactive in-console log viewer" — both are BUILT | FEATURE-MAP reaches the **public mirror** (`tests/test_feature_map_claims.py:3`). It understates the shipped alerting surface and overstates a retired one; the BACKLOG lies about build state — exactly what `backlog-hygiene.yml` exists to prevent | **No** — the existing guard tests links and ASVS score claims, not row currency | **P2** |

### 14.4 Test matrix

**Row class (`Cls`, plan-wide).** **T** = *Test* — a falsifiable assertion with an observable pass
criterion; **only T rows count toward the release gate**. **C** = *Characterisation* — produces a
recorded measurement, finding or documented decision with no threshold yet; legitimate work, but it
**cannot fail**, so it never gates a release, and it becomes a T row the day its threshold or
decision is recorded. **A** = *Assurance* — an external engagement (penetration test, third-party
review, DAST), blocking only for an off-loopback / production-exposure release and excluded from the
ordinary P0 count.

This chapter has **68 rows — 64 T, 4 C (ALERT-56, 61, 62, 63), 0 A**. Among the **T** rows, **12 are
P0** (ALERT-01..10, 58, 67), 25 are P1 and 27 are P2. The four C rows are all manual real-estate
observations whose falsifiable halves are carried by T rows (ALERT-18/40/41 and ALERT-19/20/21/68).

| ID | Test | Type | Method | Env | Backend | Cls | Pri | Pass criteria |
|---|---|---|---|---|---|---|---|---|
| ALERT-01 | Alert-vocabulary mirror invariant: every `type` literal emitted by a `NotifierAlertSink` method is in `_ALERT_EVENT_TYPES` or in `_AUTO_RESOLVE` | Functional | pytest | dev-PC | n/a | T | P0 | AST-walk `alert_sinks.py`; collect every `"type": <literal>` in a `self._emit({...})` / `self._record_state({...})` call. Each literal is in `_ALERT_EVENT_TYPES ∪ set(_AUTO_RESOLVE)`. The set of emitted-and-routable literals equals `_ALERT_EVENT_TYPES` exactly (currently **18** members, [`config/settings.py:2499-2526`](../../../messagefoundry/config/settings.py)). `saturation_rising` → `"saturation"` is asserted by name so the method-name≠type case is pinned, not a false failure. A planted extra emit type fails the test |
| ALERT-02 | Alert-vocabulary mirror invariant: the three classes expose identical public method sets | Functional | pytest | dev-PC | n/a | T | P0 | `{m for m in dir(AlertSink) if not m.startswith("_")}` == the same for `LoggingAlertSink` == the emit-method subset of `NotifierAlertSink` (excluding the sink-lifecycle methods `start`/`aclose`/`set_store`/`set_control_callback`/`suspend`/`resume`/`forget`/`prime_suspensions`, named explicitly as an allowlist). Test **currently FAILS** on `content_match` — record the failure as the acceptance evidence for the G2 decision, then make it pass by whichever way OQ-1 resolves |
| ALERT-03 | `LoggingAlertSink` fallback survives every emit the runner can make | Negative/Security | pytest | dev-PC | n/a | T | P0 | For each of the **20** methods on the `AlertSink` Protocol ([`pipeline/alerts.py:27`](../../../messagefoundry/pipeline/alerts.py) — the Protocol lives in `alerts.py`, **not** `alert_sinks.py`; the 35-def `NotifierAlertSink` at [`alert_sinks.py:578`](../../../messagefoundry/pipeline/alert_sinks.py) is a different class and its count is not the Protocol's), call it on `LoggingAlertSink` ([`alerts.py:231`](../../../messagefoundry/pipeline/alerts.py), the same 20) with representative PHI-free args; no `AttributeError`, no exception, and exactly one log record at the documented level (`WARNING`, except `leadership_lost`/`dr_released` at `INFO` and `connection_restored` a no-op). Calling `content_match` on the fallback raises `AttributeError` today — assert the *current* behaviour explicitly so the divergence is a pinned fact |
| ALERT-04 | `content_match` reachability from a real Handler | Functional | pytest | dev-PC | SQLite | T | P0 | Author a sample Handler under a temp config dir that attempts to raise a content alert using only the public `messagefoundry` surface. Assert either (a) a working export (`messagefoundry.alert_content` or an injected sink) produces exactly one `content_match` event whose payload keys are `{type, connection, label}` (+ optional `rule_id`) and **no** other key, **or** (b) an explicit, documented refusal. Assert `"content_match"` in `messagefoundry.__all__` iff (a) |
| ALERT-05 | `content_match` unavailable in dryrun and on a Router | Negative/Security | pytest | dev-PC | n/a | T | P0 | If OQ-1 resolves to a Handler export: calling it from a Router or under `messagefoundry dryrun` raises, matching the `db_lookup`/`fhir_lookup` carve-out posture (CLAUDE.md §2). No event is enqueued in either case |
| ALERT-06 | A restarted stopped lane clears its open `connection_stopped` instance | HA/Resilience | pytest | dev-PC | SQLite | T | P0 | Drive an outbound to `connection_stopped` through `RegistryRunner`; assert one `alert_instance` row `status='open'`. Call `RegistryRunner.restart_outbound(name)`; assert the instance reaches `status='resolved'` **and** `count_open_alerts_by_connection` drops that connection to 0 within one poll. Fails today (nothing emits `connection_started`) — see 14.5 §S1 |
| ALERT-07 | The `_AUTO_RESOLVE` map has no dead keys | Functional | pytest | dev-PC | n/a | T | P0 | Every key of `_AUTO_RESOLVE` is either emitted by at least one code path (AST-derived, repo-wide) or is listed in an explicit, dated `KNOWN_UNEMITTED` allowlist inside the test with a comment naming the owner decision. Adding a new map key with no emitter fails |
| ALERT-08 | `[alerts]` SMTP TLS posture is pinned at send time | Negative/Security | pytest | dev-PC | n/a | T | P0 | Monkeypatch `smtplib.SMTP` to capture the `starttls` call. Assert the observed `(context, keyfile, certfile)` arguments and, from the resulting context, `check_hostname` and `verify_mode`. The test asserts **the decided posture** (OQ-3) and fails if the code silently changes in either direction. Same assertion applied to `pipeline/security_notify.py`, which shares `send_plain_email` |
| ALERT-09 | SMTP hop refuses / warns per the decided posture against an untrusted server cert | Negative/Security | pytest | container-CI | n/a | T | P0 | Stand a local STARTTLS SMTP responder with a self-signed cert. Under the decided posture: either the send raises `ssl.SSLCertVerificationError` (verifying) or it succeeds **and** emits a single explicit posture WARNING naming the unauthenticated hop. No silent success with no signal |
| ALERT-10 | `[alerts]` is startup-only — reload divergence is a pinned fact and is surfaced | Functional | pytest | dev-PC | SQLite | T | P0 | Start a serve app with rule set A. Rewrite the service-settings TOML to rule set B (via `messagefoundry alert add`). `POST /config/reload`. Assert `GET /alerts/rules` still returns A **and** that the response (or `GET /status`) carries an explicit pending-restart indicator naming the divergence. Without the indicator the test fails — silence is the defect |
| ALERT-11 | Runner drives `queue_buildup` end to end, once per re-alert window | Functional | pytest | dev-PC | SQLite | T | P1 | With a controllable store and a lane over `max_depth`, exactly **one** `queue_buildup` event is captured per `_BUILDUP_REALERT_SECONDS` window; the payload carries `depth` and `oldest_age_seconds` matching the store's `pending_depth` return; a second tick inside the window emits nothing; a tick after the window emits again |
| ALERT-12 | Runner drives `message_stall` on the age dimension only | Functional | pytest | dev-PC | SQLite | T | P1 | A lane with `depth=1` whose oldest row exceeds `StallThreshold.max_oldest_seconds` emits exactly one `message_stall` with `oldest_age_seconds` ≥ the threshold. With `max_oldest_seconds=None` nothing is emitted at any depth or age (deny-by-default) |
| ALERT-13 | Runner drives `saturation` on a rising backlog, not on a bursty-draining one | Functional | pytest | dev-PC | SQLite | T | P1 | Feed a monotonically rising `pending_depth` across `sustain_samples+1` ticks → exactly one `saturation` event with `depth > depth_start` and `growth_per_second > 0`. Feed a spike-then-fall sequence over the same tick count → zero events. With `sustain_samples=None`, `store.pending_depth` is **not called at all** (assert the mock's call count is 0 — the documented zero-cost path) |
| ALERT-14 | `_outbound_paused` suppresses buildup, stall and saturation, and the suppression lifts on resume | Functional | pytest | dev-PC | SQLite | T | P1 | With the outbound paused and the lane far over every threshold: zero `queue_buildup`, zero `message_stall`, zero `saturation`. After `start_outbound`, the very next tick emits `queue_buildup`. Assert the guard is keyed to `Stage.OUTBOUND` — an `ingress`/`routed` lane of the same name still alerts |
| ALERT-15 | The outbound saturation blind spot is a pinned, documented fact | Functional | pytest | dev-PC | SQLite | T | P1 | A **healthy** outbound (every delivery succeeds) whose backlog climbs monotonically emits **zero** `saturation` events, because the sampling tick is only reached from the delivery-failure/retry path. The test carries the ADR 0014 amendment / BACKLOG #93 reference in its docstring and fails if coverage silently widens or narrows |
| ALERT-16 | Every `AlertSink` emit call site scrubs its `detail`/`reason` argument | PHI | pytest | dev-PC | n/a | T | P1 | AST-enumerate every call to an `AlertSink` method across `messagefoundry/`; for each `detail=`/`reason=` keyword argument, assert the expression is a call to `safe_exc(...)` / `safe_text(...)`, a literal, an f-string over non-exception locals, or a name assigned from one of those in the same function. A planted `detail=str(exc)` fails. Enumerate at least the 20 known sites (`wiring_runner.py:1200/2063/2688/4070/4115/4294/4405/4439`, `stage_dispatcher.py:817/837/860`, `dr_backup.py:557`, `reference_sync.py:390`, `state_convergence.py:141`, `engine.py:845`, `cluster.py:981`) |
| ALERT-17 | An HL7-bearing exception cannot reach the webhook wire | PHI | pytest | dev-PC | n/a | T | P1 | Raise a delivery failure whose exception text embeds a synthetic `PID\|1\|\|...` segment and a name/DOB run; capture the JSON body handed to `WebhookTransport._post`. Assert no `PID`/`MSH`/`OBX` segment id, no `\|`-delimited field run of length ≥ 3, and no synthetic patient token appears in any value. Repeat for the email body and the `alert_instance.reason` at rest |
| ALERT-18 | No alert payload key is a message body under any event type | PHI | pytest | dev-PC | n/a | T | P1 | For each of the **18** routable event types (`_ALERT_EVENT_TYPES`), emit a representative event through `NotifierAlertSink` with a capture transport; assert the delivered dict's key set is a subset of a per-type allowlist derived from the emit method's own signature, and that every value is a `str`/`int`/`float`/`bool`/`None` under 512 chars. Internal `_`-prefixed keys are absent from the delivered dict |
| ALERT-19 | Alert-storm bound: a wedged transport drops with a warning and never blocks the emitter | Performance | pytest | dev-PC | n/a | T | P1 | Install a transport whose `send` blocks on an `asyncio.Event`. Emit `_MAX_QUEUE + 250` distinct events (distinct `(type, connection)` so the throttle does not mask). Assert: (a) every `_emit` call returns in under 1 ms mean; (b) at least 250 `"queue full; dropping"` WARNING records; (c) after releasing the block, exactly `_MAX_QUEUE` events are delivered and `aclose()` drains without hanging. See 14.5 §S2 |
| ALERT-20 | Dropped alerts are countable | Performance | pytest | dev-PC | n/a | T | P1 | After ALERT-19's flood, an operator-observable count of dropped alerts is non-zero — a `/metrics` counter, a `/stats` field, or (fallback) a structured WARNING with a parseable count. If the decision (OQ-9) is "log only", the test asserts the exact log shape so the signal is at least machine-greppable |
| ALERT-21 | A wedged webhook does not starve the email transport | HA/Resilience | pytest | dev-PC | n/a | T | P1 | With a blocking webhook and a working email transport, `_handle` still delivers to email for every event; the per-transport failure is logged once per event with the transport name and event type, and never propagates |
| ALERT-22 | `email_password_secret` → `SecretProvider` resolves through `notifier_from_settings` and fails closed | Negative/Security | pytest | dev-PC | n/a | T | P1 | With `[alerts].email_password_secret` set and a stub provider, the built `EmailTransport.password` equals the provider's value and the literal `email_password` is ignored. With the ref set and **no** `[secrets].provider`, `notifier_from_settings` raises — startup refuses rather than sending with a blank password. Closes the FEATURE-COVERAGE-PLAN `FCP:ALERT-5` / `FCP:CRYPTO-8` dispute |
| ALERT-23 | Vault-backed SMTP password end to end | Negative/Security | pytest | container-CI | n/a | T | P2 | Against a Vault dev-mode container, `[alerts].email_password_secret = "kv/mefor#smtp"` resolves at notifier construction and the value never appears in `GET /alerts/rules`, the support bundle, any log record, or a `/metrics` sample |
| ALERT-24 | Post-restart re-page volume is bounded and documented | HA/Resilience | pytest | dev-PC | SQLite | T | P1 | Open N=25 distinct `alert_instance` rows, then construct a fresh `NotifierAlertSink` over the same store and re-emit every condition. Assert the observed notification count against a **documented expectation** (today: 25 immediate re-pages, every `escalation_tier` back at 0). The number is asserted, not merely observed, so a change in re-page behaviour is a test failure |
| ALERT-25 | Post-failover re-page across a real leadership move | HA/Resilience | pytest | container-CI | x2 | T | P1 | On a two-node Postgres/SQL Server cluster with M open conditions, kill the leader. Assert: exactly one `leadership_acquired` on the new leader; the old leader's `leadership_acquired` instance auto-resolves via `leadership_lost`; and the re-page count on the new node matches the ALERT-24 documented expectation. See 14.5 §S3 |
| ALERT-26 | `_suspended` survives a restart but `_last_sent`/`_occurrences` do not — pinned | HA/Resilience | pytest | dev-PC | SQLite | T | P1 | Suspend `(type, connection)` until `now+3600`, restart the sink, call `prime_suspensions()`; assert the next emit is muted. In the same test assert `_last_sent` and `_occurrences` are empty after the restart (the accepted ADR 0014 §4 asymmetry is a pinned fact, not an accident) |
| ALERT-27 | Cluster duplicate-page behaviour for the four ungated periodic runners | HA/Resilience | pytest | dev-PC | n/a | T | P1 | Under a fixture with three coordinators where only one is leader, run one pass each of `CertExpiryRunner`, `SecretRotationRunner`, `UpdateCheckRunner`, `GcmInvocationRunner`. Assert the observed emit count per condition (3 today) against the decided expectation (OQ-5). `RetentionRunner` in the same fixture emits 1 (leader-gated) — the contrast is the point |
| ALERT-28 | Duplicate `alert_instance` upserts under concurrent nodes do not violate the open-unique index | Cross-backend | pytest | container-CI | x2 | T | P1 | Three concurrent `upsert_alert_instance` calls for the same `(event_type, connection)` against a live Postgres and a live SQL Server produce exactly one `open` row with `count == 3`; no `IntegrityError` escapes; `ux_alert_instance_open` holds |
| ALERT-29 | IDE alert editor event-type parity | Compat | ide-mocha | container-CI | n/a | T | P1 | `EVENT_TYPES` in `ide/src/alertEditor.ts` equals `["any", ...sorted(_ALERT_EVENT_TYPES)]` read from a generated constant. New file `ide/src/test/suite/alert-editor.test.ts`. Fails today: the dropdown holds **5** entries (`any` + 4 real types, [`alertEditor.ts:13-19`](../../../ide/src/alertEditor.ts)) against the required **19** (`any` + the 18 `_ALERT_EVENT_TYPES` members) |
| ALERT-30 | IDE alert editor field parity | Compat | ide-mocha | container-CI | n/a | T | P1 | The `NewRule` field set equals `AlertRule.model_fields` from the same generated constant, or a decided, explicitly-listed subset with the omitted fields named. Mirrors the `tests/test_alerts_edit.py:153` `_RULE_FIELDS` pattern |
| ALERT-31 | The generated IDE constant is regenerated from the engine and drift fails CI | Compat | pytest | container-CI | n/a | T | P1 | An engine-side test regenerates the constant from `_ALERT_EVENT_TYPES` + `AlertRule.model_fields` and asserts the committed file is byte-identical. Adding an event type without regenerating fails the `test` leg (not only the `ide` leg) |
| ALERT-32 | Cross-surface rule parity after a restart | Functional | pytest | dev-PC | SQLite | T | P1 | Add a rule via `messagefoundry alert add`, restart the serve app, then assert `messagefoundry alert list --json`, `GET /alerts/rules`, and the `/ui/alerts` rendered rule table all contain the same rule count, ids and event types |
| ALERT-33 | Cross-surface divergence before a restart is surfaced, not silent | Usability | pytest | dev-PC | SQLite | T | P1 | Same as ALERT-32 but **without** the restart: the three views may disagree, but at least one of them must show an explicit pending-restart state. Paired with ALERT-10 |
| ALERT-34 | An alert-triggered `control_action` writes a tamper-evident audit row | Negative/Security | pytest | dev-PC | SQLite | T | P2 | A `control_action` rule that restarts an outbound produces exactly one audit row with a decided actor (e.g. `alert-rule`), the rule `id`, the action and the target; the row chains (`prev_hash` verifies). A **failed** dispatch also writes a row with the failure marker. Fails today (no `record_audit` on either path) |
| ALERT-35 | Unbounded open-instance growth: bounded query cost | Performance | pytest | dev-PC | x3 | T | P2 | Insert 10 000 never-resolved `alert_instance` rows. `GET /alerts/active?limit=200` returns in under a documented ceiling on each backend; `count_open_alerts_by_connection` stays under the same ceiling; a retention pass deletes **zero** of them (the documented resolved-only policy). Assert the nav bell's `limit=200` cap is reported as a saturated count, not a silently truncated one |
| ALERT-36 | The serve path really wires a `NotifierAlertSink` onto the runner | Functional | pytest | dev-PC | SQLite | T | P2 | After a `create_serve_app` lifespan with `[alerts].webhook_url` set, `engine.registry_runner._alert_sink` is a `NotifierAlertSink` with a live store and a live control callback. With `[alerts]` empty it is a `LoggingAlertSink`. A third case asserts the embedded `Engine` path is `LoggingAlertSink` (the documented behaviour, pinned) |
| ALERT-37 | A newly-opened alert reaches the console within a bounded number of polls | Usability | pytest | dev-PC | SQLite | T | P2 | Upsert an `alert_instance`, then poll `/ui/nav-status`; the alerts `count` reflects it on the first poll after the write and the `severity` field equals the worst open severity. Assert the documented ~15 s poll cadence is what the page's script uses |
| ALERT-38 | `/ui/alerts` ack / resolve / suspend / resume round-trip and CSRF posture | Functional | pytest | dev-PC | SQLite | T | P2 | Each of the four POST routes in `messagefoundry_webconsole/routes/monitoring_writes.py` mutates the instance and 303-redirects to `/ui/alerts`; a cross-site POST is refused; an operator without `monitoring:diagnose` gets no forms rendered |
| ALERT-39 | `POST /alerts/test-email` exercises the identical send path a real alert uses | Functional | pytest | dev-PC | SQLite | T | P2 | With a capturing SMTP stub, the frames produced by `/alerts/test-email` and by a real fired alert differ only in subject/body content — the same `EmailTransport` → `send_plain_email` → `starttls` → `send_message` sequence, the same allowlist check, the same timeout. Guards against the test path drifting into a false-confidence stub |
| ALERT-40 | `/metrics` cardinality and scrape cost on a large estate — **the owning row** (the API chapter's `API-54` points here) | Performance | load-harness | dev-PC | SQLite | T | P2 | Derive the expected series count **from the registry**, don't guess it: `_MetricsCollector.collect` ([`api/metrics.py:246-441`](../../../messagefoundry/api/metrics.py)) yields a fixed block (`build_info`, `in_pipeline`, `store_committed_txns`, `store_body_copies`, + 4 host gauges when psutil reads, + the 9-series pool block on a server backend), `outbox_status` at one series per outbox status, **2 per inbound connection** (`messages_received`, `messages_errored`), **4 per (connection, destination) pair** (`deliveries`, `deliveries_dead`, `queue_depth`, `oldest_pending_age_seconds`) and **15 per pair** for `delivery_latency_seconds` (12 `DEFAULT_LATENCY_BUCKETS` + `+Inf` + `_sum` + `_count`). On the `harness/load/profiles/connscale.toml` estate assert total series `== K + 2·I + 19·D` **exactly** — i.e. growth is linear in inbound connections and in *existing* destination pairs, never the connection×destination×status product — that the scrape stays under a committed latency ceiling at that estate size, and that the label-**name** set is exactly the strict allowlist `{connection, destination, status, version, le}` (extending `tests/test_metrics_exporter.py:135`) with no PHI-shaped label value |
| ALERT-41 | `/metrics` counter semantics survive a service restart | Compat | pytest | dev-PC | SQLite | T | P2 | Counters that are store-derived resume from the store value after a restart; process-local counters reset to 0 and are documented as such in the exporter's HELP text. No counter silently goes backwards without a documented reason |
| ALERT-42 | `/metrics/history` is in-process and lost on restart, by design | Functional | pytest | dev-PC | n/a | T | P2 | Record samples, restart the app, assert `GET /metrics/history` returns an empty ring; assert `capacity == 900` and `min_interval == 0.9`; assert two concurrent `/ws/stats` samplers do not double-append the same instant |
| ALERT-43 | OTel guarded-import failure message when `[otel]` is absent | Negative/Security | pytest | container-CI | n/a | T | P2 | With `opentelemetry` uninstalled, `build_otel_meter_provider()` and `OtelMetricsExporter(...)` each raise `RuntimeError` whose message names `pip install messagefoundry[otel]`. Currently marked `pragma: no cover` — this row removes the blind spot |
| ALERT-44 | OTLP export round-trip into a real collector | Compat | CI-leg | container-CI | n/a | T | P2 | New CI leg with an `otel/opentelemetry-collector` container: after `[otel]` install, exported metrics arrive at the collector's debug exporter with the expected instrument names (`messagefoundry_in_pipeline`, …) and a resource attribute set containing no host PHI. The leg is required-on-`[otel]`-touch, advisory otherwise |
| ALERT-45 | Support-bundle redaction against an adversarial synthetic corpus | PHI | pytest | dev-PC | n/a | T | P1 | Generate ≥ 500 synthetic PHI-shaped log lines with `messagefoundry/anon` fixtures + `messagefoundry generate` (HL7 segments in 5 encodings of the delimiter set, names, DOBs, MRNs, base64/`mfb64:` blobs, `MEFOR_*` values, bearer tokens, and each embedded mid-line, at line start, and inside a traceback). Run `redact_log_line` over each; a fail-closed leak gate asserts **zero** residual matches against the corpus's own known-token list. The single-token residual is the only allowed class and is asserted as a *measured* count, not an unbounded excuse. See 14.5 §S8 |
| ALERT-46 | The support bundle's own `status.json` / `config-summary.json` carry no secret or PHI | PHI | pytest | dev-PC | SQLite | T | P2 | Build a bundle from a config with SMTP passwords, webhook URLs, DB connection strings and a `[secrets]` provider ref. Assert no member contains any of those values, the store path is basename+backend only, and every count-only field really is an integer |
| ALERT-47 | Support-bundle handling has no RBAC / audit / retention — pinned | PHI | pytest | dev-PC | n/a | T | P2 | The `support-bundle` CLI writes without any permission check and writes no audit row; assert this **current** behaviour explicitly, with `docs/PHI.md` row 14 cited in the docstring, so a future silent change is caught either way |
| ALERT-48 | Runtime log-level change never emits PHI at DEBUG on a live PHI-shaped stream | PHI | pytest | dev-PC | SQLite | T | P2 | Send a synthetic PHI-bearing HL7 message through a running engine while `PATCH /logging/level {"level":"DEBUG"}` is applied mid-flight. Assert the captured records contain no HL7 segment run, no name/DOB run, no `mfb64:` blob. Also assert the prod-DEBUG refusal still fires for a *startup* DEBUG on a prod-PHI instance |
| ALERT-49 | `/logs/tail` redaction on the same live stream | PHI | pytest | dev-PC | SQLite | T | P2 | After ALERT-48's traffic, every served `/logs/tail` line passes the ALERT-45 leak gate; each served page writes exactly one `logs_view` audit row with a line count and no content |
| ALERT-50 | Syslog TLS round-trip into a live collector | Compat | CI-leg | container-CI | n/a | T | P2 | New CI leg with an `rsyslog` container listening on UDP, TCP and RFC 5425 TLS. For each transport a known synthetic record arrives, correctly framed (octet-counted on TLS/TCP), with the three PHI filters applied. A deliberately mismatched collector cert is **refused**, not silently downgraded |
| ALERT-51 | NSSM `AppRotateBytes` rollover on a real Windows service | Compat | CI-leg | W2025-box | n/a | T | P2 | Extend `windows-service-smoke`: force > 10 MB of stdout, assert a rotated `service.out.log` sibling appears, the live file is truncated, the service stays Running, and `GET /logs/tail` still serves from the newest file. See 14.5 §S7 |
| ALERT-52 | `[retention].app_log_days` / `app_log_compress_days` on a real Windows service | Compat | manual | W2025-box | n/a | T | P2 | On the W2025 box with backdated `.log` mtimes, a retention pass gzips at the compress window and deletes at the delete window; the gzip is integrity-validated before the original is removed and keeps the source mtime; the live file NSSM holds open is never deleted out from under it |
| ALERT-53 | Log ACLs on the NSSM DataDir | Negative/Security | manual | W2025-box | n/a | T | P2 | After `install-service.ps1`, `icacls <DataDir>\logs` shows inheritance removed and grants limited to SYSTEM + Administrators + the service account; a non-admin interactive user cannot read `service.out.log` |
| ALERT-54 | WER / crash-dump machine policy after `-SuppressCrashDumps` | Negative/Security | manual | W2025-box | n/a | T | P2 | After install with `-SuppressCrashDumps`, `HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps` and `AeDebug` are set as documented; force a deliberate crash of the service process and confirm **no** heap dump file lands on disk anywhere under the DataDir or `%LOCALAPPDATA%` |
| ALERT-55 | Operator detectability sweep — every injected failure mode surfaces | Functional | acceptance-probe | dev-PC | SQLite | T | P1 | For each failure the other chapters inject (inbound listener down, outbound transport down, router exception, transform exception, dead-letter, store unavailable, cert expired, DEK overdue, backup failed, integrity drift, leadership move, DR promotion, RCSI-off start, stuck pooled lane, disk over threshold), assert at least one of: an `alert_instance` row, a `connection_event` row, a distinct `/metrics` series change, or a distinct `/stats` field change. Any mode with **none** of the four is reported as a detectability hole with its name. See 14.5 §S9 |
| ALERT-56 | Real webhook target round-trip and pager routing | Functional | manual | any | n/a | C | P2 | **Characterisation — records a third-party integration finding, does not gate.** A Slack/Teams/PagerDuty test space receives a severity-tagged JSON alert; **record** how the pager side routes on `severity` and whether it de-dups on the `(type, connection)` grain (their triage rules, not our behaviour). The falsifiable half — no `_`-prefixed key and no recipient address on the wire — is asserted at the sink by ALERT-18 and `tests/test_alert_recipients.py`. Becomes a T row if a pager-side routing contract is ever committed |
| ALERT-57 | A 3xx-redirecting webhook target on a real network | Negative/Security | manual | any | n/a | T | P2 | Against a real redirector, the POST **fails** (logged once with the transport name) rather than following the redirect; the alert is not delivered to the redirect target |
| ALERT-58 | Real SMTP relay end to end with three server certs | Negative/Security | manual | W2025-box | n/a | T | P0 | Against a real relay (Exchange/Postfix/MailHog) with a valid-trusted, a self-signed and a hostname-mismatched cert: record the observed behaviour of `POST /alerts/test-email`, a real fired alert, and a per-user security-event email for each cert. The recorded matrix must match ALERT-08's asserted posture exactly. See 14.5 §S4 |
| ALERT-59 | Browser: `/ui/alerts` and the nav bell against a hostile alert `reason` | Negative/Security | browser | browser-matrix | SQLite | T | P2 | In Chromium and Firefox: the alerts page renders ack/resolve/suspend/resume controls; a `reason` containing `<img onerror>` renders as text with no console CSP violation beyond the expected report; the bell colour tracks the worst open severity and the count updates within one poll |
| ALERT-60 | VS Code: the "New Alert" webview on a real workspace | Usability | manual | dev-PC | n/a | T | P2 | The dropdown lists exactly the parity set decided in OQ-7; an invalid rule surfaces the CLI's validation error inline (not a silent no-op); add and remove round-trip against `messagefoundry.toml` preserving comments; the panel states the restart requirement |
| ALERT-61 | Prometheus + Grafana on a large estate — the measurement half of the `/metrics` ownership | Performance | manual | dev-PC | SQLite | C | P2 | **Characterisation — publishes the numbers ALERT-40 then gates on.** A real Prometheus scrapes the connscale estate at 15 s for 30 minutes with the Grafana dashboard loaded; **record** the observed scrape duration distribution, the live series count against ALERT-40's registry-derived formula, the TSDB ingest rate, and the counter behaviour across a service restart. Outcome is a recorded measurement filed with the release evidence; the falsifiable ceilings live in ALERT-40 (cardinality + scrape cost) and ALERT-41 (counter semantics). Becomes a T row once the ceiling measured here is committed as a threshold |
| ALERT-62 | Alert storm on a real estate with a deliberately wedged webhook | Performance | manual | W2025-box | x2 | C | P2 | **Characterisation — a recorded estate observation, not a gate.** With ~50 connections and a webhook target that accepts and never responds, trip a broad failure and **record**: alerts delivered, alerts dropped, whether engine message throughput moved measurably, and whether `/ui/alerts` still showed every open condition. The falsifiable versions of all four are ALERT-19 (non-blocking emit + drop-with-warning), ALERT-20 (countable drops), ALERT-21 (no cross-transport starvation) and ALERT-68 (a dead notifier never blocks a stage), which do gate |
| ALERT-63 | Multi-node duplicate-page observation on a 3-node cluster | HA/Resilience | manual | W2025-box | x2 | C | P2 | **Characterisation while OQ-5 is open** — there is no decided per-condition page count to fail against yet. With a near-expiry cert, an overdue DEK and a newer pinned version present on all three nodes, **record** the pages received per condition per cooldown (expected 3 today, one per node) and file the number with the OQ-5 decision. It becomes a T row — "the observed count equals the decided expectation" — the day OQ-5 records that expectation; the automated equivalent, ALERT-27, already gates against today's 3 |
| ALERT-64 | DST-boundary correctness of schedule-aware rules | Functional | manual | W2025-box | n/a | T | P2 | A rule with an IANA-tz window spanning a DST transition activates and deactivates at the correct wall-clock local times on a real host clock across the boundary, in both the spring-forward and fall-back directions |
| ALERT-65 | `docs/FEATURE-MAP.md` §9/§10 currency guard | Compat | — | dev-PC | n/a | T | P2 | **Pointer.** Covered by MIG's consolidated FEATURE-MAP drift-guard row (`MIG-28`, one extension of `tests/test_feature_map_claims.py`); no separate work scoped here. The alerting-specific claims this chapter hands to MIG as that row's inputs: §9 names **every** member of `_ALERT_EVENT_TYPES` (all **18** — `messagefoundry/config/settings.py`); §9 has a row for each of alert state, escalation, templates, per-rule recipients, control actions, test-email, support bundle, crashdump suppression, `connection_event`, `/logs/tail`, `/metrics/history`, host metrics; and **no** §10 row nor any line references a module path absent from disk (catches `messagefoundry/console` and the `:131` "PySide6 desktop console stays" claim) |
| ALERT-66 | `docs/BACKLOG.md` #171 build-state correction | Functional | pytest | dev-PC | n/a | T | P2 | #171's banner no longer claims DEMAND-GATE / "no runtime control and no viewer"; the existing `tests/test_backlog_status_check.py` + `.github/workflows/backlog-hygiene.yml` pass on the edited entry, and the entry cites `api/app.py:4541`, `:4570` and ADR 0130 |
| ALERT-67 | `docs/PHI.md` row 11 vs `docs/BACKLOG.md:5152` — a CI guard binding both docs to the code's SMTP posture | Functional | pytest | dev-PC | n/a | T | P0 | The pass criterion is the **guard**, not the decision (OQ-3 decides *which* posture; the row can fail under either). `tests/test_phi_logging_inventory.py` gains an assertion that reads the observed `starttls` posture the way ALERT-08 pins it — verifying context vs `check_hostname=False`/`verify_mode=CERT_NONE` — and asserts (a) `docs/PHI.md` row 11's STARTTLS wording describes **that** posture, and (b) no other doc sentence contradicts it, so any doc sentence about this posture must either match the code or be gone. **THE GUARD IS STILL WORTH BUILDING; ITS STATED STARTING CONDITION IS NOT.** "Fails today, because the two documents disagree" was already false when written (BACKLOG #1100): #323 closed the divergence on 2026-08-02, and `docs/PHI.md` row 11 now states the verifying posture with the old one recorded as history. So this test is expected to PASS on arrival and earns its keep by failing on a FUTURE doc-code divergence — which is the only thing it was ever able to catch. Note also that the cited `docs/BACKLOG.md:5152` anchor has drifted; re-derive it by content rather than by line number |
| ALERT-68 | The notifier itself is the thing that is down: an unreachable SMTP host and a 500-looping webhook block no pipeline stage, and the failure is itself observable | HA/Resilience | pytest | dev-PC | SQLite | T | P1 | Two fault modes driven through a live `RegistryRunner` with a real `NotifierAlertSink` and a live store: (a) `[alerts].email_smtp_host` pointed at a closed port so `send_plain_email` raises `ConnectionRefusedError`/`socket.gaierror` at (and at the far end of) the connect timeout; (b) a webhook target returning HTTP 500 to every POST — 50 consecutive events each. Assert for both: **no stage blocks** — every `_emit` returns sub-millisecond, the ingress→routed→outbound handoffs keep committing, and end-to-end message throughput stays within 5% of a no-alert control run (a transport that awaits inside `_emit`, or a retry loop on the emitting worker, fails here); the durable `alert_instance` row is still upserted `open`, so `/ui/alerts` shows the condition nobody was paged about; a healthy sibling transport still delivers every event (distinct from ALERT-21's *wedged* transport — here the transport **fails fast** rather than hanging); and the failure is observable — exactly one WARNING per event naming the transport and the event type, carrying neither recipient addresses nor webhook credentials, plus the ALERT-20 counter if OQ-9 adds one. A silent swallow with no record fails the row |

### 14.5 Detailed scenarios

#### S1 — ALERT-06 / ALERT-07: a restarted lane must clear its open alert

**Preconditions.** Clean SQLite store; a config dir with one inbound and one outbound whose
destination connector raises a non-transport (internal) error so `InternalErrorPolicy.STOP` fires;
`[alerts]` configured with a capture transport (in-test), so a real `NotifierAlertSink` with a live
store is on the runner.

**Steps.**
1. Start `RegistryRunner` over the registry; submit one synthetic message (`messagefoundry generate adt --count 1`, held in memory — never written to a committed path).
2. Wait for the outbound to STOP. Observe the emit at `wiring_runner.py:4405` or `:4439`.
3. Read `store.list_active_alert_instances()`; assert exactly one row, `event_type='connection_stopped'`, `status='open'`, `connection=<outbound name>`.
4. Read `store.count_open_alerts_by_connection()`; assert `{<outbound>: 1}`.
5. Fix the fault (swap in a working destination) and call `await runner.restart_outbound(<outbound>)` — the same primitive an ADR 0128 `control_action` fires.
6. **Observation point:** re-read `list_active_alert_instances()` and `count_open_alerts_by_connection()` after the restart settles (poll up to 5 s).

**Expected result (target).** The `connection_stopped` instance is `resolved`; the per-connection
open count is 0; the console's `alerts_active` badge clears without operator action.

**Expected result (today).** The instance stays `open` forever. Record this as the acceptance
evidence for OQ-2 and keep the test as an `xfail` with a dated reason until the owner decides.

**Cleanup.** `await runner.stop()`; delete the temp store; no state leaves the temp dir.

---

#### S2 — ALERT-19 / ALERT-20 / ALERT-21: alert storm against a wedged transport

**Preconditions.** No real network. A `_BlockingTransport` whose `send` awaits an
`asyncio.Event` that the test controls, plus a `_CountingTransport` that records and returns.
`NotifierAlertSink([blocking, counting], realert_seconds=0.0)` so the throttle never masks a drop.

**Steps.**
1. `sink.start()`; assert the drain task is alive.
2. Emit `_MAX_QUEUE + 250` events with **distinct** `connection` values (`f"OB_{i}"`) so each has its own throttle key. Time every `_emit` call.
3. **Observation point A:** the wall time of the slowest `_emit` — it must stay sub-millisecond (the emit path is enqueue-only; a regression that makes it await would show here as the emitting delivery worker blocking).
4. **Observation point B:** `caplog` — count records matching `"queue full; dropping"`. Expect ≥ 250.
5. Set the blocking event; `await sink.aclose()` with a 30 s timeout.
6. **Observation point C:** `len(counting.events)` — exactly `_MAX_QUEUE` (1000), never more, and the drain completed rather than hanging.
7. Query whatever dropped-alert signal ALERT-20 settles on.

**Expected result.** Sub-ms emits, ≥ 250 drop warnings, exactly 1000 delivered, clean `aclose`,
a machine-readable drop signal.

**Easy to run wrong.** Using the same `connection` for every event makes the `(type, connection)`
throttle collapse the flood to one event and the test passes vacuously. Distinct keys are
mandatory. Equally, `realert_seconds` must be 0 — the default 300 s would do the same.

**Cleanup.** Set the event and `aclose()` in a `finally`; a leaked blocked drain task poisons the
rest of the session.

---

#### S3 — ALERT-25 / ALERT-24: alert delivery across a real leadership move

**Preconditions.** A two-node cluster over one shared Postgres (repeat on SQL Server 2022 / ODBC
Driver 18). Both nodes on the same store, `[alerts]` pointed at a local capture receiver per node
so pages are attributable to a node. M = 10 open `alert_instance` rows seeded by driving 10
outbounds to `connection_stopped` on node A.

**Steps.**
1. Confirm node A is leader (`GET /cluster/status` on each).
2. Record each receiver's delivered-event count; reset both.
3. `Stop-Process` node A's engine (hard kill — not a graceful stop, so no clean release fires).
4. Wait for node B's lease acquisition.
5. **Observation point A:** node B receives exactly one `leadership_acquired` for its own node id.
6. **Observation point B:** node A's `leadership_acquired` instance transitions to `resolved` (via node B's takeover path emitting `leadership_lost` for A, or by the documented alternative) — read from the shared store, not from a node's memory.
7. Re-trigger the 10 conditions on node B (the lanes are now B's). **Observation point C:** count the notifications node B's receiver gets in the first cooldown window.

**Expected result.** One `leadership_acquired`; A's instance resolved; the observation-C count
matches the documented ALERT-24 expectation (today: 10 immediate re-pages, tiers at base).

**Destructive — cleanup.** Restart node A, confirm it rejoins as follower, resolve every remaining
open instance via `POST /alerts/{id}/resolve`, truncate the seeded `alert_instance` rows on the
shared DB before the next run.

---

#### S4 — ALERT-58 / ALERT-08 / ALERT-09: SMTP posture against three server certificates

**Preconditions.** W2025 box. An SMTP relay reachable from the engine, provisioned with three
server certs it can be switched between: (a) valid + trusted by the host store, (b) self-signed,
(c) valid CA but hostname-mismatched. `[alerts].email_smtp_host` / `email_from` / `email_to` set to
a synthetic mailbox; `email_use_tls = true`; `smtp_allowed_hosts` containing the relay only.
**No real PHI anywhere** — the test email is the built-in synthetic PHI-free event.

**Steps (repeat for each cert a/b/c).**
1. Switch the relay to the cert under test; restart the relay.
2. `POST /alerts/test-email` as a `service:configure` operator. Record `success`, `duration_ms`, `detail`.
3. Trip a real `connection_stopped` on a synthetic outbound; record whether the alert mail arrives.
4. Trigger a per-user security event (`account_locked` via repeated bad logins on a synthetic local account); record whether the notification mail arrives.
5. **Observation point:** capture the relay-side TLS log — did the client present/verify anything, and did the session complete?
6. Cross-check every observation against ALERT-08's asserted posture.

**Expected result.** For (a): all three succeed. For (b) and (c): the observed behaviour is
**identical to what ALERT-08 asserts**. Any divergence between this recorded matrix and the unit
test's assertion is a finding.

**THE PARENTHETICAL THAT USED TO STAND HERE WAS STALE WHEN WRITTEN (BACKLOG #1100):** it read "today
that means all three still succeed (unauthenticated STARTTLS)". #323 closed that on 2026-08-02 —
`send_plain_email` passes a verifying context — so a self-signed (b) and a hostname-mismatched (c)
cert are now expected to be **REJECTED**, not to succeed. Running this procedure against the old
sentence would have recorded three passes as the expected matrix and read a working control as a
finding, which is the inversion this row exists to prevent. Derive the expectation from ALERT-08's
assertion at run time rather than from any prose here.

**Cleanup.** Restore cert (a); unlock the synthetic account; purge the synthetic mailbox.

---

#### S5 — ALERT-10 / ALERT-32 / ALERT-33: the mid-incident suppression rule that does nothing

This is the operator-visible shape of G5 + G14. Run it as one scripted sequence, because the
failure only exists in the seam between three surfaces.

**Preconditions.** A running `serve` app with `--service-config messagefoundry.toml` containing
zero `[[alerts.rules]]`; a capture transport receiving pages; one outbound paging steadily.

**Steps.**
1. Confirm pages are arriving and `GET /alerts/rules` returns `rules: []`.
2. As the operator would mid-incident, run `messagefoundry alert add --service-config messagefoundry.toml --data '{"event_type":"connection_stopped","connection":"OB_SYNTH","transports":[]}'`.
3. Run `messagefoundry alert list --service-config messagefoundry.toml --json` — **it shows the rule** (it reads the file).
4. **Observation point A:** `GET /alerts/rules` — still `[]`.
5. **Observation point B:** the capture transport — still paging.
6. `POST /config/reload`. Repeat A and B — unchanged.
7. **Observation point C:** does *any* surface tell the operator a restart is required? Check `GET /alerts/rules`, `GET /status`, `/ui/alerts`, and the IDE panel text.
8. Restart the service. Repeat A and B — the rule now applies and paging stops.

**Expected result (target).** Either the reload takes effect, or every surface in step 7 shows an
explicit pending-restart indicator naming the file mtime that diverged.

**Expected result (today).** Steps 4-6 diverge silently; only the IDE webview prose and
`alerts_edit.py:19-21` mention the restart.

**Cleanup.** Remove the rule with `messagefoundry alert remove --index 0`; restart; confirm the
file's comments and sibling sections survived (already covered by `tests/test_alerts_edit.py` —
just don't leave the file dirty).

---

#### S6 — ALERT-11..ALERT-15: driving the runner's three lane alerts

**Preconditions.** A `RegistryRunner` over a real SQLite store with one outbound. A test double
for `store.pending_depth` is **not** acceptable for ALERT-11/12 (the point is the real read);
use real rows and a frozen-clock helper for the age dimension. For ALERT-13 the detector is fed
via real depth changes across ticks.

**Steps.**
1. Configure `BuildupThreshold(max_depth=5)`, `StallThreshold(max_oldest_seconds=30)`, `SaturationThreshold(sustain_samples=4)` on the outbound.
2. Insert 6 pending outbound rows; drive one delivery-failure tick. **Observation point:** exactly one `queue_buildup` on the capture sink, `depth == 6`.
3. Tick again immediately → zero new events (inside `_BUILDUP_REALERT_SECONDS`). Advance the runner's clock past the window → one more.
4. Backdate the oldest row's `created` by 45 s; tick. **Observation:** one `message_stall` with `oldest_age_seconds >= 30`.
5. `pause_outbound(name)`; push depth to 50 and age to 300 s; tick five times. **Observation:** zero of all three types.
6. `start_outbound(name)`; tick once. **Observation:** `queue_buildup` fires immediately.
7. Saturation: reset, then across 5 ticks grow the depth 1→3→6→10→15 with **successful** deliveries interleaved so no failure tick occurs. **Observation:** zero `saturation` events — this is ALERT-15, the pinned blind spot. Then repeat with failing deliveries so the tick is reached → exactly one `saturation`.
8. Bursty control: 1→9→2→8→1 across 5 failure ticks → zero `saturation`.

**Expected result.** As stated per step. Step 7's two halves are the whole point: the detector is
correct; the *sampling* is what has the hole.

**Cleanup.** `await runner.stop()`; drop the temp store.

---

#### S7 — ALERT-51: forcing an NSSM log rollover on a real Windows service

**Preconditions.** W2025 box (or the `windows-service-smoke` runner) with the service installed by
`scripts/service/install-service.ps1`; `AppRotateBytes` at its installed 10485760.

**Steps.**
1. Confirm the service is `Running` and `service.out.log` exists under `<DataDir>\logs`.
2. Generate > 10 MB of stdout without touching PHI: raise the level with `PATCH /logging/level {"level":"DEBUG"}` on a **non-PHI, synthetic-only** instance and drive the `smoke.toml` load profile until the file crosses the bound. (Do **not** use `dryrun`/`generate` stdout redirection — those can carry bodies.)
3. **Observation point A:** `Get-ChildItem <DataDir>\logs` shows a rotated sibling and a truncated live file.
4. **Observation point B:** `Get-Service` still reports `Running`; `GET /health` still 200s.
5. **Observation point C:** `GET /logs/tail?limit=50` serves from the **newest** file and its lines pass the redaction gate.
6. Restore the log level.

**Expected result.** Rotation happens online (`AppRotateOnline 1`) with no service interruption
and no gap in `/logs/tail`.

**Cleanup.** Delete the rotated artifacts (they are synthetic), restore `[logging].level`, and do
**not** upload the raw log to CI artifacts unless it has passed the redaction gate.

---

#### S8 — ALERT-45: adversarial corpus for the support-bundle redactor

**Preconditions.** No real PHI. Corpus built at test time from `messagefoundry/anon` fixtures plus
`messagefoundry generate` output held in memory. Every synthetic identifier is registered in a
`known_tokens` set as it is generated — that set is the leak gate's oracle.

**Steps.**
1. Build ≥ 500 lines across these shapes: a full HL7 segment mid-line; a segment at line start; a segment inside a `Traceback` block; a `|`-delimited field run with no segment id; a name run (`Smith, John Q`); a DOB in three formats; an MRN-shaped token; an `mfb64:v1:` blob; a `MEFOR_STORE_ENCRYPTION_KEY=...` assignment; `Authorization: Bearer ...`; a bare 40-char base64 run; and each of the above prefixed by an ISO log timestamp.
2. Run `redact_log_line` over every line.
3. **Observation point:** for each output line, assert no member of `known_tokens` survives, except tokens explicitly classified `single_token_residual`.
4. Count the `single_token_residual` survivors and assert the count against a **committed ceiling**. A rise fails the test.
5. Assert the leading ISO timestamp survives on every line that had one (the `_LEADING_TS` carve-out) — over-redaction of the timestamp would make bundles unusable.

**Expected result.** Zero non-residual survivors; the residual count at or under the committed
ceiling; timestamps intact.

**PHI discipline.** The corpus is generated, asserted against, and discarded in-process. It is
never written to a file, never printed on failure (print the token *class* and the line index,
never the line), and never uploaded as a CI artifact.

---

#### S9 — ALERT-55: the operator-detectability sweep

This is the chapter's cross-cutting obligation: for every failure the rest of the plan injects,
can an operator *see* it?

**Preconditions.** A single-node engine with `[alerts]` on a capture transport, `connection_events`
on (the default), `/metrics` reachable, and a scripted list of failure injections imported from the
other chapters' harness helpers.

**Steps.** For each injection in the list:
1. Snapshot four observables: `list_active_alert_instances()`, `list_connection_events()`, the `/metrics` exposition text, and `GET /stats`.
2. Inject the failure.
3. Wait a bounded settle window (documented per injection, default 10 s).
4. Re-snapshot; diff each observable.
5. **Observation point:** record which of the four changed. Zero changes = a detectability hole.

**Expected result.** Every injection produces at least one changed observable. The test emits a
table (metadata only: injection name × which observable moved) as its failure message, so a hole is
named, not just counted.

**Known candidates for holes** to look for specifically: a healthy-but-behind outbound (G11); a
restarted-after-stop lane whose alert never clears (G3); an alert dropped by the storm bound (G8);
a `content_match` a Handler cannot raise (G2).

**Cleanup.** Each injection's own teardown, run in a `finally` per iteration so one hole does not
cascade.

### 14.6 Automation disposition

**New pytest modules** (all under `tests/`, all synthetic-data-only):

| Module | Rows | Effort |
|---|---|---|
| `test_alert_vocabulary_parity.py` — the G1 mirror invariant: AST-derived emit types, `_ALERT_EVENT_TYPES`, three-class method-set parity, `_AUTO_RESOLVE` dead-key guard, the `saturation_rising`→`"saturation"` carve-out | ALERT-01, 02, 03, 07 | **S** |
| `test_alert_emit_sites.py` — runner integration for buildup / stall / saturation + the paused guard + the blind-spot pin, plus the AST `safe_exc`/`safe_text` boundary guard | ALERT-11..16 | **M** |
| `test_alert_storm.py` — the `_MAX_QUEUE` drop path, non-blocking emit, drain-after-unblock, per-transport isolation, drop countability, **plus the dead-notifier faults** (unreachable SMTP host, 500-looping webhook) proving no stage blocks and the failure is logged/counted | ALERT-19, 20, 21, 68 | **M** |
| `test_alert_reload.py` — `[alerts]` startup-only pin, cross-surface parity after restart, divergence surfacing | ALERT-10, 32, 33 | **M** |
| `test_alert_smtp_posture.py` — the `starttls` context assertion for both `[alerts]` and `security_notify`, the untrusted-cert responder, the Vault password path | ALERT-08, 09, 22 | **M** |
| `test_alert_content_reach.py` — Handler reachability for `content_match`, dryrun/Router refusal | ALERT-04, 05 | **S** (grows to **M** if an export is built) |
| `test_alert_cluster_dedup.py` — the four ungated periodic runners under a multi-coordinator fixture, plus the concurrent-upsert index test | ALERT-27, 28 | **M** |
| `test_support_redact_corpus.py` — the adversarial synthetic corpus + fail-closed leak gate + residual ceiling | ALERT-45 | **M** |
| `test_alert_growth.py` — 10 000 open instances, bounded query cost on all three backends, resolved-only retention, bell saturation | ALERT-35 | **S** |

**Extends an existing module:**

| Existing module | Added rows | Effort |
|---|---|---|
| `tests/test_alert_state.py` | ALERT-06 (restart clears the instance — likely `xfail` pending OQ-2), ALERT-26 (restart asymmetry pin) | **S** |
| `tests/test_alert_failover.py` | ALERT-24 (documented re-page expectation) | **S** |
| `tests/test_alert_control.py` | ALERT-34 (audit row on success and failure) | **S** |
| `tests/test_alert_sinks.py` | ALERT-18 (per-type payload allowlist), ALERT-17 (HL7-bearing exception never reaches the wire) | **S** |
| `tests/test_alerts_test_email.py` | ALERT-39 (identical send path) | **S** |
| `tests/test_metrics_exporter.py` | ALERT-41 (counter reset semantics), ALERT-43 (missing-extra `RuntimeError`) | **S** |
| `tests/test_metrics_history_graph.py` | ALERT-42 | **S** |
| `tests/test_logging_surfaces.py` | ALERT-48, ALERT-49 (live PHI-shaped stream at DEBUG) | **M** |
| `tests/test_support_bundle.py` | ALERT-46, ALERT-47 | **S** |
| `tests/test_api_alerts.py` | ALERT-36 (serve-path sink identity) | **S** |
| `tests/test_feature_map_claims.py` | ALERT-65 | **S** |
| `tests/test_backlog_status_check.py` | ALERT-66 | **S** |
| `tests/test_phi_logging_inventory.py` | ALERT-67 (row 11 wording ↔ code posture) | **S** |
| `packaging/messagefoundry-webconsole/tests/test_webui.py` | ALERT-37 (bell freshness), ALERT-38 (four write routes + CSRF) | **S** |
| `tests/test_postgres_store.py` / `tests/test_sqlserver_store.py` | ALERT-28's live half | **S** |

**New ide-mocha tests:** `ide/src/test/suite/alert-editor.test.ts` — ALERT-29, ALERT-30. Paired with
the engine-side generator test ALERT-31 so drift fails the `test` leg, not only `ide`.
Effort **M** (the generator plus the editor widening it implies is the real cost).

**New / extended CI legs** (`.github/workflows/ci.yml`):

| Leg | Rows | Effort |
|---|---|---|
| `otel-collector` — `otel/opentelemetry-collector` service container, install `messagefoundry[otel]`, assert instrument arrival | ALERT-44 | **M** |
| `syslog-collector` — `rsyslog` container on UDP/TCP/TLS with a test CA; assert receipt, framing, redaction, mismatched-cert refusal | ALERT-50 | **M** |
| extend `windows-service-smoke` (`:1081`) — force a > 10 MB rollover and assert the rotated sibling | ALERT-51 | **S** |
| extend `load-test` (`:878`) — a `/metrics` scrape-cost + series-count assertion on the `connscale` profile | ALERT-40 | **M** |
| extend `sqlserver-store` (`:483`) / `postgres-store` (`:732`) — the ALERT-25 two-node failover re-page count | ALERT-25 | **L** |

**New harness / probe capability:** an `acceptance-probe` "detectability sweep" (ALERT-55) that
imports the other chapters' injection helpers and diffs the four observables. This belongs in
`harness/acceptance/` alongside the existing matrix; it is the only artifact that can answer the
chapter's cross-cutting question. Effort **L** — it depends on the other chapters landing their
injection helpers first, so schedule it last.

**Stays manual, with the reason:**

| Rows | Why it cannot be automated |
|---|---|
| ALERT-56, 57 | Requires a real third-party pager/chat tenant and a real network redirector; the value is the *pager-side* triage behaviour, which is outside our process |
| ALERT-58 | Requires three real server certs on a real relay and inspection of the relay's own TLS log; the client-side half **is** automated as ALERT-08/09 |
| ALERT-52, 53, 54 | Windows machine policy, `icacls` ACLs and WER dump behaviour are host-state facts; a hosted runner cannot prove them for a domain-joined W2025 box |
| ALERT-59 | Real browser CSP behaviour and glyph rendering in two engines |
| ALERT-60 | A real VS Code webview on a real workspace; the mocha leg covers the model, not the rendered panel |
| ALERT-61, 62, 63 | Real Prometheus/Grafana, a real wedged endpoint at estate scale, and a real 3-node cluster |
| ALERT-64 | A real host clock crossing a DST boundary |

Manual ≠ non-gating: **ALERT-57, 58, 59, 60, 64 and 52/53/54 are class `T`** — they have hard pass
criteria and a failed run blocks (58 at P0). **ALERT-56, 61, 62, 63 are class `C`** — they produce a
recorded measurement or finding and are complete when that record is filed; their falsifiable halves
are held by ALERT-18/40/41 and ALERT-19/20/21/68.

Rough totals: **new pytest ≈ M+M+M+M+M+S+M+M+S ≈ 3 engineer-weeks**; **ide parity ≈ M**;
**CI legs ≈ M+M+S+M+L ≈ 2 weeks**; **harness probe ≈ L, 1 week, scheduled last**; **manual ≈ 3 days
of W2025/browser/VS Code time** plus the procurement in 14.7.

### 14.7 Environment, data & prerequisites

**Hosts.**
- **W2025 box** (`W2025` / `WIN-NAFGLU5SH1J`) with NSSM, an interactive Administrator, and a dedicated local service account or AD gMSA — for ALERT-51..54, 58, 62, 63, 64. Shared with the WIN2025 plan's host; **coordinate scheduling**, since ALERT-62's storm and ALERT-54's deliberate crash disturb other runs.
- **dev-PC** for every pytest row, the load-harness rows, and the VS Code manual row.
- **container-CI** (`ubuntu-latest`) for the otel, syslog, Vault and live-backend legs; **windows-latest** for `ide` and `windows-service-smoke`.

**Services to stand up (procurement).**
- **SMTP relay** (Postfix / Exchange / MailHog) with STARTTLS, provisioned with **three** switchable server certs: valid+trusted, self-signed, hostname-mismatched. Required for ALERT-58 — this is the single biggest procurement item and gates a **P0** row.
- **Webhook receiver**: a Slack/Teams/PagerDuty test space **plus** a local HTTPS receiver with a controllable CA **plus** a 3xx redirector endpoint (ALERT-56, 57).
- **Prometheus + Grafana** (ALERT-61).
- **OpenTelemetry collector** (OTLP/gRPC) and the `[otel]` optional extra installed (ALERT-43, 44).
- **Syslog/SIEM collector** with UDP, TCP and RFC 5425 TLS listeners (rsyslog / Splunk / Sentinel) plus a CA and a client cert (ALERT-50).
- **SQL Server 2022** (ODBC Driver 18) and **PostgreSQL** instances (ALERT-25, 28, 35).
- A **2-3 node active-passive cluster** over a shared server DB, plus a third-tier DR standby box (ALERT-25, 63).
- **HashiCorp Vault** (dev mode) for `[alerts].email_password_secret` (ALERT-22, 23 — closes the FEATURE-COVERAGE-PLAN `FCP:ALERT-5` / `FCP:CRYPTO-8` dispute).
- **TLS certificates with controllable `notAfter`** (near-expiry and expired) for `CertExpiryRunner` (ALERT-27, 63).
- An **SNTP/NTP peer** and a controllable host clock for the time-sync startup gate and the DST-boundary row (ALERT-64).
- **Chromium and Firefox** (ALERT-59); **VS Code + `@vscode/test-electron`** — the existing `ide` CI leg (ALERT-29..31, 60).
- `QT_QPA_PLATFORM=offscreen` for any PySide6 harness leg (`$env:QT_QPA_PLATFORM="offscreen"` in PowerShell). None of this chapter's rows are Qt-dependent, but the harness process is.

**Accounts.** A `service:configure` operator (for `/alerts/test-email`), a `monitoring:diagnose`
operator (for `/alerts/*` and `/ui/alerts`), a `monitoring:read`-only operator (to prove the bell
hides rather than showing an untrustworthy zero), a `logs:view` holder (for `/logs/tail`), and a
channel-scoped operator (for the per-channel scope refusals). A PagerDuty/on-call integration
account for ALERT-56.

**Synthetic data — hard rule.**
- Every message is generated: `python -m messagefoundry generate adt --count <n>` (corpus is git-ignored). Never real PHI, in any row, on any host.
- `dryrun` / `generate` stdout can carry **full message bodies** — never redirect either into a committed file, a ticket, or a CI log. S7 deliberately uses a load profile rather than `generate` redirection for exactly this reason.
- The ALERT-45 corpus is built, asserted against and discarded **in process**; on failure the test prints the token *class* and line index, never the line.
- Every report this chapter produces carries **metrics and metadata only** — counts, latencies, series names, event types. Never a message body, never a control-id list, never a recipient address.
- Load profiles used: `harness/load/profiles/connscale.toml` (ALERT-40, 61), `sustained-overload.toml` (to trip buildup/stall/saturation at scale), `smoke.toml` (S7's rollover fill).

### 14.8 Exit criteria

**Only class-`T` rows gate.** The four **C** rows (ALERT-56, 61, 62, 63) are signed off by their
*recorded outcome being filed*, never by passing; a C row can neither block nor clear this list.
There are no **A** rows in this chapter.

This area is signed off for release when **all** of the following hold:

1. **All 12 P0 (class-`T`) rows pass or are explicitly waived by the owner with a dated ADR entry:** ALERT-01, 02, 03, 04, 05, 06, 07, 08, 09, 10, 58, 67. (ALERT-02 and ALERT-06 may exit as `xfail` **only** if OQ-1/OQ-2 resolve to "designed-not-built", and only with the ADR amendment merged.)
2. **The G1 mirror invariant is enforced in CI.** A planted emit type outside `_ALERT_EVENT_TYPES`, and a planted method on one of the three classes only, each fail the `test` leg. Falsifiability is itself asserted (mirror `tests/test_alerts_edit.py:160`).
3. **Zero PHI leaks.** ALERT-16, 17, 18, 45, 46, 48, 49 all pass; the ALERT-45 residual count is at or under its committed ceiling; the leak gate is fail-closed.
4. **The documents agree with the code, and the SMTP-posture half is ALREADY SATISFIED.** `docs/PHI.md` row 11 and the ALERT-08 assertion state one posture (ALERT-67); `docs/BACKLOG.md` #171 no longer claims unbuilt (ALERT-66); `docs/FEATURE-MAP.md` §9 names every routable event type and §10 references no non-existent module (ALERT-65).
   **This criterion previously read "the three CONTRADICTING documents agree with the code" and named a contradiction that #323 had already closed on 2026-08-02 (BACKLOG #1100).** An exit criterion demanding that a resolved contradiction be resolved is a gate that can never inform anyone: it cannot fail, so passing it says nothing, and a reader who trusts it believes a check ran. What remains genuinely gating is the *guard* (ALERT-67), which earns its keep on a future divergence rather than on this one.
5. **The four superseded FEATURE-COVERAGE-PLAN rows are recorded as closed** with the dated re-verification in 14.2, and the remaining open ones (`FCP:ALERT-3`, `FCP:ALERT-5`, `FCP:ALERT-9`, `FCP:ALERT-10`) map 1:1 onto ALERT-19, ALERT-22, ALERT-13, ALERT-11 here.
6. **Every P1 class-`T` row passes or carries a dated, owner-accepted waiver.** In particular the three that are pure *pins of known non-coverage* (ALERT-15 outbound saturation blind spot, ALERT-26 restart asymmetry, ALERT-47 support-bundle no-RBAC) must be **passing pins**, not waivers — a pin that is waived is worthless.
7. **The detectability sweep (ALERT-55) reports zero unnamed holes.** Any hole is either closed or listed by name in the release notes with an operator workaround.
8. **The IDE parity decision (OQ-7) is implemented and guarded.** Either the editor reaches the decided parity level and ALERT-29..31 pass, or the console and the IDE panel both state the supported-subset limitation and ALERT-30 asserts the *decided* subset.
9. **New CI legs are green and required:** `otel-collector`, `syslog-collector`, the extended `windows-service-smoke` rotation assertion, and the extended `load-test` `/metrics` ceiling.
10. **The W2025 manual pass is recorded**, with the S4 three-cert matrix, the S7 rollover evidence, the ALERT-53 `icacls` output, the ALERT-54 no-dump confirmation, and the ALERT-62 storm observation — metadata only, filed outside any git checkout.
11. **No open `alert_instance` row is left behind** by any test run on a shared backend (ALERT-25/28/35 all clean up), and the shared cluster DB's `alert_instance` table is empty at sign-off.

### 14.9 Open questions

1. **`content_match` reachability (ADR 0133 D3).** Should a Handler get a first-class exported way to raise it — an injected sink, or a `messagefoundry.alert_content(...)` export alongside `db_lookup`/`fhir_lookup` — or should ADR 0133 D3 be re-scoped as *designed, not built*? Today no Handler can reach it and `LoggingAlertSink` has no fallback method, so a fallback-path caller would `AttributeError`. **Blocks:** ALERT-02, 04, 05; whether `content_match` stays in `_ALERT_EVENT_TYPES`; the ADR 0133 AC-3 wording.
2. **`connection_started`.** Should a lane restart auto-resolve an open `connection_stopped`, or is manual operator resolve the intended workflow — and if the latter, should the dead `_AUTO_RESOLVE` key be removed? **Blocks:** ALERT-06, 07; and, downstream, ALERT-35's growth expectation (G16 is largely a consequence of this).
3. **Alert / security-notification SMTP posture — ANSWERED, AND IT WAS ANSWERED BEFORE THIS QUESTION WAS WRITTEN (BACKLOG #1100).** This asked whether the unauthenticated STARTTLS was an accepted residual or had to adopt the ADR 0092/0153 hop gradient, and asserted that `docs/PHI.md` row 11 and `docs/BACKLOG.md` "currently contradict each other". **Neither premise holds.** #323 closed it on 2026-08-02: `send_plain_email` passes an explicit verifying context, so the hop is authenticated. And the gradient half has a recorded answer too — per `docs/PHI.md` row 11 this path did **not** adopt the connector hop gradient; its deviations (`email_use_tls = false`, `email_tls_verify = false`) are gated by a `[security].allow_unverified_alert_smtp_tls` **acknowledgment switch at the serve gate**, which refuses to start on an enforcing PHI instance without it and `AUDIT`-logs the start with it.
   **It therefore BLOCKS NOTHING.** ALERT-08, 09, 58 and 67 are unblocked and should be built against the posture as shipped. Leaving this open was the more expensive error of the two: an open P0 "with a real security consequence" reads as a live exposure, and this chapter's only such row was describing a fix.
4. **Should `[alerts]` become reloadable** (via `POST /config/reload` or a dedicated route), or is restart-only the intended contract — and if so, must the IDE editor **and** the console surface a `pending restart` state? **Blocks:** ALERT-10, 32, 33 and scenario S5.
5. **Leader-gating for `cert_expiry` / `secret_rotation` / `update_check` / `gcm_invocations`.** They report **cluster-wide** facts, unlike the per-node lane events ADR 0014 §4 reasons about, so an N-node cluster pages N times per condition. Gate them, dedupe at the store, or accept? Note `gcm_invocations.py:28-29` already argues against gating the *refill* — the alert is a separable question. **Blocks:** ALERT-27, 28, 63.
6. **Is the outbound saturation blind spot acceptable for release** (a healthy-but-behind lane is never sampled), or must BACKLOG #93's periodic owned-outbound depth sweep land first? **Blocks:** whether ALERT-15 is a pin or a bug; and one entry in the ALERT-55 sweep.
7. **What is the release bar for the IDE alert editor** — full parity with `AlertRule` (the 18 `_ALERT_EVENT_TYPES` members + `any` = 19 dropdown entries, and all 15 fields), or is the CLI/TOML the supported authoring path with the editor frozen at today's 5 entries and 7 fields? If frozen, should the console warn that GUI-authored rules are a subset? **Blocks:** ALERT-29, 30, 31, 60.
8. **Should an alert-triggered `control_action` write a tamper-evident audit row,** and under what actor identity (`alert-rule`, the rule `id`, or a synthetic principal)? A rule can currently restart a production connection with no attributable trail while every other control path is audited. **Blocks:** ALERT-34.
9. **Is a dropped alert allowed to be invisible?** `_MAX_QUEUE` overflow logs a WARNING and nothing else — no counter, no metric, no `/stats` field. Add a counter, or accept log-only? **Blocks:** ALERT-20 and the shape of ALERT-62's manual observation.
10. **Failover alerting behaviour.** Is a full re-page of every open condition on the new leader — with escalation tiers resetting to base, so a long-running critical drops back to warning — acceptable, or should `_last_sent` / `_occurrences` be primed from `alert_instance` the way `_suspended` already is? ADR 0014 §4 (lines 91-92, 117) records the current behaviour as accepted, but nothing bounds it. **Blocks:** ALERT-24, 25, 26.
11. **Is unbounded growth of never-resolved `alert_instance` rows acceptable,** or should open instances be capped / aged under an explicit, operator-visible policy? Related: the nav bell's `list_active_alerts(limit=200)` silently saturates. **Blocks:** ALERT-35 and its documented ceiling.
12. **Which observability paths are release-blocking?** Is `/metrics` + `/ws/stats` + the console sufficient, or must a working Prometheus/Grafana **and** a working SIEM forwarding path be proven on the W2025 box before sign-off? This decides whether ALERT-50, 61 are P2 rows or exit criteria. **Blocks:** exit criterion 9 and 10's scope.
13. **Do we formally supersede the stale FEATURE-COVERAGE-PLAN `ALERT` rows** (`FCP:ALERT-4`/`FCP:ALERT-12`/`FCP:ALERT-19` closed, `FCP:ALERT-24` citing a deleted test, the `settings.py:1755` drift) with the dated re-verification in 14.2, or edit that document in place? 14.2 currently assumes *supersede here, leave the artifact untouched*. **Blocks:** nothing technical — but it decides whether the release budget re-litigates three already-closed gaps.
