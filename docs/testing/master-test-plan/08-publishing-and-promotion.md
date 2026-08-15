[← Master Test Plan index](../MASTER-TEST-PLAN.md) · *Part II — Subsystem chapters*

---

## 7. Publishing & Promotion to Non-Production and Production Engines

**ID prefix:** `PUB` · **Surface:** IDE + engine + web console + CLI + infra (tray touches it only via Restart)
· **Primary risk:** a promote reports success while the production engine is running *different bytes* than the operator believes — and nothing in the product can tell them so.

### 7.1 Scope & objectives

This chapter owns **the whole path by which authored configuration reaches a running engine**, and
specifically the **non-production vs production** distinction. Concretely:

- **The IDE Stage → Promote flow** — [`ide/src/promote.ts`](../../../ide/src/promote.ts) (validate →
  environment pick → engine-shard pick → host policy → env-aware dry-run pre-flight → modal confirm →
  apply), [`ide/src/promoteTarget.ts`](../../../ide/src/promoteTarget.ts) (pure target resolution),
  [`ide/src/engineTarget.ts`](../../../ide/src/engineTarget.ts) (SEC-005 host policy).
- **The engine reload contract** — `POST /config/reload`
  ([`messagefoundry/api/app.py:2741-2891`](../../../messagefoundry/api/app.py)), reload-root confinement
  (`Engine._resolve_reload_target`, [`engine.py:1508-1521`](../../../messagefoundry/pipeline/engine.py)),
  `config:deploy` + `require_step_up`, ADR 0041 D2 dual-control, and the quiesce-and-swap in
  `RegistryRunner.reload` ([`wiring_runner.py:3046-3184`](../../../messagefoundry/pipeline/wiring_runner.py)).
- **The web console config-deploy page** — `/ui/config` +
  [`messagefoundry_webconsole/routes/config.py`](../../../messagefoundry_webconsole/routes/config.py)
  (fixed `ReloadRequest(config_dir=None, dry_run=False)`) and the provenance badge in
  [`pages/config.py`](../../../messagefoundry_webconsole/pages/config.py).
- **Attestation & attribution** — ADR 0041 D1 content fingerprint
  ([`config/fingerprint.py`](../../../messagefoundry/config/fingerprint.py)), `GET /config/provenance`,
  the `config_reload*` audit family, and ADR 0041 D3 wheel self-attestation
  ([`integrity.py`](../../../messagefoundry/integrity.py)) where it interacts with a publish.
- **Environment values and target isolation** — `environments/<env>.toml` + `MEFOR_VALUE_*`
  ([`config/environments.py`](../../../messagefoundry/config/environments.py)), ADR 0050 project-root
  anchoring, deferred `env()` resolution *on the target*, and wrong-target / environment-crossing safety.
- **Multi-target publishing** — several named `messagefoundry.environments` entries, engine-shard
  sub-targets within one environment, and cluster config-version convergence
  ([`pipeline/config_convergence.py`](../../../messagefoundry/pipeline/config_convergence.py)).
- **Atomicity, partial publish, rollback, and behaviour of in-flight messages / open connections across
  a publish**, including publishing during a cluster failover.
- **Per-artifact-kind publish semantics** — Router/Handler `*.py`, `connections.toml`, `codesets/*`,
  and (critically) the artifacts that are **not** publishable at all: alert rules, `[security]`/auth
  config and AI policy in `messagefoundry.toml`.
- **Version control as the delivery mechanism** — [`docs/VERSION-CONTROL.md`](../../VERSION-CONTROL.md),
  the offline git init + `messagefoundry check` pre-commit hook
  ([`ide/src/sourceControl.ts`](../../../ide/src/sourceControl.ts)), and the air-gapped `git bundle` path.

**Explicitly NOT in scope here (owned elsewhere — cited, not restated):**

| Out of scope | Owner |
|---|---|
| RBAC role/permission matrix, step-up primitive, audit chain integrity as such | `docs/testing/FEATURE-COVERAGE-PLAN.md` §RBAC (rows `FCP:RBAC-15`, `FCP:RBAC-17`) and `docs/SECURITY.md` |
| Approvals API surface itself (list/approve/reject, expiry, self-approve refusal) | FEATURE-COVERAGE-PLAN row `FCP:API-26`; `tests/test_approvals.py` |
| Windows Server 2025 host build, NSSM service identity, config-dir ACL posture | `docs/testing/WIN2025-TEST-PLAN.md` (`W25:S1.AC-ACL`, matrix `W25:F5`) — this chapter only *consumes* that box |
| Config-reload under the service identity as a host concern | `WIN2025-TEST-PLAN.md:107` (`W25:B5`) and `:1549` — **explicitly deferred to Phase 2**; PUB rows that need the box are marked `W2025-box` and depend on it |
| Steady-state throughput/latency SLOs and failover-under-load conformance | `docs/LOAD-TESTING.md` (`python -m harness --load …`, `--failover`) — this chapter adds only the *publish-under-load* perturbation |
| On-box deployment acceptance (host/store/smoke/federation) | `docs/testing/VERIFY.md` + `messagefoundry/verify/` — one new row (PUB-60) proposes adding a provenance check *to* it |
| ADR 0036 DACL policy matrix as a policy | `tests/test_config_source_trust.py` (15 tests) — this chapter tests only its behaviour **on the reload path** |
| The `deployed=False` staged-rollout primitive as a feature | `tests/test_not_deployed.py` (ADR 0111 / #233) — including two reload cells already covered (see 7.2) |

**Objective.** After this chapter is executed and green, an operator can answer, from the product,
*"which reviewed commit and which exact bytes is each of my engines running, and did my last promote
actually apply them?"* — and a bad production publish has a rehearsed, timed rollback.

### 7.2 Already covered — do not re-test

| Evidence | What it proves |
|---|---|
| `tests/test_api_reload.py` (11 tests) | `POST /config/reload` applies a graph; `dry_run` validates without applying; missing `env()` value → 422; missing dir → 404; invalid config → 422; empty dir → 422; path outside allowed roots → 403; defaults to the startup dir; failures audited; the audit carries the ADR 0041 fingerprint; an extra `[api].config_reload_roots` entry is honoured. **Caveat:** the fixture builds the app with `allow_no_auth=True` (`tests/test_api_reload.py:27`) — it proves nothing about RBAC/step-up. |
| `tests/test_dual_control_reload.py` (5 tests) | ADR 0041 AC-5..AC-8: a gated non-dry-run reload is held 202 and the graph is **not** swapped; self-approval refused 403; a distinct approver releases it and both identities + the fingerprint-bearing row are audited; inline when not gated; a `dry_run` is never held. |
| `tests/test_approvals.py` (9 tests) | The generic dual-control mechanics `config_reload` rides: disabled = inline; held pending; no self-approve; release executes + audits both identities; reject does not execute; viewer refused on the approval routes; expired/unknown refused; `[approvals].operations` rejects an unknown op name. |
| `tests/test_config_fingerprint.py` (11 tests) | Fingerprint stability, 64-hex form, path-relativity, sensitivity to `*.py` / `_*.py` helper / `connections.toml` / `codesets` / `environments` edits, new-file sensitivity, insensitivity to unrelated files, detail file count. **Caveat:** the `environments` case writes `environments/` *inside* the tmp config dir (`:81-88`) — see PUB-03. |
| `tests/test_config_provenance.py` (5 tests) | `loaded=false` before any load; clean after a reload; on-disk drift detected; rebaseline on reload; auth required. Every case establishes the baseline via `/config/reload` — the `serve`-startup case is never exercised (PUB-01). |
| `tests/test_wiring_reload.py` (16 tests) | Quiesce-and-swap swaps Router/Handler; outbound directory change; in-flight outbox preserved; `build_check` rejects a bad connector **before** quiesce; a removed outbound keeps draining; invalid config leaves the graph untouched; missing dir; empty dir refused; half-started runner reset; starts a graph when none loaded; dry-run validates without swapping; dry-run rejects/resolves env values; reload re-gathers env values; reload never resumes a paused outbound. |
| `tests/test_environments.py` (24 tests) | `env()` ref/resolve/cast/missing-key-lists-all; file + `MEFOR_VALUE_` overlay and lower-casing; missing file is empty; build resolves env for an outbound; `build_check` fails loud on a missing value; not-deployed connections skip env resolution; committed `dev.toml`/`prod.toml` define the **same key set** (`:185`); `resolve_values_base_dir` cwd/relative/absolute/drive-relative-warning; the anchor finds the value file when cwd is elsewhere; `serve --project-root` is parsed. |
| `tests/test_not_deployed.py:436,473` | **A reload cannot resurrect a `deployed=False` outbound, and cannot bind a `deployed=False` inbound.** (The recon under-counted this: two of the four operator-intent cells are already covered — see PUB-32 for the remainder.) |
| `tests/test_shard_recovery_engine.py:206-234` | `Engine.reload` **refuses** a config whose engine-shard universe changed, the refusal names both engine-shard sets, and the running registry is untouched (`engine.py:1415-1433`). |
| `tests/test_config_source_trust.py` (15 tests) | The ADR 0036 NTFS-DACL / POSIX policy matrix plus the end-to-end Windows load refusal and its escape. |
| `tests/test_startup_attestation.py` | ADR 0041 D3 AC-9..AC-12: RECORD attestation, alert-only default, fail-closed when opted in, editable-install no-op. |
| `tests/test_cluster.py:943` | The **operator-initiated** arm of cluster config convergence (what `/config/reload` drives with `propagate=True`) bumps the shared `config_version`. |
| `tests/test_security_doc_drift.py:544+` | `POST /config/reload`'s gate wiring (`config:deploy` + `require_step_up`) matches the documented route table — structurally, by closure introspection, **not** by a real request (PUB-14/PUB-15). |
| `tests/test_auth_hardening.py:594-626` | `CONFIG_DEPLOY` on the WebSocket authorize path: a viewer is denied and audited; an admin grant is audited. |
| `tests/test_auth_entry_hardening.py:133` | `ReloadRequest.config_dir`'s 4096-char bound rejects an oversized path (ASVS 1.3.3). |
| `packaging/messagefoundry-webconsole/tests/test_webui.py:1798-1841` | `/ui/config` renders with no `config_dir` input and no file picker; a VIEWER is 403'd; a cross-site POST is 403'd; `/ui/config/reload` is in the step-up auto-retry allow-list and a query-bearing variant is rejected. |
| `packaging/messagefoundry-webconsole/tests/test_pages_config.py` (4 tests) | The provenance badge renders clean / DRIFTED / fingerprint-only-when-no-git / absent-when-not-loaded. |
| `ide/src/test/suite/promote-target.test.ts` (7 tests) | `planTargetResolution` / `resolveTargetUrl`: 0 engine shards → env url; 1 engine shard auto-selected; ≥2 → pick required; the composite environment/engine-shard label (`PROD / shard-2`, `promoteTarget.ts:8`); malformed engine-shard entries dropped. |
| `ide/src/test/suite/engine-target.test.ts` (6 tests) | `assertTargetAllowed` / `isLocalEngine`: loopback http allowed (`127.0.0.1` / `localhost` / `::1`); non-loopback http **refused** with a host-naming, https-recommending reason; https off-box allowed; an unparseable URL fails safe. |
| `ide/src/test/suite/settings-scope.test.ts` (4 tests) | `engineUrl` / `environments` / `pythonPath` are machine-scoped; every declared setting is classified; any target-smelling key must be machine-scoped; `untrustedWorkspaces.supported === 'limited'`. |
| `ide/src/test/suite/engine-doctor.test.ts:221-284` | A drifted engine's **first** offered action is `messagefoundry.promote`, and the trusted status hover cannot be command-injected. |
| `ide/src/test/suite/config-refresh.test.ts` (10 tests) | Config-dir watcher debounce and `watchableConfigDir` containment. |
| `.github/workflows/ci.yml` `test` job (**required**) | The whole engine pytest suite — every reload / approvals / fingerprint / provenance / environments test — on `ubuntu-latest` + `windows-2022` + `windows-2025`, plus the web console suite. |
| `harness/acceptance/matrix.py:400-405` + `WIN2025-TEST-MATRIX.md:81` (`W25:F5`) | Row *"Config reload confined to allow-listed roots"* maps to `tests/test_api_reload.py` — an evidence mapping only, no on-box execution. |
| `messagefoundry/checks.py` + `tests/test_checks.py` | The `messagefoundry check` commit/CI gate (validate + fixture dryrun + posture + build-check + reference-backend + handler-security; ruff/mypy advisory) — the authoring-side gate promote does **not** run. |

**Done — do not re-plan.** The *mechanics* of the reload endpoint (path confinement, the four status
codes, the four `config_reload*` audit actions, the dual-control hold/release/reject ceremony), the
*purity* of the fingerprint function, the *shape* of the provenance API, the IDE's *pure* target
resolver and host policy, and the machine-scoping SEC-005 invariant are all genuinely covered. What is
**not** covered anywhere is: the composite promotion pipeline; whether a promote's reported outcome
matches reality; provenance on the restart-based publish path; the fingerprint's blindness to the real
`environments/` location; cross-node/cross-engine-shard content divergence; and the residue left by a
post-quiesce failure. Those are this chapter's centre of gravity.

### 7.3 Risk analysis

| Risk | Failure mode | Blast radius | Detected today? | Priority |
|---|---|---|---|---|
| Restart-based publish has zero attribution | **CONFIRMED 2026-08-15 (BACKLOG #1100); both anchors had drifted and are re-pointed.** The startup path loads at **`api/app.py:5725`** (`loaded = load_config(config_dir)`) and **`:5730`** (`engine.add_registry(loaded)`) — the cited `:5455-5462` now lands on a function signature's keyword parameters, ~270 lines away. And **only `Engine.reload()` sets `loaded_config_fingerprint`**: it is initialised `None` at **`engine.py:450`** and assigned at **`:1610`/`:1615`, both inside `reload()`** (def `:1479`; the cited `:1488-1500` is the right method, wrong lines). Verified from the other side too — **`Engine.start()` (`engine.py:875`, 301 lines) mentions none of `loaded_config_fingerprint`, `config_fingerprint`, `add_registry` or `load_config`.** The fingerprint-bearing `config_reload` audit row is written only from the reload path (`api/app.py:554-573`, registered as a gate action at `:547`). Copy-files + NSSM restart (and the tray **Restart Service**) leave `loaded=false` and write no fingerprint-bearing audit row. | Every engine that was ever restarted rather than reloaded — i.e. the primary CI/CD path and every service restart. `/ui` badge blank, IDE can never show DRIFTED, no `who activated these bytes` row. | **No.** `GET /config/provenance` returns `loaded=false`, which reads as "nothing loaded", not "unattested". | P0 |
| Fingerprint is blind to the real `environments/` | `_FINGERPRINT_GLOBS` includes `environments/*.toml` **relative to the config dir** (`fingerprint.py:44`, globbed at `:59` as `base.glob(pattern)` where `base` is the directory passed in — i.e. `engine.last_reload_dir` / `engine.config_dir`), but every shipped/documented layout keeps `environments/` as a project-root **sibling** of `--config` (ADR 0017 layout; ADR 0050 anchoring). **CONFIRMED 2026-08-15 (BACKLOG #1100), measured on this checkout:** repo-root `environments/` holds **2** `.toml` files, and **`samples/config/environments/` does not exist** — so the glob resolves to nothing for the documented layout. **The redirect surface is exactly the peer endpoints:** those files declare `acme_adt_host`, `acme_adt_port`, `demo_oru_host`, `demo_oru_port`, `fhir_base_url`, `payer_rte_host`, `payer_rte_port` (14 keys each). **And ADR 0041 states the opposite as a REQUIREMENT, not a description** — `:100` *"It spans `connections.toml` **and** `environments/` so a transport/env-value redirect cannot change [the graph without changing the fingerprint]"*, and `:153` *"...or `environments/*.toml` — **THE SYSTEM SHALL** produce a different fingerprint."* **The shipped code does not meet that SHALL in the documented layout.** (ADR 0041 `:238` separately leaves "Fingerprint env-value scope" open, but that question is about hashing *resolved* values — it does not cover this, which is the declared scope failing to resolve at all.) | Repointing `acme_adt_host` in `environments/prod.toml` redirects PHI to a new peer with an **identical** fingerprint, no drift flag, and an audit row indistinguishable from a clean reload. | **No** — and ADR 0041 explicitly claims the opposite ("spans … `environments/`"). The existing test passes only because it writes `environments/` *inside* the tmp config dir. | P0 |
| "Promoted to PROD" can be false | A remote promote sends `config_dir: null` (`promote.ts:135-149`) so the engine reloads its **own** on-disk dir; `ReloadResult` (`api/models.py:351-360`) carries no fingerprint. If CI/CD never delivered the commit, PROD reloads stale bytes and the toast still says "promoted". | Silent whenever element counts are unchanged — i.e. almost every Handler-logic change. Highest-frequency wrong belief in the publish path. | **Partly — and the partial coverage is the trap. RE-MEASURED 2026-08-15 (BACKLOG #1100).** "Nothing recomputes or compares a fingerprint" is **FALSE**: `ConfigProvenance` (`api/app.py:4570-4590`) reads `engine.loaded_config_fingerprint`, **recomputes** `config_fingerprint_detail(target)` off the loop, and **compares** them — `drift = current.get("fingerprint") != fp` — returning a `drift` flag. ADR 0041 D1 also writes a fingerprint-bearing `config_reload` audit row on every reload (`:554-581`). **BUT IT COMPARES THE WRONG TWO THINGS FOR THIS RISK.** `drift` is *loaded-vs-disk-now*; the failure here is *disk-vs-the-commit-CI-was-meant-to-deliver*. **If CI/CD never delivered, disk still equals what was loaded, so `drift` is `False` and provenance reports clean.** So the row's concern survives its evidence completely — and is now *harder* to see, because a reviewer who finds `ConfigProvenance` will reasonably conclude it is covered. Still true: `ReloadResult` (**`api/models.py:371`**, cited `:351-360`) carries no fingerprint, so the promoting caller never receives one; and there is no `messagefoundry fingerprint` CLI (subcommands are `graph`, `serve`, `validate`). **The fix is smaller than this row implied** — the fingerprint is already computed on every reload; it needs *surfacing in `ReloadResult`* and comparing against an expected value, not building | P0 |
| A held (dual-control) promote renders as success | `engineClient.postJson` resolves any 2xx and casts the body (`engineClient.ts:92-102`); a 202 `PendingApprovalResponse` becomes a `ReloadResult` with `undefined` counts, and `promote.ts:191` prints "promoted to PROD — live graph: undefined inbound…". | Exactly the deployments that enabled dual-control **for production**. Operator believes the graph swapped; it is sitting in a queue. | **No — CONFIRMED 2026-08-15 (BACKLOG #1100), and both anchors still land, which is rare in this sweep.** `engineClient.ts:94-96` is exactly `if (status >= 200 && status < 300) { resolve((text ? JSON.parse(text) : {}) as T)` — **any** 2xx resolves and blind-casts, so a 202 body becomes a `ReloadResult` of `undefined`s; `promote.ts:191-195` then prints the success toast with **no status check**. Measured: **41 IDE test files exist and NOT ONE drives `promote.ts`** (`promote-target.test.ts` tests `promoteTarget.ts`, a different module). **Stronger than the row states: `PendingApproval` appears nowhere in `ide/`, and there is no 202 handling anywhere in `ide/src`** — the client does not model the pending-approval response at all, so this is not a missed branch but an absent concept. **The fix is one status check** at the `postJson` call site, not new machinery | P0 |
| Split-config cluster / split engine-shard estate | Convergence coordinates *when* nodes reload; each reloads its **own** dir (`config_convergence.py:16-20`). `ClusterStatus` exposes only the integer `config_version` (**`api/models.py:786`**, cited `:737-748`), never a content fingerprint. **CONFIRMED 2026-08-15 (BACKLOG #1100):** `ClusterStatus` fields are exactly `node_id, clustered, is_leader, role, config_version`, and `ClusterNode` (`:800`) adds none either — neither mentions `fingerprint`. The convergence anchor lands exactly: `config_convergence.py:16-18` states the assumption in its own words — *"The version token coordinates when nodes reload; each node reloads its OWN config dir. Skewed config dirs would diverge."* **THIS IS THE THIRD FACET OF ONE GAP, NOT THREE GAPS.** ADR 0041 D1 computes a content fingerprint on every reload, and it is surfaced in **none** of the three places a consumer could compare it: not in `ReloadResult` (row 109), not in `ClusterStatus` here, and not at all on the restart path (row 107, which never sets it). **One change — surfacing the already-computed fingerprint on those responses — addresses all three rows**, which is worth knowing before any of them is scoped separately. Promote picks **one** engine-shard URL (`promoteTarget.ts:53-55`). | Node A runs the new graph, node B re-applies its old one; both write clean `config_reload` rows and report the same `config_version`. After a failover the wrong graph serves production. Engine shards over one unified store diverge per lane. | **No.** ADR 0041 lists this as unresolved — its open item to coordinate with the engine-shard owner. | P0 |
| Composite pipeline never exercised | Every unit exists; the assembly (author → check → non-prod → traffic → identical artifact to prod → per-environment substitution → rollback) has no test, no harness rig, and `FEATURE-COVERAGE-PLAN.md` excludes the IDE from every subsystem (`:946, :1216, :1379, :1420, :1471, :1521`). | The interfaces between the pieces — env substitution, artifact identity, pre-flight-vs-apply ordering, rollback — are where the real defects live. | **No.** | P0 |
| Post-quiesce failure leaves partial state | Rollback restores **only** `self.registry` + inbound intake (`wiring_runner.py:3151-3164`). By then the live-lookup executor has been rebuilt and the old one `aclose`d (`:3096-3104`), sandbox sessions dropped (`:3086-3095`), and `_reconcile_outbounds` may have partially applied (`:3149`). | Old Routers/Handlers run against **new-graph** `db_lookup`/`fhir_lookup` pools. If the new graph dropped a `DbLookup`, every old-graph lookup raises post-ACK — a silent per-message ERROR/dead-letter storm behind an audit row the operator reads as a clean no-op. | **No.** No test drives a failure at the inbound-bind or `_reconcile_outbounds` step. | P1 |
| Same bytes, two different outcomes | `reload()` has **no** ADR-0031 per-inbound fault isolation (`wiring_runner.py:3108-3134`) while `start()` does (`:2236-2242` `_record_failed`). One unbindable inbound aborts the whole publish; the same bundle on a restart comes up with that connection isolated and everything else running. | An operator who "retries via a service restart" gets a partially-live graph they believed the engine had refused. | **No**, and undocumented. | P1 |
| Duplicate ingest on publish | Quiescing closes established MLLP client connections (`transports/mllp.py:1352-1372`); the body is committed before the ACK, so nothing is lost, but a **not-yet-sent ACK** is — the sender retries and the engine ingests a duplicate. | Clinically material for non-idempotent downstreams (duplicate orders/results). The scope requirement is "must not lose **or duplicate**". | Partially — the consequence is documented in the code comment, but no test drives a reload under concurrent inbound traffic and no duplicate rate is published. | P1 |
| In-flight ingress rows are processed by the **new** graph | `reload()`'s docstring claims a message in flight "completes under its arrival-time registry (snapshotted in `_make_handler`)" (`wiring_runner.py:3068-3069`), but `_make_handler` (`:3188-3197`) records that under the staged pipeline the listener no longer routes — the router worker routes against the **live** registry. | A message ACKed under graph A is routed/transformed by graph B. Legitimate and arguably desirable, but the code contradicts itself and nothing pins the semantic. | **No.** Two comments in one file disagree. | P1 |
| Dual-control approver approves blind | The pending list returns `id/operation/label/requester/requested_at/expires_at` only (`api/approvals.py:100-111`) — no `config_dir`, no fingerprint. The captured `config_dir` is replayed at **release** time, and the fingerprint recorded is of the bytes present **then**. | Between request and release the on-disk bundle can change; the second approver's signature attaches to bytes they never saw and could not have seen. Defeats the one preventive control on the broadest-blast-radius action. | **No.** | P1 |
| Restart-only artifacts silently not published | Alert rules, `[security]`/auth config and AI policy live in `messagefoundry.toml`; the IDE editors write the **local** file (`alertEditor.ts`, `securityEditor.ts`) and no API route writes config files. Promote neither ships nor applies them. | An operator edits alert rules or the security posture, clicks Promote, gets a green toast — and the alert that was supposed to start firing does not. | **No**, and the promote UX names nothing about what it did not apply. | P1 |
| Wrong-target / environment-crossing | ADR 0017's per-instance "expected environment" assertion is a **Minor** row and is **unbuilt** (`grep expected_environment` over `messagefoundry/` = no hits). A dev artifact is not refused by a prod engine. The `env()` missing-key backstop does not fire, because `dev.toml` and `prod.toml` are guaranteed to define the same key set (`tests/test_environments.py:185`). | Only the IDE's client-side host-confirm dialog stands between a typo and a production publish. | **No** server-side control exists. | P1 |
| Local gate is weaker than the commit gate | `promote.ts:82` runs `validate --json`; the pre-commit hook and CI run `messagefoundry check`. A dangling `code_set("old_name")` resolves at **run** time (post-ACK, forever) — `validate` misses it, `check`'s dryrun catches it (`docs/USER-GUIDE.md:446`). | A promote from a `--no-verify` commit or an uncommitted edit reaches the target under the weaker gate. | Partially — the target's dry-run pre-flight runs `build_check`, which catches connector/posture problems but not a run-time `code_set` miss. | P1 |
| No rollback | No `/config/rollback` route, no previous-bundle or last-known-good fingerprint retention (`grep -i 'rollback\|revert'` over `api/app.py` + `pipeline/engine.py` → only the in-reload intake rollback). | Recovery from a bad prod publish is `git revert` → out-of-band redelivery → reload, done by hand under time pressure, with no engine-reported target fingerprint to aim at. Recovery time unbounded and unrehearsed. | n/a — it does not exist. | P1 |
| Trust-anchor re-verification skipped on the pre-flight | `run_anchor_preflight` runs only when `anchor_specs and not req.dry_run` (`api/app.py:2789`, call at `:2791`). | A substituted/pin-mismatched anchor passes the pre-flight, the operator confirms the modal, and the **apply** 422s. Confusing at best; at worst the operator retries past it. | Partially — the apply does refuse. | P1 |
| No behavioural RBAC/step-up test on the publish route | `test_api_reload.py` runs `allow_no_auth=True`; the gate is asserted only structurally by the doc-drift route walk (`test_security_doc_drift.py:544+`). | A refactor swapping `require_step_up` for `require` stays green as soon as `SECURITY.md` is edited in the same commit — which is this project's convention. | **No** request-level negative test. | P1 |
| `ide` CI job is not required | `.github/workflows/ci.yml:263-283` — `ci-gate` does not `needs: ide`; the job is skipped unless the PR touches `ide/**` or `ci.yml`; the promote-resolution suite is additionally excluded from `npm run test:unit` and runs only on the Windows electron leg (dropped on forks). | An engine-side change to the `/config/reload` contract merges green with nothing having compiled or exercised the promote client. | **No.** | P1 |
| Secret rotation is invisible to attestation | `MEFOR_VALUE_*` resolved values are not folded into the fingerprint (ADR 0041 "To resolve", first bullet). The rotation watcher fingerprints credentials separately (`config/wiring.py connector_secret_env_values`) but that is not joined to config provenance. | Swapping `MEFOR_VALUE_ACME_ADT_HOST` on the prod host redirects PHI while `/config/provenance` reports clean. | **No.** | P2 |
| Publish is an unannounced outage window | No characterization of how long intake is quiesced during quiesce-and-swap, nor how deep the ingress backlog grows, at realistic connection counts (pooled claim mode at ~1,500 lanes is the documented stress point). | An operator promoting during business hours has no published expectation for the intake pause. | **No.** | P2 |
| No who-changed-what report | `store.list_audit` supports actor/action/since/until (`store/store.py:7195-7228`) but nothing joins `config_reload` rows to fingerprints/commits, and no registry documents the publish event set. | "Show every config change to PROD last quarter and the commit each activated" cannot be answered from the product. | **No.** | P2 |
| Status catalog points at a dead surface | `docs/FEATURE-MAP.md:131` still says "The PySide6 desktop console stays (additive)" and `:162` carries a "Surfaces — Admin Console (PySide6)" section, while `messagefoundry/console/` does not exist; "Multi-engine switcher" is listed against that dead surface. | A reader scopes multi-target-publishing tests at a deleted component. | **No.** | P2 |

### 7.4 Test matrix

**Row class (`Cls`).** `T` = *Test* — a falsifiable assertion with an observable pass criterion; **only
T rows count toward the release gate**. `C` = *Characterisation* — produces a recorded measurement,
finding or dated owner decision, with no threshold yet; legitimate work that **cannot fail**, so it
never gates a release, and it becomes a T row the day its threshold or decision is recorded. `A` =
*Assurance* — an external engagement; blocking only for an off-loopback / production-exposure release.
**This chapter has 70 rows: 63 T, 7 C (PUB-23, PUB-31, PUB-35, PUB-39, PUB-41, PUB-47, PUB-58), 0 A.
12 of the 63 T rows are P0** (PUB-01…PUB-11 and PUB-67). One T row — **PUB-64** — is a *pointer row*
(Method `—`): the deliverable is owned by another chapter and no separate work is scoped here.

**Env.** `container-CI` = a hosted CI runner (`Backend: x2` means two engine processes over one
server-DB service container — the cluster / engine-shard rigs). `dev-PC` = one workstation engine.
`E10-pair` = the **two-engine** environment E10 of Part I ch. 2: a non-production engine **and** a
production-like engine with different derived postures, plus a config-repo remote — the only rig that
can show a posture-divergent, environment-divergent promotion. `W2025-box` = the WIN2025 acceptance
host (a `W25:` deliverable this chapter consumes, never owns).

| ID | Test | Type | Method | Env | Backend | Cls | Pri | Pass criteria |
|---|---|---|---|---|---|---|---|---|
| PUB-01 | `serve` startup captures the provenance baseline | Functional | pytest | container-CI | SQLite | T | P0 | Start an `Engine` with `config_dir=<dir>` and no reload; `GET /config/provenance` returns `loaded=true`, `fingerprint == config_fingerprint(<dir>)`, `files == len(_iter_entries(<dir>))`, `drift=false`. Currently RED. |
| PUB-02 | A boot publish writes a fingerprint-bearing audit row | Functional | pytest | container-CI | SQLite | T | P0 | After the same startup, `store.list_audit(action=<boot action>)` returns exactly one row whose JSON `detail` contains `fingerprint` matching PUB-01 and the resolved config dir. Requires the ADR 0041 D1 `service_started` emitter to be built. Currently RED (no emitter in the tree). |
| PUB-03 | Fingerprint under the **shipped** layout folds the project-root `environments/` | Negative/Security | pytest | container-CI | n/a | T | P0 | Build `root/environments/dev.toml` + `root/config/*.py` (the ADR 0017 layout, mirroring this repo). `config_fingerprint(root/config)` recorded; edit `root/environments/dev.toml`; the fingerprint **moves**. Currently RED — today the glob is config-dir-relative and folds zero env files. |
| PUB-04 | Provenance reports DRIFTED after an env-value edit under the shipped layout | Negative/Security | pytest | container-CI | SQLite | T | P0 | Reload under the PUB-03 layout, then rewrite `acme_adt_host` in the project-root `environments/dev.toml`; `GET /config/provenance` returns `drift=true`. Currently RED. |
| PUB-05 | `messagefoundry fingerprint --config <dir> --json` exists and matches the engine | Functional | pytest | container-CI | n/a | T | P0 | A new CLI subcommand emits `{"fingerprint","files"[, "git_head"]}` byte-identical to `config_fingerprint_detail(<dir>)` for the same bundle, and its digest equals the one in the engine's `config_reload` audit row for the same bytes. No such subcommand exists today (`grep fingerprint messagefoundry/__main__.py` → no parser). |
| PUB-06 | `ReloadResult` carries the loaded fingerprint | Functional | pytest | container-CI | SQLite | T | P0 | A non-dry-run `POST /config/reload` 200 body includes a `fingerprint` field whose 64-hex digest is **string-equal** both to the `config_reload` audit row's fingerprint and to `config_fingerprint(<dir>)` recomputed independently in the test; a `dry_run=true` 200 body carries the digest of the dir that **would** load. Schema change required — `ReloadResult` (`api/models.py:351-360`) today carries only `inbound/outbound/routers/handlers/running/dry_run`. |
| PUB-07 | Promote refuses/warns when the target fingerprint ≠ the locally staged bundle | Negative/Security | ide-mocha | dev-PC | n/a | T | P0 | An extracted pure `interpretReloadResponse(status, body, localFingerprint)` returns a `mismatch` outcome whenever the target digest differs from the locally staged bundle's by even one byte (exact 64-hex string compare, `body.fingerprint !== localFingerprint` — never a prefix or truncated match), and an `ok` outcome only on an exact match; `promote.ts` then surfaces a warning naming **both** digests in full instead of the success toast. Depends on PUB-05 + PUB-06. |
| PUB-08 | A 202 dual-control hold never renders as a successful promote | Negative/Security | ide-mocha | dev-PC | n/a | T | P0 | `interpretReloadResponse(202, {approval_id, operation, detail})` returns a `held` outcome; the driven flow shows "held for a second approver (id …)" and the string `undefined` appears nowhere in the emitted message. Currently RED (`engineClient.ts:92-102` resolves any 2xx). |
| PUB-09 | The 202 body shape the IDE branches on is pinned server-side | Compat | pytest | container-CI | SQLite | T | P0 | With `[approvals].enabled` + `config_reload` in `operations`, `POST /config/reload {"dry_run": false}` returns **202** with exactly `{approval_id, operation:"config_reload", detail}`; a contract test fails if a key is added/removed/renamed. |
| PUB-10 | Cross-node content divergence is detectable | HA/Resilience | pytest | container-CI | x2 | T | P0 | Two `Engine`s on one Postgres store with **divergent** config dirs; reload on A (`propagate=True`), let B converge; a cluster-level surface (e.g. `fingerprint` on `ClusterNode`) reports two distinct digests and a divergence signal is raised. Requires surfacing the fingerprint per node first. Currently no such surface. |
| PUB-11 | End-to-end promotion pipeline rig (author → non-prod → prod → rollback) | Functional | harness | E10-pair | SQLite | T | P0 | See §7.5 scenario A. Needs both E10 engines — a non-production engine **and** a production-like engine — driven from one bundle. Pass = the two engines' `GET /config/provenance.fingerprint` digests are **string-identical** (same artifact bytes), **different** resolved connector settings per environment, synthetic traffic reaching `PROCESSED` on the non-production engine, and a post-rollback digest equal character-for-character to the pre-publish value. |
| PUB-12 | `ReloadRequest` carries no value-bearing field | Negative/Security | pytest | container-CI | n/a | T | P1 | A frozen-shape guard asserts `ReloadRequest.model_fields.keys() == {"config_dir","dry_run"}`; the test fails if any field is added, so a future "send resolved values" change cannot land silently. |
| PUB-13 | The promote request body never contains environment data | PHI | ide-mocha | dev-PC | n/a | T | P1 | With a stubbed `postJson`, the captured body for both the pre-flight and the apply is exactly `{config_dir, dry_run}`; no key whose name matches value / secret / token / env / host / password (case-insensitive) beyond `config_dir` is present, and `config_dir` is `null` for every non-loopback target. |
| PUB-14 | A caller without `config:deploy` is refused and audited | Negative/Security | pytest | container-CI | SQLite | T | P1 | A real authenticated request as a VIEWER → 403; exactly one `permission_denied`-class audit row; the running graph's element counts are unchanged. (Today only `allow_no_auth=True` paths are exercised.) |
| PUB-15 | A stale step-up session is refused on the publish route | Negative/Security | pytest | container-CI | SQLite | T | P1 | A session whose `reauth_at` is older than `[auth].step_up_max_age_seconds` → 403 carrying the MFA-required signal; after a fresh step-up the same request → 200. |
| PUB-16 | Reload error bodies never echo the rejected path | Negative/Security | pytest | container-CI | SQLite | T | P2 | For crafted `config_dir` values driving 403 / 404 / 422, the response body contains no substring of the supplied path; the server log **does** name it (assert via `caplog`). |
| PUB-17 | The dry-run pre-flight audit row is correct and does not rebaseline | Functional | pytest | container-CI | SQLite | T | P1 | Dry-run against a dir **other** than the startup dir: a `config_reload_check` row is written whose `dir` and `fingerprint` are those of the dry-run dir; `GET /config/provenance` still reports the **pre-dry-run** fingerprint and `drift` is unchanged. Pin whatever `engine.last_reload_dir` mutation (`engine.py:1402`) is intended. |
| PUB-18 | Trust-anchor substitution is caught on the pre-flight, not only the apply | Negative/Security | pytest | container-CI | SQLite | T | P1 | With a pinned trust anchor configured and the on-disk PEM substituted, `dry_run=true` → 422 carrying the anchor-mismatch reason, and the apply that follows → 422 for the same reason. Currently RED: the pre-flight passes because `run_anchor_preflight` is gated on `anchor_specs and not req.dry_run` (`app.py:2789`). Whether the gate moves is §7.9 Q16; this row asserts the target behaviour and fails until it holds. |
| PUB-19 | A fingerprint failure never drops the reload audit row | Negative/Security | pytest | container-CI | SQLite | T | P2 | Monkeypatch `config_fingerprint_detail` to raise `OSError`; the reload still returns 200 and a `config_reload` row is still written, without the `fingerprint`/`files` keys. |
| PUB-20 | Sibling / reserved port collision is refused **before** any quiesce | Negative/Security | pytest | container-CI | SQLite | T | P1 | Publish a `connections.toml` whose inbound claims a sibling inbound's (or the API listener's) resolved `(host, port)` → 422; the pre-existing inbounds are still listening throughout (assert `inbound_running` never went False); a `config_reload_failed` row with `reason:"invalid_config"` is written. This path is `inbound_binding_conflicts` inside `build_check_registry` (`wiring_runner.py:5768-5778`) — pre-quiesce. |
| PUB-21 | An **externally** occupied port fails post-quiesce and rolls intake back | Negative/Security | pytest | container-CI | SQLite | T | P1 | Bind a real socket from the test process; publish a graph claiming it → 422; the previous graph's inbounds are listening again after the call; the response detail stays generic while the log names the contended port and connection (`wiring_runner.py:1997-2016`). |
| PUB-22 | Post-quiesce failure leaves no partial-publish residue | Negative/Security | pytest | container-CI | SQLite | T | P1 | Force a failure at the inbound-bind step (PUB-21) **and** at `_reconcile_outbounds`; afterwards the live lookup executor, the FHIR-read executor, the sandbox session set, and the outbound retry/ordering/internal-error maps all match the **old** graph exactly. Currently expected RED (`wiring_runner.py:3096-3104` vs `:3151-3164`). |
| PUB-23 | Reload vs restart produce the same outcome for the same bytes | Negative/Security | pytest | container-CI | SQLite | C | P1 | Apply one bundle containing a single unbindable inbound via `reload()` and via a fresh `start()`; either both isolate that connection (ADR 0031 `_record_failed`) and run the rest, or the divergence is asserted and pinned as intended with a docs note. Today they differ. |
| PUB-24 | A Handler importing a missing module is refused, graph untouched | Negative/Security | pytest | container-CI | SQLite | T | P1 | Bundle containing `import _gone`; `dry_run=true` → 422; a forced apply → 422 with the previous graph's Router/Handler/element counts and intake state unchanged; one `config_reload_failed` row with `reason:"invalid_config"`. |
| PUB-25 | A malformed `connections.toml` is refused, graph untouched | Negative/Security | pytest | container-CI | SQLite | T | P1 | Publish a `connections.toml` with a TOML syntax error and, separately, an unknown connector `type`; both → 422 pre-quiesce; the running inbounds never stop; the error detail is generic. |
| PUB-26 | A dangling `code_set("old")` is caught by `check` but not by `validate` | Negative/Security | pytest | container-CI | n/a | T | P1 | For a bundle whose Handler references a renamed code set: `messagefoundry validate --config <dir> --json` reports **no** error, `messagefoundry check --config <dir> --messages <synthetic fixtures>` reports a **blocking** dryrun failure naming the set. Pins the gate gap `promote.ts:82` leaves open. |
| PUB-27 | Promote's local gate selection is explicit and testable | Usability | ide-mocha | dev-PC | n/a | T | P1 | An extracted `promoteGateArgs()` returns the argv the flow shells; the test pins whether it is `["validate","--config",…]` or `["check","--config",…]` so a change is a reviewed decision, not a drift. |
| PUB-28 | Promote warns on a dirty config worktree | Negative/Security | ide-mocha | dev-PC | n/a | T | P1 | With an injected git runner reporting a dirty `--config` tree, the flow surfaces a warning naming the modified files before the target pick; a clean tree is silent. Pairs with PUB-29. |
| PUB-29 | `config_fingerprint_detail` reports (or suppresses) `git_head` on a dirty tree | Negative/Security | pytest | container-CI | n/a | T | P1 | On a work tree whose config files differ from HEAD, the detail either carries `git_dirty: true` or omits `git_head`. Today `_git_head` reads refs from files only and never compares the worktree (`fingerprint.py:110-170`); ADR 0041 defers this. |
| PUB-30 | Publish under sustained synthetic MLLP traffic loses nothing | HA/Resilience | load-harness | dev-PC | SQLite | T | P1 | See §7.5 scenario B. Every control id the sender got an AA for is present in the store exactly once **or** more (never zero) — **zero loss**, asserted by `harness/reconcile`. |
| PUB-31 | Publish duplicate rate is measured and bounded | HA/Resilience | load-harness | dev-PC | SQLite | C | P1 | Same run: report `duplicates / messages_in_flight_at_swap`; pin an upper bound in the profile and fail the run above it. Duplicates are expected (a lost pre-swap ACK is retried) — the requirement is that the figure is **known and bounded**, not zero. |
| PUB-32 | A publish never resurrects operator intent | Functional | pytest | container-CI | SQLite | T | P1 | Matrix × reload for the cells not already covered by `tests/test_not_deployed.py:436,473`: (a) an inbound an operator explicitly **stopped**, (b) `auto_start=False` never started, (c) DR-filtered below threshold. In each cell the listener stays unbound after the reload **and** the router/transform workers still drain a pre-seeded backlog to completion. |
| PUB-33 | In-flight ingress rows are processed under the post-swap graph | Functional | pytest | container-CI | SQLite | T | P1 | Seed an ingress row under Router A, reload to Router B, let the worker run: the row is routed by **B**. Then correct the contradicting docstring at `wiring_runner.py:3068-3069` and add a doc-drift guard so the two comments cannot disagree again. |
| PUB-34 | Code sets reload with the graph, and the re-run caveat is characterized | Functional | pytest | container-CI | SQLite | T | P2 | (a) Editing `codesets/x.csv` and reloading changes the value a Handler reads on the next message. (b) Force a stage re-run across a code-set reload and record that the re-derived output differs — the one sanctioned exception to the pure-re-run invariant (`docs/CONFIGURATION.md:271-273`). Pin the documented caveat with a doc-drift guard. |
| PUB-35 | Quiesce duration and ingress depth at connection scale | Performance | load-harness | dev-PC | SQLite | C | P2 | Reload under sustained load at 16 / 200 / 1500 inbound connections (`harness/load/connscale`); report intake-pause wall time (last accept before swap → first accept after) and peak ingress backlog per tier. Pass = a published figure per tier and a documented scaling shape; regression bound set from the first run. |
| PUB-36 | `samples/config` build-checks clean under **prod** values + prod posture | Cross-backend | pytest | container-CI | SQLite | T | P1 | `load_config("samples/config")`, gather values with `environment="prod"` from the repo-root `environments/`, run `build_check_registry` under the prod-derived posture (`handles_real_patient_data=True`) → no `WiringError`. This is the only automated proof that a promote to PROD pre-flights clean, incl. type/cast correctness, the egress allow-list, and the ADR 0092 posture-keyed cleartext-hop refusal against the non-loopback prod peers. |
| PUB-37 | `samples/config` build-checks clean under **dev** values + dev posture | Cross-backend | pytest | container-CI | SQLite | T | P2 | Mirror of PUB-36 with `environment="dev"`; both must pass, so a value added to one file and not the other fails here rather than on a real promote. |
| PUB-38 | Prod secrets are never resolvable on the dev PC | PHI | pytest | container-CI | n/a | T | P1 | With only `MEFOR_VALUE_*` for dev set, `load_environment_values(environment="prod", …)` yields the file's non-secret values and **no** secret keys; a graph requiring a prod-only secret raises `WiringError` naming the missing key and never a blank host. Documents that isolation is by construction (resolution happens on the target). |
| PUB-39 | A dev artifact is accepted by a prod engine (characterization of today) | Negative/Security | pytest | container-CI | SQLite | C | P1 | Today: publish a bundle authored for dev to an engine started `--env prod`; assert it **is** accepted (nothing refuses it) and record that as the current, unmitigated behaviour, with the resolved prod values it silently picked up. Characterization only — the enforcement assertion is PUB-68, which owns the release gate for this behaviour. |
| PUB-40 | Project-root anchoring survives a reload launched from an arbitrary cwd | Functional | pytest | container-CI | SQLite | T | P1 | Start an engine with `--project-root <repo>` from a different cwd; reload; the re-gathered `env_values` (`engine.py:1405-1411`) still contain the project-root `environments/<env>.toml` keys. Guards the NSSM footgun ADR 0050 exists for. |
| PUB-41 | Publish to one engine shard leaves siblings divergent (characterization) | HA/Resilience | pytest | container-CI | x2 | C | P1 | Two `serve --shard` processes over ONE unified store; publish to engine shard A only; record that the two report different content fingerprints once PUB-10's surface exists, and that `Engine.reload`'s engine-shard-universe guard (`engine.py:1415-1433`) does **not** fire for a content-only divergence. |
| PUB-42 | A follower converges to its own dir on an operator reload | HA/Resilience | pytest | container-CI | x2 | T | P1 | Two clustered engines with **identical** dirs: reload A (`propagate=True`); B's convergence loop reloads within one interval, B's applied version equals A's, and B's fingerprint equals A's. Extends `tests/test_cluster.py:943` from the version bump to the content outcome. |
| PUB-43 | A publish in flight across a leadership flip never half-applies | HA/Resilience | pytest | container-CI | x2 | T | P1 | With a stand-in coordinator that flips leadership mid-`RegistryRunner.reload` (which holds `_reload_lock`, `wiring_runner.py:3058`, while `_reconcile_graph`/`_start_graph` hold `_graph_lock`, `engine.py:1242`), in **both** flip directions the result is all-or-nothing: the started graph is the **post-reload** registry in its entirety or the pre-reload one in its entirety — never a mix of pre- and post-reload inbounds/outbounds — intake is listening again when the call returns, and exactly one of `config_reload` / `config_reload_failed` is written (never both, never neither). Pairs with PUB-22 (post-quiesce residue) and Scenario D. |
| PUB-44 | Restart-only artifacts are provably untouched by a publish | Functional | pytest | container-CI | SQLite | T | P1 | Change `[alerts].rules`, `[security]` and `[ai]` in `messagefoundry.toml` on disk, then `POST /config/reload`: the live notifier rules, the resolved security posture and the AI policy are byte-identical to pre-reload. Plus a doc-drift guard pinning the restart-only set against `docs/CONFIGURATION.md`. |
| PUB-45 | Promote names what it did **not** apply | Usability | ide-mocha | dev-PC | n/a | T | P1 | The success message (or a companion notice) states that alert rules, security/auth config and AI policy are not part of a promote and require a service restart. Today the toast is silent about them. |
| PUB-46 | Rollback by revert-and-reload restores the exact prior fingerprint | Functional | harness | E10-pair | SQLite | T | P1 | See §7.5 scenario A, rollback leg: after `git revert` + redelivery + reload, each engine's `GET /config/provenance.fingerprint` equals the digest captured before the bad publish, character-for-character, and the graph counts match. Run on both E10 engines — a rollback that restores non-prod but not the production-like engine is the failure this catches. |
| PUB-47 | Last-known-good is reachable from the engine | Functional | pytest | container-CI | SQLite | C | P2 | Decision-gated (see §7.9 Q9): if adopted, `GET /config/provenance` carries `previous_fingerprint`; a rollback target is then readable without git archaeology. If declined, a doc-drift guard pins "rollback is git-revert-and-redeliver" in the runbook. |
| PUB-48 | ADR 0036 config-source trust refuses a writable load path **on the reload path** | Negative/Security | pytest | W2025-box | SQLite | T | P1 | On Windows, make the reload target dir modifiable by `BUILTIN\Users`; `POST /config/reload` → 422 and the running graph untouched; restore the DACL and the same reload → 200. The policy matrix itself is owned by `tests/test_config_source_trust.py`; this row proves the reload seam. |
| PUB-49 | Reload-root confinement holds for a sibling dir inside the same root | Negative/Security | pytest | container-CI | SQLite | T | P2 | With the startup dir at `<root>/config`, a `config_dir` of `<root>/other-config` is accepted only if `<root>` is an allow-listed reload root, and refused 403 otherwise — pinning the backstop behind the deliberately workspace-scoped `messagefoundry.configDir` classification (`settings-scope.test.ts:33-43`). **This chapter owns reload-root confinement**; MIG-48 is a pointer here and scopes no separate work. |
| PUB-50 | `/ui/config` reload actually swaps the graph | Functional | pytest | container-CI | SQLite | T | P2 | In `packaging/messagefoundry-webconsole/tests`, an engine fixture **with** a `config_dir`: POST `/ui/config/reload` as a DEPLOYMENT role → the live graph swaps and the result page shows the new counts. Today only RBAC/CSRF/allow-list are covered. |
| PUB-51 | `/ui/config/reload` is immune to a crafted body or query | Negative/Security | pytest | container-CI | SQLite | T | P2 | Spy on `core.reload_config`; for a form body, a JSON body and a query string all carrying `config_dir`/`dry_run`, the captured `ReloadRequest` is always `config_dir=None, dry_run=False` (`routes/config.py:57-58`). |
| PUB-52 | `/ui` pending-approval page renders on a held reload | Functional | pytest | container-CI | SQLite | T | P2 | With dual-control gating `config_reload`, POST `/ui/config/reload` renders `reload_pending` with the approval id and **not** `reload_result`; the graph is unchanged. |
| PUB-53 | `/ui` reload result reports the full element set | Usability | pytest | container-CI | SQLite | T | P2 | The result table lists inbound, outbound, routers **and handlers**; today `pages/config.py reload_result` omits handlers while `ReloadResult` carries the count. |
| PUB-54 | Promote survives a hung / down / TLS-wrong target | Negative/Security | ide-mocha | dev-PC | n/a | T | P2 | `postJson` against a server that accepts the socket and never answers rejects within a POST timeout mirroring `GET_TIMEOUT_MS` (`engineClient.ts:110-113`); a refused connection and a TLS failure classify distinctly and the flow shows an actionable message rather than hanging. Today `postJson` has **no** timeout. |
| PUB-55 | The IDE offers a recovery path on a step-up 403 | Usability | ide-mocha | dev-PC | n/a | T | P2 | An extracted response classifier maps 403-with-MFA-required to a "re-authenticate" outcome; `withAuth` (`ide/src/auth.ts:202-224`) retries only on 401 today, so the promote dead-ends. |
| PUB-56 | Dual-control approvers see what they are approving | Negative/Security | pytest | container-CI | SQLite | T | P1 | The pending-approval record for `config_reload` carries the target dir **and** the fingerprint captured **at request time**; on release, if the on-disk fingerprint has changed, the release is refused (409) or the divergence is audited on the `approval.approved` row. Today the listing exposes neither (`api/approvals.py:100-111`). |
| PUB-57 | A "who changed what" report exists | Functional | pytest | container-CI | SQLite | T | P2 | A report primitive over `store.list_audit` returns, for a time window, each publish event with actor, client address, dir, fingerprint and `git_head`; a `/ui` audit filter surfaces it. Plus a doc-drift guard pinning the publish event set: `config_reload`, `config_reload_check`, `config_reload_failed`, `config_reload_denied`, `approval.requested`, `approval.approved`, `approval.rejected`, `startup_integrity`. |
| PUB-58 | `MEFOR_VALUE_*` scope decision is pinned | Negative/Security | pytest | container-CI | n/a | C | P2 | Either a salted digest of the resolved `MEFOR_VALUE_*` **key set** (never the values) appears in the provenance detail and changes when a key is added/removed, or a doc-drift guard asserts the documented carve-out. Decision-gated (§7.9 Q14); becomes a T row on the day that decision is recorded. |
| PUB-59 | `messagefoundry verify` reports config provenance | Functional | verify | W2025-box | SQLite | T | P2 | A new `config.provenance` verify row reports `loaded`, `fingerprint`, `git_head` and `drift`, and returns MANUAL when the engine is unreachable. Depends on PUB-01 (otherwise it reports `loaded=false` on every restarted box). |
| PUB-60 | Set Up Version Control never touches the network | Negative/Security | ide-mocha | dev-PC | n/a | T | P2 | With an injected git runner, the command's whole invocation list contains no `clone`/`fetch`/`pull`/`push`/`ls-remote`; only `init`, config writes and `remote add`/`set-url` appear (`ide/src/sourceControl.ts`, `ide/src/git.ts:72-75`). Pins the `VERSION-CONTROL.md` §4 "offline-safe" promise. |
| PUB-61 | Air-gapped publish rehearsal (git bundle across the boundary) | Functional | manual | W2025-box | SQLite | T | P2 | See §7.5 scenario G. Pass = the bundle applies on the isolated host, the engine reloads, and the fingerprint on the isolated engine equals the one computed on the authoring PC. |
| PUB-62 | `ide` CI leg is required and path-gated on the API contract | CI-leg | CI-leg | container-CI | n/a | T | P1 | `.github/workflows/ci.yml`: the `ide` job is added to `ci-gate`'s `needs` (or an equivalent required context), the `changes.ide` path filter also fires on `messagefoundry/api/app.py` + `messagefoundry/api/models.py`, and `promote-target.test.ts` is removed from the `test:unit` ignore list so it runs on every leg. |
| PUB-63 | ADR 0041 / FEATURE-COVERAGE-PLAN / ADR 0017 status drift is pinned | Compat | pytest | container-CI | n/a | T | P2 | A doc-drift guard asserts: every ADR 0041 acceptance criterion names a test node id that **exists** (AC-5..AC-8 currently name `tests/test_approvals.py`; the D2 tests live in `tests/test_dual_control_reload.py`); ADR 0041's status line is not "Proposed" while D1+D2+D3 are built; ADR 0017's "nothing in this ADR is built" header is corrected; FEATURE-COVERAGE-PLAN row `FCP:RBAC-17` no longer says "none (BACKLOG #53, not wired)" (`FEATURE-COVERAGE-PLAN.md:1113`). |
| PUB-64 | `FEATURE-MAP.md` cannot claim a surface that does not exist | Compat | — | — | — | T | P2 | **Pointer row.** Covered by the MIG chapter's single consolidated FEATURE-MAP drift-guard row (one extension of `tests/test_feature_map_claims.py`); no separate work scoped here. The PUB-specific symptom that guard must catch: `docs/FEATURE-MAP.md:131` still says "The PySide6 desktop console stays (additive)" and `:162` carries "## 10. Surfaces — Admin Console (PySide6)" with "Multi-engine switcher" (`:173`) filed under it, while `messagefoundry/console/` does not exist. |
| PUB-65 | Shipped environment tiers and the docs agree | Functional | pytest | container-CI | n/a | T | P1 | Every environment name the docs or `samples/` present as a promotion tier has a shipped `environments/<name>.toml`, and `tests/test_environments.py:185`'s key-parity guard covers **exactly** the shipped set (today `dev.toml` + `prod.toml`) — so a value file added without extending the guard, or a doc naming a third tier with no value file, fails here rather than on a real promote. §7.9 Q12 decides whether `staging.toml` joins the set; the row is falsifiable under either answer. |
| PUB-66 | Wheel self-attestation does not misfire across a publish | Upgrade | pytest | container-CI | n/a | T | P2 | On a **non-editable** wheel install, a `POST /config/reload` does not emit a `startup_integrity` drift row and does not alter the D3 baseline — config publishing and engine-code attestation stay orthogonal (`messagefoundry/integrity.py`). |
| PUB-67 | One artifact, two environment targets: identical bytes, divergent `env()` resolution | Functional | pytest | container-CI | SQLite | T | P0 | The core multi-environment invariant, asserted without a rig: load **one** bundle twice, once per named environment. `config_fingerprint(<bundle>)` yields the **same** 64-hex digest under `dev` and `prod` (the artifact is byte-identical — `env()` refs live unresolved in the source), while the built registry's outbound connector settings resolve to **different** hosts/ports per environment (`load_environment_values(environment=…)`, `config/environments.py:92`). Fails if one artifact produces two digests, or if two environments produce identical resolved settings (which would mean substitution silently did nothing). The two-engine proof of the same invariant is PUB-11. |
| PUB-68 | A prod engine refuses a dev-authored artifact (wrong-target enforcement) | Negative/Security | pytest | container-CI | SQLite | T | P1 | A bundle whose environment marker says `dev` is refused by an engine started `--env prod`: `serve` refuses at startup and `POST /config/reload` → 422 naming **both** the artifact's environment and the engine's; a matching-marker bundle → 200; the running graph is untouched on the refusal. Currently RED — ADR 0017's Minor "expected environment" assertion is unbuilt (`docs/adr/0017-consumer-deployment-model.md:165`; `grep expected_environment messagefoundry/` → no hits), and the `env()` missing-key backstop provably cannot fire because both value files define the same key set (`tests/test_environments.py:185`). §7.9 Q11 decides whether it gates the release; PUB-39 records the unmitigated behaviour until then. |
| PUB-69 | Publishing to one environment target leaves the sibling target untouched | Functional | harness | E10-pair | SQLite | T | P1 | With both E10 engines live on the same bundle, promote to the **non-production** engine only. The production-like engine's `GET /config/provenance` digest, `loaded` flag and element counts are unchanged; its store gains **no** `config_reload`, `config_reload_check` or `config_reload_failed` row; its inbounds never stop accepting synthetic traffic. Then repeat in the reverse direction. Pins the blast radius of a promote at exactly one named target — the property an operator assumes when one workspace holds several `messagefoundry.environments` entries. |
| PUB-70 | The confirmed target is the promoted target, and no credential precedes confirmation | Negative/Security | ide-mocha | dev-PC | n/a | T | P1 | With ≥2 `messagefoundry.environments` entries, a stubbed `postJson` and a stubbed modal: (a) the URL named in the confirm modal is character-identical to the URL both the pre-flight and the apply POST to — no re-resolution between confirm and apply; (b) the modal names the environment **and** the URL (`promote.ts:169-177`); (c) declining the off-box host-confirmation modal (`promote.ts:119-133`) issues **zero** HTTP requests and reads no token, and declining the final confirm issues no apply; (d) changing the environment pick changes the posted URL accordingly. The only wrong-target protection that exists until PUB-68 lands. |

### 7.5 Detailed scenarios

#### Scenario A — the promotion pipeline rig (PUB-11, PUB-46, PUB-69, and the substitution proof)

**Preconditions.** A dev PC with the repo checked out and the engine installed. Three free API ports.
Local MLLP receivers on the `environments/dev.toml` ports (`2601`, `2641`, `2701`, `2731`, `2732`,
`2761`) — `python -m harness` provides receive panels, or use `harness/receive.py`. A synthetic corpus:

```bash
python -m messagefoundry generate --type ADT --count 25 --seed pubrig --out out/pub/messages
```

*(`generate` writes full message bodies — keep `out/` git-ignored and never redirect it into a ticket
or CI log.)*

**Steps.**

1. **Author + gate on the dev PC.** Copy `samples/config` to a scratch bundle root that mirrors the
   shipped layout — `out/pub/repo/config/` for the modules, `out/pub/repo/environments/{dev,prod}.toml`
   copied from the repo root, and `git init` in `out/pub/repo`. Commit. Then run the real gate:
   ```bash
   python -m messagefoundry check --project-root out/pub/repo --config config --env dev \
       --messages out/pub/messages/ADT
   ```
   Record the exit code and the local digest (`messagefoundry fingerprint --config out/pub/repo/config
   --json`, PUB-05).
2. **Stand up the NON-PROD engine.** From a directory that is *not* the repo root, to exercise the
   anchor:
   ```bash
   python -m messagefoundry serve --project-root out/pub/repo --config out/pub/repo/config \
       --db out/pub/nonprod.db --env dev --port 8801
   ```
3. **Promote to non-prod through the real API.** `POST /config/reload {"config_dir": null, "dry_run":
   true}` then `{"dry_run": false}` as a `config:deploy` holder with a fresh step-up.
   **Observation point:** the 200 body, `GET /config/provenance`, and `store.list_audit(action=
   "config_reload")`.
4. **Validate with synthetic traffic.** Send the corpus over MLLP
   (`python samples/send_mllp.py out/pub/messages/ADT/<f>.hl7 --port 2575`, or the harness sender) and
   assert every message reaches `PROCESSED` and the receiver saw the dev peer ports.
5. **Stand up the PROD-shaped engine** on the **same bundle bytes**, different environment:
   ```bash
   python -m messagefoundry serve --project-root out/pub/repo --config out/pub/repo/config \
       --db out/pub/prod.db --env prod --port 8802
   ```
   with `MEFOR_VALUE_*` set only for the prod-only secrets, and prod peers pointed at local
   stand-ins (never a real partner endpoint — the committed `prod.toml` hosts are placeholders).
6. **Promote the identical artifact to prod.** Same two calls against `:8802`.
   **Observation point:** the two engines' `/config/provenance.fingerprint` must be **equal**
   (byte-identical artifact), while `GET /connections` (or the built connector settings) must show
   **different resolved hosts/ports** — `127.0.0.1:2601` on non-prod vs the `prod.toml` value on prod.
   That pair of assertions is the whole point of the rig.
   **Isolation check (PUB-69):** immediately after each promote, re-read the *other* engine's
   `/config/provenance` and audit tail — its digest, `loaded` flag and element counts must be
   unchanged and it must have gained no `config_reload*` row. A promote reaches exactly one target.
7. **Roll back.** `git revert` the last config commit in `out/pub/repo`, redeliver (here: the same
   working tree), reload both engines, and assert each `/config/provenance.fingerprint` equals the
   value captured in step 3/6 *before* the reverted change. Time the operation end to end.

**Expected result.** Steps 3–6 all 200; identical fingerprints across environments; divergent resolved
settings; zero `ERROR` dispositions on the synthetic traffic; step 7 restores the prior fingerprint
exactly.

**Cleanup.** Stop both engines, delete `out/pub/*.db` and `out/pub/repo`, and confirm no generated
message bodies were committed.

#### Scenario B — publish under sustained synthetic MLLP traffic (PUB-30, PUB-31)

**Preconditions.** The load config served per `docs/LOAD-TESTING.md`:

```bash
MEFOR_LOAD_FANOUT=4 MEFOR_LOAD_TRANSFORM=edit MEFOR_LOAD_SINK_PORT=2700 \
  python -m messagefoundry serve --config harness/config/load --db ./load.db --env dev
```

A synthetic-only corpus. A second copy of `harness/config/load` with a trivial Handler edit (so the
graph *changes* but element counts do not), reachable from an allow-listed reload root.

**Steps.**

1. Start the load runner at a steady rate below the SLO knee:
   `python -m harness --load fanout-baseline --engine http://127.0.0.1:8765 --token <T>
   --sink-port 2700 --report-json out/load/pub-reload.json`.
2. Mid-measured-phase, issue one real `POST /config/reload` (non-dry-run) pointing at the edited copy.
3. Let the run drain to completion.

**Observation point.** `harness/reconcile` over sent-vs-stored control ids; the sink's arrival log; the
engine poller's ingress depth series; the wall time between the last accept before the swap and the
first accept after it.

**Expected result.** **Zero** control ids present in the sender's AA set and absent from the store.
A non-zero but bounded duplicate count, reported as a rate and pinned in the profile. The intake pause
recorded as a number, not a shrug.

**Cleanup.** Delete `load.db` and `out/load/`. Note the run's duplicate rate in the runbook — this is
the figure an operator needs before deciding to publish during business hours.

#### Scenario C — externally occupied port: the post-quiesce failure path (PUB-21, PUB-22)

**Preconditions.** An engine running a two-inbound graph with live intake. A helper process holding
TCP `127.0.0.1:2999`.

**Steps.**

1. Confirm both inbounds are listening and note the live lookup-executor identity, the sandbox session
   set and the outbound retry/ordering maps.
2. Publish a bundle whose second inbound binds `2999`. `build_check`'s `inbound_binding_conflicts`
   cannot see an external holder, so the graph passes the pre-quiesce gate and the failure lands in
   `_start_inbound_unsafe` → `OSError` → `PortConflictError` (`wiring_runner.py:1997-2016`), inside
   `reload()`'s `try` — i.e. **after** the quiesce.
3. Observe the 422 and inspect the runner's internals.

**Observation point.** `_sources` (both old inbounds re-listening), `_lookup_executor` (must be the
**old** one — today it is not), `_sandbox_sessions`, `_retry`/`_ordering`/`_internal_error`, and the
`config_reload_failed` audit row.

**Expected result (target).** Intake restored **and** every rebuilt subsystem restored. Expected RED
today at the executor/sandbox/outbound assertions — record that as the finding, then fix or explicitly
accept with a documented operator note.

**Cleanup.** Release port `2999`; reload the original bundle; confirm provenance is clean.

#### Scenario D — partial fleet publish on a real 2-node cluster (PUB-10, PUB-42)

**Preconditions.** PostgreSQL (or SQL Server 2025) reachable; two engine hosts (or two processes)
sharing that one unified store with `[cluster].enabled`; **deliberately skewed** config dirs — node B
one commit behind node A.

**Steps.**

1. Confirm both nodes healthy; record `GET /cluster/status.config_version` on each.
2. `POST /config/reload` on node A (leader) with `propagate=true`.
3. Wait one convergence interval; re-read both nodes' status, provenance and `config_reload` audit rows.

**Observation point.** Both nodes report the **same** `config_version`; both wrote clean `config_reload`
rows; and — the whole point — their `/config/provenance.fingerprint` values **differ**.

**Expected result (today).** Divergence is real and completely undetected from any operator surface.
**Expected result (after PUB-10).** A cluster-level surface exposes both digests and a divergence
signal fires.

**Cleanup.** Re-sync node B's dir, reload, confirm the fingerprints converge. Drop the test database.

#### Scenario E — production dual-control ceremony with a mid-hold byte change (PUB-56, PUB-08)

**Preconditions.** A prod-shaped engine with `[approvals].enabled` and `config_reload` in
`[approvals].operations`. Two accounts on **separate hosts**: a requester with `config:deploy` (MFA
enrolled) and a distinct approver with `approvals:approve`.

**Steps.**

1. Requester promotes from the IDE. **Observation point 1:** the toast text — today it reads
   "promoted to PROD — live graph: undefined inbound, undefined outbound…" (this is how PUB-08 is
   observed by a human).
2. Approver opens the pending list. **Observation point 2:** what the record shows. Today: id,
   operation, label, requester, timestamps — **no dir, no fingerprint**.
3. **Before** the approver releases, edit a Handler in the engine's on-disk config dir.
4. Approver releases. Read the `config_reload` audit row's fingerprint.

**Expected result (target).** The release is refused (409) or the fingerprint change between request
and release is explicitly audited on the `approval.approved` row. **Expected result today.** The
release silently activates the *post-edit* bytes, and the approver's signature attaches to a bundle
they never saw.

**Cleanup.** Revert the Handler edit, reload, confirm provenance clean, and reject/expire any leftover
pending requests.

#### Scenario F — environment-crossing and wrong-target safety (PUB-38, PUB-39, PUB-68, PUB-70)

**Preconditions.** Two engines from Scenario A (`:8801` dev, `:8802` prod). Prod-only secrets exported
**only** in the prod engine's process environment.

**Steps.**

1. On the dev PC, with only dev `MEFOR_VALUE_*` set, run
   `python -m messagefoundry dryrun --project-root out/pub/repo --config config --env prod
   --messages out/pub/messages/ADT` and observe that no prod secret is resolvable locally.
2. Drive the IDE promote against `:8802` and confirm from a packet/stub capture that the request body
   is exactly `{"config_dir": null, "dry_run": …}` — no values leave the PC.
3. Aim a promote at the **wrong** target: pick DEV in the QuickPick while the staged bundle was
   authored for prod (and vice versa). Observe that nothing server-side refuses it (PUB-39 records
   this; PUB-68 is the enforcement row that turns it green once ADR 0017's environment marker lands).
4. Aim a promote at an off-box `https://` host that is not an engine. **Observation point:** the
   confirmation modal must name the hostname *before* any credential prompt (`promote.ts:119-133`),
   and the URL it names must be the one the apply actually POSTs to (PUB-70).

**Expected result.** (1) and (2) pass by construction and are now asserted. (3) is a recorded
**gap** — no server-side wrong-target protection exists (ADR 0017's `expected_environment` is unbuilt).
(4) passes; the host name appears in the modal, no token is sent if the user declines, and the
confirmed URL and the promoted URL are the same string.

**Cleanup.** Unset any exported values; sign out of both engines in the IDE (SecretStorage).

#### Scenario G — air-gapped publish and timed rollback on the W2025 box (PUB-61, PUB-46)

**Preconditions.** The WIN2025 host from `docs/testing/WIN2025-TEST-PLAN.md` (NSSM service, dedicated
service account, config dir ACL-locked via `install-service.ps1 -LockConfigDir`). An isolated network
segment. Removable media or a UNC share reachable from both sides. **This row depends on `W25:B5`
being lifted from Phase 2 — do not plan it as a WIN2025 deliverable; it consumes that host.**

**Steps.**

1. On the authoring PC: commit, then `git bundle create mefor-config.bundle main`; record the local
   fingerprint (PUB-05).
2. Carry the bundle across; on the isolated host `git pull /path/to/mefor-config.bundle main` into the
   engine's config repo.
3. Reload — from the web console `/ui/config` (the sole operator console) under the service identity.
4. Compare `GET /config/provenance.fingerprint` to step 1.
5. Introduce a deliberately bad change (a Handler importing a missing module), repeat 1–3, and observe
   the 422 with the running graph untouched.
6. Timed rollback: `git revert`, re-bundle, carry, pull, reload; stopwatch from "operator decides to
   roll back" to "provenance fingerprint equals the pre-publish value".

**Expected result.** Fingerprints match across the air gap; the bad publish is refused pre-quiesce; the
rollback completes within a documented target and the fingerprint returns exactly.

**Cleanup.** Remove the bundle from removable media; leave the host on the last-known-good commit;
confirm the ACL posture is still locked.

### 7.6 Automation disposition

| Bucket | Contents | Effort |
|---|---|---|
| **New pytest module — `tests/test_promotion_provenance.py`** | PUB-01, PUB-02, PUB-03, PUB-04, PUB-17, PUB-19, PUB-29, PUB-58. The startup-baseline and shipped-layout fingerprint work is the heart of this chapter; several rows are RED on arrival by design. | M |
| **New pytest module — `tests/test_reload_atomicity.py`** | PUB-20, PUB-21, PUB-22, PUB-23, PUB-24, PUB-25, PUB-32, PUB-33. Needs a small fixture that exposes the runner's internals (lookup executor, sandbox sessions, retry/ordering maps) for before/after comparison. | L |
| **New pytest module — `tests/test_promote_contract.py`** | PUB-06, PUB-09, PUB-12, PUB-14, PUB-15, PUB-16, PUB-18, PUB-56. Must build the app **with** auth (not `allow_no_auth=True`) — that is the point of PUB-14/PUB-15. | M |
| **New pytest module — `tests/test_environment_promotion.py`** | PUB-36, PUB-37, PUB-38, PUB-39, PUB-40, PUB-65, **PUB-67**, **PUB-68**. Loads the real `samples/config` against the real committed `environments/`. PUB-67 is the P0 of this module — one artifact, two environments, one digest, two resolved settings; PUB-68 is RED until ADR 0017's environment marker exists. | M |
| **Extends `tests/test_cluster.py`** | PUB-42, PUB-43. **Extends a new `tests/test_multi_shard_publish.py`** (or `tests/test_shard_recovery_engine.py`): PUB-41. **Extends `tests/test_config_fingerprint.py`**: nothing — PUB-03 deliberately lives in the new module so the existing (config-dir-relative) cases stay as the regression baseline for the old scheme. | M |
| **Extends `tests/test_checks.py`** | PUB-26 (dangling `code_set` caught by `check`, missed by `validate`). | S |
| **Extends `packaging/messagefoundry-webconsole/tests/test_pages_config.py` + a new `test_ui_config_reload.py`** | PUB-50, PUB-51, PUB-52, PUB-53. Needs an engine fixture carrying a real `config_dir` — the existing page tests hand-build a `ConfigProvenance`. | S |
| **New pytest doc-drift module — `tests/test_publish_doc_drift.py`** | PUB-44 (restart-only set), PUB-57 (publish event registry), PUB-63 (ADR 0041 / 0017 / FEATURE-COVERAGE-PLAN status). Cheap and high-leverage; three artifacts currently disagree. **Not** PUB-64 — the FEATURE-MAP surface↔package guard is one consolidated MIG row over `tests/test_feature_map_claims.py`; PUB-64 is a pointer. | S |
| **New CLI surface + test** | PUB-05 — a `messagefoundry fingerprint --config <dir> [--json]` subcommand in `messagefoundry/__main__.py` reusing `config_fingerprint_detail`, covered in `tests/test_cli_fingerprint.py`. It is the enabling dependency for PUB-07, PUB-11, PUB-46 and PUB-61. | S |
| **New ide-mocha suite — `ide/src/test/suite/promote-flow.test.ts`** | PUB-07, PUB-08, PUB-13, PUB-27, PUB-28, PUB-45, PUB-54, PUB-55, PUB-60, **PUB-70**. Requires extracting pure functions from `promote.ts` first — `interpretReloadResponse(status, body, localFingerprint)`, `promoteGateArgs()`, and a git-cleanliness probe — so they run in the vscode-free `test:unit` leg, not only on the Windows Extension Host leg. | M |
| **New harness capability — `harness/promotion/`** | PUB-11, PUB-46, **PUB-69** — all three need the `E10-pair` environment (a non-production **and** a production-like engine), not a single dev-PC engine. A rig owning two (optionally three) `serve` subprocesses over one bundle with different `--env`, driving the real HTTP API, asserting identical fingerprints and divergent resolved settings, and executing the revert-and-reload leg. Reuses `harness/load/coord.py`'s subprocess pattern and `harness/reconcile`. | L |
| **Extends the load harness** | PUB-30, PUB-31, PUB-35. A `--reload-at-fraction` perturbation in `harness/load/runner.py` mirroring `--failover`'s `kill_at_fraction`, plus intake-pause and duplicate-rate metrics in `harness/load/report.py`. | M |
| **CI leg changes** | PUB-62 — make `ide` a required context, widen the `changes.ide` path filter to `messagefoundry/api/app.py` + `messagefoundry/api/models.py`, and un-ignore `promote-target.test.js` (and the new `promote-flow.test.js`) in `test:unit`. | S |
| **Verify capability** | PUB-59 — a `config.provenance` row in `messagefoundry/verify/checks.py` + `docs/testing/VERIFY.md`. Blocked on PUB-01. | S |
| **Stays manual (and why)** | The IDE flow end to end in a real VS Code window (modal dialogs + SecretStorage are not meaningfully scriptable headlessly): the environment and engine-shard QuickPicks, the off-box host-confirmation modal, the sign-in prompt, the final confirm modal, and — critically — **reading the toasts** (that is how PUB-08 is *observed*). The `/ui/config` page in a real browser: badge, step-up interstitial and its auto-retry, pending-approval page. The two-person dual-control ceremony across two hosts (Scenario E). The config-dir NTFS ACL posture under NSSM on the real W2025 box (PUB-48) including the not-locked WARNING path. IDE-promote-then-reload under the constrained service identity (`WIN2025-TEST-PLAN.md:1549`). Copy-files + NSSM restart, and the tray **Restart Service**, observed to produce no audit row and no provenance. The air-gap rehearsal (Scenario G). Cross-node publish and publish-during-failover on real server DBs (Scenario D). A promote aimed at a hostile/typo'd https host. Determining from the operator console alone which commit each engine runs (today: you cannot). Confirming DRIFTED actually appears in the IDE status bar (blocked on PUB-01). Promote for a developer with MFA enrolled but a stale step-up window. | — |

### 7.7 Environment, data & prerequisites

**Hosts and instances**

- **Dev PC** — repo checked out, engine installed, Python 3.14+, Node 24 + npm for `ide/`. For PUB-66
  the engine must be installed as a **non-editable wheel** (an editable install makes ADR 0041 D3 a
  no-op).
- **Non-production engine** — a second instance: distinct API port, `--env dev`, its own store, its own
  `MEFOR_VALUE_*` set. Together with the next bullet this is the **`E10-pair`** environment; PUB-11,
  PUB-46 and PUB-69 all require **both** engines and cannot be run on a single dev-PC engine.
- **Production-shaped engine** — a third instance: `--env prod`, prod-only `MEFOR_VALUE_*`, prod peers
  pointed at **local stand-ins**. The committed `environments/prod.toml` hosts are placeholders
  (`receiver-prod.example.org` etc.) and must never be replaced with a real partner endpoint in a
  rehearsal.
- **Windows Server 2025 box** — NSSM, a dedicated service account, config dir ACL-locked
  (`scripts/service/install-service.ps1 -LockConfigDir`). Shared with, not owned by, this chapter:
  `docs/testing/WIN2025-TEST-PLAN.md` `W25:S1`/`W25:S2`. Needed for PUB-48, PUB-59, PUB-61.
- **Air-gapped / isolated host** plus removable media or a UNC share (PUB-61).
- **Two clustered nodes** over one unified store (PUB-10, PUB-42, PUB-43) **and, separately**, two
  `serve --shard` processes over one unified store (PUB-41). These are different axes — an *engine
  shard* estate shares one store and partitions intake by connection; a *cluster* is leader/follower
  over the same store. Do not conflate the rigs.

**Services to procure or stand up**

- **PostgreSQL** and **SQL Server 2025** instances (CI service containers are the CI equivalent) for
  the cluster legs.
- **A git remote for the config repo** — self-hosted Forgejo/Gitea/GitLab CE, or simply
  `git init --bare \\server\repos\mefor-config.git` on a share (`docs/VERSION-CONTROL.md` §3). A bare
  repo on a share is sufficient for everything here and is the air-gap-friendly choice.
- **A TLS certificate + private CA** for the https off-box promote target, so
  `assertTargetAllowed`'s *allowed* branch and the host-confirmation modal are exercised for real
  (PUB-54, Scenario F step 4).
- **Local MLLP receivers** on the `dev.toml` ports (`2601`, `2641`, `2701`, `2731`, `2732`, `2761`) and
  a sender (`samples/send_mllp.py` or `harness/send.py`).
- **A free TCP port and a deliberately occupied one** (Scenario C uses `2999`).
- **A headless VS Code runner** (`@vscode/test-electron`) on Windows for the Extension Host suite.

**Accounts**

| Account | Purpose |
|---|---|
| `config:deploy` holder (DEPLOYMENT role), MFA/TOTP enrolled | The requester on every publish; PUB-15 needs its step-up window to be allowed to expire |
| A **distinct** `approvals:approve` holder, on a separate host/session | The second approver (Scenario E); must be distinct or the ceremony cannot be exercised |
| A VIEWER | PUB-14 and the `/ui` negative cases |
| A Windows service account for the NSSM instance | PUB-48, PUB-59, PUB-61 |

**Data**

All traffic is **synthetic and PHI-free**. Generate with
`python -m messagefoundry generate --type ADT --count 25 --seed pubrig --out out/pub/messages`
(add `--type ORU` for the demo ORU feed). `generate` and `dryrun` emit **full message bodies** to
stdout/files: keep every output path git-ignored, never redirect them into a committed file, a ticket,
or a CI log, and never point a rehearsal at a real feed. The config bundles used by the rig are copies
of `samples/config`; the code sets under `samples/config/codesets/` are synthetic reference data and
are safe to commit.

### 7.8 Exit criteria

This area is signed off for release when **all** of the following hold:

1. **All 12 P0 rows are green or explicitly waived by the owner with a recorded decision:** PUB-01,
   PUB-02, PUB-03, PUB-04, PUB-05, PUB-06, PUB-07, PUB-08, PUB-09, PUB-10, PUB-11, PUB-67. (Waiver,
   not silence — each waiver names the §7.9 question it answers.) The 7 `C` rows (PUB-23, PUB-31,
   PUB-35, PUB-39, PUB-41, PUB-47, PUB-58) are **not** gates: each needs a recorded outcome, and
   converts to a `T` row the day its threshold or owner decision is written down.
2. **A fresh `serve` startup is attested.** On a box that has never received a `POST /config/reload`,
   `GET /config/provenance` reports `loaded=true` with the correct fingerprint, and the audit trail
   contains exactly one boot row binding those bytes to that start.
3. **The fingerprint covers the bytes that decide behaviour under the shipped layout.** Editing a
   project-root `environments/<env>.toml` value moves the fingerprint and raises `drift` on a running
   engine — or the ADR 0041 claim is corrected and a doc-drift guard pins the narrower scope.
4. **A promote can prove what went live.** `ReloadResult` carries a fingerprint, the IDE compares it to
   the locally staged bundle, and a mismatch is surfaced rather than a success toast. A 202 hold never
   renders as success anywhere in the product.
5. **The promotion-pipeline rig runs green in CI** (SQLite tier at minimum): identical fingerprints on
   the non-prod and prod engines, provably different resolved connector settings, synthetic traffic to
   `PROCESSED`, and a rollback that restores the prior fingerprint byte-for-byte.
6. **Rollback is rehearsed and timed** at least once on a production-shaped engine, with the elapsed
   time recorded in the runbook.
7. **Publish-under-load figures are published:** zero message loss, a measured and bounded duplicate
   rate, and an intake-pause figure at 16 / 200 / 1500 connections, all in the operator runbook and
   referenced from the promote UX.
8. **Every atomicity row has a verdict.** PUB-20 through PUB-25 are either green or the divergence
   (notably the missing post-quiesce rollback of the lookup executor / sandbox sessions / outbounds, and
   reload-vs-restart isolation asymmetry) is explicitly accepted, documented in
   `docs/CONFIGURATION.md`, and pinned by a characterization test.
9. **Real request-level RBAC/step-up negatives exist** on `POST /config/reload` (PUB-14, PUB-15) — the
   structural doc-drift walk is no longer the only evidence.
10. **The restart-only artifact set is pinned and surfaced.** A doc-drift guard names exactly which
    `messagefoundry.toml` sections a publish does not apply, and the promote UX says so.
11. **The `ide` CI job is a required check** and fires on `messagefoundry/api/app.py` /
    `messagefoundry/api/models.py` changes; the promote suites run on every leg.
12. **The three disagreeing artifacts agree.** ADR 0041's status line, ADR 0017's "nothing is built"
    header and FEATURE-COVERAGE-PLAN row `FCP:RBAC-17` are corrected with doc-drift guards
    preventing recurrence (PUB-63); `docs/FEATURE-MAP.md` §10 is corrected under the MIG chapter's
    consolidated FEATURE-MAP guard, which PUB-64 points to.
13. **Every manual row in §7.6 has a dated, signed execution record** naming the host, the operator,
    and the observed toast/badge text — in particular the dual-control ceremony and the air-gap
    rehearsal.
14. **No rehearsal used real PHI**, and no `generate`/`dryrun` output was committed or attached to a
    ticket or CI log.
15. **Multi-environment publishing is proven, not assumed.** One artifact resolves differently per
    named environment while keeping one digest (PUB-67), a promote reaches exactly one target
    (PUB-69), the confirmed target is the promoted target (PUB-70), prod secrets are unresolvable
    from the dev workstation (PUB-38), and wrong-target enforcement is either green (PUB-68) or the
    §7.9 Q11 decision to live without it is recorded alongside PUB-39's characterization.

### 7.9 Open questions

1. **Fingerprint scope vs the shipped layout.** Should `config_fingerprint` follow the real layout —
   also hashing the project-root sibling `environments/<env>.toml` resolved via
   `[environments].base_dir` / `--project-root` — or is the config-dir-relative glob the intended
   scope, with ADR 0041's "spans `environments/`" claim to be corrected instead?
   *Blocks:* PUB-03, PUB-04, and whether an env-value redirect is auditable at all.
2. **Startup attestation.** Should a plain `serve` startup capture the provenance baseline and write a
   fingerprint-bearing boot audit row (ADR 0041 D1's `service_started` follow-on)?
   *Blocks:* PUB-01, PUB-02, PUB-59, and every "which commit is this box running?" question on the
   restart-based publish path (which includes the tray's Restart action).
3. **Provable promote outcome.** Should `ReloadResult` return the loaded fingerprint, and should the
   IDE then **refuse** (not merely warn) when the target's fingerprint differs from the locally staged
   bundle? *Blocks:* PUB-06, PUB-07, and the credibility of every "Promoted to PROD" message.
4. **Per-node fingerprint surface.** Should the content fingerprint appear per node on the cluster
   status/nodes API (ADR 0041's open item to coordinate with the engine-shard owner)?
   *Blocks:* PUB-10, PUB-41, PUB-42 — without it a partial fleet publish and a partial engine-shard
   publish are both undetectable.
5. **Dual-control default.** Should `config_reload` join `_DEFAULT_APPROVABLE_OPERATIONS` for
   production postures, or stay opt-in (`settings.py:3125-3134`)? ADR 0041's "D2 default" is still open.
   *Blocks:* whether PUB-52/PUB-56 are default-path or opt-in-path tests.
6. **Approver visibility and request-time binding.** Should the pending-approval record carry the
   target dir **and** the request-time fingerprint, and should a release be refused when the on-disk
   bytes changed in the interim? *Blocks:* PUB-56 — today the second approver signs blind, which
   substantially weakens the one preventive control on the highest-blast-radius action.
7. **Git dirty flag.** Should `config_fingerprint_detail` record a dirty flag (or suppress `git_head`
   on a dirty tree), and should promote refuse — or only warn on — a dirty config dir?
   *Blocks:* PUB-28, PUB-29.
8. **Reload fault isolation.** Should `reload()` isolate a per-connection fault the way `start()` does
   (ADR 0031), or is abort-and-roll-back-everything the intended publish semantic? Today the same bytes
   behave differently via reload and via restart. *Blocks:* PUB-23, and the completeness target for
   PUB-22.
9. **Last-known-good / rollback.** Should the engine retain a previous bundle (or at least its
   fingerprint) so rollback is a first-class, timed operation — or is git-revert-and-redeliver the
   permanent answer? *Blocks:* PUB-47 and the rollback-time target in exit criterion 6.
10. **Publish semantics under live traffic.** Is quiescing intake — dropping established MLLP
    connections, with duplicate risk on a lost ACK — an acceptable production publish semantic, or
    should `ack_after=delivered` / a drain-before-swap mode land before promote-to-prod is declared
    safe? *Blocks:* the pass bound on PUB-31 and the operator guidance derived from PUB-35.
11. **Wrong-target protection.** Should a config bundle carry an environment/target marker so a prod
    engine can refuse a dev artifact, and should ADR 0017's unbuilt `expected_environment` assertion
    become a release gate? *Blocks:* PUB-68 (and decides how long PUB-39's characterization and
    PUB-70's client-side-only protection have to stand in for it) — today nothing server-side
    enforces target correctness, and the `env()` missing-key backstop provably does not fire.
12. **Three-tier or two-tier?** Should `environments/staging.toml` ship so the documented
    dev → non-prod → prod pipeline is exercisable from the repo, or is the shipped two-tier reality the
    intended model? *Decides:* which file set PUB-65's parity guard must cover (the row is
    falsifiable under either answer) and the naming used throughout the rig.
13. **Promote's local gate.** Should promote run the full `messagefoundry check` (fixture dryrun +
    posture + build-check + reference-backend) rather than bare `validate --json`?
    *Blocks:* PUB-26, PUB-27 — and note the dryrun would need a synthetic fixture set the IDE can find.
14. **`MEFOR_VALUE_*` in provenance.** Fold a salted digest of the resolved **key set** (never the
    values) into the provenance detail, or document an explicit carve-out?
    *Blocks:* PUB-58, and whether a credential/host rotation is visible to attestation at all.
15. **`ide` as a required check.** Making it required means a fork's dropped Windows leg or a flaky
    Electron download can block merges. Is a Python-side contract test pinning the `/config/reload`
    response shapes (PUB-09) an acceptable substitute for the required-check change?
    *Blocks:* PUB-62.
16. **Trust-anchor re-verification on the pre-flight.** Should `run_anchor_preflight` also run for
    `dry_run=true` (`api/app.py:2789`), so a substituted or pin-mismatched anchor is caught before the
    operator confirms the modal — or is "the apply refuses it" the intended, documented semantic?
    *Blocks:* PUB-18, which asserts the pre-flight-refuses target behaviour and stays RED until this
    is answered one way and the docs say so.
