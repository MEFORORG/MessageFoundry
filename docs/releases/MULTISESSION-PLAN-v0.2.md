# MessageFoundry — v0.2+ Multisession Execution Plan

> **⚠️ SUPERSEDED (2026-06-19) by [`MULTISESSION-PLAN-3.md`](MULTISESSION-PLAN-3.md).** This is **Plan 2** — the
> v0.2 candidate board. Its NOW phase has since **merged** (#19/#20/#21/#22a/#22b/#26/#27 + ADR 0022) and the
> 2026-06-19 value review **culled** several remaining items. Kept as the historical record; the **living plan is
> Plan 3**.

> **Provenance.** Generated 2026-06-18 from the value-ranked open backlog (post-`v0.1.0`, every item
> re-verified absent in code on 2026-06-18) via a multi-agent workflow: each item was grounded in its
> cited source (code/ADRs/reviews), a file-level contention matrix was computed from verified per-item
> footprints, the laned plan was synthesized, then adversarially reviewed (the review pinned the
> heavy `transports/base.py` + `transports/__init__.py` + `config/models.py` connector collision to a
> single serialized lane, pinned the four store-hot files to one store-owning lane, phased the
> shared `docs/CONNECTIONS.md` / `docs/FEATURE-MAP.md` connector docs, true-sequenced the `pyproject.toml`
> and `api/app.py`/`api/models.py` NOW collisions, and corrected several phantom-ADR gates). Shared across
> the parallel worktrees per [`../WORKTREES.md`](../WORKTREES.md). This is a planning artifact, not a gate —
> update it as items land. The v0.1 plan that shipped successfully is
> [`MULTISESSION-PLAN.md`](MULTISESSION-PLAN.md); its rules are carried forward verbatim where they still apply.

> **📊 STATUS — NOW phase SHIPPED (updated 2026-06-19).** Every NOW item merged: **ADR 0022 (FHIR)** Accepted +
> merged (#405); **`obs-metrics` #21** (#407); **`ci-py311-finalizer` #17** (#409 finalizer + #414 shared-loop) —
> **but #17 is REOPENED**: the py3.11 cross-loop race recurs *intermittently* (it hung even a docs-only PR), so
> **py3.11 is advisory, not required** (`py3.13 ×3` is the cross-platform gate) and Lane X.2 continues the residual
> fix; **`user-guide` #19** (#412); **`console-pages` #22 — re-scoped** (the `GET /alerts` premise was a phantom;
> see the Lane D note below): **#22a Dead Letters** shipped (#413) + **#22b `GET /alerts/rules` endpoint** shipped
> (#415), thin Alerts GUI page still TODO; **declines #26/#27** (#411); **`fhir-codec` #20 BUILD DONE → 🎯
> Objective B complete** (#416). **#13 counsel engagement opened** (#406, awaiting counsel). Lanes A/D/L/X/B are
> closeable. **Remaining is on-trigger only:** the other connectors #7/#23/#25 (+ FHIR server facade) + their ADRs
> 0023/0024/0026, `eventlog` #16 + ADRs 0020/0021, Lane Sec `least-priv-svc`/`secretprovider` (Then), `per-key` #3,
> `webauthn` #11; #24 DICOM deferred to v0.3.

> **Every window runs UltraCode.** Each session (the one coordinator + every worker) enables UltraCode and,
> for each *substantive* item, **authors and runs a Workflow** — ground (read the cited code/ADR/footprint) →
> build (smallest coherent layer) → adversarially verify (ruff + mypy + pytest + a written test, plus a
> second adversarial pass against the count-and-log / ACK-on-receipt / one-way-dependency invariants).
> UltraCode goes **solo (no Workflow)** only on trivial edits (a one-line config default, a doc link, a
> decline marker). Per-session operating notes are inline under each lane.

---

## 0. The dominating objectives

| | Objective | Critical path | Posture |
|---|---|---|---|
| **A** | Ship the **operator-visibility quick wins** that close the biggest Mirth/Corepoint gaps cheaply | `obs-metrics` (#21) + `console-pages` (#22) + `user-guide` (#19) — all **Low/Med effort, parallelizable, no ADR** | **Staff NOW.** Highest value-per-day on the board; front-load. |
| **B** | Land the marquee **FHIR codec + REST client** (#20) | `fhir-codec` — High value, **XL**, design-first (ADR 0022, **to be authored**) | **NOW = author + ratify ADR 0022 (design only).** The **build** is **NEXT**, gated on *ADR 0022 Accepted*. Longest *build* pole. |

Objective A is the front-loaded value: three independent, low-effort wins that make the engine
*observable and operable* (the standing gap vs. Mirth Command Center / Corepoint). Objective B is the
strategic build — its design ADR (0022) does **not yet exist**, so NOW is *authoring + ratifying* it
(design, owner sign-off); the long XL build begins only once 0022 is Accepted (NEXT).

**Hard rule for all lanes:** no two items from the [contention matrix](#appendix-a--file-contention-matrix)
are ever concurrently active in different worktrees — contended files are pinned to one lane or phased
apart (**true sequencing, not a "merge window"**). Where two NOW lanes share a file, the second lane
**holds its commits to that file until the first lane's PR has merged to `main`, then rebases** — that
is sequencing, not an aspirational "lands first."

---

## 1. Lane assignment (worktrees)

The board's dominant constraint is the **connector collision**: FHIR (#20), SOAP/REST-source (#7),
email (#23), DICOM (#24), JMS (#25), and the eventlog protocol-trace (#16) all edit the *same*
`transports/base.py`, `transports/__init__.py`, `config/models.py`, `tests/conftest.py`,
`pyproject.toml`, `docs/CONNECTIONS.md`, and `docs/FEATURE-MAP.md`. Every connector therefore lives in
**one serialized lane** (Lane B), ordered by value. The second constraint is the **store-hot-files
collision** (metrics #21, eventlog #16, WebAuthn #11/WP-14b, per-key #3) — pinned to **one
store-owning lane** (Lane S); other lanes cede their store-backend edits to it.

### Lane A — `observability` (Objective A; P1 quick wins — **staff first**)
**Branch:** `observability` · **Worktree:** `MessageFoundry-observability` (`-Sqlserver` — touches all store backends read-only)
1. `obs-metrics` (#21, M, ~5d) — **build first.** `/metrics` Prometheus exporter (+ optional OTel) in a NEW
   `api/metrics.py`; per-connection counters/gauges/histograms (received, delivered, errored, queue_depth,
   delivery latency p50/p95/p99). Engine already exposes per-connection metrics in memory (`/stats`,
   `outbox_by_status`); new work is the scrape surface + latency/histogram tracking. **No PHI in metrics.**
   Touches `store/base.py` + all three backends (read-only counter reads) → **this lane is the sole metrics
   editor of those files this phase; it cedes nothing back to Lane S because the two phases never overlap (§3).**
   - **`pyproject.toml` (NOW): `obs-metrics` (Lane A) is the SOLE editor of `pyproject.toml` this phase.**
     It adds its scrape-surface deps (`prometheus-client` + optional OpenTelemetry) to the dependencies block.
     Lane B (`fhir-codec`) **holds** its FHIR dependency + `[[tool.mypy.overrides]]` additions until this
     PR merges, then rebases (§3). No second worktree edits `pyproject.toml` deps in NOW.
   - **`api/app.py` + `api/models.py` (NOW): `obs-metrics` is the first editor.** Its `/metrics` route +
     response models land first; `console-pages` (Lane D) holds its API edits until this PR merges (§3).
   - *UltraCode note:* Workflow per the exporter + the OTel option; adversarial pass asserts **no field value
     ever lands in a label** (PHI guard) and that the scrape adds no event-loop blocking.

> **Cross-lane store note (conditional, not a NOW gate):** Lane S is entirely on-trigger and **not staffed
> now**, so there is no concurrent store-file holder this phase. **IF/WHEN** a Lane S store item is triggered,
> it **rebases onto `obs-metrics`' counter-read additions** to `store/base.py` / `store/store.py` /
> `store/postgres.py` / `store/sqlserver.py` (`obs-metrics` will have long since merged). This is a rebase rule
> for the eventual trigger, **not** a day-1 dependency of any NOW/NEXT item (§3).

### Lane D — `docs-console` (Objective A; P1/P2 — UI + docs, no engine work)
**Branch:** `docs-console` · **Worktree:** `MessageFoundry-docs-console` (`-Ide` — console + IDE deps)
1. `user-guide` (#19, M, ~4d) — NEW `docs/USER-GUIDE.md` only (zero code touch — **genuinely isolated**,
   **parallel with anything**, including `obs-metrics`). End-to-end task-oriented guide; links to the existing
   reference docs, anchors on `samples/config` + `send_mllp.py`. **Land any time** — no gate.
2. `console-pages` (#22, M, ~5d) — real **Alerts** + **Dead Letters** pages
   (`console/alerts_page.py`, `console/dead_letters_page.py`) replacing the `PlaceholderPage('Alerts')`;
   `console/shell.py` + `console/client.py` wiring. ✅ **SHIPPED + RE-SCOPED (2026-06-19):** the **Dead Letters**
   APIs exist (`GET /dead-letters`, `POST /dead-letters/replay`) — GUI-only, shipped as **#22a** (PR #413).
   **There is NO `GET /alerts` API — that was a plan defect** (`alerts_active` was a hardcoded-0 stub); **Alerts**
   is re-scoped to **#22b** = a NEW read-only `GET /alerts/rules` endpoint (PR #415, built by Lane A) **+ a thin
   Alerts GUI page still TODO** (consume it, replace the `PlaceholderPage`).
   - **Contention note (true-sequenced, not a merge window):** `console-pages` edits `api/app.py` +
     `api/models.py`, which `obs-metrics` (Lane A) and `eventlog` (Lane S) also touch. `console-pages`
     **does NOT begin its `api/app.py` + `api/models.py` edits until `obs-metrics`' api PR has merged to
     `main`**, then rebases onto it. Because `console-pages` is item 2 in this lane (after `user-guide`),
     that ordering buys the time naturally. `eventlog` (on-trigger) takes those files last. Never concurrent
     on the two API files. (`user-guide`, item 1, has no API touch and proceeds in parallel with anything.)
   - *UltraCode note:* `QT_QPA_PLATFORM=offscreen` for the console tests; Workflow per page; verify the GUI
     calls the API client only (no engine/DB import — §4 one-way rule).

### Lane B — `connectors` (the **serialized** connector lane; owns `transports/base.py`, `transports/__init__.py`)
**Branch:** `connectors` · **Worktree:** `MessageFoundry-connectors`
Strict internal order (value-ranked; each rebases onto the prior — they share `transports/base.py`,
`transports/__init__.py`, `config/models.py`, `pyproject.toml`, `tests/conftest.py`, `docs/CONNECTIONS.md`,
`docs/FEATURE-MAP.md`):
1. `fhir-codec` (#20, XL, ~12–15d) — **Objective B.** FHIR R4+R5 resource codec (JSON+XML) in NEW
   `parsing/fhir/` (parallel to `parsing/x12/`); REST **destination** (outbound client) in NEW
   `transports/fhir.py` wrapping the already-shipped `rest.py`; `content_type=fhir` in the ContentType enum;
   register `ConnectorType.FHIR`. HL7v2↔FHIR mapping stays in handlers. **Build is NEXT, gated on *ADR 0022
   Accepted*** (ADR 0022 does not exist yet — the coordinator authors + ratifies it NOW; the build is
   **build-on-gate, not build-now**). **The codec + REST-destination build depends ONLY on ADR 0022** — a
   destination/codec needs nothing from the inbound HTTP listener.
   - **FHIR server facade (inbound) is a SEPARATE sub-item, sequenced with #7** (the REST/SOAP inbound
     listener) and gated on **ADR 0023** (the inbound-listener ADR). It is **on-trigger**, not part of the
     NOW/NEXT codec+client build. The inbound-listener ADR is a blocker of *this sub-item only* — not of the
     codec+client.
   - **Gate on `tests/conftest.py` / `pyproject.toml`:** `fhir-codec` **holds its first `tests/conftest.py`
     fixture commit and its `pyproject.toml` dependency/mypy-override additions until BOTH (a) `ci-py311-finalizer`
     (#17, Lane X, NOW) has merged its conftest teardown finalizer, AND (b) `obs-metrics` (#21, Lane A, NOW)
     has merged its `pyproject.toml` deps** — then rebases onto both (§3). This keeps the XL conftest churn
     stacked on the stabilized teardown finalizer and keeps `pyproject.toml` single-edited in NOW.
2. `rest-soap-source` (#7, XL, ~15–18d) — inbound SOAP/REST **listener** (`transports/rest_source.py` +
   `transports/soap_source.py`); listener lives in `transports/`, **not** `api/` (one-way dependency preserved).
   Gated on **ADR 0023** (must resolve the sync-response seam vs. staged pipeline + ACK-on-receipt + count-and-log;
   the separate host/port/TLS/auth posture distinct from the `api/` `127.0.0.1` bind; the fail-closed
   ingress/egress allowlist). The **FHIR server facade** sub-item rides this same ADR 0023 + listener. **On-trigger**
   — staff only when a real inbound web-service feed emerges *and* ADR 0023 is authored + Accepted.
3. `email` (#23, M, ~8–10d) — **SMTP send is the cheaper half, land it first** (`transports/email.py` destination);
   then IMAP/POP source (`email_imap.py` + `email_pop.py`) with OAuth2/XOAUTH2 for M365/Google; mailbox poll
   gates on leader (like the File/DB sources). Gated on **ADR 0024**. **On-trigger** (real mailbox feed).
4. `dicom` (#24, L, ~5–7d DICOMweb) — DICOMweb (HTTP) preferred over DIMSE to reuse the HTTP/TLS stack; codec in
   NEW `parsing/dicom/`, HTTP destination `transports/dicom.py`. Gated on **ADR 0025**. **On-trigger** (real
   radiology/imaging feed). *Footprint is `parallelizable:true`, but it still edits the connector-shared files —
   so it runs in this lane's queue, never a second worktree.*
5. `jms` (#25, M, ~6–8d AMQP / ~10–12d JMS) — gated on **ADR 0026**, which must first decide *JMS-specific vs.
   generic broker* (recommend **AMQP / aio-pika** as the modern interop default; Kafka via aiokafka the
   alternative). **On-trigger** (broker-interop demand).

> **Lane B never runs two items at once.** Everything in it shares the connector registry surface. FHIR (#20)
> codec + client is the only NEXT build; #7/#23/#24/#25 (and the FHIR server facade) are on-trigger and queue
> behind it in value order when their ADR is authored + Accepted and a real feed/demand exists.
>
> *UltraCode note (Lane B):* one Workflow per connector; ground in the matching ADR + `transports/x12.py` as the
> existing tolerant-codec/raw-TCP template; adversarial pass asserts payload-agnostic ingress (RawMessage,
> never HL7-parse a non-HL7 body — §8) and that the new connector resolves only through the registry
> (`transports/base.py`), never special-cased in `pipeline/` (§4).

### Lane S — `store-eventlog` (**SOLE owner** of the four store-hot files; serialized store work)
**Branch:** `store-eventlog` · **Worktree:** `MessageFoundry-store-eventlog` (`-Sqlserver`)
Owns every edit to `store/store.py`, `store/base.py`, `store/postgres.py`, `store/sqlserver.py`. Other lanes
hand their store-backend edits here. It additionally **single-owns** `pipeline/retention.py` and
`api/field_authz.py` (touched only by `eventlog` — no cross-lane contention; flagged so a future toucher
routes through this lane). Strict internal order — **ordered by readiness, not list position**:
1. `eventlog` (#16, M+L, ~7–12d) — **first in this lane (most ready).** Corepoint event-log parity.
   **Build ADR 0021 first** (Response Sent, ~3–4d: extend the **`0013-query-response-orchestration`**
   `response` table — *that file, not `0013-increment-2-reingress-design`; the ADR-0013 number is duplicated,
   so name the file* — with a `kind` discriminator + `ack_code`/`ack_phase`; reuses its cipher/purge machinery),
   **then ADR 0020** (Protocol Trace, ~6–8d: NEW `transports/protocol_trace.py` + a NEW `protocol_trace` table,
   off-by-default, RAM-first, encrypted, RBAC-gated `MESSAGES_VIEW_RAW`, audited). **On-trigger** — ratify
   **ADRs 0020 and 0021** (both already **Drafted / Status: Proposed** → drive to Accepted) first; its other
   prerequisites (MFA + tee-relay stack merged, ADR 0019 KeyProvider seam) are already satisfied. Touches
   `transports/base.py`, `transports/mllp.py`, `config/wiring.py`, `config/models.py`, `api/app.py`,
   `api/models.py`, `pipeline/retention.py`, `api/field_authz.py` → **phase against Lane B (connectors) and
   Lane A/D (api) — never concurrent on those files.**
2. `webauthn` (#11 / WP-14b, L, ~7d) — **On-trigger** (L3 control preference; TOTP shipped 2026-06-17 already
   satisfies L2 6.3.3 on loopback). NEW `auth/webauthn.py`; enroll/verify flows in `auth/service.py` +
   `api/auth_routes.py`; new store columns (`user.webauthn_credentials` + metadata) across all four backends;
   `console/mfa.py`; `[auth].webauthn_enabled` (off by default). **Gate: the off-loopback exposure trigger +
   ADR 0002 WP-14b design amendment AUTHORED and Accepted.** Phishing-resistant MFA's value is exposure-driven
   (ADR 0002 §3 ties MFA value to exposure — "recommended on for local admins *when exposed*"); WP-14b is today
   only a **sketch** ("not designed in detail here"), so the gate is *author the WP-14b design amendment THEN
   ratify*, not merely ratify. **Serialized with `approve-step-up`** (both touch `api/auth_routes.py`, *only if
   both active concurrently*) and with `eventlog` (both touch `docs/SECURITY.md` + the store backends — it
   rebases onto `eventlog`).
3. `per-key` (#3, XL/L, ~long) — **On-trigger** (long-term optimization, pending real single-feed workload
   demand; owner-confirmed v0.2 *candidate*). `partition_key` as a first-class Router/Connection setting;
   store-side lane identity in outbox across all four backends; delivery-worker per-lane FIFO refactor; A40
   patient-merge hazard guard. **Byte-identical when off** (`partition_key=None` → today's per-connection FIFO).
   **Gate: a NEW per-key/partition ADR authored and Accepted (no ADR exists yet — the #3 footprint itself says
   "no ADR yet, design phase") + the owner real-single-feed-workload throughput trigger.** (ADR 0001 Steps A+B
   and the FIFO per-connection Phase 1 Layers 1–4 are *already shipped/satisfied* — they are **not** the blocker;
   there is **no "ADR 0001 Step C"**. The missing artifact is the per-key design ADR.) **Last in this lane** —
   its store churn rebases onto everything prior.

> **Lane S serialization order:** `eventlog → webauthn → per-key` (ordered by readiness — `eventlog`'s ADRs
> 0020/0021 are already drafted and its deps satisfied; `webauthn` is the least-ready, only a WP-14b *sketch*
> with the softest trigger, so it must not become the long pole ahead of `eventlog`). All three rewrite the four
> store-hot files; `eventlog` + `webauthn` additionally collide on `docs/SECURITY.md`; `eventlog` + `per-key`
> additionally collide on `config/wiring.py`, `config/models.py`, `pipeline/wiring_runner.py`. None overlaps;
> each rebases onto the prior. **All three are on-trigger — not staffed now.** Whichever Lane S item opens first
> is the one that rebases onto `obs-metrics`' merged counter reads (the lead position is incidental).
>
> *UltraCode note (Lane S):* Workflow per item; ground in the cited ADR; adversarial pass asserts the
> **reliability invariant** (single committed handoff per stage; idempotent re-run), the **count-and-log
> invariant**, and **byte-identical-when-off** for `per-key`.

### Lane Sec — `secrets-stepup` (small security seams; isolated config/api)
**Branch:** `secrets-stepup` · **Worktree:** `MessageFoundry-secrets-stepup`
1. `least-priv-svc` (ASVS 13.2.2/13.3.2, S, ~2d) — flip the install default from LocalSystem to
   `NT SERVICE\MessageFoundry` (with a `-AllowLocalSystem` opt-out) in `scripts/service/install-service.ps1`; the
   `-ServiceAccount` param + `Set-ConfigReadAcl` / `Set-SecureDataDirAcl` already shipped (WP-11d). **Gating: Then**
   — the `windows-service-smoke` CI job must prove out-of-tree configs + repo venvs are readable under the
   least-priv account *before* the default flips. Edits `.github/workflows/ci.yml` → phase against `per-key` +
   `eventlog` (both also touch `ci.yml`).
2. `secretprovider` (ASVS 13.3.1/13.2.1, M, ~4d) — NEW `config/secretprovider.py`: a `SecretProvider` protocol
   (same shape as the shipped `KeyProvider`), routing connector-credential resolution (`config/environments.py`
   `env()` + `config/models.py` Destination/Connector fields) through it; **env stays the built-in, byte-identical**.
   Zero store/cipher impact. **Gating: Then — a NEW ADR 0019 §5 follow-on amendment that *authorizes the
   SecretProvider build*.** ADR 0019 §5 records the SecretProvider as design-only ("**not** part of the core
   store-key seam and **not** built here"), so the core KeyProvider shipping is **not** a build authorization;
   the seam *shape* is decided (low-risk) but the build needs the §5 follow-on amendment first. Edits
   `config/settings.py`, `config/models.py`, `__main__.py` → phase against Lane S (`config/models.py`) and any
   other `config/settings.py` toucher.
3. `approve-step-up` (#8 remainder, S, ~1 line) — **On-trigger; OWNER DECISION (primary gate).** Optionally gate
   the approver's `POST /approvals/{id}/approve` with its own `require_step_up` check (`api/approvals.py` /
   `api/auth_routes.py`; add `ApprovalsSettings.require_approve_step_up`, default false). Dual-control already
   satisfies ASVS 2.3.5; this is strictly defense-in-depth. The `api/auth_routes.py` serialization with
   `webauthn` applies **only if both are active concurrently** — if the owner approves this while `webauthn` is
   dormant, it **lands immediately** (it just owns `api/auth_routes.py` for its tiny edit). **Do not make this
   1-line owner-approved change wait on the on-trigger, undesigned `webauthn`.** **Do not staff** without an
   explicit owner call.

> **Lane Sec contention:** `approve-step-up` shares `api/auth_routes.py` with `webauthn` (Lane S) and shares
> `config/settings.py` with `secretprovider` + `obs-metrics` + `eventlog`. Serialize: `obs-metrics` settings edit
> (Lane A, NOW) → `secretprovider` + `least-priv-svc` (Then) → `approve-step-up` (on-trigger; serialized behind
> `webauthn` *only if `webauthn` is concurrently active*, otherwise it lands standalone on the owner call).
>
> *UltraCode note (Lane Sec):* `least-priv-svc` and `approve-step-up` are near-trivial (solo-allowed for the
> code edit) but the **CI proof** for `least-priv-svc` is a full Workflow — ground in the
> `windows-service-smoke` job, build the ACL scenarios, adversarially verify a real least-priv service start.

### Lane X — `ci-infra` (test-harness only; fully isolated)
**Branch:** `ci-infra` · **Worktree:** `MessageFoundry-ci-infra`
1. `ci-py311-finalizer` (#17, S, ~2d) — **NOW (land first, ahead of Lane B's conftest churn).** Suite-wide
   teardown-ordering finalizer in `tests/conftest.py` to detach root log-capture handlers + quiesce
   background-component loggers (aiosqlite, engine, harness, starlette) **before** caplog teardown (root cause:
   aiosqlite/asyncio lost-wakeup on py3.11). Re-adds py3.11 as a **required** CI leg once green. Touches only
   `tests/conftest.py` + `pyproject.toml`.
   - **Contention (true-sequenced):** `tests/conftest.py` is touched by every connector item + `per-key` +
     `eventlog`; `pyproject.toml` by every connector item + `obs-metrics`. **`ci-py311-finalizer` is staffed
     day 1 (NOW) alongside the other NOW lanes and MUST merge BEFORE `fhir-codec` (Lane B) commits any
     `tests/conftest.py` fixture additions** — matching the plan's intent that the connector lane rebases its
     conftest additions onto the stabilized teardown finalizer. Since #17 is only ~2d and isolated, landing it
     first is cheap and de-risks both the flake and the XL connector conftest churn. (The coordinator's Lane B
     start-gate is therefore *"ADR 0022 Accepted **and** `ci-py311-finalizer` merged."*)
   - *UltraCode note:* Workflow grounded in the #17 lead (teardown-ordering finalizer, not per-emit banner drops);
     adversarial pass = run the py3.11 store-soak repeatedly to confirm the lost-wakeup is gone.

### Lane L — `decisions` (decision-only; **no build**, `-NoInstall`)
**Branch:** `decisions` · **Worktree:** `MessageFoundry-decisions` (`-NoInstall`)
Coordinator-adjacent; carries the non-engineering items so they don't starve build lanes:
1. `decline-visual-authoring` (#26, S) — **Now.** Decision recorded, **decline-by-design**. Only edit: a one-line
   note in `CLAUDE.md` confirming no visual/template authoring (code-first IS the differentiator). Solo edit.
2. `decline-serial-astm` (#27, S) — **Now.** Decision recorded, **decline-by-design** (sibling decline of #26 in
   the same BACKLOG.md bullet: Serial RS-232 + ASTM E1381/E1394/E1318 lab-instrument connectivity). Only edit: a
   one-line decline marker in `CLAUDE.md` / `docs/CONNECTIONS.md` recording that serial/ASTM is declined for v0.2+
   (no real feed demand; out of the HL7/FHIR/X12/DICOM scope). Solo edit.
3. `licensing-counsel` (#13, S) — **Then.** Legal/business, not engineering. `v0.1.0` shipped without counsel
   sign-off (accepted risk). Counsel ratifies `docs/DUAL_LICENSING_PLAN.md` + `COMMERCIAL-LICENSE.md` + ADR 0017
   decision #6 before any commercial offering. **No code; doc review only.** Front-load the *engagement* (longest
   human lead time) even though no file moves until counsel responds.
4. `git-offering` (#18, S) — **On-trigger; owner product decision only, no build.** Vendored git client vs.
   embedded git server vs. documented conventions + IDE wiring; any bundled component must be AGPL-compatible
   (ADR 0017 #6). **Do not staff** without an owner call.

> *UltraCode note (Lane L):* the `#26` and `#27` decline markers and the `#18` decision are **solo (no Workflow)**
> trivial edits (a one-line marker / an owner-call record). The `#13` counsel item is doc-review only — but if any
> refinement of `docs/DUAL_LICENSING_PLAN.md` / `COMMERCIAL-LICENSE.md` turns into *substantive* editing rather
> than recording counsel's ratification, run a **short Workflow** for that edit.

---

## The coordinator session (no building)

**One coordinator window**, UltraCode-enabled, builds nothing. It owns:
- **Shared-memory writes** — single-writer; records every ADR-status change and gating decision before any lane
  acts on it (see §3).
- **ADR authoring + ratification + decision tracking** — **authors and drives ADR 0022 (FHIR) to Accepted NOW**
  (design-only, owner sign-off; it gates the Objective B build, which is NEXT), then authors/ratifies
  **0023 (HTTP listener — also gates the FHIR server facade)**, **0024 (email)**, **0025 (DICOM)**,
  **0026 (JMS/AMQP)**, drives **0020/0021 (eventlog — already Drafted/Proposed)** to Accepted, and authors the
  **NEW per-key/partition ADR (#3 — none exists)**, the **ADR 0002 WP-14b design amendment (currently only a
  sketch)**, and the **ADR 0019 §5 follow-on amendment (SecretProvider build authorization — design-only today)**
  as their items approach; tracks the owner/counsel calls (`#13` counsel, `#18` git-offering, `#8` approve
  step-up, the "is there a real feed?" + off-loopback-exposure triggers for `#7`/`#23`/`#24`/`#25`/`#11`).
- **Scaffolding/teardown** of worktrees (§5 command block) — `new.ps1` to create, `remove.ps1` to retire.
- **PR review + merge ordering** — enforces the §3 sequencing (esp. `ci-py311-finalizer` + `obs-metrics`
  `pyproject.toml`/api edits before any Lane B conftest/dep/api churn; `obs-metrics` api before `console-pages`
  api; Lane B's strict internal order).
- **Keeping this plan current** — flips item statuses as lanes land.

*Coordinator UltraCode note:* runs a short Workflow for any **non-trivial** coordination act (e.g. authoring an
ADR, or composing a merge-order decision across three contended files); solo for routine status flips and memory
releases.

---

## 2. Phasing — Now / Next / Then / On-trigger

```
PHASE      LaneA observability   LaneD docs-console     LaneB connectors      LaneS store-eventlog   LaneSec secrets        LaneX ci-infra   LaneL decisions
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
NOW        obs-metrics (#21)     user-guide  (#19)      ADR 0022 authored     —                      —                      ci-py311 (#17)   decline-visual (#26)
           (build first)         console-pages (#22)    + ratified (DESIGN)   (await triggers)       (await Then/trigger)   (land FIRST,     decline-serial (#27)
           (sole pyproject +     (item2 holds api edits (build is NEXT)                                                      before LaneB     (one-line declines)
            api editor NOW)       until obs-metrics                                                                          conftest churn)  OWNER+COUNSEL
                                  api merges)                                                                                                  ENGAGEMENT (#13)
NEXT       (merged → frees        (merged)              fhir-codec (#20)      —                      —                      (re-require 3.11) —
           LaneB pyproject;                             BUILD (codec+REST     (await triggers)       (Then prereqs)         (merged)
           rebase target)                               dest; ADR 0022 ✓)
THEN       —                     —                       —                    —                      least-priv-svc         —                licensing-counsel
                                                                                                       secretprovider                          (#13, doc only)
ON-TRIG    —                     —                       rest-soap-source (#7) eventlog (#16)         approve-step-up (#8)   —                git-offering (#18)
                                                          + FHIR server facade webauthn (#11/WP-14b)                                          (owner decision)
                                                          email (#23)          per-key (#3)
                                                          dicom (#24)          *SERIALIZED*
                                                          jms  (#25)           (by readiness)
                                                          *SERIALIZED*
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

**Do NOT staff now (build-on-trigger / build-on-gate):** the `fhir-codec` (#20) **build** (NEXT, gated on
ADR 0022 Accepted + `ci-py311-finalizer` merged), `rest-soap-source` (#7) + FHIR server facade, `email` (#23),
`dicom` (#24), `jms` (#25), `eventlog` (#16), `webauthn` (#11/WP-14b), `per-key` (#3), `approve-step-up` (#8),
`git-offering` (#18). Each is gated on a ratified (and in several cases *not-yet-authored*) ADR, a real
feed/demand / off-loopback exposure, or an explicit owner call.

**Front-loaded value (NOW):** `obs-metrics` (#21), `user-guide` (#19), `console-pages` (#22) — the three P1/P2
operator-visibility wins — plus `ci-py311-finalizer` (#17, land first) and the `#26`/`#27` decline markers. The
two day-1 coordinator priorities with the longest lead time: **author + ratify ADR 0022 (FHIR)** (the build it
gates is NEXT) and **open the counsel engagement (#13)** — both start day 1 though one is design and the other
legal.

**Gating decisions the coordinator must record before the dependent lane acts:**
- **`ci-py311-finalizer` (#17) merged** → unblocks Lane B's first `tests/conftest.py` fixture commit (and is a
  hard pre-req of the Lane B build start).
- **`obs-metrics` `pyproject.toml` PR merged** → unblocks Lane B adding its FHIR dependency / mypy-override
  (Lane B rebases onto it).
- **`obs-metrics` api PR merged** → unblocks `console-pages` `api/app.py`/`api/models.py` edits.
- **ADR 0022 (FHIR codec + REST client) authored + Accepted** → unblocks the Lane B `fhir-codec` **build** (NEXT,
  Objective B). The codec+client depends ONLY on ADR 0022; the FHIR server facade additionally needs ADR 0023.
- **ADR 0019 §5 follow-on amendment authored** (build-authorizing, not merely "core shipped") → unblocks
  `secretprovider` (Then).
- **ADRs 0020 + 0021 Accepted** (drive the existing drafts), **a NEW per-key/partition ADR authored + Accepted**
  (#3 — none exists), **ADR 0002 WP-14b design amendment authored + Accepted** + the **off-loopback exposure
  trigger** (#11) → unblock the respective Lane S triggers.

---

## 3. Coordination rules for parallel sessions

- **Store hot files** (`store/store.py`, `store/base.py`, `store/postgres.py`, `store/sqlserver.py`) — **exclusively
  Lane S** for *write*/schema work (`eventlog`, `webauthn`, `per-key`). The single read-only exception this phase is
  **Lane A `obs-metrics`**, which adds counter-read methods to these files **NOW while Lane S is quiescent** (Lane S is
  all on-trigger). No two worktrees ever hold a store file open. **IF/WHEN** a Lane S store item is eventually
  triggered, it **rebases onto `obs-metrics`' merged counter reads** — `obs-metrics` will have long since merged, so
  this is a rebase rule for the trigger, not a live NOW/NEXT dependency. Lane S internal order is strict and by
  readiness: `eventlog → webauthn → per-key`.
- **Connector registry surface** (`transports/base.py`, `transports/__init__.py`, `config/models.py` connector fields,
  `pyproject.toml` connector deps, `tests/conftest.py` connector fixtures, `docs/CONNECTIONS.md`, `docs/FEATURE-MAP.md`)
  — **exclusively Lane B**, serialized: `fhir-codec → rest-soap-source (+ FHIR server facade) → email → dicom → jms`.
  `eventlog` (Lane S) also touches `transports/base.py` + `transports/mllp.py` → it is **phased after** all active
  Lane B work, never concurrent.
- **`pyproject.toml` (NOW)** — **`obs-metrics` (Lane A) is the SOLE editor this phase.** It adds
  `prometheus-client` + optional OpenTelemetry to the dependencies block. **`fhir-codec` (Lane B) HOLDS its FHIR
  dependency + `[[tool.mypy.overrides]]` additions until `obs-metrics`' `pyproject.toml` PR has merged to `main`,
  then rebases.** `ci-py311-finalizer` (Lane X, NOW) also edits `pyproject.toml` (CI-leg/marker) and likewise merges
  before Lane B touches it. No two concurrently-building lanes edit the dependencies block at once. (Later connectors
  #7/#23/#24/#25 take `pyproject.toml` on-trigger, within Lane B's serialization.)
- **`config/models.py`** — touched by every connector (Lane B), `eventlog` + `per-key` (Lane S), and `secretprovider`
  (Lane Sec). Serialize: Lane B owns it during connector builds; Lane S's `eventlog`/`per-key` (on-trigger) and Lane
  Sec's `secretprovider` (Then) take it only in windows when Lane B is quiescent on it.
- **`config/settings.py`** — `obs-metrics` (Lane A, NOW) → `secretprovider` (Lane Sec, Then) → `eventlog` + `webauthn`
  (Lane S, on-trigger) → `approve-step-up` (Lane Sec, on-trigger). Sequenced, each rebases onto the prior.
- **`config/wiring.py`** + **`pipeline/wiring_runner.py`** — `eventlog` and `per-key` (both Lane S) are the only
  touchers; Lane S's internal serialization handles it.
- **`pipeline/engine.py`** — `obs-metrics` (Lane A, NOW) lands first; `rest-soap-source` (#7) + `email` (#23) (both
  Lane B, on-trigger) take it later, never concurrent — same pattern as the `api/app.py` bullet. (obs-metrics' NOW
  edit and the on-trigger connectors are unlikely to overlap regardless, but the order is explicit.)
- **`api/app.py`** + **`api/models.py`** — **true-sequenced, not a merge window:** `obs-metrics` (Lane A, NOW)
  merges first → `console-pages` (Lane D) **holds its edits until that PR merges**, then rebases onto it →
  `eventlog` (Lane S, on-trigger) + `rest-soap-source` (Lane B, on-trigger) last. Never concurrent.
- **`api/auth_routes.py`** — `webauthn` (Lane S) + `approve-step-up` (Lane Sec) serialize **only if both are active
  concurrently**; otherwise whichever is triggered first owns the file standalone (`approve-step-up`'s ~1-line edit
  does **not** wait on the on-trigger `webauthn`).
- **`pipeline/retention.py`** + **`api/field_authz.py`** — **single-owner: `eventlog` (Lane S) only.** No
  cross-lane contention (omitted from the matrix by design); a future toucher routes through Lane S.
- **`docs/SECURITY.md`** — `eventlog` + `webauthn` (both Lane S); Lane S serialization handles it.
- **`docs/CONFIGURATION.md`** — `obs-metrics` (Lane A) + `webauthn` (Lane S); phased (metrics NOW, webauthn on-trigger).
- **`.github/workflows/ci.yml`** — `ci-py311-finalizer` (Lane X, NOW, touches `pyproject.toml` not `ci.yml` directly —
  *re-requires* the leg) + `least-priv-svc` (Lane Sec) + `per-key` + `eventlog` (Lane S). Phase: `least-priv-svc`
  (Then) before the on-trigger Lane S items; coordinator owns the merge order.
- **`tests/conftest.py`** + **`pyproject.toml`** — `ci-py311-finalizer` (Lane X, **NOW**) lands **before** Lane B's
  FHIR conftest/dep churn so the connector lane rebases onto the stabilized teardown finalizer. **Lane B's first
  conftest-touching commit is gated on `ci-py311-finalizer` merged** (added to the coordinator's Lane B start-gate).
- **`parsing/__init__.py`** — `fhir-codec` (#20) + `dicom` (#24), both Lane B, serialized internally.
- **Shared memory** — single-writer; announce intent, read-before-write, write, release. The **coordinator** records
  all ADR-status changes (0022 / 0023 / 0024 / 0025 / 0026 / 0020 / 0021 / the NEW per-key ADR / ADR 0002 WP-14b
  amendment / ADR 0019 §5 follow-on) and every gating decision before any lane starts work against them.
- **Verification (every PR, no exceptions):** `ruff check` + `ruff format --check` → `mypy messagefoundry` (strict) →
  `pytest -q` (`QT_QPA_PLATFORM=offscreen` for console tests). **New behavior ships with a test.**
- **Branch + PR discipline:** each lane = its own worktree + `.venv` + PR; one coherent layer per commit; no direct
  pushes to `main`; the `PreToolUse` hook blocks blanket `git add -A/./-u/--all` and `git commit -a/-am` — **stage
  explicit paths**.

---

## 4. Summary table

| Item | Lane | Phase | Effort | Parallelizable | Blocked by / blocks |
|---|---|---|---|---|---|
| `obs-metrics` (#21) | A observability | Now | M (~5d) | yes | no ADR; **sole NOW editor of `pyproject.toml` + `api/app.py`/`api/models.py`** (Lane B holds deps, console-pages holds api until it merges); IF a Lane S store item later triggers, that item rebases onto it |
| `user-guide` (#19) | D docs-console | Now | M (~4d) | yes | fully isolated (new doc only); no gate; blocks nothing |
| `console-pages` (#22) | D docs-console | Now | M (~5d) | yes | APIs exist; **holds api edits until `obs-metrics` api PR merges**, then rebases |
| `ci-py311-finalizer` (#17) | X ci-infra | Now | S (~2d) | yes | isolated; **must merge before Lane B's first conftest commit** (de-risks XL connector conftest churn) |
| `fhir-codec` (#20) codec + REST dest | B connectors | Next (build) | XL (~12–15d) | no | **ADR 0022 authored+Accepted (NOW)** + `ci-py311-finalizer` merged; first in Lane B; **depends ONLY on ADR 0022** |
| FHIR server facade (inbound) | B connectors | On-trigger | (part of #20) | no | **ADR 0023** (inbound-listener) + real feed; sub-item sequenced w/ #7 |
| `rest-soap-source` (#7) | B connectors | On-trigger | XL (~15–18d) | no | **ADR 0023** + real feed; serialized in Lane B |
| `email` (#23) | B connectors | On-trigger | M (~8–10d) | no | **ADR 0024** + real mailbox; SMTP half first |
| `dicom` (#24) | B connectors | On-trigger | L (~5–7d) | no* | **ADR 0025** + real imaging feed (*shared registry files → Lane B queue) |
| `jms` (#25) | B connectors | On-trigger | M (~6–8d AMQP) | no* | **ADR 0026** (JMS vs AMQP/Kafka) + demand |
| `eventlog` (#16) | S store-eventlog | On-trigger | M+L (~7–12d) | no | **ADRs 0020+0021 Accepted** (drafts exist; 0021 first; grounds in `0013-query-response-orchestration`); **first in Lane S (most ready)** |
| `webauthn` (#11/WP-14b) | S store-eventlog | On-trigger | L (~7d) | no | **off-loopback exposure trigger + ADR 0002 WP-14b design amendment authored+Accepted** (today only a sketch); after `eventlog` |
| `per-key` (#3) | S store-eventlog | On-trigger | XL (~long) | no | **NEW per-key/partition ADR authored+Accepted** (none exists — *not* "ADR 0001 Step C") + workload throughput trigger; last in Lane S |
| `least-priv-svc` (ASVS 13.2.2) | Sec secrets-stepup | Then | S (~2d) | yes | `windows-service-smoke` CI proof before default flip |
| `secretprovider` (ASVS 13.3.1) | Sec secrets-stepup | Then | M (~4d) | yes | **NEW ADR 0019 §5 follow-on amendment authorizing the build** (design-only today; core KeyProvider shipped ≠ build-authorized) |
| `approve-step-up` (#8) | Sec secrets-stepup | On-trigger | S (~1 line) | yes | **owner decision (primary)**; `api/auth_routes.py` serialization w/ `webauthn` only if both concurrent |
| `decline-visual-authoring` (#26) | L decisions | Now | S | yes | decline-by-design; one-line `CLAUDE.md` note |
| `decline-serial-astm` (#27) | L decisions | Now | S | yes | decline-by-design (sibling of #26); one-line `CLAUDE.md`/`docs/CONNECTIONS.md` note |
| `licensing-counsel` (#13) | L decisions | Then | S | yes | **counsel sign-off**; doc-only; **blocks** commercial offering |
| `git-offering` (#18) | L decisions | On-trigger | S | yes | **owner product decision**; no build |

---

## 5. Scaffolding command block

Create each worker worktree off `origin/main` via `scripts/worktree/new.ps1` (branch == lane == `MessageFoundry-<lane>`
suffix). The coordinator runs these from the main checkout; `spawn.ps1` is the one-step variant that also opens a VS
Code window (start the lane's chat there). **Staff the NOW lanes first; create the on-trigger lanes only when their
trigger fires.**

```powershell
# --- NOW (front-loaded value: build immediately) ---
scripts\worktree\spawn.ps1 -Name observability -Sqlserver   # Lane A — obs-metrics #21 (reads all store backends; sole pyproject+api editor NOW)
scripts\worktree\spawn.ps1 -Name docs-console   -Ide         # Lane D — user-guide #19 (any time) + console-pages #22 (after obs-metrics api)
scripts\worktree\spawn.ps1 -Name ci-infra                    # Lane X — ci-py311-finalizer #17 (land FIRST, before Lane B conftest churn)
scripts\worktree\spawn.ps1 -Name connectors                  # Lane B — ADR 0022 authored NOW; fhir-codec BUILD is NEXT (after 0022 + #17)
scripts\worktree\new.ps1   -Name decisions      -NoInstall   # Lane L — #26 + #27 declines now; #13/#18 decisions (no venv)

# --- THEN ---
scripts\worktree\spawn.ps1 -Name secrets-stepup              # Lane Sec — least-priv-svc + secretprovider

# --- ON-TRIGGER (create only when the ADR is authored + Accepted / a real feed or owner call exists) ---
scripts\worktree\spawn.ps1 -Name store-eventlog -Sqlserver   # Lane S — eventlog → webauthn → per-key (store-hot files; by readiness)
#   (Lane B's on-trigger connectors #7/#23/#24/#25 + FHIR server facade reuse the existing `connectors` worktree — same lane, queued in value order)

# --- TEARDOWN (from the MAIN checkout, after a lane's PRs merge) ---
scripts\worktree\remove.ps1 -Name <lane> -DeleteBranch
```

**Notes.**
- `-Sqlserver` on Lane A and Lane S because both touch all store backends (Lane A read-only counters; Lane S schema).
- `-Ide` on Lane D for the PySide6 console + VS Code extension deps (`console-pages` GUI work).
- `-NoInstall` on Lane L (decisions-only; bootstrap a venv only if a decision later turns into an artifact edit).
- Lane X (`ci-infra`) is created **NOW**, not NEXT — its #17 finalizer must merge before Lane B's conftest churn.
- Lane B is **one worktree for all connectors** — do not spin a second worktree per connector; they share the registry
  surface and run in the lane's serialized value order. The Lane B worktree is created NOW (ADR 0022 authoring/grounding),
  but the `fhir-codec` build commits begin only once ADR 0022 is Accepted **and** `ci-py311-finalizer` has merged.
- A `SessionStart` hook auto-injects the UltraCode reminder + the parallel-session block (which worktree/branch the
  chat owns + the full worktree list + the shared-memory single-writer rule) into every new window.

---

## Appendix A — file-contention matrix

Files touched by more than one open item (must be same-lane or phased apart, **never concurrent across worktrees**).
Computed from the verified per-item footprints (2026-06-18). Single-owner files (e.g. `pipeline/retention.py` +
`api/field_authz.py`, owned solely by `eventlog`) are intentionally omitted — no contention — and noted in §3.

| File | Items |
|---|---|
| `config/models.py` | fhir-codec (#20), rest-soap-source (#7), email (#23), dicom (#24), jms (#25), secretprovider, per-key (#3), eventlog (#16) |
| `transports/base.py` | fhir-codec (#20), rest-soap-source (#7), email (#23), dicom (#24), jms (#25), eventlog (#16) |
| `transports/__init__.py` | fhir-codec (#20), rest-soap-source (#7), email (#23), dicom (#24), jms (#25) |
| `tests/conftest.py` | fhir-codec (#20), rest-soap-source (#7), email (#23), dicom (#24), jms (#25), per-key (#3), eventlog (#16), ci-py311-finalizer (#17) |
| `pyproject.toml` | obs-metrics (#21), ci-py311-finalizer (#17), fhir-codec (#20), rest-soap-source (#7), email (#23), dicom (#24), jms (#25) |
| `docs/CONNECTIONS.md` | fhir-codec (#20), rest-soap-source (#7), email (#23), dicom (#24), jms (#25), decline-serial-astm (#27) |
| `docs/FEATURE-MAP.md` | fhir-codec (#20), rest-soap-source (#7), email (#23), dicom (#24), jms (#25) |
| `store/store.py` | obs-metrics (#21), eventlog (#16), webauthn (#11), per-key (#3) |
| `store/base.py` | obs-metrics (#21), eventlog (#16), webauthn (#11), per-key (#3) |
| `store/postgres.py` | obs-metrics (#21), eventlog (#16), webauthn (#11), per-key (#3) |
| `store/sqlserver.py` | obs-metrics (#21), eventlog (#16), webauthn (#11), per-key (#3) |
| `config/settings.py` | obs-metrics (#21), secretprovider, eventlog (#16), webauthn (#11), approve-step-up (#8) |
| `api/app.py` | obs-metrics (#21), console-pages (#22), eventlog (#16), rest-soap-source (#7) |
| `api/models.py` | obs-metrics (#21), console-pages (#22), eventlog (#16) |
| `pipeline/engine.py` | obs-metrics (#21), rest-soap-source (#7), email (#23) |
| `config/wiring.py` | per-key (#3), eventlog (#16) |
| `pipeline/wiring_runner.py` | per-key (#3), eventlog (#16) |
| `api/auth_routes.py` | webauthn (#11), approve-step-up (#8) |
| `docs/SECURITY.md` | eventlog (#16), webauthn (#11) |
| `docs/CONFIGURATION.md` | obs-metrics (#21), webauthn (#11) |
| `.github/workflows/ci.yml` | least-priv-svc, eventlog (#16), per-key (#3) |
| `parsing/__init__.py` | fhir-codec (#20), dicom (#24) |
| `CLAUDE.md` | decline-visual-authoring (#26), decline-serial-astm (#27) |

> **Reading the matrix.** The top cluster (`config/models.py` through `docs/FEATURE-MAP.md`) is the **connector
> collision** → all in **Lane B, serialized**. The `store/*` cluster is the **store-hot-files collision** → all in
> **Lane S, serialized**, with `obs-metrics` (Lane A) the one read-only exception that merges (long) before any Lane S
> trigger fires. The NOW `pyproject.toml` and `api/app.py`/`api/models.py` collisions are **true-sequenced** (sole NOW
> editor `obs-metrics`; Lane B + `console-pages` hold their edits until it merges, then rebase). `CLAUDE.md` is the
> two declines (#26/#27), both Lane L, both trivial. Every other row is phased per §3. No row ever has two items active
> in different worktrees at the same time.
