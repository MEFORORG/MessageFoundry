# MessageFoundry — Multisession Execution Plan 3 (2026-06-19)

> **Lineage.** This is the **third** MessageFoundry multisession plan, driven by a dedicated **coordinator lane**
> (see "The coordinator lane" below). Plan 1 = [`MULTISESSION-PLAN.md`](MULTISESSION-PLAN.md) (v0.1, shipped).
> Plan 2 = [`MULTISESSION-PLAN-v0.2.md`](MULTISESSION-PLAN-v0.2.md) (the v0.2 candidate board — **now mostly
> merged**; kept as the historical record). **Plan 3 supersedes Plan 2** as the living plan.
>
> **Provenance.** Built 2026-06-19 from the 2026-06-19 backlog **value review** + **bad-idea cull**, reconciled
> against `origin/main` (Plan 2's NOW board had collapsed — see §A). Lane names, contention discipline, the
> **UltraCode-per-substantive-item rule**, and the §3 coordination rules of the v0.1 plan are carried forward
> where they still apply. Five value-reviewed items not in Plan 2 (#30, #31, #32, #33, #34) are slotted in with
> verified footprints; three items were **culled as bad ideas** (#18 and #25 declined; #16's ADR-0020 raw-frame
> tier dropped) and two **trimmed** (#23 SMTP-only; #30 to a constrained core) — see §G and the decline markers
> in [`../BACKLOG.md`](../BACKLOG.md). This is a planning artifact, not a gate — update it as items land.
>
> **Every window runs UltraCode**: ground → build the smallest coherent layer → adversarially verify (ruff +
> `ruff format --check` + mypy strict + pytest + a written test, plus a second pass against the
> count-and-log / ACK-on-receipt / one-way-dependency / reliability invariants). Solo (no Workflow) only on
> trivial edits (a one-line default, a doc link, a decline marker).

---

## A. Status delta since 2026-06-18 — the board collapsed

Most of the original NOW/NEXT board has **landed to `origin/main`** (this plan was authored on a worktree ~8
commits behind). Critically, **ADR 0022 is Accepted and the FHIR codec build (#20) is merged** — the marquee item
is done, not pending.

| Item | Prior plan state | Now | Evidence |
|---|---|---|---|
| `obs-metrics` (#21) | NOW, build first | ✅ **DONE** | PR #407 / `a5aed9d`; `api/metrics.py`, `/metrics` route (`MONITORING_READ`-gated) |
| `user-guide` (#19) | NOW | ✅ **DONE** | PR #412 / `3c3bbc7`; `docs/USER-GUIDE.md` |
| `console-pages` — Dead Letters (#22a) | NOW | ✅ **DONE** | PR #413 / `c2ce7be`; `console/dead_letters_page.py` |
| `console-pages` — `GET /alerts/rules` (#22b) | (premise corrected) | ✅ **DONE** | PR #415 / `399fd77` (the original `GET /alerts` was a phantom — `alerts_active` was a hardcoded-0 stub) |
| **`fhir-codec` (#20)** + ADR 0022 | NEXT, gated | ✅ **DONE** | ADR 0022 Accepted (PR #405); build PR #416 / `2086d02` — `parsing/fhir/` + `transports/fhir.py` |
| `#26` / `#27` declines | NOW | ✅ **DONE** | PR #411 / `adc8f53` |
| `licensing-counsel` (#13) engagement | Then | 🟡 **OPENED** | PR #406 — awaiting counsel; doc-only |
| `ci-py311-finalizer` (#17) | NOW, land first | ⚠️ **REOPENED / advisory** | PR #409 + #414 reduced but did not eliminate the cross-loop lost-wakeup; py3.11 is now **advisory** (py3.13 ×3 is the required gate). Residual = Lane X.2. **NB: BACKLOG #17 "✅ RESOLVED" → reconciled to "⚠️ REOPENED / advisory" by coord 2026-06-19.** |
| `console-pages` — **Alerts GUI page** | NOW | 🟡 **OPEN** — the only remaining #22 piece | Still `PlaceholderPage('Alerts')` on `origin/main` |

**Net:** Lane A (`observability`) is **retired**. `user-guide`, both #22 API endpoints, the Dead-Letters page, and
the whole FHIR build are **struck off**. The active board is now **small**.

---

## B. Refreshed lane assignment (open work only)

The connector collision (**Lane B**, serialized) and store-hot-files collision (**Lane S**, serialized) are
unchanged. With `obs-metrics` and `fhir-codec` merged, every prior "hold until obs-metrics/fhir merges" simply
becomes **rebase onto merged `main`**.

### Lane D — `docs-console` (UI; one item left)
**Branch:** `docs-console` · **Worktree:** `MessageFoundry-docs-console` (`-Ide`)
1. **`alerts-page` (#22 remainder, S–M) — ✅ DONE pending CI: PR #420** (GUI-only, 4 files +426/−7, no api edit; closes #22 ENTIRELY on merge → retire the `alerts-page` wt; stale `docs-console` wt also cleanable). Thin PySide6 **Alerts** page (`console/alerts_page.py`) consuming
   the merged `GET /alerts/rules` (#22b), replacing `PlaceholderPage('Alerts')`; wire into `console/shell.py`.
   Fold the ADR-0014 alert-rule view/test in. **Fired-alert-history is OUT of scope** (separate engine work). No
   gate, **no `api/app.py` edit** (read-only consume). `QT_QPA_PLATFORM=offscreen`; GUI calls the API client only
   (§4 one-way rule). **On merge, retire the `docs-console` worktree.**

### Lane B — `connectors` (serialized; owns the connector registry surface + `pyproject.toml` deps + `parsing/__init__.py`)
**Branch:** `connectors` · **Worktree:** `MessageFoundry-connectors`
`fhir-codec` (#20) is **merged** and no longer leads. Remaining items rebase onto its merged `pyproject.toml`
deps block + `parsing/__init__.py` re-export + `parsing/fhir/`. Internal order (value-ranked; each rebases onto
the prior on the shared `transports/base.py`, `transports/__init__.py`, `config/models.py`, `pyproject.toml`,
`tests/conftest.py`, `docs/CONNECTIONS.md`, `docs/FEATURE-MAP.md`, `parsing/__init__.py`):

1. **`xml-accessor` (#31, S) — ✅ DONE pending CI: PR #422** (`defusedxml>=0.7.1` landed — locked hashes match the coordinator vet; confined to `RawMessage`; 7 files; all XXE/DTD/billion-laughs vectors raise; retire the `xml-accessor` wt on merge). Hardened `RawMessage.xml()` accessor **only**, in
   `parsing/message.py`. Adds **`defusedxml`** to `[project].dependencies` + re-lock (`uv lock`/`uv export`).
   Touches `parsing/message.py`, `pyproject.toml`, `requirements.lock`, `uv.lock`,
   `tests/test_payload_agnostic_ingress.py`, `docs/adr/0004-payload-agnostic-ingress.md`, `docs/BACKLOG.md`. **No
   new ADR** (ADR 0004 §"To resolve" #1 pre-decided it). Rebases onto merged `main`. **Deliberately does NOT touch**
   `parsing/__init__.py` (RawMessage already exported) or `config/models.py` (`ContentType.XML` already exists) —
   keep it confined to `RawMessage` so it stays off the connector-shared claims; **adds no conftest fixture**.
   **DEFER** the `parsing/xml/` `XmlMessage` + lxml/XSD/`[xml]` extra to a real namespace-heavy SOAP/CDA feed.
2. **`rest-soap-source` (#7, XL) — On-trigger.** Inbound SOAP/REST listener in `transports/` (not `api/`). Gated on
   **ADR 0023** (sync-response seam vs. staged pipeline + ACK-on-receipt + count-and-log; separate host/port/TLS/auth
   posture; fail-closed allowlist). The **FHIR server facade** rides this same ADR 0023 + listener. *(Outside the
   value-reviewed set; listed for Lane B serialization context.)*
3. **`x12-strict` (#32, S) — On-trigger.** Opt-in `[x12]` strict IG-validation tier completing ADR 0012's deferred
   SEF validator: NEW `parsing/x12/validate.py` + `parsing/x12/ack.py` (997/999) + test; **lazy** function-local
   `pyx12` import (mirror `validate.py`'s lazy hl7apy). Touches `parsing/__init__.py` + `pyproject.toml` (the
   Lane-B-owned files that bar a separate worktree), `parsing/x12/__init__.py`, `parsing/x12/peek.py`,
   `docs/adr/0012-x12-edi-codec.md`. **No new ADR** (ADR 0012 §Resolved #2 pre-authorized `[x12]`). **Do NOT wire
   into `wiring_runner.py`/`dryrun.py`** — on-demand in a Handler against `RawMessage` (ADR 0012 zero-routing-edit
   invariant). Gate: **real-feed demand** (partner conformance / 997-999) + **dep-vet `pyx12`** (sole runtime dep
   `defusedxml` — **shared with #31**; coordinate the floor; confirm bundled IG-map coverage vs. partner guides).
4. **`email` (#23, M) — On-trigger; SMTP-SEND HALF ONLY.** Build `transports/email.py` (SMTP **destination**) — a
   near-free parity tick reusing `send_plain_email`. Gated on **ADR 0024** (not authored). **The IMAP/POP source +
   OAuth2/XOAUTH2 half is trimmed** — do **not** build it until a real mailbox-ingest feed exists (it carries the
   entire M365/Google token-refresh maintenance tail; see §G).
5. **`dicom` (#24, L) — On-trigger (imaging feed).** Imaging connector + codec. **Build DICOMweb (HTTP) first, not
   classic DIMSE** — STOW-RS/QIDO-RS/WADO-RS over HTTP **reuses the merged FHIR/REST `rest.py` + TLS stack**
   (`transports/dicom.py` as a DICOMweb destination/poller), keeping the heavyweight DIMSE upper-layer (C-STORE/
   C-FIND/C-MOVE SCP via `pynetdicom`) as a *later* sub-item only if a feed truly needs DIMSE. A pure
   `parsing/dicom/` codec wraps **`pydicom`** (BSD, offline) behind a `messagefoundry[dicom]` extra — the
   `parsing/x12`/`parsing/fhir` "tolerant core, on-demand against `RawMessage`" pattern (DICOM is **binary** →
   payload-agnostic ingress as `RawMessage`; never pushed through the pipeline; no `wiring_runner`/`dryrun` edit).
   Touches the connector-shared files (`transports/base.py`, `transports/__init__.py`, `config/models.py`
   `ConnectorType.DICOM`, `pyproject.toml` `[dicom]` extra, `tests/conftest.py`, `docs/CONNECTIONS.md`,
   `docs/FEATURE-MAP.md`) + `parsing/__init__.py`. **Gate: ADR 0025 authored + Accepted** (DICOMweb-vs-DIMSE
   scope; binary-payload handling; the `[dicom]` deps) **+ a real radiology/imaging feed.** **Dep-vet `pydicom`**
   (and `pynetdicom` only if DIMSE is pursued). Highest-effort connector for the narrowest audience — last in the
   value-ordered queue; do not pull forward without an actual imaging feed.

> **Lane B never runs two items at once.** With #20 merged, **`xml-accessor` (#31) is the only NOW-buildable Lane B
> item**; everything else is on-trigger and queues in **value order**: `rest-soap-source` #7 → `x12-strict` #32 →
> `email` #23 (SMTP) → **`dicom` #24** (last — biggest surface, narrowest audience). **`jms` #25 is declined — §G**
> and not on the queue.

### Lane S — `store-eventlog` (SOLE owner of the four store-hot files + `pipeline/retention.py`; serialized)
**Branch:** `store-eventlog` · **Worktree:** `MessageFoundry-store-eventlog` (`-Sqlserver`)
Owns every edit to `store/store.py`, `store/base.py`, `store/postgres.py`, `store/sqlserver.py`. With `obs-metrics`
merged, any Lane S item **rebases onto merged counter-reads**. Internal order (by readiness):

1. **`eventlog` (#16, M) — On-trigger; DOWNSCOPED (cull, §G).** Corepoint event-log parity, **ADR 0021 only +
   a lightweight structured connection-error event log.** Drive **ADR 0021** (inbound ACK/NAK "Response Sent" —
   twin of ADR 0013's outbound capture; Proposed) to Accepted; extend the `0013-query-response-orchestration`
   `response` table with a `kind` discriminator (+ `ack_code`/`ack_phase`), reusing its cipher/purge machinery.
   Add a **metadata-only** connection-error event row for the genuine gap — **pre-message failures with no
   `message_id`** (bad framing, TLS-accept failure, peer reset, allowlist refuse). **The ADR-0020 raw-frame
   `protocol_trace` table is DROPPED** (new raw-PHI-at-rest tier, no customer pull — bad idea, §G). **Single-owner
   of `pipeline/retention.py`.**
2. **`per-conn-retention` (#34, M) — On-trigger (DEFER).** Per-connection retention/pruning over the global
   `[retention]` lever. **MUST join Lane S** — every modified file is Lane-S-owned/contended; a separate worktree
   is impossible. Touches `pipeline/retention.py` (**single-owned by #16 — the collision flag**), all four store
   backends, `config/settings.py`, `config/wiring.py`, `docs/CONFIGURATION.md`, `docs/PHI.md`; NEW test + **ADR
   0027**. **Slots AFTER `eventlog`** (rebase onto its `retention.py` + store rewrite). ADR 0027 decides: (a) the
   override is a **`[retention.connections.<name>]` settings overlay** (NOT a Router/Handler knob, NOT a built
   "channel" object — keep it transport-adjacent **data** per the CLAUDE.md guardrail; settings-only keeps it **off**
   the contended `config/models.py`); (b) leader/audit semantics. **Reliability:** the per-connection cutoff must
   **AND** with the existing "never purge an in-flight body" predicate; three-backend purge-SQL parity test required.
   **Run #33 (config-UX review) first** so its conventions shape the overlay surface (§F).
3. `webauthn` (#11/WP-14b, L) — On-trigger. *(Outside the value-reviewed set; unchanged: off-loopback exposure
   trigger + ADR 0002 WP-14b amendment authored + Accepted.)*
4. `per-key` (#3, XL) — On-trigger. *(Outside the value-reviewed set; unchanged: NEW per-key ADR + workload trigger.)*

> **Lane S serialization:** `eventlog → per-conn-retention (#34) → webauthn → per-key`. #34 depends on eventlog's
> `retention.py`/store rewrite, so it is serialized directly behind it.

### Lane X — `ci-infra` (test-harness only; reopened residual)
**Branch:** `ci-infra` · **Worktree:** `MessageFoundry-ci-infra`
1. ✅ `ci-py311-finalizer` (#17) — PRs #409 + #414 merged (teardown finalizer + shared-session loop).
2. **`ci-py311-residual` (#17, Lane X.2) — ✅ DONE pending required py3.13 legs: PR #423** (`continue-on-error` py3.11-advisory + off-by-default `MEFOR_PY311_QUARANTINE` lever; `conftest.py` + `ci.yml` only; **do NOT re-promote py3.11 to required** — false-green hazard; retire the `ci-py311` wt on merge). The shared-loop fix **reduced but did not eliminate** the
   intermittent aiosqlite↔asyncio cross-loop lost-wakeup. **py3.11 is now advisory**, not required (py3.13 ×3 is the
   gate). Continue the residual fix; re-promote py3.11 to required only once provably green across repeated soak
   runs. (Stale **BACKLOG #17** "✅ RESOLVED" → "⚠️ REOPENED / advisory" already reconciled by the coordinator
   2026-06-19 — Lane X does **not** edit BACKLOG #17.) Touches `tests/conftest.py` + the CI marker only — isolated.

### Lane L — `decisions` (no build, `-NoInstall`)
**Branch:** `decisions` · **Worktree:** `MessageFoundry-decisions` (`-NoInstall`)
1. ~~`decline-visual-authoring` (#26)~~ ✅ · ~~`decline-serial-astm` (#27)~~ ✅ (PR #411).
2. **`config-ux-review` (#33, M) — ✅ DONE (review delivered): PR #421** (docs-only; 31 confirmed/3 refuted; candidates A–E recorded in BACKLOG OUT of #33; ADR 0027/#34 must decide dotted-section env-reachability — see the coordinator ledger; do NOT retire `config-ux` wt yet — #13 "Then" lives there). A **review/design item, no build** — output is NEW
   `docs/research/config-ux-review.md` (uncontended dir) + an append-only `docs/BACKLOG.md` edit. Reviews the two
   config surfaces (service settings vs. graph values) + the CWD/anchor footgun. **No ADR gates it; an ADR is a
   possible OUTPUT.** **Time-box + date-stamp.** Top finding to capture: the split-anchor inconsistency
   (`environments/` anchorable via `[environments].base_dir`/`--project-root`, but `messagefoundry.toml` resolves
   bare CWD and `codesets/` under `--config`). **Scope guard:** any *acted-on* recommendation becomes a SEPARATE
   backlog item with real contention — keep that OUT of #33. **The hazard is influence-sequencing, not
   merge-collision:** circulate findings **before** #34 / secretprovider / any new config-knob author finalizes
   `[section]`/key shapes (§F).
3. `licensing-counsel` (#13, S) — Then; engagement OPENED (PR #406). Counsel ratifies `docs/DUAL_LICENSING_PLAN.md`
   + `COMMERCIAL-LICENSE.md` + ADR 0017 #6. Doc-only; `docs/COUNSEL_ENGAGEMENT_BRIEF.md` staged.

### Deferred background monitor — `update-check` (#30) — NO new worktree
1. **`update-check` (#30, M) — On-trigger (DEFER); CONSTRAINED CORE (trim, §G).** MEFOR **version**-update check as a
   background runner **cloning the `cert_expiry.py`/`retention.py` runner pattern** (cooperatively cancellable,
   `asyncio.to_thread` for any fetch, failure-isolated). **NO separate worktree** — it collides with five
   contention-matrix files (`config/settings.py`, `pipeline/engine.py`, `api/app.py`, `api/models.py`,
   `pyproject.toml`) plus `console/*` + `ide/`; it joins whichever owning lane is live at trigger time, and hands
   the thin `console/status.py`+`console/client.py` feed + `ide/src/home.ts` banner to Lane D. **Gate: a NEW ADR
   settling off-box egress posture FIRST** — off-by-default; release-feed vs. internal-mirror vs. **fully air-gapped
   no-network**; environment-clamped on the `[ai]` OFF→PHI-safe precedent; RBAC + audit on any outbound check.
   **Owner call: is a live-egress auto-check even wanted, or only a passive "pinned-vs-current lock diff" with no
   network?** (recommended default = the no-network diff). **Trimmed:** the **auto dependency-vulnerability scan**
   half is NOT built — CI's DEP-1 audit + the hash-locked `requirements.lock` already cover dep staleness; do not
   build a second runtime mechanism. **Dep posture:** prefer **no new dep** (stdlib `urllib`, no-redirect +
   https-only + host-allowlist, like `alert_sinks` `WebhookTransport`); **never** add requests/httpx; **never**
   introduce an auto-install/lock-mutating path (advisory-only). Rides merged `obs-metrics` #21 (the `/status`
   signal it extends) + the #5 AlertSink (`update_available` event — change the Protocol + `LoggingAlertSink` +
   `NotifierAlertSink` + `_subject` + `_ALERT_EVENT_TYPES` in lockstep).

---

## The coordinator lane (drives Plan 3; builds nothing)

**Branch:** `coord-plan3` · **Worktree:** `MessageFoundry-coord-plan3` (`-NoInstall` — no venv; carries this plan).
One coordinator window, UltraCode-enabled, **builds no product code**. It owns:

- **This plan + shared-memory single-writer.** Keeps `MULTISESSION-PLAN-3.md` current as items land (flips
  statuses, retires lanes), and is the **sole writer** of the shared AI project memory — records every ADR-status
  change and gating decision *before* a worker lane acts on it. Also reconciles the **stale BACKLOG #17** ("✅
  RESOLVED" → "REOPENED / advisory") and updates the [`../BACKLOG.md`](../BACKLOG.md) plan reference.
- **ADR authoring + ratification.** Authors/drives, as each item approaches: **ADR 0021** (eventlog "Response
  Sent" + the metadata-only connection-error event log) Proposed→Accepted; **ADR 0027** (per-connection
  retention); the **off-box-egress ADR** for `update-check` #30; **ADR 0023** (HTTP listener), **0024** (email);
  the **per-key ADR** (#3, none exists). **ADR 0020's raw-frame tier is NOT authored — dropped (§G).**
- **Dep-vets.** `defusedxml` (gates #31, NOW) and `pyx12` (gates #32) — verify reputability/advisory posture/hash
  before any worker adds the dependency (§7 guardrail).
- **Merge ordering + worktree scaffolding/teardown.** Enforces the §3 sequencing across the small NOW board,
  creates/retires worker worktrees (§5), and owns the owner-call tracking (#33 scope, #30 "is live-egress even
  wanted?", #13 counsel).

**Coordinator day-1 priorities (longest lead-time first):** (1) **dep-vet `defusedxml`** → unblocks Lane B `#31`
NOW; (2) **scope `config-ux-review` #33** (owner call) → it should circulate before any config-knob lane; (3)
**owner call on `update-check` #30** + author the off-box-egress ADR; (4) **drive ADR 0021** for when `eventlog`
is triggered. Everything else is on-trigger.

> *Coordinator UltraCode note:* runs a short Workflow for any non-trivial coordination act (authoring an ADR,
> composing a cross-file merge-order decision); solo for routine status flips and memory releases.

---

## C. Updated phasing table

```
PHASE      LaneD docs-console    LaneB connectors        LaneS store-eventlog    LaneSec secrets     LaneX ci-infra        LaneL decisions
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
DONE ✅    user-guide #19        fhir-codec #20 (built;  —                       —                   ci-py311 #409+#414    declines #26/#27
           Dead-Letters #22a     ADR 0022 Accepted)                                                  (partial+shared-loop) obs-metrics #21 ✅
           /alerts/rules #22b                                                                                              (Lane A retired)
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
NOW        alerts-page (#22      xml-accessor (#31, S;   —                       —                   ci-py311-residual     —
           remainder; consume    defusedxml; do early)   (await triggers)        (await Then/trig)   (#17 advisory; X.2)   OWNER+COUNSEL
           /alerts/rules)                                                                                                  ENGAGEMENT (#13)
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
NEXT       (merged → retire wt)  —                       —                       —                   (re-promote 3.11      config-ux-review
                                                                                                      only when green)     (#33 NEW, FIRST,
                                                                                                                            review-only)
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
THEN       —                     —                       —                       least-priv-svc      —                    licensing-counsel
                                                                                  secretprovider                           (#13 doc only)
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
ON-TRIG    update-check #30      rest-soap-source #7     eventlog #16 (0021 +    approve-step-up #8  —                    —
           UI feed (to Lane D)   x12-strict #32           error-event log only)
                                 email #23 (SMTP only)    per-conn-retention #34
                                 dicom #24                webauthn #11 · per-key #3
                                 *SERIALIZED*             *SERIALIZED*
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
DECLINED   —                     jms #25 (§G)            —                       —                   —                    git-offering #18 (§G)
```

**Do NOT staff now (on-trigger / deferred):** `rest-soap-source` #7, `x12-strict` #32, `email` #23 (SMTP-only when
triggered), `eventlog` #16, `per-conn-retention` #34, `webauthn` #11, `per-key` #3, `approve-step-up` #8,
`update-check` #30. Each is gated on a not-yet-authored/-Accepted ADR, a real feed/demand/exposure, or an owner call.

---

## D. Contention-matrix additions (NEW/changed rows only)

All resolve into an **existing lane** — **no new worktree** is justified for any new item.

| File | Items (new italic) | Resolution |
|---|---|---|
| `parsing/message.py` | *xml-accessor (#31)* | Lane B; sole toucher (fhir-codec used `parsing/fhir/`). Kept off `parsing/__init__.py`. |
| `pyproject.toml` (deps) | obs-metrics ✅, ci-py311 ✅, fhir-codec ✅, *xml-accessor (#31)*, *x12-strict (#32)*, #7/#23 | Lane B, serialized. #31 rebases onto merged `main` + **owns the `defusedxml` line**; #32 rebases onto it. |
| `parsing/__init__.py` | fhir-codec ✅, *x12-strict (#32)*, *dicom (#24)* | Lane B, serialized. #31 deliberately does NOT touch it. |
| `parsing/x12/` (`validate.py`/`ack.py`/`peek.py`/`__init__.py`) | *x12-strict (#32)* | Lane B; new/self-owned. No pipeline wiring (ADR 0012 invariant). |
| `parsing/dicom/` + `transports/dicom.py` | *dicom (#24)* | Lane B; new (pydicom codec + DICOMweb destination over the merged `rest.py`). Binary → on-demand against `RawMessage`, no pipeline wiring. |
| `transports/base.py` · `transports/__init__.py` · `config/models.py` · `tests/conftest.py` · `docs/CONNECTIONS.md` · `docs/FEATURE-MAP.md` | …connectors #7/#23…, *dicom (#24)* | **Lane B, serialized.** #24 takes the connector-shared surface last in the queue, rebasing onto whatever Lane B item preceded it. |
| `pipeline/retention.py` | eventlog (#16), *per-conn-retention (#34)* | **Lane S. COLLISION FLAG:** was #16-single-owned; now multi-claimed. **#34 sequenced AFTER #16, rebases onto its rewrite.** |
| `store/{store,base,postgres,sqlserver}.py` | obs-metrics ✅, eventlog, webauthn, per-key, *per-conn-retention (#34)* | Lane S, serialized. #34 threads per-connection cutoff into all three backends' purge SQL (parity test). |
| `config/settings.py` | …existing…, *per-conn-retention (#34)*, *update-check (#30)* | Lane S owns #34's `[retention]` overlay; #30 (deferred) takes it in its owning lane at trigger. |
| `config/wiring.py` | per-key, eventlog, *per-conn-retention (#34)* | Lane S, serialized. |
| `console/{status,client}.py` · `ide/src/home.ts` | console-pages (Lane D), *update-check (#30)* | **Lane D** sole `console/*`/`ide/` editor — #30's thin UI feed handed to Lane D. |
| `docs/research/config-ux-review.md` | *config-ux-review (#33)* | Lane L; NEW file, untouched dir — uncontended. |

> **Settings-overlay preference (#34):** keep the per-connection override a `[retention.connections.*]` **settings**
> key, NOT a `config/models.py` `ConnectionSpec` field — that keeps #34 off the most heavily contended config file.

---

## E. Concrete "staff now" recommendation

With the headline items merged, the active board is **small**. Staff exactly these (the three build lanes are
mutually contention-free and run in parallel):

**Build lanes — NOW:**
1. **Lane D `docs-console`** — the **Alerts GUI page** (#22 remainder). No gate, no API edit. Closes #22 entirely;
   then retire the worktree.
2. **Lane B `connectors`** — **`xml-accessor` (#31, S)**. Only NOW-buildable Lane B item; rebases onto merged
   `main`; adds `defusedxml` + re-lock; confined to `RawMessage.xml()`. Do early so it owns the shared `defusedxml`
   line for #32.
3. **Lane X `ci-infra`** — **`ci-py311-residual` (#17 / X.2)**: keep py3.11 advisory, drive the residual cross-loop
   fix, reconcile stale BACKLOG #17.

**Review/decision lane — NEXT (no build, no contention; runs alongside the above):**
4. **Lane L `decisions`** — **`config-ux-review` (#33)** FIRST/early (review-only); circulate findings before any
   config-knob lane sets its `[section]` shapes. Keep the **`licensing-counsel` (#13)** engagement open (PR #406).

**Coordinator, day 1 — parallel owner-calls / ADRs / dep-vets that gate the next wave:**

| Action | Type | Gates |
|---|---|---|
| Dep-vet **`defusedxml`** (PSF, pure-Python, zero runtime deps; verify advisory posture + hash) | dep-vet | `xml-accessor` #31 (NOW) |
| Owner call: scope **`config-ux-review` #33** | owner | #33 (review) |
| Owner call: is a **live-egress update-check** even wanted (vs. no-network lock diff)? + author the **off-box-egress ADR** | owner + ADR | `update-check` #30 (DEFER) |
| Drive **ADR 0021** Proposed → Accepted (and design the metadata-only error-event log) | ADR | `eventlog` #16 (on-trigger; 0020 dropped) |
| Author **ADR 0027** (per-connection retention; settings-overlay vs. ConnectionSpec; leader/audit) | ADR | `per-conn-retention` #34 |
| Dep-vet **`pyx12`** (BSD-3; IG-map coverage vs. partner guides; dep `defusedxml` floor coordinated w/ #31) | dep-vet | `x12-strict` #32 (on feed) |
| Author **ADR 0023** (HTTP listener) / **0024** (email) / **0025** (DICOM — DICOMweb-vs-DIMSE, binary payload, `[dicom]` deps) | ADR | #7 / #23 SMTP / #24 (on feed) |
| Dep-vet **`pydicom`** (BSD, offline; `pynetdicom` only if DIMSE is pursued) | dep-vet | `dicom` #24 (on imaging feed) |

**Do NOT spin up:** Lane A `observability` (retired); a separate worktree for #30/#31/#32/#33/#34 (all bind to an
existing lane); Lane Sec / Lane S / on-trigger Lane B connectors (await triggers/ADRs).

```powershell
# NOW only. Item-specific worktree names — the v0.2 lane worktrees
# {connectors,docs-console,ci-infra,decisions} still exist on disk and new.ps1 throws
# on a collision. Paste-ready kickoff prompts: PLAN-3-LANE-HANDOFFS.md.
scripts\worktree\spawn.ps1 -Name alerts-page  -Ide          # Lane D — Alerts page (#22 remainder), then retire
scripts\worktree\spawn.ps1 -Name xml-accessor               # Lane B — xml-accessor #31 (rebase onto merged main)
scripts\worktree\spawn.ps1 -Name ci-py311                   # Lane X — ci-py311-residual (#17 / X.2)
scripts\worktree\new.ps1   -Name config-ux    -NoInstall    # Lane L — config-ux-review #33 + #13 engagement
# Coordinator: already created (MessageFoundry-coord-plan3) — open it; do NOT new.ps1.
```

---

## F. Shared-leverage callouts

- **`parsing/` codec bundle — one `defusedxml` adoption serves three items.** `xml-accessor` (#31) lands the
  hardened-XML door (`RawMessage.xml()` via `defusedxml`, forbid-DTD/external/entities ON; raise-don't-parse on
  DOCTYPE so a Handler routes to FILTERED/ERROR — mirror `soap.py`). **FHIR-XML (#20, merged) reuses that
  substrate** → sequence #31 right after #20. **`x12-strict` (#32) shares the same `defusedxml` dep** (pyx12's sole
  runtime dep) → **#31 lands and owns the dep line; #32 rebases onto it** (net new transitive weight ≈ zero). Keep
  the DEFERRED `lxml`/XSD/`signxml`/`[xml]` layer OUT (`defusedxml` does not cover `lxml`; `lxml` is a real-feed
  -gated compiled dep with its own CVE history).
- **engine-emits-a-signal monitor — #30 clones `cert_expiry`/`retention`, rides #21 + #5.** `update-check` is not
  new infrastructure; the engine-side advisory (one AlertSink event + one `/status` field) is canonical, and the two
  UIs stay thin per the one-way rule. The AlertSink Protocol + both sinks + `_subject` + `_ALERT_EVENT_TYPES` must
  change in lockstep.
- **per-connection config surface — #33 before #34 (influence, not merge-gate).** Circulate `config-ux-review`'s
  conventions before #34 finalizes its `[retention.connections.*]` overlay (and before secretprovider's `[secrets]`
  surface). #33 blocks nothing at the file level, so the hazard is rework if it lands late.

---

## G. Culled & trimmed items (2026-06-19 bad-idea review)

Recorded as decline/scope markers in [`../BACKLOG.md`](../BACKLOG.md).

| Item | Action | Rationale |
|---|---|---|
| **#18** Bundle an OSS git offering | **DECLINE (no build)** | An embedded git service contradicts the loopback-default minimal-attack-surface posture + bloats the thin AGPL wheel, for zero demand. The valuable half (BYO-git + IDE "Set Up Version Control") already ships. |
| **#25** JMS connector | **DECLINE (no build)** | Java/JNDI interop, near-zero pull for a Python on-prem HL7 engine; pulls against the no-external-broker reliability invariant. If broker interop ever becomes real, it's a fresh ADR + a thin `aio-pika` AMQP source/dest — not a scheduled item. |
| **#16** ADR-0020 raw-frame `protocol_trace` | **DROP the raw tier; keep ADR 0021** | The raw-frame table is the most sensitive new raw-PHI-at-rest surface in the backlog, for a diagnostic with no customer pull. Replace with a metadata-only structured connection-error event log; keep the cheap, PHI-safe ADR-0021 "Response Sent" capture. |
| **#23** Email — IMAP/POP + OAuth half | **TRIM (SMTP-send only)** | SMTP-send is a near-free parity tick; the IMAP/POP + OAuth2 source carries the entire M365/Google maintenance tail and is speculative — build only on a real mailbox feed. |
| **#30** Auto dependency-scan + dual UI | **TRIM to a constrained version-check core** | Dep staleness is already covered by CI DEP-1 + the hash-locked lock; don't build a second runtime mechanism. Keep only the off-by-default (prefer no-network) MEFOR-version advisory. |
