# Plan 3 Multisession — Lane Kickoff Prompts

Companion to [`MULTISESSION-PLAN-3.md`](MULTISESSION-PLAN-3.md) (the plan of record). These are the
**paste-ready first-prompt handoffs** for the one **coordinator** (its worktree **already exists**:
`MessageFoundry-coord-plan3`) and the **4 NOW worker lanes**. Each begins with `ultracode` to enable
UltraCode (it's session-only), and each tells the new window to **spin up its own git worktree**
before doing any work (the coordinator opens its existing one).

## How to use

Open a **new VS Code / Claude window per lane** and paste the matching prompt — each worker prompt
instructs the session to create its own worktree (`scripts\worktree\new.ps1 -Name <lane> [flags]`: a
sibling `..\MessageFoundry-<lane>` directory on branch `<lane>` off `origin/main`, with its own
`.venv`) and work only in it. The coordinator prompt opens the **already-existing**
`MessageFoundry-coord-plan3` worktree instead — it does **not** run `new.ps1`.

> If you'd rather have a worker window open **already inside** the worktree, run
> `scripts\worktree\spawn.ps1 -Name <lane> [flags]` first (it creates the worktree **and** opens a VS
> Code window in it), then paste the prompt there.

**Start order:** the coordinator + all **4 NOW worker lanes can start in parallel**. The only
sequencing is on-trigger / day-1: **#31 (xml-accessor) must merge before any future #32**
(`x12-strict`) conftest/pyproject work, and the **coordinator must dep-vet `defusedxml` before #31
adds it**.

**Cross-cutting rules** (baked into every prompt): each session works only in its own worktree
(never edits a sibling); branch → PR (never push to `main`); stage explicit paths (a hook blocks
`git add -A`); **only the Coordinator writes project memory** (workers read only); every PR runs the
gate (`ruff check` + `ruff format --check`, `mypy messagefoundry` strict, `pytest` with
`QT_QPA_PLATFORM=offscreen` for console tests). **Plan-3 specifics:** the v0.2 board has **collapsed**
— #19, #20, #21, #22a, #22b, #26, #27 are merged and **ADR 0022 is Accepted** — and the backlog was
**culled**: **#18 and #25 declined**, **#16's ADR 0020 raw-frame tier dropped**, **#23 narrowed to
SMTP-only**, and **#30 (update-check) constrained** pending an owner call + off-box-egress ADR.

**Worktree naming:** the v0.2 worktrees `{connectors, docs-console, ci-infra, decisions}` **still exist
on disk**, and `new.ps1` throws if the path already exists — so Plan-3 lanes use **collision-free,
item-specific names** (`xml-accessor`, `alerts-page`, `ci-py311`, `config-ux`). The coordinator
**retires the stale v0.2 worktrees** (via `scripts\worktree\remove.ps1`) once their PRs are confirmed
merged to `origin/main`.

**Not started now:** Lane S (`store-eventlog` **#16**, ADR 0021 only — the raw-frame tier is dropped)
and **per-connection retention #34**; the on-trigger Lane B connectors (**#7**, **#32** `x12-strict`,
**#23** email **SMTP-only**, **#24** DICOM); and the **#30** update-check (owner call + off-box-egress
ADR first). BACKLOG **#28 / #29** (load + throughput) are run **ad hoc** for a fresh baseline.
**#18 and #25 are DECLINED.**

---

## Coordinator — coord-plan3 (drives Plan 3; builds nothing)

> Create command: Open the existing worktree C:\Users\Scott\Code\MessageFoundry-coord-plan3 (branch coord-plan3) — already carries Plan 3; do NOT run new.ps1.

```
ultracode. You are the COORDINATOR for the MessageFoundry Plan-3 effort — you build NO product code. Your worktree ALREADY EXISTS: open C:\Users\Scott\Code\MessageFoundry-coord-plan3 (branch coord-plan3, which carries this plan) and do ALL your work there — DO NOT run scripts\worktree\new.ps1 (it throws on an existing path), and never edit files in another worktree.

Then read docs/releases/MULTISESSION-PLAN-3.md — especially "## The coordinator lane (drives Plan 3; builds nothing)" and §E "staff now" — plus CLAUDE.md. (Plan 2, MULTISESSION-PLAN-v0.2.md, is the superseded historical record.) You own:
- ALL project-memory writes (single-writer; workers read memory, never write it). Record every ADR-status change + gating/dep-vet decision in memory BEFORE a worker lane acts on it.
- Keeping MULTISESSION-PLAN-3.md current as items land (flip statuses, retire lanes); and reconcile the STALE BACKLOG #17 — docs/BACKLOG.md still reads "✅ RESOLVED 2026-06-19" but the py3.11 cross-loop lost-wakeup is only mitigated → re-mark it REOPENED / advisory and update the plan reference.
- ADR authoring + ratification, as each item approaches: ADR 0021 (eventlog "Response Sent" + the metadata-only connection-error event log) Proposed→Accepted; ADR 0027 (per-connection retention); the off-box-egress ADR for update-check #30; ADR 0023 (HTTP listener); 0024 (email); 0025 (DICOM); the new per-key ADR (#3, none exists). DO NOT author ADR 0020's raw-frame tier — it is DROPPED (§G).
- Dep-vets (verify reputability/advisory posture/hash per §7 BEFORE any worker adds the dep): defusedxml → gates xml-accessor #31 NOW; pyx12 → gates x12-strict #32; pydicom → gates dicom #24.
- Merge ordering across the small NOW board; owner-call tracking: #33 (config-ux-review) scope, #30 ("is a live-egress update-check even wanted vs a no-network lock diff?"), #13 (licensing counsel, PR #406).
- Worktree teardown: once their PRs are confirmed merged to origin/main, RETIRE the leftover v0.2 worktrees MessageFoundry-{connectors,docs-console,ci-infra,decisions} via scripts\worktree\remove.ps1 (this also frees those names — but Plan-3 workers use new, collision-free, item-specific names anyway).

DAY-1 PRIORITIES (longest lead-time first): (1) dep-vet defusedxml → unblocks Lane B xml-accessor #31 NOW; (2) owner call to scope config-ux-review #33 (circulate before any config-knob lane sets its [section] shapes); (3) owner call on update-check #30 + author the off-box-egress ADR; (4) drive ADR 0021 Proposed→Accepted for when eventlog is triggered (and design the metadata-only error-event log).

Run a short Workflow for any non-trivial coordination act (authoring an ADR, composing a cross-file merge-order decision); go solo for routine status flips and memory releases. START by dep-vetting defusedxml and recording the day-1 gating decisions in project memory. Discipline: work on branches off origin/main and open PRs — never push to main; stage EXPLICIT paths (a hook blocks git add -A); you are the SOLE writer of project memory; gate every PR with ruff check + ruff format --check, mypy messagefoundry (strict), and pytest (QT_QPA_PLATFORM=offscreen for console tests).
```

---

## Lane B — connectors: xml-accessor (#31)

> Create command: scripts\worktree\new.ps1 -Name xml-accessor

```
ultracode. You own Lane B's `xml-accessor` item (BACKLOG #31). Spin up your own git worktree first: run `scripts\worktree\new.ps1 -Name xml-accessor` (creates ..\MessageFoundry-xml-accessor on branch `xml-accessor` off origin/main + its own .venv) and do all your work in that worktree, using its .venv — never edit files in another worktree. (Use this new collision-free name: the leftover v0.2 `MessageFoundry-connectors` worktree still exists on disk and new.ps1 throws if the path exists.) Rebase onto current origin/main before you commit.

Read docs/releases/MULTISESSION-PLAN-3.md (your lane — §B Lane B item 1, §F shared-leverage) + CLAUDE.md.

Task — BACKLOG #31: add a hardened `RawMessage.xml()` accessor ONLY, in messagefoundry/parsing/message.py (the `RawMessage` class, ~L425). Back it with `defusedxml` with forbid_dtd / forbid_external / forbid_entities ON — raise-don't-parse on a DOCTYPE so a Handler can route the message to FILTERED/ERROR — MIRRORING the existing stdlib-xml hardening in messagefoundry/transports/soap.py (`_assert_well_formed_fragment`: external entities OFF, DOCTYPE rejected outright). Closes the XXE footgun ADR 0004 flagged and is the shared hardened-XML substrate the merged FHIR-XML (#20) reuses. Add `defusedxml` to [project].dependencies in pyproject.toml and re-lock (`uv lock` then `uv export` -> requirements.lock; uv.lock also updates). Write a test in tests/test_payload_agnostic_ingress.py (well-formed parse succeeds; a DOCTYPE / external-entity / billion-laughs payload RAISES, not parses). Update docs/adr/0004-payload-agnostic-ingress.md (§"To resolve" #1, which pre-decided `.xml()`) and docs/BACKLOG.md to reflect it shipped.

CONFINE strictly to `RawMessage`: do NOT touch messagefoundry/parsing/__init__.py (RawMessage is already exported) or messagefoundry/config/models.py (ContentType.XML already exists) — that keeps you off the connector-shared claims and off the contended config file. Add NO conftest fixture. DEFER the parsing/xml/ XmlMessage + lxml/XSD/`[xml]` extra to a real namespace-heavy SOAP/CDA feed (defusedxml does not cover lxml). NO new ADR (ADR 0004 §"To resolve" #1 pre-decided this).

GATE/DEPENDENCY: the coordinator dep-vets `defusedxml` (PSF, pure-Python, zero runtime deps; advisory posture + hash verified) BEFORE you add it — confirm it's cleared with the coordinator, then add it to pyproject.toml and re-lock.

UltraCode: one Workflow — ground in soap.py's hardening pattern + ADR 0004, build the smallest layer, adversarially verify the XXE/DTD/entity-expansion payloads all RAISE (never resolve a network/file URL, never expand entities) and that nothing outside RawMessage moved. Gate every PR: ruff check + ruff format --check, mypy messagefoundry (strict), pytest with QT_QPA_PLATFORM=offscreen for console tests. Branch -> PR (never push to main); stage explicit paths (a hook blocks `git add -A`); workers never write project memory (the coordinator is the single writer) — read only.
```

---

## Lane D — docs-console (Alerts page, #22 remainder)

> Create command: scripts\worktree\new.ps1 -Name alerts-page -Ide

```
ultracode. You own Lane D (docs-console) — the LAST #22 piece. Spin up your own git worktree first: run `scripts\worktree\new.ps1 -Name alerts-page -Ide` (creates ..\MessageFoundry-alerts-page on branch `alerts-page` off origin/main + its own .venv + npm) and do ALL your work in that worktree, using its .venv — never edit a sibling worktree (the older MessageFoundry-docs-console leftover is NOT yours; new.ps1 throws on a name collision, which is why this lane uses `alerts-page`). Console tests need QT_QPA_PLATFORM=offscreen.

Read docs/releases/MULTISESSION-PLAN-3.md (Lane D, §B "alerts-page (#22 remainder)") + CLAUDE.md.

Task — BACKLOG #22 remainder: build a thin PySide6 Alerts page that consumes the ALREADY-MERGED read-only endpoint `GET /alerts/rules` (#22b) and replaces the Alerts stub. This is GUI-only — NO engine work and NO api/* edit (read-only consume of an existing endpoint). Concretely:
1. NEW messagefoundry/console/alerts_page.py — an `AlertsPage(QWidget)` modeled on the sibling shipped by #22a, messagefoundry/console/dead_letters_page.py: copy its off-thread fetch/apply pattern exactly (AsyncRunner submit → `_fetch` on a worker thread does only blocking I/O → `_apply` on the main thread touches widgets; the `_loading`/`_pending` latch; `reload`/`refresh`/`stop`; an `error = Signal(str)`). It is READ-ONLY — there is no replay/action button and no PHI in this payload, so no step-up/MFA and no PHI-audit concern; you may `refresh()` on the auto-refresh tick (unlike Dead Letters). Render the AlertsConfig: a transports summary (webhook_configured, email_configured + counts, realert_seconds — note the endpoint deliberately returns NO secrets/recipients) and a table of `rules` (AlertRuleInfo: event_type, connection, min_depth, min_oldest_seconds, severity, transports, cooldown_seconds).
2. messagefoundry/console/client.py — add `alerts_rules(self) -> AlertsConfig` calling `self._get("/alerts/rules")` and `_decode(...)`; import `AlertsConfig` (and `AlertRuleInfo`) from messagefoundry.api.models. The endpoint is gated by `monitoring:read` (Permission.MONITORING_READ), like `/stats`.
3. messagefoundry/console/shell.py — REPLACE `PlaceholderPage("Alerts")` (line ~144, in the `_pages` list) with an `AlertsPage(client, poll_client=self._poll_client)` instance (mirror how `self.dead_letters` is constructed/wired ~line 135 and stopped in `closeEvent`); connect its `error` signal to `self._show_error`. `_NAV` already lists "Alerts" — keep ordering aligned with `_pages`.
4. Fold the ADR-0014 alert-rule view/test in: add a console test (tests/, QT_QPA_PLATFORM=offscreen) that drives AlertsPage against a fake/stub client returning a sample AlertsConfig and asserts the rules render; ground its shape in docs/adr/0014-alerting-rules-engine.md and the AlertsConfig/AlertRuleInfo models in messagefoundry/api/models.py.

OUT of scope: a fired-alert-history view (separate engine work). Enforce the §4 ONE-WAY rule — the console imports the API client ONLY; never import pipeline/store/transports/config (importing api/models for the Pydantic types is allowed). GUI on the main thread; all engine reads off-thread via AsyncRunner + Signal/Slot. On merge this closes #22 entirely; the coordinator retires the worktree.

UltraCode: one Workflow — ground in dead_letters_page.py + the `/alerts/rules` route in api/app.py + ADR 0014, build the smallest coherent layer, then adversarially verify (the one-way import rule holds; the read runs off the main thread and applies on it; no api/* file changed). Gate every PR: ruff check + ruff format --check, mypy messagefoundry (strict), pytest with QT_QPA_PLATFORM=offscreen for the console tests. Branch→PR (never push to main); stage EXPLICIT paths (a hook blocks `git add -A`); workers never write project memory (read only) — flag any memory/ADR need to the coordinator.
```

---

## Lane X — ci-infra (py3.11 residual, #17 / X.2)

> Create command: scripts\worktree\new.ps1 -Name ci-py311

```
ultracode. You own Lane X (ci-infra) for Plan 3. Spin up your own git worktree first: run `scripts\worktree\new.ps1 -Name ci-py311` (creates ..\MessageFoundry-ci-py311 on branch `ci-py311` off origin/main + its own .venv) and do ALL your work in that worktree, using its .venv — never edit a sibling worktree. (Do NOT reuse the leftover `MessageFoundry-ci-infra` dir — new.ps1 throws on an existing path; the Plan-3 name is `ci-py311`.)

Read docs/releases/MULTISESSION-PLAN-3.md (Lane X, item 2 `ci-py311-residual`) + CLAUDE.md.

Task — BACKLOG #17 RESIDUAL (Lane X.2). PRs #409 (teardown finalizer) + #414 (shared session loop) REDUCED but did NOT eliminate the intermittent py3.11 aiosqlite<->asyncio CROSS-LOOP lost-wakeup (it hung even a docs-only PR). py3.13 ×3 (ubuntu/win-2022/win-2025) is the REQUIRED gate; `test (ubuntu-latest, py3.11)` is now ADVISORY. scripts/soak/store_soak.py (one long-lived asyncio.run loop, no pytest, heavy concurrent aiosqlite) passes clean on py3.11 — proving this is a pytest-LIFECYCLE artifact, NOT a product defect. Continue the residual fix in tests/conftest.py (already carries `_quiesce_background_loggers_at_teardown` + `_QUIESCE_TARGETS` + `_tolerate_logging_on_closed_capture_streams`): tighten the suite-wide teardown-ordering finalizer that quiesces background-component loggers (aiosqlite worker, engine, harness monitor, starlette) before caplog teardown, and/or pin the heaviest aiosqlite-backed async tests to a session-scoped loop, or skip those tests on py3.11 only. Re-promote `test (ubuntu-latest, py3.11)` to a REQUIRED status check ONLY once it is PROVABLY green across repeated soak runs (needs a real py3.11 box to validate — do not flip the gate blind). SCOPE: tests/conftest.py + the CI marker/config ONLY — touch no product code; this is isolated from the other lanes. Do NOT edit docs/BACKLOG.md #17 ("✅ RESOLVED" -> "advisory") or write any project memory yourself — hand the BACKLOG #17 reconcile and any memory note to the COORDINATOR (workers read memory, never write it).

UltraCode: one Workflow — ground in BACKLOG.md §17 + the conftest top-of-file write-up + the soak script, build the smallest coherent change, then adversarially verify by running the py3.11 store soak + the suite repeatedly to prove the lost-wakeup is gone (a real py3.11 env is required to validate; the soak job is the meanwhile regression guard). Gate every PR: ruff check + ruff format --check, mypy messagefoundry (strict), pytest (QT_QPA_PLATFORM=offscreen for console tests). Branch -> PR (never push to main); stage EXPLICIT paths (a hook blocks `git add -A`).
```

---

## Lane L — config-ux (review: config-UX #33)

> Create command: scripts\worktree\new.ps1 -Name config-ux -NoInstall

```
ultracode. You own Lane L (config-ux) — a REVIEW/design item, NO build. Spin up your own git worktree first: run `scripts\worktree\new.ps1 -Name config-ux -NoInstall` (creates ..\MessageFoundry-config-ux on branch `config-ux` off origin/main; review/doc only, no .venv) and do all your work in that worktree — never edit a sibling worktree. (Use this NEW collision-free name, not "decisions": the v0.2 leftover worktrees still exist on disk and new.ps1 throws if the path exists.)

Read docs/releases/MULTISESSION-PLAN-3.md (Lane L, item 2) + CLAUDE.md.

Task — BACKLOG #33, config-UX review. Output is exactly two things: (1) a NEW date-stamped, time-boxed docs/research/config-ux-review.md (uncontended dir), and (2) an append-only note in docs/BACKLOG.md. NO code, no config changes. Use docs/research/non-hl7-transform-components.md as the date-stamped/time-boxed research-doc template (match its header: Date / Status: research, no code / Owner action). Inventory EVERY config surface for consistency, discoverability, validation, and footguns: the standalone config repo loaded via --config (the code-first graph + connections.toml, ADR 0007/0017); the full messagefoundry.toml service-settings catalog ([store], [api], [inbound], [delivery], [environments], [logging], [auth] incl. AD/MFA, [ai], [retention]) per docs/CONFIGURATION.md; environments/<env>.toml + MEFOR_VALUE_* graph values; and MEFOR_* secrets (the MEFOR_<SECTION>_<KEY> env naming). TOP finding to capture — the split-anchor inconsistency: environments/ is anchorable via [environments].base_dir / serve --project-root (config/environments.py resolve_values_base_dir(base_dir, *, cwd); config/settings.py base_dir defaults to "" → cwd), but messagefoundry.toml resolves a BARE CWD (./messagefoundry.toml, --service-config) and codesets/ resolves under --config (config/code_sets.py, CODESETS_DIR_NAME="codesets") — three different anchors for one logical config bundle. Ground every claim by reading the real symbols/paths first: docs/CONFIGURATION.md, config/environments.py, config/settings.py, config/wiring.py, config/code_sets.py, messagefoundry/__main__.py (--config / --service-config / --project-root), docs/adr/0007 + 0017 — confirm each exists before citing it.

SCOPE GUARD (hard): #33 only IDENTIFIES and circulates findings. Any ACTED-ON recommendation (e.g. anchoring messagefoundry.toml to a project root, renaming/normalizing [section] keys) becomes a SEPARATE backlog item with real contention (config/environments.py + config/settings.py + __main__.py) — record it as a candidate item in the doc + the BACKLOG note, do NOT implement it here. An ADR is a possible OUTPUT, not a gate. The hazard is influence-sequencing, NOT merge-collision: the review blocks nothing at the file level, but its conventions must circulate BEFORE any config-knob lane finalizes [section] shapes — flag #34 (the [retention.connections.*] overlay) and the secretprovider [secrets] surface explicitly as the consumers to circulate to. Run this review FIRST/early so those conventions land before #34 commits its shapes.

ALSO (coordinator-led, Then) — #13 licensing-counsel doc refinement: the coordinator owns the engagement; once counsel responds, carry any doc-only refinement to docs/DUAL_LICENSING_PLAN.md / COMMERCIAL-LICENSE.md (short Workflow only if it becomes substantive). Do not start it before counsel responds.

Discipline: branch → PR (never push to main); stage EXPLICIT paths (a hook blocks git add -A); workers NEVER write project memory (read only — the coordinator is the single writer). Even doc-only, run the gate before the PR: ruff check + ruff format --check, mypy messagefoundry (strict), pytest (QT_QPA_PLATFORM=offscreen for console tests).
```
