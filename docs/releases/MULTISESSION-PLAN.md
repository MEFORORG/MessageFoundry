# MessageFoundry — Multisession Execution Plan

> **Provenance.** Generated 2026-06-17 from the open items in [`../BACKLOG.md`](../BACKLOG.md) via a
> multi-agent workflow: 17 items were each grounded in their cited source (code/ADRs/reviews), a
> file-level contention matrix was computed, the laned plan was synthesized, then adversarially
> reviewed (the review caught 2 unsafe-parallelism collisions on `store/store.py` and `__main__.py`
> plus 2 ungated dependencies — all fixed below). Shared across the parallel worktrees per
> [`../WORKTREES.md`](../WORKTREES.md). This is a planning artifact, not a gate — update it as items land.

> **✅ STATUS — ALL NOW/NEXT LANES LANDED (2026-06-17).** Every staffed lane shipped to `main`:
> **Lane 1 parity** (#354 endpoint + store cession · #364 full tee parity tool — closes backlog #14) ·
> **Lane 2 store-core** (#359 lockfree-reads RO-WAL pool · #361 + #363 cross-backend off-box audit-tee) ·
> **Lane 3 security-posture** (#356 `require_mfa` enforcement · #357 off-box log forwarder + `__main__.py` SPDX) ·
> **Lane 4 quickwins** (#347 · #348 · #349 · #351) · **Lane 5 licensing** (#350 — artifacts drafted; counsel review deferred to v0.2).
> Plus coord: #346 (this plan) · #352 (backlog markers) · #353 (Dependabot → 0 vulns). What remains is
> **on-trigger only** (`sec-842`/`sec-1214`/`wp14b`/`sec-accepted`, `16-eventlog`, `3-perkey`, `7-soap-source`,
> `misc-tail`) plus #13 licensing/counsel review — **deferred to v0.2** (accepted risk 2026-06-17: `v0.1.0` ships on the drafted AGPL posture without counsel sign-off; see backlog #13). The lane
> tables below are kept as the historical plan of record.

---

## 0. The two dominating objectives

| | Objective | Critical path | Status |
|---|---|---|---|
| **A** | Cut the public **0.1.0** tag | Engine work done; gated **only** on `13-licensing` (legal, not code) | Front-load owner + counsel decisions NOW — longest lead time |
| **B** | Corepoint→MEFOR **migration cutover** | `14-parity-tool` is the live build (prereqs #335/#337/#340 shipped) | Staff immediately — active work |

Objective A's long pole is *human* (entity name, pricing, counsel) — that calendar starts day 1 even
though no code moves. Objective B is pure build and starts day 1 in its own lane. Everything else is
sequenced so it never starves these two.

**Hard rule for all lanes:** no two items from the [contention matrix](#appendix-a--file-contention-matrix)
are ever concurrently active in different worktrees — contended files are pinned to one lane or phased
apart (true sequencing, not a "merge window").

---

## 1. Lane assignment (worktrees)

### Lane 1 — `parity` (Objective B; high value)
**Branch:** `parity` · **Worktree:** `MessageFoundry-parity`
1. `14-parity-tool` (L, ~8d) — start now. See the [detailed Lane 1 design](#6-lane-1-detail--14-parity-tool).
   - One cross-lane dependency: a **1-line `store.py` decrypt change** (Lane 2's file) to expose the
     transformed outbound payload — landed via the §3 cession protocol before Lane 2's build starts.

### Lane 2 — `store-core` (SOLE owner of `store/store.py`, `store/base.py`, all DB backends)
**Branch:** `store-core` (create when un-gated)
1. `lockfree-reads` (M, ~5.5d) — **✅ UNBLOCKED** (read-conn decision recorded §2: dedicated read-only WAL
   connection pool). Builds **first** so later schema churn rebases onto a stable read strategy. **Sequencing:**
   Lane 1's 1-line `payload`-decrypt cession edit (§3) must land *before* this build starts.
2. `sec-offbox-log` **store.py audit-tee slice** (carved out of Lane 3) — lands after `lockfree-reads`
   merges, owned here so no second worktree ever holds `store.py` open.
3. `16-eventlog` (M, ~9.5d) — on-trigger, after ADR 0021→0020 ratify.
4. `3-perkey` (XL, ~21d) — last, on-trigger; may need a per-stage lane re-scope.

### Lane 3 — `security-posture` (owns `config/settings.py` Now/Next, `auth/service.py`, security/PHI docs, TLS)
**Branch:** `security-posture` · **Worktree:** `MessageFoundry-security-posture`
1. `sec-mfa-on` (S, ~0.25d) — enable `[auth].require_mfa` config flag + docs. Now.
2. `sec-offbox-log` **non-store slice** (~1.5d) — JSON formatter in `logging_setup.py`, `[logging]`
   settings block, SysLog/forwarder wiring in `__main__.py`, docs. Now. (Store audit-tee slice → Lane 2.)
3. `sec-842` (M, ~3d) — on-trigger (off-loopback; device-posture + contextual-risk on built MFA step-up).
4. `sec-1214` (M, ~3d) — on-trigger, **`parallelizable:false`** (TLS revocation, OCSP/CRL).
5. `wp14b` (L, ~7d) — on-trigger (TOTP single-use flips ASVS 6.5.1; WebAuthn is the larger half).
6. `sec-accepted` (L, ~8d) — build-on-trigger only (per-message sigs ADR 0018 / HSM-KeyProvider ADR 0019).
> **On-trigger serialization:** these four share `docs/SECURITY.md` + store backends + `auth/service.py`,
> and `sec-1214` is non-parallelizable → when triggers fire they run **one at a time** within Lane 3
> (order: `sec-842 → sec-1214 → wp14b → sec-accepted`). Their store-backend edits are handed to Lane 2.

### Lane 4 — `quickwins` (small, isolated config/check/tooling)
**Branch:** `quickwins` · **Worktree:** `MessageFoundry-quickwins`
1. `12-content-type` (S, ~0.5d) — `wiring.py` string→enum coercion; **land first** so other `wiring.py`
   touchers rebase onto it. Now.
2. `10-worktree-base` (S, ~0.5d) — `new.ps1` fetch + default `-Base origin/main`; fixes the staleness
   this very workflow worked around. Now.
3. `11-check-dryrun` (M, ~2d) — `checks.py`/`dryrun.py` per-feed fixture mapping. Now.
4. `6-ide-tests` (M, ~2d) — `@vscode/test-electron` harness + `ide` CI job. Now.
5. `7-soap-source` (L, ~8d) — on-trigger (ADR follow-up); phase apart from `sec-1214` on transports.
6. `misc-tail` (M, ~3.5d) — deferred housekeeping; owner-gated items. Then.

### Lane 5 — `licensing` (Objective A long pole; mostly non-code)
**Branch:** `licensing` · **Worktree:** `MessageFoundry-licensing` (`-NoInstall` — decisions-only now)
1. `13-licensing` (M, ~7d):
   - **NOW:** owner + counsel **decisions only** (entity name, pricing, counsel engagement). **No artifact
     files** — `NOTICE`/SPDX headers/`CLA.md`/`COMMERCIAL-LICENSE.md` encode the legal entity name, a hard
     dependency; writing them first is rework.
   - **NEXT** (entity name = **"MessageFoundry Organization"**, resolved §2): write the artifacts
     (`NOTICE`, SPDX per-file headers, `CLA.md`, `COMMERCIAL-LICENSE.md`) + `__init__.py`/`__main__.py` headers.
   - **THEN:** `0.1.0` tag, gated on counsel sign-off.

---

## 2. Phasing — Now / Next / Then / On-trigger

```
PHASE   Lane1 parity     Lane2 store-core         Lane3 security        Lane4 quickwins     Lane5 licensing
──────────────────────────────────────────────────────────────────────────────────────────────────────────
NOW     14-parity        [read-conn DECISION]     sec-mfa-on            12-content-type     OWNER+COUNSEL
        (build)          → lockfree-reads          sec-offbox-log        10-worktree-base     DECISIONS ONLY
                          (once decision logged)    (non-store slice)     11-check-dryrun      (no artifacts)
                                                                          6-ide-tests
NEXT    (ships)          sec-offbox store.py       (await off-loopback)  7-soap-source       LICENSING
                          slice (after lockfree)    (await trigger)       (await ADR)          ARTIFACTS
THEN    —                16-eventlog              misc-tail (settings   misc-tail           0.1.0 TAG
                          (after 0021/0020          quiescent)                                (counsel sign-off)
                          ratified)
ON-TRIG —                3-perkey (owner +        sec-842 → sec-1214    —                   —
                          ADR 0001 Step C)          → wp14b → sec-accepted
                                                    *SERIALIZED*
```

**Do NOT staff now (build-on-trigger):** `sec-842`, `sec-1214`, `wp14b`, `sec-accepted`, `3-perkey`,
`16-eventlog`, `7-soap-source`, `misc-tail` (owner items).

**Two day-1 decisions that gate NOW builds — ✅ RESOLVED 2026-06-17:**
- **Read-connection strategy → dedicated read-only WAL connection pool (best practice).** Stop serializing
  reads behind the write lock. Keep the single writer connection (writes still serialized under `self._lock`);
  add a small bounded pool of **read-only** connections to the same file (`PRAGMA query_only=ON`, `busy_timeout`
  set), and route *every* read method through it (the 3 metrics reads already fixed + `list_messages`,
  `get_message`, `list_dead`, `count_*`, `outbox_for`, `events_for`, `roles_for_ad_groups`, …). WAL gives each
  reader a consistent snapshot concurrent with the writer, so reads take **no** write lock — this both removes
  the serialization and closes the mid-transaction interleave hazard, and generalizes the deferred load-test
  fix to all reads. **Unblocks `lockfree-reads` (Lane 2).**
- **Legal entity name → "MessageFoundry Organization".** Used as the copyright holder in `NOTICE`, per-file
  SPDX headers, `CLA.md`, and `COMMERCIAL-LICENSE.md`. (Counsel confirms the exact registered legal form
  during the §A licensing review; the artifact work proceeds on this name.) **Unblocks `13-licensing` artifacts (Lane 5 NEXT).**

---

## 3. Coordination rules for parallel sessions

- **Store hot files** (`store/store.py`, `base.py`, `postgres.py`, `sqlserver.py`) — **exclusively Lane 2.**
  No other lane edits `_SCHEMA`/`_migrate`/`_CIPHER_COLUMNS`. The single exception this phase is Lane 1's
  1-line `payload`-decrypt edit to `outbox_for`: Lane 2 is quiescent on `store.py` until the read-conn
  decision, so it **cedes that single edit via the memory log**, and it must **merge before** `lockfree-reads`
  starts (so lockfree rebases onto it). Lane 2 internal order is strict: `lockfree-reads → sec-offbox slice
  → 16-eventlog → 3-perkey`.
- **`__main__.py`** (`13-licensing` / `sec-offbox-log` / `sec-accepted`) — **sequenced, not windowed:**
  `sec-offbox-log` forwarder wiring (NOW, Lane 3) → `13-licensing` header (NEXT, Lane 5) → `sec-accepted`
  (on-trigger). Each rebases onto the prior.
- **`config/settings.py`** — Lane 3 owns it Now/Next (`sec-mfa-on`, `[logging]` block). Lane 2's
  (`16-eventlog`, `3-perkey`) and Lane 4's (`misc-tail`) `settings.py` edits wait for Then.
- **`config/wiring.py`** — `12-content-type` lands first; `16-eventlog`/`3-perkey`/`7-soap-source` rebase onto it.
- **`config/models.py`** — serialized via Lane 2's order + `misc-tail`'s Then window.
- **`transports/rest.py`/`soap.py`** — `7-soap-source` (Lane 4) and `sec-1214` (Lane 3) phased apart, never concurrent.
- **Shared memory** — single-writer; announce intent, read-before-write, write, release. Record the two
  day-1 gating decisions and all ADR-status changes (0021/0020/0018/0019 + the SOAP follow-up) before any
  lane starts work against them.
- **Verification (every PR, no exceptions):** `ruff check` + `ruff format --check` → `mypy messagefoundry`
  (strict) → `pytest -q` (`QT_QPA_PLATFORM=offscreen` for console tests). New behavior ships with a test.
- **Branch + PR discipline:** each lane = its own worktree + `.venv` + PR; one coherent layer per commit;
  no direct pushes to `main`.

---

## 4. Summary table

| Item | Lane | Phase | Effort | Now? | Blocked by / blocks |
|---|---|---|---|---|---|
| `14-parity-tool` | 1 parity | Now | 8d | ✅ | prereqs shipped; blocks cutover; 1-line store.py via Lane 2 cession |
| `lockfree-reads` | 2 store-core | Now | 5.5d | ✅ | read-conn decision resolved (RO WAL pool); after Lane-1 cession edit |
| `sec-offbox-log` (store) | 2 store-core | Next | (of 2d) | ❌ | after lockfree merges |
| `16-eventlog` | 2 store-core | Then | 9.5d | ❌ | ADR 0021/0020 ratify |
| `3-perkey` | 2 store-core | On-trigger | 21d | ❌ | owner throughput + ADR 0001 Step C |
| `sec-mfa-on` | 3 security-posture | Now | 0.25d | ✅ | value gated on off-loopback exposure |
| `sec-offbox-log` (non-store) | 3 security-posture | Now | ~1.5d | ✅ | `__main__.py` sequenced before Lane 5 header |
| `sec-842` | 3 security-posture | On-trigger | 3d | ❌ | off-loopback; serialized in Lane 3 |
| `sec-1214` | 3 security-posture | On-trigger | 3d | ❌ | **parallelizable:false** — runs alone |
| `wp14b` | 3 security-posture | On-trigger | 7d | ❌ | ASVS 6.5.1 + WebAuthn decision |
| `sec-accepted` | 3 security-posture | On-trigger | 8d | ❌ | off-prem/BAA; design-only today |
| `12-content-type` | 4 quickwins | Now | 0.5d | ✅ | lands before other `wiring.py` touchers |
| `10-worktree-base` | 4 quickwins | Now | 0.5d | ✅ | enables clean worktree workflow |
| `11-check-dryrun` | 4 quickwins | Now | 2d | ✅ | isolated |
| `6-ide-tests` | 4 quickwins | Now | 2d | ✅ | isolated (`ide/` + CI) |
| `7-soap-source` | 4 quickwins | Next | 8d | ❌ | ADR follow-up; phase vs `sec-1214` |
| `misc-tail` | 4 quickwins | Then | 3.5d | ❌ | owner decisions; quiescent window |
| `13-licensing` | 5 licensing | Now→Next→Then | 7d | ✅ | entity name resolved ("MessageFoundry Organization"); artifacts unblocked; **blocks 0.1.0 tag** (counsel sign-off) |

---

## 5. Scaffolding status (2026-06-17)

Worktrees created off `origin/main` (`8e5bc14`) via `scripts/worktree/new.ps1`:

| Lane | Worktree | Branch | venv | Notes |
|---|---|---|---|---|
| 1 | `MessageFoundry-parity` | `parity` | yes | active build |
| 3 | `MessageFoundry-security-posture` | `security-posture` | yes | `security` was rejected — collides with the `security/*` branch namespace |
| 4 | `MessageFoundry-quickwins` | `quickwins` | yes (+npm) | created with `-Ide` for the `6-ide-tests` harness |
| 5 | `MessageFoundry-licensing` | `licensing` | no (`-NoInstall`) | decisions-only now; bootstrap a venv before the NEXT-phase artifact work |

Lane 2 (`store-core`) is **not** scaffolded yet — its first build (`lockfree-reads`) is gated on the
read-connection-strategy decision; create the worktree when that decision is recorded.

---

## 6. Lane 1 detail — `14-parity-tool`

**Goal.** A `tee compare` capability that, for the same input message, diffs the shadow MEFOR's
routed/transformed **output** against Corepoint's output and produces a PHI-safe parity report — so the
migration can prove output equivalence on real-shaped traffic *before* any feed is cut over.

**Grounded facts (verified against current code):**
- Simulate mode (#337) **retains** the would-have-sent transformed payload on the done outbound row —
  [`pipeline/wiring_runner.py:870`](../../messagefoundry/pipeline/wiring_runner.py#L870) (`response = None`,
  `mark_done`, payload kept "for parity comparison").
- That payload lives in `queue.payload` (AES-256-GCM at rest — [`store/store.py:406`](../../messagefoundry/store/store.py#L406),
  `_CIPHER_COLUMNS` [`:750`](../../messagefoundry/store/store.py#L750)), correlated to the inbound via
  `messages.id` → `queue.message_id`, with MSH-10 in the indexed `messages.control_id`.
- `store.outbox_for()` already `SELECT *`s the outbound rows ([`store.py:2651`](../../messagefoundry/store/store.py#L2651))
  but `_decode_row(r, "last_error")` decrypts only `last_error`, **not** `payload` — so the row dict carries
  payload as ciphertext.
- **No API endpoint exposes the transformed outbound payload.** `GET /messages/{id}` returns raw inbound +
  outbox **metadata** (no payload); `GET /messages/{id}/responses` is the *partner's* reply (ADR 0013), not
  MEFOR's transform output. ← **the one real engineering gap.**

**Data sources for the diff:**
- **MEFOR side:** transformed outputs via a NEW engine API endpoint (below), correlated by source MSH-10.
- **Corepoint side:** Corepoint's actual outbound, captured by the tee's Listener B (`corepoint_copy` feed
  mirrored from a Corepoint action-list duplicate-send) into `relay_capture` (needs body capture on).

**Build order (commits):**
1. **Engine: expose the transformed payload (small, PHI-gated).**
   - `store.py`: decrypt `payload` in `outbox_for` (add `"payload"` to the `_decode_row` columns) or add a
     `outbox_payloads_for()` read method. **1 line in Lane 2's file → §3 cession, merge before `lockfree-reads`.**
   - `api/models.py`: add `payload` to `OutboxInfo` (or a new `OutboundPayload` model).
   - `api/app.py`: a route returning the transformed payload(s) for a message — e.g. `GET /messages/{id}/outbound` —
     gated `MESSAGES_VIEW_RAW` (PHI), audited via `record_view`. Reuses `outbox_for`. + api test (payload, RBAC, audit).
2. **Tee: capture Corepoint's output bytes.** Ensure the `corepoint_copy` `relay_capture` retains control_id +
   raw for correlation; decide capture posture for a compare run. Standalone (`tee/store.py`/`relay.py`, no engine import).
3. **Parity engine (`tee/compare.py`, pure):** normalize HL7 (read encoding chars from MSH; never hardcode
   `|^~\&`), an **ignore-list** for legitimately-divergent fields (MSH-7 datetime, MSH-10 control id, MSH-3/4
   sending app/facility, segment timestamps — configurable), segment/field-level diff. Unit-testable, no I/O.
4. **Correlation:** match a MEFOR output to a Corepoint output for the same input. Default key = source
   MSH-10; **open decision** when each engine rewrites the control id (source-MSH-10 propagation vs a content
   key: patient id + event type + datetime). Handle fan-out (1 input → N/M outputs) and the **A40 patient-merge**
   cross-MRN hazard.
5. **CLI + report (`tee compare`):** `python -m tee compare --db ./tee.db --mefor-api URL --token … [--since 24h]
   [--out parity.json]`. Pulls MEFOR via the new endpoint (httpx, no engine import) + Corepoint from
   `relay_capture`; runs normalize→correlate→diff. **Report:** counts (exact / semantic / field-mismatch /
   missing-on-a-side) — PHI-safe; per-message field diffs behind a flag — **PHI, test-data-only** (never commit
   or redirect to CI, same guardrail as `--capture-bodies`/dryrun).

**Verification:** unit tests for normalize/diff/correlate (synthetic HL7 only); api test for the new endpoint;
an end-to-end test (known input → stub MEFOR + recorded Corepoint output → asserted parity verdict). ruff + mypy + pytest.

**Open decisions to confirm:** endpoint shape (`/messages/{id}/outbound` vs a payload field, + by-control_id
lookup for the tool); correlation key under control-id rewrite; whether `tee/compare.py` may take a `python-hl7`
dependency (the tee is currently dependency-free) or must vendor a minimal parser; default copy-feed capture posture.

---

## Appendix A — file-contention matrix

Files touched by more than one open item (must be same-lane or phased apart, never concurrent across worktrees):

| File | Items |
|---|---|
| `config/settings.py` | 16-eventlog, sec-mfa-on, sec-offbox-log, sec-842, sec-accepted, 3-perkey, misc-tail |
| `store/store.py` | 16-eventlog, sec-offbox-log, sec-842, wp14b, lockfree-reads, 3-perkey *(+ 14-parity 1-line)* |
| `store/base.py` | 16-eventlog, sec-842, sec-accepted, wp14b, lockfree-reads, 3-perkey |
| `docs/SECURITY.md` | sec-mfa-on, sec-offbox-log, sec-842, sec-1214, sec-accepted, wp14b |
| `store/postgres.py` | 16-eventlog, sec-842, sec-1214, 3-perkey |
| `store/sqlserver.py` | 16-eventlog, sec-842, sec-1214, 3-perkey |
| `config/wiring.py` | 16-eventlog, 12-content-type, 3-perkey, 7-soap-source |
| `docs/PHI.md` | 16-eventlog, sec-offbox-log, sec-1214, sec-accepted |
| `__main__.py` | 13-licensing, sec-offbox-log, sec-accepted |
| `config/models.py` | 16-eventlog, 3-perkey, misc-tail |
| `transports/mllp.py` | 16-eventlog, sec-1214 |
| `pipeline/wiring_runner.py` | 16-eventlog, 3-perkey |
| `docs/CONFIGURATION.md` | sec-mfa-on, sec-accepted |
| `auth/service.py` | sec-842, wp14b |
| `transports/rest.py` | sec-1214, 7-soap-source |
| `transports/soap.py` | sec-1214, 7-soap-source |
| `docs/adr/0002-…` | sec-1214, wp14b |
