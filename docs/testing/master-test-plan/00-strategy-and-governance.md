[← Master Test Plan index](../MASTER-TEST-PLAN.md) · *Part I — Strategy, environments & tooling*

---

## 0.1 Purpose, audience & how to use this document

**Purpose.** This is the **umbrella master test plan** for MessageFoundry. It states *what the product
is*, *what has to be true before it ships*, *who proves it*, and *where each proof lives*. It is the
single index that the project's existing, deeper test artifacts plug into — it does **not** restate
them (§0.5).

It exists because the estate is now large enough to lose things between artifacts: 535 `test_*.py` modules
under [`tests/`](../../../tests), 35 mocha suites under [`ide/src/test/suite/`](../../../ide/src/test/suite), 16 GitHub
Actions workflows under [`.github/workflows/`](../../../.github/workflows), a load/failover rig
([`harness/load/`](../../../harness/load)), an on-box acceptance runner
([`harness/acceptance/`](../../../harness/acceptance)), a parallel-run reconciliation harness
([`harness/reconcile/`](../../../harness/reconcile)), an in-product deployment-acceptance command
([`messagefoundry/verify/`](../../../messagefoundry/verify)), and a commit/CI gate
([`messagefoundry/checks.py`](../../../messagefoundry/checks.py)). Each is well-run in isolation. Nothing until
now said, in one place, how they compose into a release decision.

**Audience.**

| Reader | What they use this for |
|---|---|
| Project owner / maintainer | Release go/no-go, priority calls, cadence, what a green run does and does not prove |
| Contributor (human or AI agent) | Which chapter owns the area they are changing, and which test IDs their change must satisfy or add |
| Evaluator / prospective adopter | The shape and honesty of the verification story (levels, environments, backends, known gaps) |
| Auditor / security reviewer | Traceability from a control (ADR / ASVS item) to an executable assertion |

**How to use it.** Part I (this chapter) is **governance** — read once, refer back for the
vocabularies and the priority rule. **Part II is the executable content**: 17 chapters, one per
subsystem, each a table of test IDs with a Type / Method / Env / Backend / **Cls** / Pri
classification and a pass condition. Work is scheduled *out of Part II*; nothing in Part I is directly runnable.

### The ID scheme

Every test in Part II carries a stable ID of the form **`<PREFIX>-<nn>`** — the chapter prefix, a
hyphen, and a zero-padded two-digit sequence within that chapter (`PIPE-07`, `STORE-14`, `TRAY-03`).

Rules:

1. **Numbers are allocated in order within a chapter and are never reused.** A retired test keeps its
   ID with a `WITHDRAWN` disposition and a one-line reason; the next test takes the next number.
2. **The ID is the citation key.** Commit messages, PR bodies, ADRs and BACKLOG items reference tests
   by ID, never by test-function name (function names get refactored; IDs do not).
3. **Disambiguation against the coverage plan (important).**
   [`docs/testing/FEATURE-COVERAGE-PLAN.md`](../FEATURE-COVERAGE-PLAN.md) uses its own
   *gap*-ID space with several colliding prefixes — it has `PIPE-14`, `STORE-4`, `API-13`, `ALERT-12`,
   `CFG-19`, `PARSE-14`, `HA-*` and more. **In this document an unqualified `PIPE-14` always means this
   plan's test ID.** A coverage-plan gap is always written **`FCP:PIPE-14`**. A WIN2025 matrix row is
   written **`W25:S2.4`** or **`W25:§C`**. Never cite a bare gap ID across documents. The full rule,
   its two real worked collisions (`HA-20`, `API-13`) and the mechanical check that enforces it are in
   **§0.5.3** — the convention is not optional and is linted.
4. An ID may map to more than one executing assertion (a cross-backend row executes three times); it
   still counts as one ID, with the Backend column recording the legs.

### The classification vocabularies

Part II tables use exactly these six controlled vocabularies. A value outside them is a defect in the
table.

**Type** — the coverage dimension being bought. Aligned to the six dimensions already used by
`FEATURE-COVERAGE-PLAN.md` §"The six dimensions", plus two this umbrella adds.

| Type | Meaning |
|---|---|
| `FUNC` | The feature does what its ADR / acceptance criteria say — happy path plus the error and edge branches |
| `SEC` | A fail-closed guard actually refuses, proven by a **negative** assertion (not by construction) |
| `PHI` | No message body, element value, or search needle reaches a log, stdout, exception, audit row, report, or CI artifact |
| `PERF` | A throughput / latency / scaling claim has a repeatable measurement with a pre-registered falsifier (§0.8) |
| `HA` | Behaviour under leader change, crash-restart, restart-recovery, or multi-node, on a real server DB |
| `XBE` | Cross-backend: a SQLite-proven behaviour is **executed** — not structurally asserted — on SQL Server and PostgreSQL |
| `UX` | An operator or author can actually complete the task on the surface (web console, IDE, tray, CLI) |
| `UPG` | Install, upgrade, schema migration, or migration-from-incumbent behaviour across versions |

**Method** — how the assertion executes. Every value below names a rig that exists in the repo today.

| Method | Rig | Invocation |
|---|---|---|
| `pytest-unit` | [`tests/`](../../../tests) | `pytest -q` (Qt tests need `QT_QPA_PLATFORM=offscreen`) |
| `pytest-int` | [`tests/`](../../../tests) with a live store / socket / service container | `pytest -q` under `MEFOR_TEST_SQLSERVER` / `MEFOR_TEST_POSTGRES` |
| `pytest-e2e` | [`tests/`](../../../tests) driving a served engine end to end | `pytest -q` |
| `mocha` | [`ide/src/test/suite/`](../../../ide/src/test/suite), host-free suites | `npm run test:unit` (ide/) |
| `electron` | Same suites under a real VS Code host | `npm test` (ide/, `@vscode/test-electron`) |
| `harness-scenario` | [`harness/`](../../../harness) headless scenarios | `python -m harness --scenario <name>` |
| `harness-load` | [`harness/load/`](../../../harness/load) | `python -m harness --load <profile>` |
| `harness-probe` | [`harness/acceptance/`](../../../harness/acceptance) | `python -m harness.acceptance [--section A,B,C]` |
| `harness-reconcile` | [`harness/reconcile/`](../../../harness/reconcile) | `python -m harness.reconcile capture` / `compare` |
| `verify` | [`messagefoundry/verify/`](../../../messagefoundry/verify) | `messagefoundry verify --section host,store,smoke,manual,federation` |
| `check` | [`messagefoundry/checks.py`](../../../messagefoundry/checks.py) | `messagefoundry check` (git hook + CI + IDE) |
| `manual` | A documented human step | Recorded in [`docs/testing/WIN2025-TEST-MATRIX.md`](../WIN2025-TEST-MATRIX.md) |

**Env** — where it runs. (The self-hosted NucBox Windows runners are retired; the `test` matrix is
GitHub-hosted, per the comment at [`.github/workflows/ci.yml`](../../../.github/workflows/ci.yml) job `test`.)

| Env | Meaning |
|---|---|
| `dev` | Developer workstation / worktree |
| `ci-hosted` | GitHub-hosted runners — `ubuntu-latest`, `windows-2022`, `windows-2025` (`ci.yml` job `test`) |
| `ci-service` | GitHub-hosted with a service container — `sqlserver-store`, `postgres-store`, `docker-smoke` |
| `ci-selfhosted` | [`selfhosted-win2025-sql.yml`](../../../.github/workflows/selfhosted-win2025-sql.yml), job `sqlserver-real` |
| `win2025-box` | The Windows Server 2025 acceptance box ([`docs/testing/WIN2025-TEST-PLAN.md`](../WIN2025-TEST-PLAN.md)) |
| `ad-lab` | The AD / Kerberos lab (WIN2025 plan, AD-lab rows) |
| `perf-rig` | The dedicated throughput rig used by [`docs/LOAD-TESTING.md`](../../LOAD-TESTING.md) and `benchmark.yml` |

**Backend** — `sqlite` · `sqlserver` · `postgres` · `all3` · `n/a`. `all3` means the assertion
**executes** on each backend (gated CI legs are acceptable; a structural DDL/`dir()` check is not).

**Cls** — the **row class**: `T` (Test) · `C` (Characterisation) · `A` (Assurance), defined in
**§0.4.4**. The column sits **immediately before `Pri`** in every Part II table. Only `T` rows count
toward the countable release gate.

**Pri** — `P0` · `P1` · `P2`, defined in §0.4.2.

### The 17 Part II chapters

| # | Prefix | Chapter | Primary code under test |
|---|---|---|---|
| 1 | `PIPE` | Staged pipeline, workers, dispositions, at-least-once | [`messagefoundry/pipeline/`](../../../messagefoundry/pipeline) |
| 2 | `STORE` | Store backends, staged queue, dead-letter, retention, at-rest crypto | [`messagefoundry/store/`](../../../messagefoundry/store) |
| 3 | `HA` | Active-passive failover, engine shards, DR backup/restore | `pipeline/`, `store/`, `backup` / `restore-verify` |
| 4 | `CONN` | Connections / transports (MLLP, File, DB, REST/SOAP/FHIR, DICOM, X12, email) | [`messagefoundry/transports/`](../../../messagefoundry/transports) |
| 5 | `PARSE` | HL7 peek/strict/tree, payload-agnostic ingress, X12 + DICOM codecs, binary carriage | [`messagefoundry/parsing/`](../../../messagefoundry/parsing) |
| 6 | `CFG` | Wiring, `connections.toml`, environments, code sets, service settings | [`messagefoundry/config/`](../../../messagefoundry/config) |
| 7 | `PUB` | The publish/promote path: `check` → dry-run pre-flight → `POST /config/reload` (incl. dual control) | `checks.py`, `api/app.py:2741`, `ide/src/promote.ts` |
| 8 | `API` | The FastAPI engine API surface | [`messagefoundry/api/`](../../../messagefoundry/api) |
| 9 | `AUTH` | Authentication (local / AD / Kerberos, TOTP, passkeys, sessions), RBAC, audit | [`messagefoundry/auth/`](../../../messagefoundry/auth) |
| 10 | `WEB` | Web console at `/ui` | [`messagefoundry_webconsole/`](../../../messagefoundry_webconsole) |
| 11 | `IDE` | VS Code extension (setup, wizards, engine link, test bench, AI commands) | [`ide/`](../../../ide) |
| 12 | `STEPS` | Steps view — the typed step vocabulary and its Python codegen/round-trip | [`messagefoundry/lens.py`](../../../messagefoundry/lens.py), `ide/src/stepsModel.ts` |
| 13 | `TRAY` | Tray app + its frozen boundary (**13a**), the NSSM Windows service (**13b**), distribution & install (**13c**), and the standalone PySide6 **test harness GUI** (**13d**) | [`messagefoundry/tray/`](../../../messagefoundry/tray), [`scripts/service/`](../../../scripts/service), [`harness/`](../../../harness) |
| 14 | `ALERT` | Alerting, alert state, health/stats, observability | [`messagefoundry/pipeline/alerts.py`](../../../messagefoundry/pipeline/alerts.py) (the `AlertSink` Protocol, `:27`), [`alert_sinks.py`](../../../messagefoundry/pipeline/alert_sinks.py) (`NotifierAlertSink`) |
| 15 | `SEC` | TLS/posture, egress allowlists, redaction, key lifecycle, supply chain | [`messagefoundry/security/`](../../../messagefoundry/security), `pki.py`, `redaction.py`, `security.yml` |
| 16 | `PERF` | Throughput, latency, engine-shard scaling, soak — and the honesty of the instruments | [`harness/load/`](../../../harness/load) |
| 17 | `MIG` | Install / upgrade / packaging, store schema migration, Corepoint import, parallel-run cutover | `packaging/`, `docker/`, `scripts/service/`, `corepoint_import.py`, `harness/reconcile/` |

---

## 0.2 What is being tested — the product surface map

MessageFoundry is **one headless engine process plus four separate client surfaces and a CLI**, deployed
as a Windows service (or container). Everything below is in scope for this plan; the right-hand column
names the chapter that owns it.

| Surface | What it is, concretely | Owning chapter(s) |
|---|---|---|
| **Engine core** | Headless **asyncio** service under uvicorn/FastAPI. One listener + a **router worker** + a **transform worker** per inbound Connection, one delivery worker per outbound Connection, supervised by `RegistryRunner` ([`pipeline/wiring_runner.py`](../../../messagefoundry/pipeline/wiring_runner.py)) | `PIPE` |
| **Staged queue** | `ingress → routed → outbound` stages on a transactional store; dispositions `RECEIVED / ROUTED / UNROUTED / PROCESSED / FILTERED / ERROR`; ACK-on-receipt; `reset_stale_inflight` recovery | `PIPE`, `STORE` |
| **Store backends (3)** | SQLite/WAL ([`store/store.py`](../../../messagefoundry/store/store.py)), SQL Server ([`store/sqlserver.py`](../../../messagefoundry/store/sqlserver.py)), PostgreSQL ([`store/postgres.py`](../../../messagefoundry/store/postgres.py)) behind the `Store` protocol + `open_store` ([`store/base.py`](../../../messagefoundry/store/base.py)) | `STORE` (+ `XBE`-typed rows everywhere) |
| **Connections** | MLLP/TCP, File + RemoteFile, DB source/destination, REST/SOAP/FHIR (+ SMART token provider), DICOM C-STORE SCP/SCU + C-ECHO, DICOMweb STOW-RS, X12 raw-TCP, email — all resolved through the connector registry ([`transports/base.py`](../../../messagefoundry/transports/base.py)) | `CONN` |
| **Routers & Handlers** | Code-first `@router` / `@handler` Python, wired by name; purity contract; the sanctioned read-only `db_lookup` / `fhir_lookup` carve-outs | `PIPE` (execution), `CFG` (loading), `STEPS` (authoring) |
| **Parsing** | python-hl7 tolerant peek on the hot path, hl7apy opt-in strict validation, tree/message model, X12 + DICOM codecs, `mfb64:v1:` binary carriage | `PARSE` |
| **HA / scale** | Active-passive engine failover over one unified store; **engine shards** (`serve --shard`, N processes over ONE store); DR `backup` / `restore-verify`. (**Database** sharding is shelved and out of scope — §0.10.) | `HA` |
| **Engine API** | The engine's only external surface: [`api/app.py`](../../../messagefoundry/api/app.py) + `api/security.py` + `auth_routes.py`, bound to `127.0.0.1` by default, deny-by-default per-route permissions | `API`, `AUTH` |
| **Web console `/ui`** | The **sole operator console** — a browser SPA served **same-origin** by the engine's own app ([`messagefoundry_webconsole/mount.py`](../../../messagefoundry_webconsole/mount.py)); talks HTTP/WS only, never imports the engine or touches the DB. Ships as its own distribution (`packaging/messagefoundry-webconsole`, released by `release.yml` job `release-webconsole`) | `WEB` |
| **VS Code IDE extension** | TypeScript authoring surface ([`ide/`](../../../ide)) — setup, connection wizard/editors, graph tree, code sets, live debug, trace view, test bench, engine link doctor, promote | `IDE`, `PUB`, `STEPS` |
| **Windows tray app** | Unprivileged notification-area service manager ([`messagefoundry/tray/`](../../../messagefoundry/tray), stdlib `ctypes`, no Qt). Reads exactly two credential-free signals — SCM service state and tokenless `GET /health` — and deep-links to `/ui`. Boundary frozen by [`tests/test_tray_boundary.py`](../../../tests/test_tray_boundary.py) | `TRAY` |
| **PySide6 test harness** | Standalone send/receive/compose/monitor GUI + headless scenarios + the load, acceptance and reconcile rigs ([`harness/`](../../../harness)). A **test instrument first**, but also a shipped distribution (`packaging/messagefoundry-harness`, `release.yml` job `release-harness`). **The retired PySide6 desktop console is not a surface** — PySide6 backs only this harness | **`TRAY` (part 13d)** owns the harness GUI — launch path, sign-in dialog, panels, and the `messagefoundry-harness` wheel; `PERF` owns the load rig's instrument correctness. *(No longer "the chapter using it": the plan's only hostile-input and fault-injection instrument has a named owner.)* |
| **CLI** | ~30 subcommands in [`messagefoundry/__main__.py`](../../../messagefoundry/__main__.py) — see the split below | distributed (table below) |
| **Deployment substrate** | NSSM Windows service ([`scripts/service/install-service.ps1`](../../../scripts/service/install-service.ps1)), the wheel, `docker/` (Dockerfile, compose, k8s), `environments/` value files (`dev.toml`, `prod.toml` today), signed release pipeline (`release.yml`) | `MIG` (+ `W25:` for on-box acceptance) |

**CLI ownership** (the CLI has no chapter of its own; each subcommand is owned by the subsystem it
drives):

| Subcommands | Owning chapter |
|---|---|
| `serve`, `supervise` | `PIPE` (and `HA` for `--shard` / failover flags) |
| `validate`, `graph`, `dryrun`, `check`, `connection`, `codeset`, `impact`, `init` | `CFG`, `PUB` |
| `generate`, `hl7schema`, `hl7structures`, `lens parse` / `lens rewrite` | `PARSE`, `STEPS` |
| `alert` | `ALERT` |
| `security`, `gen-key`, `protect-key`, `cert import` / `inventory` / `self-signed`, `audit-verify`, `rekey-audit`, `rotate-key`, `ai-policy` | `SEC`, `AUTH` |
| `backup`, `restore-verify` | `HA` |
| `verify`, `service`, `support-bundle`, `import corepoint` | `MIG` |
| `adr-analyze` | governance tooling — not a product surface; excluded (§0.10) |

---

## 0.3 Test levels & types

### The levels

| Level | Question it answers | Where it lives here |
|---|---|---|
| **Unit** | Does this function/class behave, including its error branches? | `tests/` (`pytest-unit`), `ide/src/test/suite/` (`mocha`) |
| **Component / integration** | Do two or more real components work against a real store / socket / service container? | `tests/` under `MEFOR_TEST_SQLSERVER` / `MEFOR_TEST_POSTGRES`; `ci.yml` jobs `sqlserver-store`, `postgres-store` |
| **Contract** | Does a boundary hold its shape — API ↔ client, matrix ↔ code, web console seam, tray boundary? | [`tests/test_webconsole_seam_snapshot.py`](../../../tests/test_webconsole_seam_snapshot.py), [`tests/test_win2025_acceptance.py`](../../../tests/test_win2025_acceptance.py), [`tests/test_tray_boundary.py`](../../../tests/test_tray_boundary.py), [`tests/test_api_health_tokenless.py`](../../../tests/test_api_health_tokenless.py) |
| **System / end-to-end** | Does a synthetic message traverse a served engine and land with the right disposition? | `harness/config` disposition graph + `python -m harness --scenario …`; `messagefoundry verify --smoke live --check-disposition` |
| **Host acceptance** | Does it install, run, survive reboot, and behave **under the service identity** on a real Windows Server 2025 box? | `harness/acceptance` probes + `WIN2025-TEST-MATRIX.md` (owned there, not here) |
| **Performance** | Throughput, latency, engine-shard scaling, failover-under-load, soak | `harness/load/` (`--load`, `--failover`, `--estate`), `benchmark.yml` (`baseline-sqlite` / `-postgres` / `-sqlserver`) |
| **Security** | Do the fail-closed guards refuse; are deps/secrets/code clean? | Negative `SEC`-typed pytest rows + `security.yml` (`pip-audit`, `npm-audit`, `sbom`, `trivy`, `bandit`, `gitleaks`, `semgrep`, `crypto-inventory`, `forbidden-content`), `codeql.yml`, `zizmor.yml`, `scorecard.yml` |
| **Resilience / chaos** | Crash-kill under load, hard process death, fault injection, degraded start | `harness/load/failover.py`; harness **Receive** fault modes (delay-then-AA, close-no-reply, fail-N-then-AA); `W25:S2.4` crash/restart durability |
| **UAT / usability** | Can an operator or author complete the task on the surface? | `UX`-typed rows: `electron` IDE runs, web console page checks, tray menu checks, and the manual rows in the WIN2025 matrix |
| **Upgrade / migration** | Does an existing install/schema/config survive the next version; does an incumbent feed port faithfully? | `MIG`: store `_migrate` paths, `import corepoint`, `harness/reconcile` shadow comparison, `docker-smoke`, `windows-service-smoke` |

### Which level each existing rig occupies

| Rig | Level(s) | Notes on what it does *not* cover |
|---|---|---|
| `pytest` (535 test modules) | Unit, integration, contract, some e2e | Single shared session event loop + a 60 s per-test watchdog (`pyproject.toml` `[tool.pytest.ini_options]`). Server-DB legs **self-skip** without the env gates — a green local run is not a cross-backend run |
| `ide` mocha (`npm run test:unit`) | Unit | Deliberately ignores 8 suites that need a VS Code host (`package.json` `test:unit`) |
| `ide` electron (`npm test`) | Component / UX | Runs the full suite under a real VS Code host; `ci.yml` job `ide` is **path-gated** (`needs.changes.outputs.ide`) |
| `harness` scenarios (`--scenario`) | System / e2e | Needs a served engine; asserts disposition, not throughput |
| `harness/load` (`--load` / `--failover` / `--estate`) | Performance, resilience | Reports metrics only; SLO verdicts and exit codes per [`docs/LOAD-TESTING.md`](../../LOAD-TESTING.md) §"Exit codes" |
| `harness/acceptance` (`python -m harness.acceptance`) | Host acceptance | Executes probes + re-runs backing pytest suites; **never fakes green** — unautomatable rows report `MANUAL` |
| `harness/reconcile` (`capture` / `compare`) | Migration / parallel run | Offline comparison core; normalizes engine-non-deterministic fields; exits non-zero on a real diff so it can gate a per-Connection sign-off |
| `messagefoundry verify` | Host + deployment acceptance | Sections `host,store,smoke,manual,federation` ([`verify/runner.py:22`](../../../messagefoundry/verify/runner.py)); `--smoke self` is side-effect-free, `--smoke live` sends **one** synthetic message |
| `messagefoundry check` | Pre-merge config gate | Required checks `validate`, `dryrun`, `posture`, `build-check`, `reference-backend`; `ruff`/`mypy`/`raise-fstring`/`accepts-candidate` are **advisory and never block** |
| CI legs (`ci.yml`) | All automated levels | `test` + `ide` + `ci-gate` on every PR; the heavy legs (`sqlserver-store`, `postgres-store`, `load-test`, `load-test-sqlserver`, `windows-service-smoke`, `docker-smoke`) run **nightly at 03:17 UTC** or on `workflow_dispatch`, plus a PR path-gate arm where `changes` provides one |
| `quality-advisory.yml` | Meta / test-quality | `complexity`, `clone`, `coverage` (diff-cover), `mutation` — all **advisory, never required**; the `liveness` job is the meta-gate that demands proof a signal actually executed |

**Anti-metric rule (inherited, restated).** Coverage % and mutation score are **surfaced, never gated**
— per [`docs/Code_Quality_Standards.md`](../../Code_Quality_Standards.md) §4.1 and the handoff at
[`docs/quality-gates/HANDOFF-mutation-coverage.md`](../../quality-gates/HANDOFF-mutation-coverage.md).
This plan does not introduce a coverage-percentage exit criterion.

---

## 0.4 Risk-based prioritisation

### 0.4.1 The stakes, named

MessageFoundry carries clinical messages containing PHI, unattended, as a Windows service, inside a
hospital network. Seven failure classes define priority; everything else is downstream of them.

| # | Failure class | Why it is the top tier |
|---|---|---|
| R1 | **Message loss** | An admission, result, or order silently never arrives. Undetectable from inside the engine once the row is gone. Guarded by the ACK-on-receipt + single-transaction stage-handoff invariant |
| R2 | **Duplicate or out-of-order clinical data** | At-least-once delivery is *by design*; the safety property is that a re-run re-derives identical output (Routers/Handlers pure) and destinations stay idempotent. A duplicate result or a reversed A08/A03 pair is a clinical-safety event, not a nuisance |
| R3 | **PHI exposure** | A body, element value, or needle reaching a log, stdout, exception, audit row, report, or CI artifact. Irreversible once published — a git history is forever |
| R4 | **Security bypass** | A fail-closed guard that does not refuse: an unauthenticated route, an RBAC hole, a cleartext or weakened-TLS hop under a production-PHI posture, an SSRF/egress-allowlist escape, an injection reaching SQL/path/subprocess |
| R5 | **Silent operator blindness** | The message flowed wrong and **nothing told anyone** — a disposition never finalized, an alert never routable, a stat that reads plausible but measures nothing. The count-and-log invariant exists precisely against this |
| R6 | **Failed install / upgrade** | The service will not start under the service identity, a schema migration wedges, DPAPI-protected material does not cross the admin→service boundary, or a container/wheel upgrade drops a queued message |
| R7 | **A bad publish reaching production** | A config promote (`POST /config/reload`) that loads a graph the engine then refuses, or that quietly changes routing. The `check` gate, the dry-run pre-flight, and dual-control approval exist for this path |

### 0.4.2 Priority definitions

| Pri | Definition | Consequence |
|---|---|---|
| **P0** | Proves an **R1–R4** property, or the **absence of silence** for R5, on a path that ships by default. A regression here is unacceptable at any release | Blocks a release. Must be automated and required in CI, or — where only a box can prove it (`win2025-box`, `ad-lab`) — must be an explicitly signed-off row before the tag |
| **P1** | Proves R5–R7, or an R1–R4 property on a **non-default / opt-in** path (a connector behind an extra, a backend not promoted for prod, a feature flagged off). Also: cross-backend (`XBE`) execution of an already-P0-proven behaviour | Blocks a release **for the affected feature**; a documented, dated deferral by the owner is permissible if the feature's status is downgraded accordingly in [`docs/FEATURE-MAP.md`](../../FEATURE-MAP.md) |
| **P2** | Breadth, ergonomics, diagnostics quality, and hardening beyond the shipped default posture | Never blocks a release. Scheduled opportunistically or when its area is being touched anyway |

### 0.4.3 The selection rule: **silent AND material**

A candidate test earns a slot only if the regression it detects is **both**:

- **Silent** — no existing test, gate, type-check, startup refusal, or operator-visible symptom would
  catch it. If `mypy --strict` already makes the bug unrepresentable, or the engine refuses to start,
  or the disposition goes `ERROR` and an alert fires, the test buys nothing.
- **Material** — the consequence maps to R1–R7. A cosmetic difference, a log-wording change, or an
  internal refactor with identical observable behaviour is not material.

**Silent AND material → P0/P1. Loud OR immaterial → do not write it.**

This is the same rule the coverage plan states as its thesis ("the places where a regression would be
*silent* … and *material*"); it is restated here because it applies to **every** chapter of Part II,
not only to the gap audit. Two corollaries:

- **A test that cannot fail is worse than no test** — it consumes runtime and manufactures confidence.
  The `liveness` meta-gate in `quality-advisory.yml` exists because three separate signals in this repo
  reported success for months while measuring nothing.
- **Prove a guard with a negative.** A `SEC`-typed row asserts the refusal, not the happy path. "It is
  guarded by construction" is not evidence.

### 0.4.4 Row class (`Cls`) — Test / Characterisation / Assurance

Pri says how much a row **matters**. Row class says whether the row can **fail at all** — and only a
row that can fail is allowed to gate a release. Every Part II table carries a `Cls` column
**immediately before `Pri`**, with exactly three values:

| Cls | Name | What it is | Effect on the gate |
|---|---|---|---|
| **T** | **Test** | A falsifiable assertion with an observable pass criterion: a stated input, a stated expected observation, and a way to come back **red** | **Counts toward the release gate. Only `T` rows do** |
| **C** | **Characterisation** | Produces a recorded measurement, finding, or documented decision, with **no threshold yet** — "record the outcome", "publish a number", "a dated owner decision". Legitimate and often necessary work (it is how a threshold gets discovered), but it **cannot fail** | Tracked and reported, **never blocking**. A `C` row may not hold a release |
| **A** | **Assurance** | An **external engagement**: penetration test, third-party review, DAST, an auditor or vendor statement. Its outcome is procured, not asserted by this repo | Blocking **only for an off-loopback / production-exposure release**; advisory otherwise. **Excluded from the ordinary P0 count** |

**How it wires to the gate** (this qualifies §0.6):

- The countable gate reads **`T` rows only**. "Every P0 passes" always means *every P0 `T` row
  passes*, and a chapter's P0 count is a count of its **P0 `T` rows**.
- **`C` rows are tracked and reported but cannot block.** An outstanding `C` row is a scheduling
  question, not a release question — it has no failing state to block with.
- **`A` rows block only an off-loopback / production-exposure release** (see §0.10 assumption 5 and
  assumption 8: there is no third-party assessment, penetration test, or DAST to date). For a
  loopback-bound, default-posture release they are advisory and are reported as *outstanding*, never
  as *failed*.

**The promotion rule.** A `C` row becomes a `T` row **the day its threshold or decision is
recorded** — the measurement it produced becomes the number an assertion is written against, or the
owner's dated decision becomes the state a guard test pins. Promotion happens **in place, on the same
ID** (IDs are never reused or re-issued, §0.1): the pass criterion is rewritten into something that
can come back red, `Cls` flips `C` → `T`, and only then does the row enter the gate.

**Re-class honestly — the smell list.** A row is `C` (or `A`), not `T`, if its pass criterion reads
*"Pass = report received"*, *"Pass = a published number"*, *"Pass = a dated owner decision"*,
*"Outcome is a written finding"*, or if it carries an escape clause of the form
*"… **or** the exception is recorded"*. An escape clause does not soften a test, it **deletes the
failing branch**: the row now passes either way. Exactly two lawful responses, no third — re-class
the row, or rewrite the criterion so it can actually fail. This is §0.4.3's first corollary — *a test
that cannot fail is worse than no test* — made **countable** rather than merely stated.

**Per-chapter declaration.** Every Part II chapter states its class split in the preamble to its
§x.4 test matrix: how many **`T`**, **`C`** and **`A`** rows it holds, and how many **P0s among its
`T` rows**. Those declarations are what §0.6's exit criteria are counted from. **Part I carries no
test rows, so no `Cls` column appears in this chapter.**

---

## 0.5 Relationship to existing artifacts

This master plan sits **above** the existing artifacts and **indexes** them. It is a layer of
governance and cross-cutting scope, not a replacement layer.

```
                    ┌─────────────────────────────────────────┐
                    │  MASTER TEST PLAN  (this document)      │
                    │  Part I  strategy & governance          │
                    │  Part II 17 chapters of test IDs        │
                    └──────────────────┬──────────────────────┘
                                       │ delegates / cites
   ┌───────────────┬───────────────┬───┴───────────┬──────────────┬─────────────┐
   ▼               ▼               ▼               ▼              ▼             ▼
FEATURE-        WIN2025-*       VERIFY.md      LOAD-TESTING   CI-QUALITY    quality-gates/
COVERAGE-PLAN   (PLAN/MATRIX/   (`verify`      .md            .md           HANDOFF-
(gap audit,     ACCEPTANCE)     command)       (perf rig)     (plain-       mutation-
 6 dimensions)  (on-box acc.)                                 language)     coverage.md
```

| Artifact | It owns | This plan's relationship |
|---|---|---|
| [`docs/testing/FEATURE-COVERAGE-PLAN.md`](../FEATURE-COVERAGE-PLAN.md) | The **gap audit**: 128 gaps across 24 subsystems and six dimensions, phased P0–P7, plus the "what NOT to re-test" list and the verification errata | **The backlog of work.** Part II chapters cite its gap IDs as `FCP:<ID>` and inherit its dimension vocabulary. This plan never re-derives a gap it already found, and never re-tests anything on its `covered` / "leave alone" list |
| [`docs/testing/WIN2025-TEST-PLAN.md`](../WIN2025-TEST-PLAN.md) + [`WIN2025-TEST-MATRIX.md`](../WIN2025-TEST-MATRIX.md) + [`WIN2025-ACCEPTANCE.md`](../WIN2025-ACCEPTANCE.md) | **Everything only a real box can prove**: the CI-OWNED / BOX-OWNED split, the 54-row matrix (sections A–H), the eight "false-green" gaps (`W25:S2.1`–`W25:S2.8`), the manual `S1.AC-*` rows, and the executable runner `python -m harness.acceptance` | **Delegated wholesale.** Any `Env: win2025-box` or `ad-lab` row in Part II is a **pointer** (`W25:<row>`), never a restatement. This plan's release exit criteria (§0.6) *require* a WIN2025 pass; it does not describe how to perform one |
| [`docs/testing/VERIFY.md`](../VERIFY.md) | The `messagefoundry verify` command: its five sections, `self` vs `live` smoke, per-DB validation, and — critically — **what a green run does not prove** | **Cited as the deployment-acceptance instrument.** Part II `Method: verify` rows name the section and flags; the semantics live in VERIFY.md |
| [`docs/LOAD-TESTING.md`](../../LOAD-TESTING.md) | The load rig: profiles, engine load-config knobs, the report schema and exit codes, backend comparison, `--failover`, the `--estate` 1,500-Connection demo, known limitations | **Cited as the performance instrument.** `PERF` chapter rows specify profile + shape + falsifier; they do not re-document the rig |
| [`docs/CI-QUALITY.md`](../../CI-QUALITY.md) | The **plain-language** account of automated testing for a non-engineer reader (~2,500 PR checks / ~2,600 post-merge, four system setups), measured 2026-06-20 | **Audience sibling, not a dependency.** When this plan changes what runs, CI-QUALITY.md's figures are refreshed from `.github/workflows/` — the workflow files remain the source of truth |
| [`docs/quality-gates/HANDOFF-mutation-coverage.md`](../../quality-gates/HANDOFF-mutation-coverage.md) | The advisory mutation + diff-coverage gates and the advisory-first ground rules | **Inherited, unchanged.** This plan adopts "surface, never gate" for coverage/mutation scores |
| [`docs/FEATURE-MAP.md`](../../FEATURE-MAP.md) | The capability catalog with ✅ / 🔬 / 🔨 / ⏭️ / 🧭 status per feature | **Traceability target** (§0.9). A ✅ row with no P0/P1 test ID is itself a finding |

### 0.5.1 The DO-NOT-DUPLICATE rule

> **If an area is owned by one of the artifacts above, this plan cites it and stops.**
> A Part II chapter may (a) point at the owning artifact, (b) add a test ID for something the owner
> explicitly leaves out, or (c) record that an owner's row is the *only* proof and flag the residual
> risk. It may **not** restate the owner's procedure, re-run its matrix, or re-derive its gap list.

Violations are a defect in the deliverable, for a concrete reason: duplicated procedure drifts, and a
drifted duplicate is exactly the "doc that lies about build state" the `backlog-hygiene` workflow was
built to stop.

**Ownership at a glance:** gap discovery → `FEATURE-COVERAGE-PLAN.md`. On-box / service-identity /
AD / reboot behaviour → the WIN2025 trio. Deployment self-check semantics → `VERIFY.md`. Throughput
methodology and rig knobs → `LOAD-TESTING.md`. Advisory test-quality signals →
`quality-advisory.yml` + the quality-gates handoff. **Everything cross-cutting — level strategy,
priority, entry/exit, cadence, defect and traceability rules, and the per-chapter test index — is
owned here.**

### 0.5.2 Duplicate deliverables — ownership registry

§0.5.1 governs this plan's relationship to *other* artifacts. This subsection governs duplication
*inside* Part II: seventeen chapters drafted against one estate inevitably scoped the same deliverable
twice. Every collision found has a **decided owner**, recorded below.

**The pointer-row form.** The owner keeps the real row. The other chapter does **not** delete its row
— deleting it would break any citation already pointing at that ID and would hide the fact that the
area was considered. It **replaces** the row with a one-line **pointer row**: the **same ID**, Method
`—`, `Cls` **`T`**, `Pri` **matching the owner's row**, and a pass criterion of **"Covered by
`<OWNER-ID>`; no separate work scoped"**. A pointer row therefore **consumes an ID and preserves
traceability but schedules no work** — the deliverable is **counted once**, in the owner's chapter,
and the pointer is excluded from the pointing chapter's work total (it passes exactly when the owner's
row passes, and cannot fail independently).

| Deliverable | OWNER (keeps the real row) | Pointer (becomes a reference) |
|---|---|---|
| Wire the six never-run live server-DB DR/backup suites into CI | **HA-02** (P0) | STORE-44 |
| ADR 0102 live seed gate on a real server DB | **HA-48** (P0) | STORE-46 |
| Config-only `.mfbak` + `DbaDelegatedError` on a server DB | **STORE-45** (P1) | HA-56 |
| Engine-shard recovery correctness (`test_shard_recovery_{sqlserver,postgres}.py`) | **PIPE-01 / PIPE-14** | PERF-07 / PERF-09 |
| Engine-shard cert ladder (`test_shard_cert_sqlserver.py`, perf/cert behaviour) | **PERF-10** | PIPE-39 |
| Purge/retention **correctness** | **STORE** (keeps its rows) | — |
| Purge/retention **under sustained load** (measurement) | **PERF-29 / PERF-31** | STORE-18 |
| Store vintage / schema-upgrade matrix (pre-migration fixture DB, alternating-hash opens) | **MIG-06 / MIG-09 / MIG-10** | STORE-40, 41, 42, 43 |
| `check --strict-handler-security` as a CI leg | **SEC-35** | CFG-08 |
| Reload-root confinement | **PUB-49** | MIG-48 |
| **FEATURE-MAP drift guard** (one consolidated row extending `tests/test_feature_map_claims.py`) | **MIG** (single new row) | PIPE-36, PIPE-37, STORE-53, HA-57, CFG-55, PUB-64, API-66, API-67, WEB-55, IDE-67, ALERT-65, SEC-08, PERF-56, CONN-32, CONN-33 |
| "Doc paths resolve" linter (one row) | **MIG** (single row) | WEB-56, SEC-09, MIG-35 folded in |
| `[console]` extra / `check_console_importable` provenance | **TRAY** | MIG-18, WEB-58 |
| `harness/acceptance/matrix.py` A7 retirement | **TRAY** | WEB-58 |
| `/metrics` cardinality + scrape cost | **ALERT-40 / ALERT-61** | API-54 |
| ADR-status-vs-code hygiene guard | **SEC-01** | PIPE-35, CONN-37, STORE-54 |

**Read the two purge/retention entries together:** they are a **split, not a duplicate**. `STORE`
keeps its purge/retention **correctness** rows outright (nothing points away — hence the `—`), while
the same behaviour **under sustained load** is a `PERF` *measurement*, so only `STORE-18` becomes a
pointer. Different assertions, different rigs, both survive.

**The two largest consolidations** are the FEATURE-MAP drift guard — **fifteen** near-identical
chapter rows collapsing into one `MIG` row extending
[`tests/test_feature_map_claims.py`](../../../tests/test_feature_map_claims.py) — and the "doc paths resolve"
linter, which collapses three.

**Why a pointer row is `Cls T` even when its owner's row is `C`.** The pointer asserts a *checkable*
fact — that the named owner row exists and covers this deliverable — which the index linter (§0.5.3)
falsifies the moment the owner ID is renamed, withdrawn, or never written. It contributes no
independent work and no independent gate weight: the owner's row, and the owner's class, govern
whether the underlying deliverable can block a release.

### 0.5.3 Cross-document ID prefixes (`FCP:` / `W25:`) — mandatory

§0.1 rule 3 states this convention. This subsection is its **enforceable** form, because the rule was
stated once and then used **zero times** across the seventeen chapters — which is precisely how the
two collisions below survived into the draft.

**The rule, in three lines.**

1. A **bare** ID (`HA-20`, `API-13`, `STORE-04`) **always** means *this plan's own Part II row*. No
   exceptions, no "obvious from context". Bare cross-*chapter* citations are fine — they still resolve
   inside Part II.
2. Every reference to **another document's** ID carries that document's prefix: **`FCP:`** for a
   [`FEATURE-COVERAGE-PLAN.md`](../FEATURE-COVERAGE-PLAN.md) gap ID (`FCP:HA-20`,
   `FCP:API-13`, `FCP:P7`, `FCP:DEPLOY-27`); **`W25:`** for a WIN2025 test, matrix row or section
   (`W25:S2.1`, `W25:S1.AC-3`, `W25:§C`). The acceptance runner's own rows already follow the same
   shape and keep it — `ACC:A7`, `ACC:F7` ([`harness/acceptance/matrix.py`](../../../harness/acceptance/matrix.py)).
3. ADR and BACKLOG numbers keep their existing unambiguous forms (`ADR 0101`, `BACKLOG #219`); they do
   not collide with the `<PREFIX>-<nn>` space and take no prefix.

**The two real collisions, worked.**

| Where | Bare ID | This plan's row | The foreign row | Correct forms |
|---|---|---|---|---|
| `12-ha.md` | `HA-20` | The chapter's own HA-20 test row | The coverage-plan gap **`FCP:HA-20`**, *"Web console HA / cluster page … legacy PySide6 only: test_console_status.py; **NO webconsole test**"*, verdict *"Web console (in scope) has no HA surface; only deprecated PySide6 renders the `/cluster/` routes"* — [`FEATURE-COVERAGE-PLAN.md:1201`](../FEATURE-COVERAGE-PLAN.md), inside §16 *HA / active-passive clustering & failover*, lines **1174–1213** | `HA-20` for this plan's row; **`FCP:HA-20`** for the gap |
| `17-api.md` | `API-13` | The chapter's own API-13 test row | The coverage-plan gap **`FCP:API-13`** — *"Resend API (RESEND step-up, cross-channel, idempotency, retention-null 409, FIFO funnel)"* ([`FEATURE-COVERAGE-PLAN.md:1147`](../FEATURE-COVERAGE-PLAN.md), §15 *FastAPI engine API surface* `[API]`) | `API-13` for this plan's row; **`FCP:API-13`** for the gap |

Both files carried **two different rows under one identifier** — the same failure mode the ledger gate
exists to stop in the ADR/BACKLOG ledgers ([`docs/LEDGER-GATE.md`](../../LEDGER-GATE.md)): two writers,
one number, a clean merge, a corrupted index.

**Maintenance — this is checked mechanically.** A convention that is only stated is a convention that
is not applied. The machine-checkable index test described in §0.9 (IDs unique, referenced files
exist, referenced ADR/BACKLOG numbers resolve) takes **one more rule**: *every bare `<PREFIX>-<nn>`
occurrence in Part II must resolve to a row allocated somewhere in Part II* — anything that does not
resolve, or that is known to name a `FEATURE-COVERAGE-PLAN` gap or a WIN2025 row, **fails the check**.
An unprefixed foreign ID is a defect in the deliverable, at the same standing as a broken file path.

---

## 0.6 Entry & exit criteria

### A test cycle

A *cycle* is one bounded pass over a defined scope (a chapter, a phase of the coverage plan, or a
campaign such as a box-acceptance run).

**Entry:**

1. The scope is written down as a set of test IDs, with Pri assigned.
2. `main` (or the campaign's base) is green on the required contexts: `test (ubuntu-latest, py3.14)`,
   `test (windows-2022, py3.14)`, `test (windows-2025, py3.14)`, and `CI gate`.
3. Every environment the scope needs is reachable and its gate is set — `MEFOR_TEST_SQLSERVER` /
   `MEFOR_TEST_POSTGRES` for server-DB legs, the box for `win2025-box`, the rig for `perf-rig`.
   **An unreachable backend produces `SKIP`, and a `SKIP` is never read as a pass.**
4. Synthetic, PHI-free corpora are in place (`messagefoundry generate`, the harness corpus, or an
   anonymized dataset produced by the ADR 0030 framework). No real PHI, ever.
5. For any `PERF` row: the falsifier is **pre-registered in writing before the first run** (ADR 0101).

**Exit:**

1. Every P0 **`T` row** in scope **executes and passes** on every Backend/Env its row declares. No
   structural-only substitutes for an `XBE` row. (`C` rows in scope are *recorded*, not passed; `A`
   rows follow §0.4.4.)
2. Every P1 **`T` row** in scope passes, or carries a dated owner deferral plus a FEATURE-MAP status
   adjustment.
3. No new `SKIP` appears that was previously a `PASS` (a silently self-skipping suite is a regression).
4. `ruff check` + `ruff format --check` + `mypy` (strict) + `pytest` are green
   (`QT_QPA_PLATFORM=offscreen` for the Qt harness tests).
5. Every defect found is either fixed **with a regression test carrying a Part II ID**, or filed as an
   allocated BACKLOG item with a severity (§0.8).
6. No PHI in any artifact produced by the cycle — reports carry IDs, counts, dispositions, SQLSTATEs
   and timings only.

### A release

**Entry:** a release candidate commit on `main`; CHANGELOG drafted; version single-sourced.

**Exit — all must hold:**

| # | Criterion | Evidence |
|---|---|---|
| 1 | Full CI green, including the nightly-only heavy legs, on the RC commit | `gh workflow run ci.yml --ref main` (`workflow_dispatch` runs **everything**), not merely the last nightly |
| 2 | Every **P0 `T` row** across all 17 chapters passes | Part II status columns + each chapter's §x.4 class declaration |
| 3 | Cross-backend (`XBE`) P0/P1 **`T`** rows executed on **all three** backends | `sqlserver-store`, `postgres-store`, and — for the real-server leg — `selfhosted-win2025-sql.yml` job `sqlserver-real` |
| 4 | A WIN2025 box-acceptance pass with no FAIL, and every MANUAL row human-closed | `python -m harness.acceptance` report + the matrix Status column ([`WIN2025-ACCEPTANCE.md`](../WIN2025-ACCEPTANCE.md)) |
| 5 | `messagefoundry verify` green per backend on the target box, including `--smoke live --check-disposition` | Saved `--report-md` / `--report-json` (metrics only) |
| 6 | Windows service install/run/uninstall proven on both Server SKUs | `ci.yml` job `windows-service-smoke` |
| 7 | Container path proven | `ci.yml` job `docker-smoke`; `manifest-lint.yml` job `kubeconform` for the k8s manifests |
| 8 | Security workflows clean or with dated, reasoned acceptances | `security.yml` (all 9 jobs), `codeql.yml`, `zizmor.yml`, `scorecard.yml` |
| 9 | Published performance numbers re-measured or explicitly carried forward with their measurement date | `benchmark.yml` baselines + `docs/benchmarks/` |
| 10 | Upgrade path proven from the previous released version on each backend (schema migration + queued-message survival) | `MIG` chapter rows |
| 11 | No open S0 or S1 defect (§0.8) | BACKLOG |
| 12 | Docs that make status claims are true — FEATURE-MAP statuses, BACKLOG banners, CI-QUALITY figures | `backlog-hygiene` + [`tests/test_backlog_status_check.py`](../../../tests/test_backlog_status_check.py) |

**Class filter (per §0.4.4).** Criteria 2 and 3 count **`T` rows only**. **`C` rows** — recorded
measurements, published numbers, dated owner decisions — are *listed* in the release record as
outstanding or landed, and **cannot hold the tag**; each becomes a `T` row on the day its threshold or
decision is recorded. **`A` rows** — third-party assessment, penetration test, DAST — are **advisory
for a loopback-bound, default-posture release and blocking for an off-loopback / production-exposure
release**; §0.10 assumption 8 records their current standing (none to date).

---

## 0.7 Roles, ownership & cadence

**Reality of the team.** One project owner/maintainer, heavy AI-agent assistance, an open-source
contributor path. This plan assigns roles to *functions*, not to headcount, and every recurring
function is automated or it does not happen.

| Role | Who | Responsibilities |
|---|---|---|
| **Test owner** | Project owner | Owns Part I; sets Pri; makes the release go/no-go; the **only** approver for pushes, PRs, merges, and any P1 deferral |
| **Chapter author** | The agent/contributor working the area | Keeps their Part II chapter true: adds IDs for new behaviour, marks WITHDRAWN, records dispositions |
| **Implementer** | Whoever writes the change | Ships the test **with** the change; runs `ruff`/`mypy`/`pytest` before claiming done; never `--no-verify` |
| **Adversarial verifier** | A second agent (Workflow mode) or the owner | Attempts to falsify a claim before it is believed — especially any `PERF` result or any "already covered" assertion. This is a standing role, not a ceremony |
| **Box operator** | Project owner (physically at the Windows Server 2025 box / AD lab) | The MANUAL rows; nothing else can close them |
| **Release manager** | Project owner | §0.6 release exit checklist; the signed `release.yml` run |

### Cadence

| Cadence | What runs | Trigger |
|---|---|---|
| **Per commit (local)** | `messagefoundry check` (validate / dryrun / posture / build-check / reference-backend) via the git hook; the ledger-gate `pre-commit` hook (**a blocking dependency of this plan; owned by `CFG`** — §0.10 carve-out, with its ungated CI `--ci` backstop); `ruff` + `mypy` + the fast `pytest` slice | Developer machine |
| **Per PR** | `ci.yml` `test` on ubuntu + windows-2022 + windows-2025 (py3.14), `ide` (path-gated), `changes`, `CI gate`; `security.yml`; `codeql.yml`; `zizmor.yml`; `quality-advisory.yml` (advisory); `backlog-hygiene`; `cla.yml`; `manifest-lint` (path-gated); plus `sqlserver-store` / `postgres-store` / `docker-smoke` when the path gate says the change touches them | `pull_request` |
| **Post-merge** | `security.yml` on push to `main` (a fork PR is scanned structural-only, so this is the first fully-loaded scan of contributed content) | `push: branches: [main]` |
| **Nightly** | `ci.yml` heavy legs at **03:17 UTC** — `load-test`, `load-test-sqlserver`, `sqlserver-store` (both majors), `postgres-store`, `windows-service-smoke` (both SKUs), `docker-smoke`. `security.yml` daily at **06:00 UTC**. `quality-advisory.yml` at **04:23 UTC**. `freethread-smoke.yml` on its own schedule | `schedule` |
| **On demand** | `gh workflow run ci.yml --ref main` re-runs **everything** including the functional matrix; `benchmark.yml` (`baseline-sqlite` / `-postgres` / `-sqlserver`); `selfhosted-win2025-sql.yml` (`sqlserver-real`) | `workflow_dispatch` |
| **Per release** | The §0.6 release exit checklist: full dispatch run, WIN2025 box pass, per-backend `verify`, upgrade proof, `release.yml` (SBOM + Sigstore + SLSA provenance + PyPI Trusted Publishing) | Tag |
| **Per campaign** | A coverage-plan phase (`FCP:P0`…`P7`), a throughput investigation (pre-registered falsifier, ADR 0101), a parallel-run migration cutover (`harness/reconcile` per Connection), or a box-acceptance exercise | Owner-initiated |

**Standing rule for agents:** substantive test-plan work is a Workflow (multi-agent, adversarially
verified) task, not a solo edit — see `CLAUDE.md` §5. Trivial mechanical edits are exempt.

---

## 0.8 Defect management

### Severity

Severity describes the **defect**; Pri (§0.4.2) describes how much the **test** matters, and Cls
(§0.4.4) whether it can fail at all. They correlate but are three distinct fields.

| Sev | Definition | Response |
|---|---|---|
| **S0** | Realised R1–R4 on a default path: message loss, a duplicate/out-of-order clinical delivery, PHI in an artifact, or a security bypass. Also: any defect already reachable in a released version | Stop-the-line. Fix before other work. Release-blocking. If PHI reached a published artifact, containment (rotation / history) comes before the code fix |
| **S1** | R5–R7, or R1–R4 on an opt-in path: a disposition that never finalizes, an unroutable alert, a failed install/upgrade, a bad publish accepted by the gate | Blocks the affected feature's release. Fix or downgrade the feature's FEATURE-MAP status |
| **S2** | Correct behaviour, wrong ergonomics: a confusing error, a missing diagnostic, a slow-but-correct path, an unhelpful log | BACKLOG item; scheduled |
| **S3** | Cosmetic / docs / tidy-up | BACKLOG item; opportunistic |

### BACKLOG and the ledger

- A defect that is **not fixed immediately** becomes a numbered item in
  [`docs/BACKLOG.md`](../../BACKLOG.md) carrying its severity, the failing test ID (or the ID of the
  test that *should* have existed), and the originating review/campaign.
- **Numbers are allocated atomically — never grepped.**
  `pwsh -NoProfile -File scripts\coord\alloc.ps1 -Kind backlog -Title "<title>"` (same for
  `-Kind adr`), with the ADR's index row added in the *same* commit. A `pre-commit` hook rejects a
  number that was not allocated. Rationale and the three real collisions:
  [`docs/LEDGER-GATE.md`](../../LEDGER-GATE.md).
- **Shipping an item updates its banner in the same PR.** Structural enforcement:
  [`tests/test_backlog_status_check.py`](../../../tests/test_backlog_status_check.py) (every item declares
  exactly one status). Behavioural enforcement: `.github/workflows/backlog-hygiene.yml` job
  `banner-on-implementation` — a PR that says `BACKLOG #N` and touches engine/IDE code must also
  update `docs/BACKLOG.md`.

### The closure rule

> **A P0 gap does not close without a regression test.**
> Closing a P0 requires an executable assertion that **fails against the unfixed code**. "Fixed and
> manually verified" is not closure; neither is a test that passes both before and after. For a
> design-only or dormant item, closure is a written build-or-supersede decision **plus a guard test
> that the recorded status still holds** — the discipline the coverage plan already applies in its
> `FCP:P7` dispositions.

Red-first is the norm here, and the repo has the receipts: ADR 0141 pins its published counter with
`test_the_rendered_copies_per_message_matches_the_2_H_N_model` and a red-first
`test_unwired_body_copies_renders_not_measured_never_zero` so an unwired counter can never render a
fabricated `0.00/msg`.

### Falsifier discipline (existing, in force)

[ADR 0101](../../adr/0101-pre-registered-falsifier-discipline-for-performance-measurement.md) —
*Pre-registered falsifier discipline for performance measurement* — is binding on every `PERF` row and
on any claim that will inform a build decision:

- **Every performance investigation is pre-registered as a falsifier.** A run that cannot come back
  "no" is not an experiment and its output is **not admissible**.
- The error class it defends against is *naming a cause from an adjacency* — from a wait's rank, a CPU
  share, or a growth rate. Five documented instances, four different people/agents, one error class.
  On a collapsing system almost everything grows.
- The same discipline extends to the **instruments**: a fixed constant bounding a parameter-scaled
  interval that, on expiry, fabricates a plausible result is a recognised bug class in this repo, with
  a structural guard tracked as BACKLOG **#219** (harness-invariant property test + cross-observer
  `INCONCLUSIVE` guard). A rig that can fabricate is a defect at the severity of what it certifies.
- Retraction is a **normal, expected outcome** and is recorded, not buried — see the coverage plan's
  own "Verification errata" block, which retracted two of its own findings after spot-checking them
  against the code.

---

## 0.9 Traceability

Every test ID answers "why does this exist?" by pointing at one or more of three durable anchors.

| Anchor | Form | Example of the linkage |
|---|---|---|
| **ADR** | `docs/adr/NNNN-*.md` (148 records; latest allocated `0153`; index at `docs/adr/README.md`) | A test cites the ADR whose decision it enforces — e.g. a purity/at-least-once row cites ADR 0001; a tray-boundary row cites ADR 0113; a Steps-view codegen row cites ADR 0076/0089/0106/0108 |
| **BACKLOG item** | `docs/BACKLOG.md` `## N.` | A test that closes a deferred item, or a guard that keeps a shipped item honest |
| **FEATURE-MAP row** | `docs/FEATURE-MAP.md` §1–13 | A ✅ ("shipped on `main`") row must be reachable from at least one P0 or P1 test ID |
| **Coverage-plan gap** | `FCP:<ID>` | Where the test was commissioned by the gap audit |
| **WIN2025 row** | `W25:<row>` | Where the proof is box-owned |

### The forward rule

> **A new ADR ships with its test IDs.**
> An ADR that records a *built* decision must, in the same PR, list the Part II test IDs that enforce
> it (or state, explicitly, that it is design-only and carries a status guard test instead). An ADR
> with no test IDs and no explicit design-only declaration is an incomplete ADR.

This mirrors what the repo already does informally: ADRs here cite their pinning tests inline (ADR 0141
names `tests/test_bytes_per_message_amplification.py`; `docs/TRAY.md` names `tests/test_tray_boundary.py`
and `tests/test_api_health_tokenless.py` as the frozen boundary).

### The reverse rule and its guard

Traceability must survive refactoring, so the **binding is asserted by a test wherever it can be**:
[`tests/test_win2025_acceptance.py`](../../../tests/test_win2025_acceptance.py) already proves every matrix row
binds to a registered probe, that every referenced pytest file exists, and that no probe raises — "so
the matrix can't silently rot". Part II adopts the same pattern for its own index: the chapter tables
are machine-checkable (IDs unique, referenced files exist, referenced ADR/BACKLOG numbers resolve, and
no bare foreign ID appears — §0.5.3), and that check is itself a test.

**Two resolver caveats — the publishing boundary, not a coverage gap.** This repo is the **public**
repo, and two classes of valid citation are deliberately not readable from it. A link checker that
does not know this will flag sound evidence as broken, and a reviewer who does not know it will read
"absent" as "does not exist":

- **BACKLOG items above #231.** The committed [`docs/BACKLOG.md`](../../BACKLOG.md) is a **published
  baseline that stops at `## 231.`**; the programme continued past it. The file says so itself at
  [`docs/BACKLOG.md:6041`](../../BACKLOG.md) — *"the file you are reading ends at #231, while #242–#246
  and their successors do not appear in it at all … their absence here is a publishing boundary, not
  evidence of completion."* Citations above the baseline (e.g. #233, #275, #310) are **sound
  evidence**; the resolver treats them as valid and never disclaims them. Where a reader may be
  helped, the only permitted annotation is neutral — *"(above the published #231 baseline)"* — used
  sparingly.
- **`docs/security/`, `docs/reviews/`, `docs/marketing/`** are **gitignored post-cutover**
  (`.gitignore:144-146`) — ~32 files of posture, assessment, risk-register and runbook detail withheld
  because published in full they are an attacker roadmap. A document such as
  `docs/security/OFF-LOOPBACK-DEPLOYMENT.md` or `docs/security/ASVS-*` is **real and current**; it is
  simply not readable here. Part II describes any such reference as **withheld from the public repo**,
  never as "missing", "absent", or "does not exist", and never counts its unreadability as a coverage
  defect.

**Known drift to fix, not to inherit:** `docs/FEATURE-MAP.md` §10 is still titled *"Surfaces — Admin
Console (PySide6)"* even though the PySide6 desktop console is retired and the web console at `/ui` is
the sole operator console. Part II's `WEB` chapter maps those capability rows to the web console; the
FEATURE-MAP heading should be corrected separately.

---

## 0.10 Assumptions & explicit non-goals

### Assumptions

1. **Python 3.14 is the only supported runtime.** Every CI leg runs py3.14; no multi-version matrix.
2. **Windows Server (2022 / 2025) under NSSM is the primary deployment target**; Linux/container is a
   supported secondary path proven by `docker-smoke` and `manifest-lint`.
3. **Three store backends, one unified store.** SQLite (single-node default), SQL Server (the promoted
   production store), PostgreSQL. **Engine shards** share ONE store.
4. **All test traffic is synthetic and PHI-free** — `messagefoundry generate` corpora, the harness
   corpus, or datasets produced by the ADR 0030 de-identification framework. `dryrun` / `generate` /
   `--show-phi` output is treated as body-bearing and is never redirected to a committed file, a
   ticket, or a CI log.
5. **The engine binds `127.0.0.1` and requires authentication by default.** Off-loopback TLS exposure
   is a configured posture with its own guards, not the default under test.
6. **Routers and Handlers are pure**, with the two sanctioned read-only carve-outs (`db_lookup`,
   ADR 0010; `fhir_lookup`, ADR 0043), whose results may legitimately differ on a replay.
7. **A green CI run is a *necessary* condition, not a sufficient one.** The box-owned and
   manual rows exist precisely because CI cannot see service identity, DPAPI across the
   admin→service boundary, reboot autostart, AD/Kerberos, or a real trusted-cert TLS store connect.
8. The security posture is a **point-in-time, AI-assisted self-assessment** — not a certification, not
   an audit, and with **no third-party assessment, penetration test, or DAST to date**. This plan does
   not change that; it only makes the self-assessment's assertions executable.

### Non-goals of this plan

| Non-goal | Why |
|---|---|
| **Restating any owned artifact** | §0.5. The WIN2025 procedure, the `verify` semantics, the load-rig knobs, and the 128-gap audit are cited, never copied |
| **A parallel test framework** | Part II schedules work into the *existing* rigs. The acceptance runner already makes this rule explicit for itself; it holds for the whole plan |
| **A coverage-percentage or mutation-score gate** | Weak and gameable as single numbers — surfaced by `quality-advisory.yml`, never required |
| **Testing declined-by-design features** | Visual / template-driven authoring (BACKLOG #26, with the narrow structured-Steps-view carve-out), serial RS-232 / ASTM lab connectivity (#27), and **database**-tier sharding (ADR 0039, L5 — shelved) are recorded as declined and never tested |
| **Re-commissioning settled dead ends** | Group-commit, inline fusion, and the transaction lever were settled by falsifier (ADRs 0098 / 0107 and the coverage plan's `FCP:P7`); they get dormancy guard tests, not new performance work |
| **A "channel"/"route" element** | There is no such built object; nothing in Part II may assume or introduce one |
| **Real-PHI testing of any kind** | Categorically excluded (§0.10 assumption 4) |
| **Procuring third-party certification, penetration testing, or DAST** | This plan does not commission or perform them, and all three remain open, acknowledged gaps in the security posture (assumption 8). Where a chapter *does* scope one, it is recorded as a **`Cls A`** row (§0.4.4) — advisory for a loopback-bound release, blocking for an off-loopback / production-exposure one — so the gap stays visible and counted instead of merely disclaimed |
| **Governance/authoring tooling as a product surface** (**the ledger *gate* excepted — see below**) | Named exhaustively so the boundary is checkable: **`adr-analyze`**, **`scripts/coord/`**, **`scripts/worktree/`**, **`scripts/bench/`** (`stage_residency.py`), **`scripts/dev/`** (`postgres.ps1`, `sqlserver.ps1`, `sqlserver-docker.ps1`, `setup-leak-gate.ps1`), **`scripts/tray/`** (`make_icons.py`) and **`scripts/kerberos_epa_spike.py`** are *development* infrastructure, not shipped surfaces: nothing an operator installs or runs in production depends on them. They may carry their own tests; they carry **no Part II chapter, no test IDs, and no gate weight** |
| **Load/throughput target-setting** | This plan requires that a performance claim be measured with a pre-registered falsifier; it does not set the numbers. Targets live in `docs/BACKLOG.md`, `docs/THROUGHPUT.md`, and the benchmark records |

**Carve-out: the ledger gate is in scope, and is owned by `CFG`.** The row above would otherwise
contradict the rest of this plan, so the boundary is drawn explicitly. The *authoring tooling* around
the ledger (`scripts/coord/alloc.ps1`, `adr-analyze`) is excluded as development infrastructure. The
**ledger gate itself is not**: §0.7's cadence table makes the `pre-commit` hook a **blocking
per-commit dependency**, and §0.8 makes atomic allocation the only lawful way to number a defect —
a plan that depends on a gate at every commit cannot also declare it untested. Its behaviour is therefore a **`CFG`** chapter
deliverable with its own test IDs: refuse an unallocated ADR/BACKLOG number, require an ADR's index
row in the same commit, and — the part that actually holds — the **CI backstop**, which re-runs the
same rules with `--ci` against a freshly fetched `origin/main` and is *deliberately ungated* in
`ci.yml`. The `pre-commit` hook alone is explicitly "a guardrail, not a security boundary"
(`git commit --no-verify` bypasses it, [`docs/LEDGER-GATE.md`](../../LEDGER-GATE.md) §3), so the
assertion worth owning is the backstop, not the hook. What is out of scope is everything the gate is *not*: the allocator's ergonomics, the
worktree helpers, and the ADR analysis tooling.
