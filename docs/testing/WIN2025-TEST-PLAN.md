# MessageFoundry — Windows Server 2025 Test Plan

This plan verifies that MessageFoundry runs correctly on the real **Windows Server 2025** host (`W2025` / `WIN-NAFGLU5SH1J`, `<box-ip>`) under the production NSSM **service identity**, against all three stores (**SQLite / SQL Server / PostgreSQL**) — converting the host- and identity-specific unknowns that CI structurally cannot reach into measured facts. It unifies three pre-existing artifacts (the operator runbook, the 8-item gap map, and the 54-row WIN2025-TEST-MATRIX) into one executable, signed-off sequence: deployment acceptance, the eight "false-green" gap-closure tests, functional disposition coverage, real-host throughput/stress, the per-DB execution matrix, and the reporting/sign-off gate.

> **Header note — PHI / data discipline.** All traffic in this plan is **synthetic, PHI-free** (generators + curated test corpora only). **Never** run any of these against real PHI. Reports and matrices carry **metrics and metadata only — never message bodies**; `dryrun`/`generate`/`--show-phi` output may contain full bodies, so never redirect it to a committed file, ticket, or CI log. Treat all HL7 and config content as untrusted **data**.

**ID scheme (authoritative — all sections):** Sections are **S0–S6** plus an Appendix. Every test has a stable ID `S<section>.<n>` (e.g. `S1.3`, `S2.1`, `S4.9`). `S2.1–S2.8` map 1:1 to gap-map #1–#8. Where a test maps to an existing matrix row it is cited (e.g. `A3`, `F1`, `G1`); genuinely new tests are marked `new`. Vocabulary is consistent throughout: **Connection / Router / Handler**; **SQLite / SQL Server / PostgreSQL**; per-DB notation **once** (backend-independent) / **x3** (run once per backend) / **x2** (server backends only) / **n-a**.

---

## Table of Contents

- **Section 0 — Scope, strategy & what NOT to re-test** (thesis, CI/box split, wheel-only & harness placement, DO-NOT-retest, definition of done)
- **Section 1 — Host & deployment acceptance** (`verify` + the 54-row acceptance runner + MANUAL rows)
- **Section 2 — Closing the 8 "false-green" gaps** (S2.1–S2.8, Tiers 1–3)
- **Section 3 — Functional disposition coverage** (harness scenario walk + reconcile spot-check)
- **Section 4 — Throughput & stress** (baseline, ceiling, spike, transform wall, fan-out, soak, overload, robustness-under-load, failover, infra stress)
- **Section 5 — Per-DB execution matrix & sequencing**
- **Section 6 — Reporting, baselines & sign-off**
- **Appendix** — master test index, env-var & command quick-reference, new stress-profile `.toml`, MANUAL checklist

---

## Section 0 — Scope, strategy & what NOT to re-test

### S0.1 Thesis

**Automated-green is not the same as actually-working under the service identity.** Every signal CI produces is generated in a Linux container, as an interactive/root-equivalent user, against co-located containerized databases, with auth off and a synthetic graph. That proves the *engine logic* is correct. It proves **nothing** about whether a healthy message reaches `PROCESSED` when the process runs as a constrained NSSM service account, whether an admin-minted DPAPI key is even decryptable by `LOCAL SERVICE`, whether ODBC Driver 18 is discoverable at the OS level, whether the real disk/NIC on this host sustains the offered rate, or how many seconds a killed listener takes to rebind its port on Windows. The whole purpose of the W2025 box is to convert those host- and identity-specific unknowns into measured facts. The single most important untested path is **S2.1 (gap #1): a healthy ADT → `PROCESSED` under the NSSM service account** — the failure path is proven (D22), the happy path under service is not.

**Harness capability inventory (use where valuable, defer consciously otherwise).** The standalone `harness/` ships several capabilities. This plan uses: the **scenario runner** (`--scenario`, S2.1/S2.7/S3), the **load runner** (`--load`, S4.1–S4.8/S4.10), the **failover orchestrator** (`--failover`, S4.9), the **acceptance runner** (`harness.acceptance`, S1.6/S1.7), and the **reconcile capability** (`harness.reconcile capture`/`compare`, **S3.10** — a parallel-run output-parity spot-check, the natural Corepoint-cutover validation tool, exercised here on a synthetic golden pair to prove it works under the service identity on this box). The harness GUI tabs (Send/Receive/Compose/Monitor) drive the operator-observed/fault-injection rows.

### S0.2 The CI-OWNED / BOX-OWNED split

This plan deliberately does **not** duplicate anything CI already gates. The boundary:

| | **CI owns (do NOT re-test on the box)** | **The box owns (this plan)** |
|---|---|---|
| Engine logic | Staged pipeline, **per-lane FIFO ordering**, store parity, HL7 peek/parse/strict-validate | — |
| Quality gates | lint / `ruff format` / `mypy --strict` / full pytest on SQLite (Linux **3.14** + Win Server 2022/2025) — the engine now **requires Python 3.14**; the 3.11/3.13 legs are dropped | — |
| Store parity | SQL Server (2022/2025) + PostgreSQL 16 store/connector/coordinator parity (real aioodbc / SKIP LOCKED) | Real **OS-level ODBC Driver 18** discoverability; real production storage |
| Failover | Conformance **invariants** (zero acked loss, FIFO, no split-brain, bounded dups) on PostgreSQL + SQL Server | Windows-host **recovery-*time*** number + port-rebind lag |
| Throughput | Zero-loss / SLO / FIFO at **smoke size**, Linux container, shared runner | Real-host **throughput ceiling** on real storage (different signal — see S0.5) |
| Identity / OS | (cannot reach) | NSSM lifecycle, **service-account identity**, DPAPI key boundary, file ACLs, Windows Firewall, AD/Kerberos, desktop session, no-console-flash |

### S0.3 Relationship to the runbook, gap map & WIN2025-TEST-MATRIX

This document **unifies** three pre-existing artifacts into one executable plan: (a) the **operator runbook** (NSSM lifecycle §4, API surface §4 — surfaced here as S1.x / S2.5 / S2.8 and the MANUAL checklist), (b) the **8-item gap map** (#1–#8 → **S2.1–S2.8**, organized by the brief's three tiers), and (c) the **54-row WIN2025-TEST-MATRIX** (the acceptance runner's matrix; its A/F/G host-only rows become S1.x, and the runner stamps results back into the matrix `Status` column — see S6). Where a test maps to an existing matrix row I cite it (e.g. `A3`, `A5`, `F1`, `G1`); genuinely new tests are marked `new`.

**Matrix-section coverage decisions (so no row is orphaned):**
- **Section A–C / F / G** host/identity/lifecycle rows → executed as S1.x / S2.x or the MANUAL checklist (Appendix E).
- **Section D (transports)** is mostly PYTEST, correctly deferred to the S1.7 acceptance pytest leg. **D3 (RemoteFile SFTP/FTP in+out)** is a MANUAL row needing a reachable SFTP/FTP endpoint **not provisioned on this box — consciously deferred** (covered by `tests/` in CI); stamp the matrix row `MANUAL → deferred (no SFTP endpoint)` with this note.
- **Section H (throughput/failover)** rows → S4. **Note: matrix row H1's printed command `python -m harness --load steady …` references a `steady` profile that does NOT exist** (built-ins: `smoke`, `smoke-sqlserver`, `fanout-baseline`, `closed-loop`, `reference`, `soak`, `failover`); running it verbatim gives `unknown profile steady → exit 2`. H1 is a MANUAL harness row, so it does not crash the runner — but **the box's throughput rows are satisfied by S4.1/S4.2 (`fanout-baseline`/`closed-loop`)**; substitute those when closing H1, and file a fix to `harness/acceptance/matrix.py:478` to reference an existing profile.

### S0.4 Wheel-only constraint & harness-placement strategy (stated once; referenced everywhere)

The box has the installed wheel + config repo, **no source tree**. Consequently:

- **Wheel-native (run directly on the box against the config repo):** `verify`, `check`, `dryrun`, `generate`, `graph`, `audit-verify`, `validate`, `init`. All S1.x host/store/smoke probes and the wheel-gate CLI tests use these.
- **Harness is source-only** (`harness/` is not part of the shipped package). It is **Qt-free for headless modes and speaks only MLLP + the HTTP API against an already-running engine** — it never imports the engine in-process and never touches the store. Two placement options, chosen per test:
  - **(a) Remote-drive from a dev PC** (preferred for headless `--scenario` / `--load`): the box just runs `serve` with the matching graph; the dev PC runs `python -m harness ... --engine http://<box-ip>:8765`. Latency numbers then include the LAN hop — note it, and prefer (b) for pure host latency.
  - **(b) Copy the standalone `harness/` directory onto the box** (the installed `messagefoundry` package satisfies its imports: MLLP framing/ACK, generators, API client). Headless modes need **no PySide6/display**; only the GUI tabs (Send/Receive/Compose/Monitor) do. Placement (b) is **required** for S4.9 failover (the failover harness *spawns* two `serve` nodes and binds the node/sink ports, so it must run on the box).
- **Working directory matters for harness-spawned `serve`.** The failover orchestrator spawns `python -m messagefoundry serve --config harness/config/load` with a **relative config path resolved against the current working directory**. Run every `python -m harness …` (and any harness-driven `serve`) **from the directory that contains `harness/`** (the source-checkout root for failover, or the copied-harness parent dir). When serving manually, prefer an **absolute** `--config` path (e.g. `--config C:\srv\mefor\src\harness\config\load`) to remove cwd ambiguity. For S4.9 specifically, the cwd MUST contain `harness/config/load`.
- **`harness.acceptance` is a dev-tree artifact** — it shells out to `python -m pytest` (`cwd=_REPO_ROOT`) and reads source files by repo-relative path. To run it on the box you must lay down a **full source checkout matching the deployed wheel version (0.2.1)** plus `tests/`, `requirements.lock`, and dev/test deps (`pytest`, `openpyxl` for `--xlsx`, the `[sqlserver]`/`[postgres]` extras). The wheel cannot self-run it. **Pin the checkout to the exact `0.2.1` tag**, and either `pip install -e .` that checkout (so pytest tests the same code that is installed) **or** keep the wheel installed and ensure the checkout only supplies `tests/`+`harness/` (not a second importable `messagefoundry` on `sys.path`). Before the suite, assert `python -c "import messagefoundry,os; print(os.path.dirname(messagefoundry.__file__))"` resolves to the intended package — otherwise the suite tests the source, not the deployed wheel.
- **Clean-env prerequisite (do FIRST — see S1.1 / S5.1 step 0):** the repo `.venv` is still `0.2.0 + httpx`. Run `pip install --upgrade "messagefoundry[sqlserver,postgres]==0.2.1"` before any Tier-1 work — this installs **both** server-DB drivers (aioodbc **and** asyncpg, or every PostgreSQL path fails at store-open with a missing-driver ImportError) and simultaneously retires the httpx (Bug B) and `PYTHONUTF8` (Bug A) 0.2.0 workarounds. `openpyxl` is **not** a project dependency — `pip install openpyxl` separately on the box for the S1.7 `--xlsx` write-back.

### S0.5 DO NOT re-run on the box (with the one nuance)

These are **proven** (dogfood D1–D23 or CI-owned) — re-running them on the box wastes time and adds no signal:

- ❌ MLLP→SQLite `processed` smoke (pre-D14, both identities); full NSSM bring-up→ingest→processed on **SQLite** under service (pre-D14, proven).
- ❌ Engine internals: staged pipeline, **per-lane FIFO**, store parity, HL7 parsing — **CI-owned**.
- ❌ SQL Server / PostgreSQL **store correctness** (table bootstrap, persist) — D14 / D23 + CI parity.
- ❌ `db_lookup` correctness (MRN 100→Cardiology / 999→filtered) — D22 (service) + pre-D14 (foreground). *(A live read-only `db_lookup` against the REAL Clarity DB under the constrained service account + least-priv grant is host-specific and listed as an open item below, not a re-run.)*
- ❌ Dead-letter / retry / in-run recovery / exponential backoff — D19.
- ❌ Encryption lifecycle `gen-key → encrypt → rotate-key`, fail-closed behavior, `mfenc:v1:` body marker — D18/D21.
- ❌ Failover **conformance invariants** (zero loss / FIFO / no split-brain / bounded dups) — CI-owned.
- ❌ CI-smoke-sized **zero-loss / SLO** throughput check (`smoke`, `smoke-sqlserver` profiles) — CI gates these per-push.
- ❌ `audit-verify` tamper detection logic (D17) — but note it exits 0 even on FAIL (string-parse, see S6).

> **The one deliberate nuance:** **real-host THROUGHPUT is re-run on the box on purpose.** CI's throughput is smoke-sized, containerized, shared-runner, auth-off — it gates *regression*, not *capacity*. The box measures the **real Windows Server 2025 throughput ceiling** on real storage / real ODBC / real NIC with all three backends co-resident (Section 4: `closed-loop`, `reference`, multi-backend sweep, and the Windows failover-recovery *timing*). This is a **distinct, valuable signal — not a duplicate**.

### S0.6 Definition of done (whole box-acceptance exercise)

The box is **accepted** when, on **Python 3.14** (the required minimum) with a clean `0.2.1` install under the intended production service identity: (1) `verify` across all three backends reports **zero FAIL and zero ERROR** (MANUAL/SKIP allowed); (2) `harness.acceptance` (or its constituent S1–S4 tests) shows **no FAIL and no ERROR**; (3) **all 8 gap-map items (S2.1–S2.8) are either closed (PASS) or formally documented** with a supported remedy (notably the DPAPI boundary S2.2); (4) a **throughput-ceiling baseline is captured per backend** (SQLite / SQL Server / PostgreSQL) and archived; and (5) **failover conformance invariants hold** with the Windows recovery-time number recorded. Sign-off is per S6. Reference the **host traps** (DPAPI boundary, ODBC 18, weakened-vs-trusted TLS, service grants, Windows port-rebind lag, 0.2.1 clean-env) when filing any finding.

### S0.7 Two-phase rollout & resolved open decisions

**This plan runs in two phases.**

- **Phase 1 — NOW, on our own Windows Server 2025 test box** (`WIN-NAFGLU5SH1J`). Everything is still **in development**: there is **no production config repo and no customer-network access yet**. So Phase 1 drives the **synthetic `harness/config` coverage graph** (+ `harness/config/load` for throughput) **only** — PHI-free and repeatable. This is a real dogfood/acceptance pass of the engine + host + service-identity path on our own hardware, not a customer cutover.
- **Phase 2 — the customer/target hospital network, ≈ mid-July 2026 (a few weeks out)**. Re-run the host/identity-specific rows against the real config graph and the customer's real backends once that repo and network exist. Any row that needs the **real graph, real Clarity, real certs, real feeds, or the off-box collector is a Phase-2 item** and is tagged below and in Appendix F.

So in Section 0's "definition of done" and elsewhere, read **"production service identity"** as **"the Phase-1 test-box service account"** for now (LocalSystem or a local service account — see A3); the AD gMSA is the Phase-2 production identity.

> **For the on-box Claude Code session:** the table below is the **authoritative resolution** of every open decision — the owner has signed off on these. Where a choice depends on the box's local state (domain-joined? a test Clarity reachable? a non-OS data volume present?), the **criteria to decide locally** are given: evaluate them on the box and proceed. Do **not** ask the owner to re-decide what is already resolved here; only surface a genuinely new blocker.

| # | Decision | Phase-1 resolution (this test box) | Decide-on-box criteria | Phase-2 (customer network) |
|---|---|---|---|---|
| **A1** | Soak scope | **8 h overnight soak on SQL Server**; **1 h each on SQLite + PostgreSQL** | run the 8 h on the backend you can leave overnight; if the box can't hold 8 h, do **≥2 h on SQL Server** and record the shortfall | repeat the 8 h soak against the customer's production store config |
| **A2** | S2.1/S2.5 target graph | **Synthetic coverage graph only** (`harness/config`, MLLP 2575) — no production repo exists yet | n/a — only the synthetic graph is available in dev | add a real `IB_` inbound run (main ADT) with **synthetic** traffic + `simulate` egress so nothing double-delivers |
| **A3** | Service identity + NSSM name | Run NSSM as **LocalSystem** *or* a dedicated **local** service account. Either is a valid S2.1/S2.2 test because **`SYSTEM`/a local svc ≠ the interactive Administrator** who mints the DPAPI key, so the per-user DPAPI boundary is still exercised. Service name: **`MessageFoundry`** | if the box is joined to a **test** domain and a test gMSA/service account exists, prefer it; otherwise **LocalSystem is correct for Phase 1** | the production identity is a dedicated **AD gMSA** (least-priv: `db_ddladmin`/`db_datawriter`/`db_datareader`) — that becomes the S2.1/S2.2 identity |
| **A4** | Store/report volume | Store/DB on the box's **largest non-OS volume** if one exists, else `C:\srv\mefor\`; reports under `C:\srv\mefor\reports\` | `Get-Volume` — if a separate data drive exists, put the store there so S4 numbers reflect real disk I/O | mirror the customer's production disk layout for the store |
| **B1** | Live `db_lookup` vs Clarity | **Promote *if* a test/Docker Clarity DB is reachable** (the one used in the Corepoint recon) — run a `db_lookup` enrichment under the service account as a **grant + capability proof**, synthetic data only; else **defer to Phase 2** | `Test-NetConnection <clarity-test-host> -Port 1433` succeeds **and** the synthetic graph wires a `db_lookup`? → run it; else skip | live read-only `db_lookup` against the real Clarity under the gMSA least-priv grant |
| **B2** | Real-cert MLLP transport TLS | **Defer to Phase 2** (no real certs/feeds in dev). *Optional:* a **self-signed-cert capability proof** now if you want to exercise the transport-TLS path | only if you have a self-signed test cert and want the capability proof | real-cert MLLP TLS round trip to the customer endpoint |
| **B3** | Key rotation under service | **Promote now** — after S2.2, run `rotate-key` under the service account with `require_encryption=true`; confirm both old+new keys decrypt and a message still reaches `processed` | always (synthetic, ~15 min add-on to S2.2) | re-confirm under the gMSA |
| **B4** | Off-box log shipping | **Defer to Phase 2** unless a test log collector is reachable from the box | is a test syslog/collector endpoint reachable? → quick reachability check; else skip | box→collector reachability on the customer network |
| **B5** | Config-reload under service | **Leave deferred** — CI-covered, and S1.AC-ACL already checks the service account's dir access | n/a | revisit when IDE-promote is wired to the box |
| **B6** | Strict-validation 2577 | **Promote now** — the synthetic coverage graph already exposes a strict inbound (`IB_Coverage_Strict`, MLLP **2577**). Drive a wrong-version message via the Compose tab to 2577 and confirm an **AE** NAK under the service identity | always (synthetic) | re-confirm against any strict prod inbound |

**Promoted-now command sketches** (for the on-box session — synthetic data only):

```powershell
# B3 — key rotation under the service identity (after S2.2; require_encryption=true).
messagefoundry rotate-key --help          # confirm exact flags on the installed wheel
messagefoundry rotate-key --service-config <active.toml>     # in the service-account context
python -m harness --scenario processed --engine http://127.0.0.1:8765 --token <T>   # still reaches processed (old+new keys decrypt)

# B6 — strict-validation AE on the synthetic strict inbound (2577), under the service identity.
#   harness/config exposes IB_Coverage_Strict on 2577. From the box's desktop GUI:
#   Compose tab -> "wrong-version" preset -> send to 127.0.0.1:2577 -> expect AE NAK; the Connection stays up.

# B1 — db_lookup grant+capability proof (ONLY if a test/Docker Clarity is reachable; synthetic data).
Test-NetConnection <clarity-test-host> -Port 1433     # reachability gate — skip B1 if this fails
#   then drive the db_lookup-bearing handler under the service account; confirm enrichment + processed (no grant error).
```

---

## Section 1 — Host & deployment acceptance (verify + acceptance runner)

This section establishes that the W2025 box is correctly provisioned and that the deployed wheel + the adopter config graph load, bind, and ACK on real Windows Server 2025. It is **wheel-native first** (`verify`, runs anywhere the wheel is installed — see S0.4), then layers the **source-tree acceptance runner** for the 54-row matrix. A core discipline of this section: be explicit about what `verify` **PROVES** (gates exit code) vs what it **reports MANUAL/SKIP** (never fails — a human must close it out).

### What `verify` proves vs reports

| `verify` outcome | Meaning | Gates exit code? |
|---|---|---|
| `PASS` | The probe ran and the condition held (e.g. store connected, MLLP bound, smoke routed/ACKed) | Yes — counts toward exit 0 |
| `FAIL` / `ERROR` | The probe ran and the condition did **not** hold | Yes — forces exit 1 |
| `MANUAL` | Cannot be machine-checked here (AD login, console-flash, NSSM lifecycle) — a human must verify | **No** — never fails the run |
| `SKIP` | Not applicable on this host/install (e.g. `host.noflash=SKIP` on non-`[console]`, ODBC skipped when no `[sqlserver]`) | **No** |

A green `verify` run is **necessary but not sufficient**: the MANUAL rows below (S1.AC-*) are the human-closed half, and the gap-map tests in Section 2 attack the documented `verify` false-greens (`store.connect` runs as interactive admin, not the service account; `smoke.live` is ACK-on-receipt only, not routing/delivery).

### S1.1 — 0.2.1 clean-env prerequisite (do FIRST, gates everything)

| Field | Value |
|---|---|
| **ID** | S1.1 |
| **Objective** | On **Python 3.14 (now the required minimum)**, replace the in-place-upgraded repo `.venv` (still `0.2.0 + httpx`) with a clean `0.2.1` carrying **both** server-DB drivers, retiring the httpx + `PYTHONUTF8` workarounds so later results are honest. |
| **Tool / command** | `python --version` (**3.14.x**), then `pip install --upgrade "messagefoundry[sqlserver,postgres]==0.2.1"`, then `messagefoundry --version`, `messagefoundry verify --help`, and a driver presence probe |
| **PASS** | **`python --version` is 3.14.x** (the wheel now declares `requires-python >=3.14`, so pip refuses to install it on an older interpreter); `--version` reports `0.2.1`; `verify --help` succeeds on cp1252 **without** `PYTHONUTF8=1` (Bug A retired); `verify --section host` completes with `host.noflash=SKIP` exit 0 on a `[sqlserver]`-only console build (Bug B retired); `python -c "import asyncpg, aioodbc"` succeeds (both server drivers present). |
| **Per-DB** | once (env-level, not per-backend). |
| **Where** | ON the box. |
| **Duration** | 10 min. |
| **Maps to** | Host trap "0.2.1 clean-env prerequisite"; dogfood 0.2.1 verify characterization. |

```powershell
python --version                         # MUST be 3.14.x — the engine now requires Python >=3.14
pip install --upgrade "messagefoundry[sqlserver,postgres]==0.2.1"
pip install openpyxl                      # for the S1.7 --xlsx write-back (NOT a project dep)
messagefoundry --version
messagefoundry verify --help              # must NOT need $env:PYTHONUTF8="1"
python -c "import asyncpg, aioodbc; print('drivers OK')"   # PG + SQL Server drivers present
```

### S1.2 — `verify --section host`

| Field | Value |
|---|---|
| **ID** | S1.2 |
| **Objective** | Prove the box's host prerequisites: **Python 3.14 (the required minimum)**, ODBC Driver 18 discoverability, local bindability of MLLP/DICOM/API ports, and surface the MANUAL/SKIP host rows. |
| **Tool / command** | `messagefoundry verify --section host --report-md C:\srv\mefor\reports\verify\host.md --report-json C:\srv\mefor\reports\verify\host.json` |
| **PASS** | Exit 0. The host probe confirms **Python 3.14.x** (the required minimum). `host.odbc` = PASS (literal `"ODBC Driver 18 for SQL Server"` present — maps A3). Port-bindability probes (2575/11112/8765) PASS. `host.noflash` = SKIP (non-`[console]`) or MANUAL — **not** counted as a failure. No `FAIL`/`ERROR` rows. |
| **Per-DB** | once. |
| **Where** | ON the box. |
| **Duration** | 5 min. |
| **Maps to** | Matrix A3 (ODBC 18), partial A5 (verify only checks *local* bindability — external firewall admit is MANUAL, see S1.AC-FW). Runbook §3 (host readiness). |

```powershell
messagefoundry verify --section host `
  --report-md  C:\srv\mefor\reports\verify\host.md `
  --report-json C:\srv\mefor\reports\verify\host.json
```

**Note — what this does NOT prove:** local bindability ≠ external reachability. The Windows Firewall admit rule (matrix A5) and service-account file ACLs (A6) are NOT covered by `host` — they are MANUAL rows (S1.AC-FW / S1.AC-ACL).

### S1.3 — per-DB `verify --section store,smoke --smoke live` (x3)

| Field | Value |
|---|---|
| **ID** | S1.3-{SQLITE,MSSQL,PG} |
| **Objective** | Per backend: prove `store.connect` succeeds, `smoke.self` routes one synthetic ADT in-process, and `smoke.live` MLLP-connects + AA-ACKs one real message against the running engine. |
| **Tool / command** | `messagefoundry verify --section store,smoke --smoke live --service-config <toml> --engine-host 127.0.0.1 --mllp-port 2575` (one `<toml>` per backend) |
| **PASS** | `store.connect` = PASS for the targeted backend; `smoke.self` = PASS; `smoke.live` = PASS (listener AA-ACKs). Exit 0. |
| **Per-DB** | **x3** — run once each with `[store].backend`/`MEFOR_STORE_*` pointed at SQLite, SQL Server, then PostgreSQL. |
| **Where** | ON the box (`smoke.live` needs the engine `serve`-ing on the box; host/store probes are local). |
| **Duration** | 10 min per backend (30 min total). |
| **Maps to** | Matrix A (store connectivity per backend); dogfood "0.2.1 store.connect PASS for SQLite/SQL Server/PostgreSQL". |

**CRITICAL false-green to record here, not retest:** `verify` is a **CLI invoked interactively** — `store.connect` runs as **whatever interactive identity launched the shell (the admin), NOT the NSSM service account**, and `smoke.live` is **ACK-on-receipt only** (it reports PASS even when the message subsequently dead-letters). **`store.connect` PASS here reflects only the interactive operator's DB access; service-identity DB grants (`db_ddladmin`/`db_datawriter`/`db_datareader`) and the true PROCESSED path are proven EXCLUSIVELY by S2.1 (under NSSM) and the DPAPI boundary by S2.2.** Do not sign off store health from S1.3 alone.

```powershell
# SQLite
messagefoundry verify --section store,smoke --smoke live `
  --service-config C:\srv\mefor\adopter-config\service.sqlite.toml `
  --engine-host 127.0.0.1 --mllp-port 2575

# SQL Server (set MEFOR_STORE_* / encrypt knobs per the targeted server first)
$env:MEFOR_STORE_BACKEND="sqlserver"
messagefoundry verify --section store,smoke --smoke live `
  --service-config C:\srv\mefor\adopter-config\service.mssql.toml `
  --engine-host 127.0.0.1 --mllp-port 2575

# PostgreSQL
$env:MEFOR_STORE_BACKEND="postgres"
messagefoundry verify --section store,smoke --smoke live `
  --service-config C:\srv\mefor\adopter-config\service.pg.toml `
  --engine-host 127.0.0.1 --mllp-port 2575
```

### S1.4 — `smoke self` pre-service gate (no store, no net)

| Field | Value |
|---|---|
| **ID** | S1.4 |
| **Objective** | Before the service ever binds a port, prove the deployed config graph loads and one synthetic ADT^A01 routes via in-process dry-run (no store/net/side-effects). |
| **Tool / command** | `messagefoundry verify --section smoke --smoke self --config C:\srv\mefor\adopter-config\config` |
| **PASS** | `smoke.self` = PASS; exit 0. (Pure in-process — confirms wiring before exposing a listener.) |
| **Per-DB** | once (store-independent). |
| **Where** | ON the box (or any wheel install — also valid as a dev-PC pre-flight). |
| **Duration** | 2 min. |
| **Maps to** | Matrix A (config-load smoke); runbook §3 pre-service gate; pairs with `check` (S6 quick-ref / dogfood D6, D16). |

```powershell
messagefoundry verify --section smoke --smoke self `
  --config C:\srv\mefor\adopter-config\config
```

### S1.5 — full saved-report acceptance run

| Field | Value |
|---|---|
| **ID** | S1.5 |
| **Objective** | Produce the single archived host+store+smoke+manual report (md + json) that is the deployment-acceptance artifact for sign-off. |
| **Tool / command** | `messagefoundry verify --section host,store,smoke,manual --smoke live --service-config <active-toml> --report-md C:\srv\mefor\reports\verify\verify-full.md --report-json C:\srv\mefor\reports\verify\verify-full.json` |
| **PASS** | Exit 0 (no FAIL/ERROR). The `manual` section enumerates every MANUAL row (AD, MFA, NSSM, no-flash, API) as an explicit checklist; each MANUAL row is then closed by its S1.AC-* below. Report files written. |
| **Per-DB** | once against the **active production backend** (re-run per backend only if storing per-backend evidence). |
| **Where** | ON the box. |
| **Duration** | 10 min. |
| **Maps to** | Matrix A–H roll-up; runbook §3-4. The MANUAL section is the index for S1.AC-* rows. |

```powershell
messagefoundry verify --section host,store,smoke,manual --smoke live `
  --service-config C:\srv\mefor\adopter-config\service.active.toml `
  --report-md  C:\srv\mefor\reports\verify\verify-full.md `
  --report-json C:\srv\mefor\reports\verify\verify-full.json
```

### S1.6 — acceptance runner: probe-only pre-flight

The acceptance runner is a **source-tree artifact** (`python -m harness.acceptance`) — it runs `tests/test_*.py` via pytest subprocess, reads source files by repo-relative path, and shells HARNESS rows out to `python -m harness`. Per S0.4, the box is wheel-only, so this requires a **full source checkout matching the deployed wheel version (0.2.1)** placed on the box with `tests/`, `harness/`, `requirements.lock`, and dev/test deps installed (pytest, openpyxl for `--xlsx`, the `[sqlserver]`/`[postgres]` extras), pinned to the `0.2.1` tag and identity-checked per S0.4. The deployed wheel cannot self-run it.

| Field | Value |
|---|---|
| **ID** | S1.6 |
| **Objective** | Fast probe-only smoke of the matrix on the box (8 probes + manual rows; pytest skipped) to confirm host posture without the full suite. |
| **Tool / command** | `python -m harness.acceptance --no-pytest --report-md C:\srv\mefor\reports\acceptance\acc-probe.md --report-csv C:\srv\mefor\reports\acceptance\acc-probe.csv` |
| **PASS** | Exit 0 (no FAIL/ERROR; MANUAL+SKIP never fail). Probe rows (e.g. ODBC present, `requirements.lock` synced, `console/service_control.py` `CREATE_NO_WINDOW` present) PASS. |
| **Per-DB** | once (probes are backend-independent). |
| **Where** | ON the box (needs source checkout + installed package). |
| **Duration** | 10 min. |
| **Maps to** | Matrix A/F/G probe rows; pre-flight before the full pytest leg. |

### S1.7 — acceptance runner: full 54-row WIN2025 matrix

The `--xlsx` flag **writes back into a PRE-EXISTING workbook** keyed by the matrix's **native row IDs** (A/F/G/…, not this plan's S<n>.<n> IDs): `write_xlsx_status` calls `load_workbook(<path>)` and stamps the `Status` column, raising `RuntimeError` ("xlsx write-back failed", exit 2) if the file is absent or lacks an `ID`/`Status` header. **Lay the seed `WIN2025-TEST-MATRIX.xlsx` (shipped in the repo / generated from the matrix) into the target dir BEFORE running**, and confirm `openpyxl` is installed (S1.1).

| Field | Value |
|---|---|
| **ID** | S1.7 |
| **Objective** | Run the full 54-row matrix (8 probes + 41 pytest suites + 3 harness(MANUAL) + 2 manual), with the per-DB server-suite env gates set, and stamp the signed xlsx workbook. |
| **Tool / command** | seed-workbook lay-down + per-DB gates then `python -m harness.acceptance --report-md ... --report-csv ... --xlsx C:\srv\mefor\reports\acceptance\WIN2025-TEST-MATRIX.xlsx` |
| **PASS** | Exit 0. SQL Server + PostgreSQL pytest suites RUN (not SKIP) because `MEFOR_TEST_SQLSERVER=1`/`MEFOR_TEST_POSTGRES=1` + `MEFOR_STORE_*` are set; no FAIL/ERROR. Workbook `Status` column stamped (openpyxl). |
| **Per-DB** | The runner itself is once, but the server-DB **suites inside it** run x3 via the env gates — set all three so the SQL Server and PostgreSQL rows execute on real aioodbc/libpq, not SKIP. |
| **Where** | ON the box. |
| **Duration** | 45–90 min (pytest-dominated). |
| **Maps to** | Full matrix A–H Status stamp; the deliverable workbook. |

```powershell
# 0) Seed the workbook to write back into (it ships in the repo / is generated from the matrix)
Copy-Item C:\srv\mefor\src\harness\acceptance\WIN2025-TEST-MATRIX.xlsx C:\srv\mefor\reports\acceptance\

# Server-DB suite gates — without these the MSSQL/PG matrix rows self-SKIP (not a real signal)
$env:MEFOR_TEST_SQLSERVER="1"; $env:MEFOR_TEST_POSTGRES="1"
$env:MEFOR_STORE_SERVER="<server>"; $env:MEFOR_STORE_DATABASE="<db>"
$env:MEFOR_STORE_AUTH="sql"; $env:MEFOR_STORE_USERNAME="<u>"; $env:MEFOR_STORE_PASSWORD="<p>"

# from the source-checkout root that matches 0.2.1 (cwd must contain harness/ and tests/)
python -m harness.acceptance --no-pytest --report-md C:\srv\mefor\reports\acceptance\acc-probe.md   # pre-flight (S1.6)
python -m harness.acceptance `
  --report-md  C:\srv\mefor\reports\acceptance\acc-full.md `
  --report-csv C:\srv\mefor\reports\acceptance\acc-full.csv `
  --xlsx       C:\srv\mefor\reports\acceptance\WIN2025-TEST-MATRIX.xlsx
```

### S1.AC-* — the MANUAL rows (human-closed; `verify`/acceptance only report these)

These are the rows CI structurally cannot reach and `verify` reports MANUAL. Each must be closed by a named operator with evidence pasted into the matrix. The MANUAL checklist is consolidated in **Appendix E**; the executed-test counterparts are cross-referenced (S1.AC-API↔S2.8, S1.AC-NSSM↔S2.5, S1.AC-DISPO↔Section 3) — keep both the checklist row and the executed test, do not duplicate the body.

| ID | Objective | Tool + exact action | PASS | Per-DB | Where | Dur | Maps to |
|---|---|---|---|---|---|---|---|
| **S1.AC-AD** | AD/Kerberos login against the real domain | Log into the console (or API auth) with a domain (AD/LDAP/Kerberos) account; confirm RBAC role applied | Domain user authenticates; role-gated route allowed, denied route 403; audit row records the AD identity | once | ON box (against real domain) | 20 min | Matrix F1; runbook §5; SECURITY.md |
| **S1.AC-MFA** | Native TOTP MFA for a local account (WP-14) | Enroll TOTP for a local user; log in supplying a current code; confirm a wrong/expired code is rejected | Correct TOTP admits; wrong code denied; enrollment audited | once | ON box | 15 min | Matrix F (MFA); ASVS WP-14 |
| **S1.AC-API** | API binds loopback + rejects unauthenticated | From the box: `Invoke-WebRequest http://127.0.0.1:8765/stats` with no token → 401; confirm no off-loopback bind without TLS | Unauthenticated call 401/403; bind is 127.0.0.1 (or TLS if off-loopback). (Full attack in **S2.8**.) | once | ON box | 10 min | Matrix #8; runbook §4 |
| **S1.AC-NSSM** | NSSM lifecycle: autostart-on-reboot + restart-after-crash | Reboot the box; confirm service auto-starts and ingests. Kill the PID; confirm NSSM `AppExit` restarts it. | Service `Running` after reboot; auto-restarts after kill; ingest resumes. (Durability detail in **S2.4/S2.5**.) | once | ON box | 25 min | Matrix G1; runbook §4; SERVICE.md |
| **S1.AC-FLASH** | No console-flash on Status poll | Watch the desktop during a console Status poll cycle; observe no cmd window flash | No visible console window appears during polling (`CREATE_NO_WINDOW` honored) | once | ON box (real desktop session) | 5 min | Matrix F7 |
| **S1.AC-DISPO** | Console disposition walk | In the console, inject via harness and watch a message transition RECEIVED→ROUTED→PROCESSED, plus a FILTERED and an ERROR, in the live disposition view | Each disposition appears correctly in the console; raw + summary viewable; PHI access audited | once (smoke) per backend if storing per-DB evidence | ON box | 15 min | Matrix (console ops); ties to **Section 3** |
| **S1.AC-FW** | Firewall admits external listener traffic | Add/confirm inbound rule for MLLP 2575; from a dev PC `Test-NetConnection <box> -Port 2575` | External TCP connect succeeds; `verify` local-bindability already PASS (S1.2) | once | dev PC → box | 10 min | Matrix A5 |
| **S1.AC-ACL** | Service-account file ACLs on store/config/log dirs | Inspect ACLs; confirm the service identity (not just admin) has the needed read/write | Service account can read config, write store + logs; least-priv elsewhere | once | ON box | 10 min | Matrix A6 |

---

## Section 2 — Closing the 8 "false-green" gaps

These are the eight gap-map tests (Tiers 1–3), **S2.1–S2.8** mapping 1:1 to gap-map #1–#8. Each attacks a path that `verify`/`check`/CI reports green (or simply never exercises) but that is unproven under real Windows Server 2025 service identity, real outbound delivery, real crash, real TLS, or real adversarial input. **Tier 1 (S2.1, S2.2) runs first.** Tools used: the functional harness Receive/Compose/Monitor tabs (GUI, desktop session) and the Qt-free headless `--scenario` path, plus `verify` where it applies. All require the box `serve`-ing the matching graph.

> **Auth note for headless harness runs (applies to all of Sections 2–4).** S2.8/S1.AC-API prove the API binds loopback and **requires auth**. Against that production-posture (auth-on) engine the load runner validates the token via `/auth/me` and the scenario runner polls auth-gated `/messages`/`/dead-letters` — so **every headless `--scenario`/`--load`/`--failover` invocation must pass `--token <T>`** (mint a bearer for the service-identity engine via the console/API auth route, or via the runbook's bootstrap-admin flow). The failover orchestrator is the one exception: it spawns its own nodes with `MEFOR_AUTH_ENABLED=false`, so it needs no `--token`. If you prefer, serve the test engine with auth disabled for the harness runs and re-enable it for the S2.8 attack; the commands below assume auth-on + `--token`.

### S2.1 (gap #1) — Healthy message → PROCESSED UNDER the NSSM service account

| Field | Value |
|---|---|
| **ID** | S2.1 |
| **Objective** | Prove that, **under the NSSM service identity**, an injected healthy ADT reaches store status `processed` (RECEIVED→ROUTED→PROCESSED) with the outbound actually delivered. |
| **Why a gap (false-green)** | The single most important untested path. `verify` cannot self-check it: `store.connect` runs as the interactive admin (not the service account) and `smoke.live` is ACK-on-receipt only (PASS even if the message later dead-letters). Healthy→processed is proven only under [Admin] (pre-D14); the **failure** path under service is proven (D22 dead-letter), but the **healthy** path under service is not. |
| **Steps** | 1. Configure + start the engine under NSSM with the real service account (LocalSystem or, preferred, the dedicated AD service account / gMSA with grants `db_ddladmin`+`db_datawriter`+`db_datareader`), serving the `harness/config` coverage graph (binds 2575). 2. Inject a healthy synthetic ADT. **Headless:** `python -m harness --scenario processed --engine http://127.0.0.1:8765 --token <T>` (the `processed` scenario sends ADT^A05 → single **file-archive** delivery; see PASS). **GUI:** Send tab → load a healthy ADT^A01 → send to inbound MLLP 2575 (A01 fans to MLLP echo on 2576 **and** file archive); Monitor tab watches disposition. 3. Inspect the store/Monitor for the final disposition. |
| **PASS** | Under the **service identity**, the injected healthy ADT shows store status `processed` (full RECEIVED→ROUTED→PROCESSED). For `--scenario processed` (ADT^A05) the single **file-archive** outbound row is `delivered`. For the GUI A01 path the **two** fan-out rows (MLLP echo + file) are `delivered` (run the harness Receive tab on 2576 with AA). Headless: `--scenario processed` exits 0. |
| **Per-DB** | **x3** — most valuable on SQL Server (the D15 grant matrix bites here), then SQLite + PostgreSQL for parity. |
| **Where** | ON the box (service identity is host-only). |
| **Duration** | 20 min per backend. |
| **Maps to** | Gap-map **#1 / T1** (highest value). |

> **Phase note (S0.7 A2):** Phase 1 (this dev test box) drives the **synthetic coverage graph only** — there is no production config repo yet. The named-production-`IB_` variant of S2.1/S2.5 is a **Phase-2** item (customer network, ≈ mid-July 2026).

> **Scenario fact (do not misread):** the built-in `processed` scenario is **ADT^A05** and the coverage graph routes A05 down the "any other ADT trigger → single send → file archive" path — it is **file-only, NOT fan-out**. Fan-out (echo + file) fires only for A01/A04/A08, and there is **no CLI flag** to make `--scenario` send a different trigger (the trigger is baked per scenario, inbound hardcoded to 127.0.0.1:2575). To prove the fan-out / MLLP-outbound path under service, drive A01 from the GUI Send tab (this also feeds S2.3). The headless `--scenario processed` proves healthy→PROCESSED-under-service via the file path.

```powershell
# Engine must already be serving the harness/config coverage graph (2575) under the NSSM service account.
python -m harness --list-scenarios
python -m harness --scenario processed --engine http://127.0.0.1:8765 --token <T> --timeout 30
# exit 0 == processed disposition asserted against the live engine (file-archive delivery)
```

### S2.2 (gap #2) — DPAPI key across the admin→service identity boundary

| Field | Value |
|---|---|
| **ID** | S2.2 |
| **Objective** | Prove (or document the failure of) a `protect-key`-minted at-rest encryption key being usable by the engine running under the NSSM service identity, with `require_encryption=true`. |
| **Why a gap (false-green) / the trap** | `protect-key --out` binds the key **per-user via DPAPI**. An admin-minted key file may be **undecryptable** by LocalSystem/LOCAL SERVICE. With `[store].require_encryption=true` this **fail-CLOSES** — the engine won't start or dead-letters everything. At-rest encryption is fail-OPEN by default (D18), so this only bites once you turn `require_encryption` on, which is exactly the production-secure posture. Likely a real bug. |
| **Steps** | 1. As admin: `messagefoundry protect-key --out C:\srv\mefor\keys\store.key`. 2. Set `[store].require_encryption=true` + key path. 3. Start the engine under the **service account** (serving `harness/config`, 2575). 4. Inject a PHI ADT (`--scenario processed --token <T>`). 5. Confirm encryption (`mfenc:v1:` body) vs decrypt failure. |
| **PASS** | **Either** (a) the PHI message encrypts (body = `mfenc:v1:`) and stores `processed` with no decrypt failure under the service account; **OR** (b) the admin→service DPAPI boundary failure is reproduced and the supported remedy is documented and shown to work (below). |
| **Per-DB** | once primary (SQL Server); the DPAPI boundary is store-agnostic, so SQLite is sufficient to characterize, SQL Server confirms with the production store. |
| **Where** | ON the box. |
| **Duration** | 40 min (includes remedy verification). |
| **Maps to** | Gap-map **#2 / T2**; host trap DPAPI. |

**Documented remedies to verify as the fallback (pick the one that starts clean under the service account):**
1. **Machine-scope DPAPI** — mint the key with machine (LocalMachine) scope instead of per-user, so any identity on the box can decrypt it.
2. **Env-var key** — supply the key via a `MEFOR_*` environment variable on the service (no DPAPI binding at all); the canonical cross-identity remedy.
3. **Mint-as-service** — run `protect-key` while logged in as / impersonating the service account so DPAPI binds to that identity.

```powershell
# As Administrator
messagefoundry protect-key --out C:\srv\mefor\keys\store.key
# set [store].require_encryption=true + encryption key path in the active service TOML, start under the service acct, then:
python -m harness --scenario processed --engine http://127.0.0.1:8765 --token <T>
# Inspect a stored row: body must be mfenc:v1:* and disposition processed (NOT dead-lettered on decrypt failure)
```

### S2.3 (gap #3) — Real outbound MLLP delivery (engine as client): delivered + ACKed round trip

| Field | Value |
|---|---|
| **ID** | S2.3 |
| **Objective** | Prove a clean delivered→AA/AE round trip from a MEFOR **outbound** Connection to a separate downstream MLLP listener. |
| **Why a gap (false-green)** | D19 exercised **retry** (transient AE), never a **clean** delivered-and-ACKed round trip. The engine-as-MLLP-client happy path on Windows is unproven. |
| **Steps (harness Receive tab drives it)** | 1. Start the harness **Receive** tab listening on the downstream port the MEFOR outbound delivers to (the coverage graph's echo destination = **2576**), set to **ACK AA** (no fault). 2. Inject a healthy **A01/A04/A08** message inbound (the **only** triggers the coverage graph fans out to the MLLP echo on 2576) — drive it from the **GUI Send tab** (not `--scenario processed`, which is A05 and never touches MLLP). The engine routes/transforms and delivers outbound to the Receive listener. 3. Observe the Receive tab logs the delivery and the engine records the echo outbound row `delivered`. |
| **Receive-tab fault modes (for the negative half):** set Receive to **fail-N** (return AE for N msgs) → engine retries (ties to D19), then **AA** → clean delivery on recovery. |
| **PASS** | Downstream listener (2576) receives the transformed A01 and returns AA; engine records the `OB_Coverage_Echo` outbound row `delivered`; on the fail-N variant the engine retries the AE and converges to `delivered` after the listener returns AA. |
| **Per-DB** | once (delivery path is store-agnostic; SQLite). |
| **Where** | ON the box (GUI) or remote dev PC driving the box's engine + a dev-PC listener. |
| **Duration** | 20 min. |
| **Maps to** | Gap-map **#3 / T2**. |

```powershell
# Receive tab listening on 2576 = AA. Then GUI Send tab: send a healthy ADT^A01 to 2575.
# (Do NOT rely on --scenario processed for this — A05 is file-only and never reaches MLLP.)
# Negative/recovery: set Receive fault "fail-N" then "AA" and watch the echo row converge to delivered.
```

### S2.4 (gap #4) — Crash/restart queue durability across hard process death

| Field | Value |
|---|---|
| **ID** | S2.4 |
| **Objective** | Prove the durable `queue` table recovers `pending` rows across a **hard process kill**, not just an in-run transient failure. |
| **Why a gap (false-green)** | D19 proved **in-run** recovery (the process stayed alive). Recovery across a real process death + restart — the `reset_stale_inflight` startup path on Windows — is unproven. |
| **Steps** | 1. Make the downstream listener (Receive tab) **stall/close** so messages back up as `pending`/in-flight outbound rows. 2. Inject several A01 messages. 3. **Hard-kill** the engine PID (resolve it by listening port, not process name — see below) while rows are pending. 4. Restart the service. 5. Restore the downstream listener to AA. 6. Confirm the previously-pending rows drain to `delivered` with **no loss and no manual replay**. |
| **PASS** | After restart, every pre-kill `pending`/in-flight row is recovered and delivered (or retried) — zero acked-message loss, no manual intervention. Disposition reconciles (received == delivered for the batch). |
| **Per-DB** | **x3** — SQLite (WAL recovery), SQL Server, PostgreSQL (each has distinct stale-inflight reset semantics). |
| **Where** | ON the box. |
| **Duration** | 25 min per backend. |
| **Maps to** | Gap-map **#4 / T2**. |

> **PID resolution (do NOT use `Get-Process -Name messagefoundry`):** under NSSM the engine is `python.exe -m messagefoundry serve` — there is no `messagefoundry.exe`, so a name lookup returns nothing and `.Id` on `$null` throws. Resolve the engine PID by the inbound listening port instead.

```powershell
# 1) GUI Receive tab: set fault = "close" (or stall) so outbound backs up; inject A01 via Send tab.
# 2) Hard kill the engine that owns the inbound MLLP port:
$enginePid = (Get-NetTCPConnection -LocalPort 2575 -State Listen).OwningProcess
Stop-Process -Id $enginePid -Force
# 3) Restart service (NSSM): Restart-Service MessageFoundry  (exact name per runbook §4)
# 4) Set Receive back to AA, 5) confirm pending rows drain to delivered (no manual replay).
```

### S2.5 (gap #5) — NSSM autostart-on-reboot + restart-after-crash

| Field | Value |
|---|---|
| **ID** | S2.5 |
| **Objective** | Prove the NSSM service lifecycle MANUAL rows: the engine autostarts on reboot and NSSM `AppExit` restarts it after a crash. |
| **Why a gap** | CI's NSSM smoke is install→serve→MLLP only; reboot-autostart and crash-restart **timing** on real Server 2025 are host-only and not asserted by CI. |
| **Steps** | 1. Reboot the box; confirm the service reaches `Running` and ingests a smoke message unattended. 2. Hard-kill the engine PID; confirm NSSM restarts it (`AppExit` = Restart) and ingest resumes. 3. Record the Windows **port-rebind recovery lag** (can be tens of seconds on Windows vs near-instant on Linux). |
| **PASS** | Service `Running` after reboot with no manual start; auto-restarts after kill; smoke ingest succeeds both times. Port-rebind lag recorded (informational — Windows-host number CI can't produce). |
| **Per-DB** | once (lifecycle is store-agnostic; run on the active backend). |
| **Where** | ON the box. |
| **Duration** | 30 min (includes a reboot). |
| **Maps to** | Gap-map **#5 / T2**; matrix G1; runbook §4. Cross-references the MANUAL row **S1.AC-NSSM** (same lifecycle; this is the durability-focused execution). |

```powershell
Restart-Computer            # after reboot, confirm service Running + smoke ingest
Get-Service MessageFoundry  # Status == Running, StartType == Automatic
# crash-restart (resolve PID by port, then kill; NSSM AppExit restarts it):
$enginePid = (Get-NetTCPConnection -LocalPort 2575 -State Listen).OwningProcess
Stop-Process -Id $enginePid -Force
Get-Service MessageFoundry  # confirm Running again; confirm smoke ingest resumes
```

### S2.6 (gap #6) — Real encrypt=true + trusted-cert TLS store connect

| Field | Value |
|---|---|
| **ID** | S2.6 |
| **Objective** | Prove a production-posture store connection: `encrypt=true` with a genuine **trusted certificate** (no weakened-TLS escape hatch). |
| **Why a gap (false-green)** | Every store test so far used weakened TLS (the **two** settings `encrypt=false`/`trust_server_certificate` **and** `MEFOR_ALLOW_INSECURE_TLS=1`). Production `encrypt=true` + trusted cert is unproven on this box. The common first mistake (secure-default `encrypt=true` against a non-TLS dev server) yields a cryptic "rejected SSL upgrade" that does NOT name the fix — so the trusted-cert path must be proven explicitly against a TLS-enabled server with a cert the box trusts. |
| **Steps** | 1. Point `[store]` at a SQL Server (and PostgreSQL) instance with TLS enabled and a cert chained to a CA the W2025 box trusts. 2. Set `encrypt=true`, `trust_server_certificate=false`, and do **not** set `MEFOR_ALLOW_INSECURE_TLS`. 3. `messagefoundry verify --section store,smoke --smoke live --service-config <toml>`. 4. Inject a smoke message to confirm read/write over the encrypted connection. |
| **PASS** | `store.connect` = PASS with `encrypt=true` and no insecure-TLS env set; smoke ingest persists. No "rejected SSL upgrade" / cert-validation error. |
| **Per-DB** | **x2** — SQL Server + PostgreSQL (SQLite has no network TLS; mark n-a). |
| **Where** | ON the box (must trust the cert at OS level). |
| **Duration** | 20 min per backend. |
| **Maps to** | Gap-map **#6 / T3**; host trap weakened-TLS vs trusted-cert. |

```powershell
# In the service TOML: [store] encrypt=true, trust_server_certificate=false; do NOT set MEFOR_ALLOW_INSECURE_TLS
$env:MEFOR_ALLOW_INSECURE_TLS=$null
messagefoundry verify --section store,smoke --smoke live `
  --service-config C:\srv\mefor\adopter-config\service.mssql.tls.toml
```

### S2.7 (gap #7) — Robustness: malformed / oversized / mid-frame disconnect (functional / at-rest)

| Field | Value |
|---|---|
| **ID** | S2.7 |
| **Objective** | Prove the listener stays up and dead-letters/NAKs cleanly under adversarial input — malformed HL7, oversized body, and a mid-frame MLLP disconnect — without crashing the Connection. **This is the idle/functional case; the same robustness under sustained load is S4.8 — see the cross-reference, do not duplicate.** |
| **Why a gap** | Robustness under malformed/oversized/torn-frame input on the real host is not exercised by the happy-path smokes. Inbound HL7 is attacker-influenceable (§8/§9). |
| **Steps (Compose presets + Receive fault modes drive it):** | 1. **Malformed HL7:** Compose tab preset **no-MSH** (or **wrong-version**) → send to inbound → expect synchronous **AE/AR NAK** + `ERROR` disposition, Connection stays up. Headless: `python -m harness --scenario error --engine http://127.0.0.1:8765 --token <T>` (this scenario sends ADT^A03, whose handler raises → ERROR/AE NAK). 2. **Oversized message:** Compose **oversized** preset → send → expect clean reject/dead-letter, no crash, no OOM. 3. **Mid-frame disconnect:** Send tab / Receive fault mode = **close mid-frame** (drop the TCP connection before the MLLP end block) → expect the listener to discard the partial frame and remain accepting new connections. |
| **PASS** | Each case: the Connection/listener **stays up** and continues accepting; malformed → `ERROR` (synchronous NAK at the listener per §8); oversized → clean reject/dead-letter; torn frame → partial discarded, next message ingests normally. No process crash, no Connection death. `--scenario error` exits 0. |
| **Per-DB** | once (input-handling is store-agnostic; SQLite). |
| **Where** | ON the box (GUI Compose presets) or remote `--scenario error`. |
| **Duration** | 25 min. |
| **Maps to** | Gap-map **#7 / T3**. Under-load counterpart: **S4.8**. |

```powershell
# Headless ERROR disposition (ADT^A03 handler raises → AE NAK → ERROR):
python -m harness --scenario error --engine http://127.0.0.1:8765 --token <T> --timeout 30
# GUI: Compose presets no-MSH / wrong-version / oversized; Send/Receive fault "close mid-frame".
# After each, re-send a healthy message to confirm the listener is still accepting.
```

### S2.8 (gap #8) — API loopback bind + unauthenticated reject

| Field | Value |
|---|---|
| **ID** | S2.8 |
| **Objective** | Prove the engine API binds loopback (127.0.0.1; TLS if off-loopback) and **rejects unauthenticated** calls. |
| **Why a gap** | The on-prem default posture (loopback + auth-required) must be confirmed on the real host, not assumed. |
| **Steps** | 1. From the box: call a protected endpoint with **no** token → expect 401/403. 2. Confirm the listener is bound to 127.0.0.1 (`Get-NetTCPConnection -LocalPort 8765`); if off-loopback, confirm TLS. 3. Call with a valid token → expect 200. |
| **PASS** | Unauthenticated request → 401/403; bind is 127.0.0.1 (or TLS-protected if off-loopback); authenticated request succeeds. |
| **Per-DB** | once (API posture is store-agnostic). |
| **Where** | ON the box. |
| **Duration** | 10 min. |
| **Maps to** | Gap-map **#8 / T3**; runbook §4. (MANUAL row **S1.AC-API** is the matrix checklist entry; this is the executed test.) |

```powershell
# Unauthenticated must be rejected:
try { Invoke-WebRequest http://127.0.0.1:8765/stats -UseBasicParsing } catch { $_.Exception.Response.StatusCode.value__ }  # expect 401
Get-NetTCPConnection -LocalPort 8765 | Select-Object LocalAddress,LocalPort,State   # LocalAddress == 127.0.0.1
# Authenticated (valid token) must succeed:
Invoke-WebRequest http://127.0.0.1:8765/stats -Headers @{ Authorization = "Bearer <T>" } -UseBasicParsing
```

---

## Section 3 — Functional disposition coverage (test harness)

This section drives `harness/config` to light up **every** disposition and delivery path against the running engine, plus a reconcile output-parity spot-check. It is the functional-correctness complement to Section 1's host smoke and Section 2's gap closure. The disposition-coverage graph in `harness/config` is purpose-built so each scenario deterministically produces one disposition.

### Reaching the wheel-only box

Per S0.4, `harness/` is **source-only** (not in the wheel). The three supported placements (remote `--engine`, copied `harness/` dir, GUI tabs) are defined once in **S0.4**. In summary for this section: headless `--scenario` is **Qt-free** (preferred via remote `--engine` from a dev PC, or run on the box with the installed wheel satisfying imports); PySide6 is needed **only** for the GUI tabs (Send/Receive/Compose/Monitor), which require a desktop session on the box for the operator-driven walk and fault injection. All headless runs pass `--token <T>` per the Section 2 auth note.

> **Scenario→disposition facts (from `harness/scenarios.py` + `harness/config/coverage.py`), so PASS criteria match the code:**
> - `processed` = **ADT^A05** → single **file-archive** delivery → PROCESSED (NOT fan-out).
> - `filtered` = **ADT^A02** → handler returns None → FILTERED.
> - `unrouted` = **ORU^R01** → router returns [] → UNROUTED.
> - `error` = **ADT^A03** → handler raises → ERROR (AE NAK).
> - `dead_letter` = **ADT^A01** echo to **a DOWNED listener on 2576** → dead-lettered after retries (run with **nothing** listening on 2576).
> - Fan-out (MLLP echo **+** file) fires only for **A01/A04/A08** — driven from the GUI Send tab, not a `--scenario`.
> - The built-in scenarios hardcode inbound **127.0.0.1:2575** (no port-override flag), so they require the `harness/config` coverage graph served on 2575 — do **not** run `--scenario` against the load graph (2600) or a production graph on another port.

### S3.0 — serve the disposition-coverage graph

| Field | Value |
|---|---|
| **ID** | S3.0 |
| **Objective** | Bring up the engine on the box `serve`-ing `harness/config` so triggers/ports/destination names line up with the scenarios. |
| **Command** | `python -m messagefoundry serve --config C:\srv\mefor\src\harness\config --db ./messagefoundry.db --env dev` |
| **PASS** | Engine running; `graph` shows the disposition-coverage wiring; tolerant MLLP 2575 / strict 2577 bound. |
| **Per-DB** | Re-served once per backend for the per-DB smoke (S3.9). |
| **Where** | ON the box. |
| **Duration** | 5 min. |
| **Maps to** | Prereq for all S3 rows. |

```powershell
python -m harness --list-scenarios   # processed, filtered, unrouted, error, dead_letter
python -m messagefoundry serve --config C:\srv\mefor\src\harness\config --db ./messagefoundry.db --env dev
```

### S3.1–S3.5 — disposition matrix (one row per disposition/path)

Every row below: headless command (`--token <T>`) + GUI equivalent. PASS = the named disposition asserted (`--scenario` exit 0) and visible in the Monitor tab.

| ID | Disposition / path | Headless command | GUI equivalent | PASS | Maps to |
|---|---|---|---|---|---|
| **S3.1** | **PROCESSED** (ADT^A05 → file archive) | `python -m harness --scenario processed --engine http://127.0.0.1:8765 --token <T>` | Send tab → ADT^A05 to inbound; Monitor shows RECEIVED→ROUTED→PROCESSED; the single **file-archive** outbound row `delivered` | Disposition `processed`; file-archive delivery succeeds; exit 0. *(To see the echo+file FAN-OUT, send A01/A04/A08 from the GUI Send tab with the Receive tab on 2576 — see S3.1b.)* | new (functional coverage) |
| **S3.1b** | **PROCESSED with fan-out** (A01 → MLLP echo + file) | (no `--scenario`; GUI only) | Send tab → healthy **ADT^A01** to 2575, harness Receive tab listening+AA on **2576**; Monitor shows **both** outbound rows (echo + file) `delivered` | Disposition `processed`; **both** fan-out deliveries succeed | new (functional coverage) |
| **S3.2** | **FILTERED** (ADT^A02 handler drops, still logged) | `python -m harness --scenario filtered --engine http://127.0.0.1:8765 --token <T>` | Send tab → ADT^A02; Monitor shows `FILTERED` (handler ran, returned None) | Disposition `filtered`, message logged not dropped; exit 0 | new |
| **S3.3** | **UNROUTED** (ORU^R01, router returns []) | `python -m harness --scenario unrouted --engine http://127.0.0.1:8765 --token <T>` | Send tab → ORU^R01; Monitor shows `UNROUTED` | Disposition `unrouted`; logged; exit 0 | new |
| **S3.4** | **ERROR / AE NAK** (ADT^A03 handler raises) | `python -m harness --scenario error --engine http://127.0.0.1:8765 --token <T>` | Compose tab **no-MSH**/**wrong-version** preset → send; Monitor shows `ERROR`; sender sees AE/AR | Disposition `error`; synchronous AE/AR NAK at the listener; Connection stays up; exit 0 | new; ties **S2.7** |
| **S3.5** | **dead-letter → replay** (A01 echo to DOWNED 2576) | (ensure **nothing** listens on 2576) `python -m harness --scenario dead_letter --engine http://127.0.0.1:8765 --token <T>` | Send ADT^A01 with 2576 down → echo row exhausts retries → `dead`; then replay via console/API; confirm delivery | Disposition reaches `dead`/dead-letter; bulk replay redelivers to `delivered` (no loss); exit 0 | new; ties D19/dead-letter recovery |

> **S3.5 source-of-dead-letter:** the headless `dead_letter` scenario requires the echo destination (2576) to be **genuinely down** (connect fails → retries exhaust → dead-letter). A Receive tab that is **up but NAKing** is a *different* (also valid) path — demonstrate that one separately via the GUI Receive **fail** mode; label them distinctly so the headless gate isn't run against an up-but-failing listener.

```powershell
# Headless disposition gate (ensure NOTHING is listening on 2576 before the dead_letter run):
foreach ($s in @('processed','filtered','unrouted','error','dead_letter')) {
  python -m harness --scenario $s --engine http://127.0.0.1:8765 --token <T> --timeout 30
  # each exits 0 on the asserted disposition
}
```

### S3.6 — independent draining (echo dead-letters while file archive succeeds)

| Field | Value |
|---|---|
| **ID** | S3.6 |
| **Objective** | Prove the outbound Connections drain **independently**: for an **A01** (fan-out: MLLP echo + file archive), make the MLLP echo destination fail (dead-letter) while the file archive **succeeds** for the same message — a slow/failing outbound never blocks its sibling. |
| **Steps** | 1. Serve `harness/config`. 2. Set the harness **Receive** tab (the echo destination on 2576) fault = **fail/close** so echo dead-letters; leave the file destination healthy. 3. Inject a healthy **ADT^A01** (GUI Send tab) so fan-out fires. 4. Confirm the file archive row is `delivered` while the echo row goes to retry/`dead`, and the finalizer reflects the mixed outcome (not `processed`, since one Handler delivered nothing). |
| **PASS** | For one A01: file-archive outbound `delivered`; MLLP-echo outbound `dead`/retrying — **independently**, with the file delivery NOT blocked by the failing echo. Finalizer disposition reflects the mix (per the count-and-log invariant: the message is not finalized `processed` while a sibling is dead-lettered). |
| **Per-DB** | once (SQLite). |
| **Where** | ON the box (GUI Receive fault) or remote with a controllable echo listener. |
| **Duration** | 15 min. |
| **Maps to** | Reliability invariant (independent per-outbound draining); new functional coverage. |

### S3.7 — retry highlight (transient AE → recover → delivered)

| Field | Value |
|---|---|
| **ID** | S3.7 |
| **Objective** | Showcase exponential-backoff retry: a transient AE on the outbound converges to `delivered` after the downstream recovers, with no manual replay. |
| **Steps** | 1. Receive tab (2576) fault = **fail-N** (return AE for N messages, then AA). 2. Inject a healthy **A01** (GUI). 3. Watch the engine retry the AE with backoff and deliver once the listener returns AA. |
| **PASS** | The echo outbound row transitions retry→`delivered` after ≤ N AE responses; no manual intervention; backoff observed in the Monitor/logs. |
| **Per-DB** | once (SQLite). |
| **Where** | ON the box (GUI) or remote with controllable listener. |
| **Duration** | 10 min. |
| **Maps to** | D19 retry behavior (functional showcase, not re-proof); new coverage row. |

### S3.9 — per-backend disposition smoke (x3)

| Field | Value |
|---|---|
| **ID** | S3.9-{SQLITE,MSSQL,PG} |
| **Objective** | Run the core disposition smoke (`processed` + `filtered` + `error`) **once per backend** to confirm the store records dispositions identically on SQLite, SQL Server, and PostgreSQL. |
| **Steps** | Re-serve `harness/config` pointed at each backend (`MEFOR_STORE_BACKEND` / `MEFOR_STORE_*`), then run the three core scenarios. |
| **Command** | per-backend `serve`, then `python -m harness --scenario {processed,filtered,error} --engine http://127.0.0.1:8765 --token <T>` |
| **PASS** | All three scenarios exit 0 on each backend; dispositions recorded identically (RECEIVED→…→PROCESSED / FILTERED / ERROR). |
| **Per-DB** | **x3**. |
| **Where** | ON the box. |
| **Duration** | 15 min per backend (45 min total). |
| **Maps to** | Store parity (functional disposition recording per backend); new. |

```powershell
$env:MEFOR_STORE_BACKEND="sqlserver"   # then "postgres", then unset for sqlite
python -m messagefoundry serve --config C:\srv\mefor\src\harness\config --db ./hsmoke.db --env dev   # adjust --db / MEFOR_STORE_* per backend
foreach ($s in @('processed','filtered','error')) {
  python -m harness --scenario $s --engine http://127.0.0.1:8765 --token <T> --timeout 30
}
```

### S3.10 — reconcile output-parity spot-check (new)

| Field | Value |
|---|---|
| **ID** | S3.10 |
| **Objective** | Prove the parallel-run **reconcile** capability works on the box under the service identity: capture a MEFOR outbound and `compare` it against a known-good (synthetic) golden export, per-connection, with HL7-aware normalization and a gating exit code. (The natural Corepoint-cutover output-fidelity tool — exercised here on a synthetic golden pair so the box has proven it functions, not a migration cutover.) |
| **Tool / command** | `python -m harness.reconcile capture …` then `python -m harness.reconcile compare …` against a synthetic golden pair |
| **Steps** | 1. With the engine serving and delivering, `capture` the MEFOR outbound for a named connection to a capture dir. 2. `compare` the capture against a synthetic golden export (generated PHI-free), using the HL7-aware normalizer. 3. Confirm the comparison exit code gates on parity. |
| **PASS** | `reconcile compare` runs under the service identity and exits 0 on a matching synthetic golden pair (and non-zero on a deliberately mismatched pair — sanity); per-connection diff report produced, metrics/metadata only. |
| **Per-DB** | once (output-parity is store-agnostic; SQLite). |
| **Where** | ON the box (or remote capture if the engine API is reachable). |
| **Duration** | 20 min. |
| **Maps to** | Reconcile capability inventory (S0.1); migration-parity readiness; new. |

> **Conscious scope note:** S3.10 is a *capability proof on the box*, not a real Corepoint cutover reconciliation (that is a migration-time artifact validated elsewhere with golden pairs from the Corepoint TEST export). Synthetic golden pair only.

**GUI walk note (operator sign-off):** the full Send→Monitor disposition walk (**S1.AC-DISPO**) plus the Compose fault presets (S3.4) and Receive fault modes (S3.5/S3.6/S3.7) are the human-observed evidence pasted into the matrix; the headless `--scenario` runs are the automated gate. Both must agree.

---

## Section 4 — Throughput & stress

### 4.0 Framing, harness placement, and the load SUT

**Why this box, not CI.** CI already proves *smoke-sized* throughput and the zero-loss / per-lane-FIFO SLO inside a Linux container: co-located DB containers on a shared 1× runner, auth off, a synthetic graph, the `smoke` and `smoke-sqlserver` profiles on push-to-main, plus an in-process load runner per PR (`test_load_runner.py`). That is a *correctness/regression* gate at a fixed small size. It deliberately does **not** — and structurally **cannot** — establish a real-host throughput **ceiling**. This box does: it is the real **Windows Server 2025** host (WIN-NAFGLU5SH1J), running the real **ODBC Driver 18** stack, under the real **NSSM service identity**, on **production-class storage with real disk/NIC**, with **all three backends (SQLite / SQL Server / PostgreSQL) co-resident**, and it is the only place to measure **Windows failover-recovery timing** (the Windows port-rebind lag CI never sees). The output of this section is therefore a **distinct, first-of-its-kind host baseline**, not a re-run of the CI zero-loss check (see S0.5). **Do not** re-prove smoke-sized zero-loss here except as the wiring sanity that precedes the real measurements (4.1 step 1).

**Harness placement (wheel-only reality).** The wheel-only / harness-placement strategy and the **cwd/auth-token** rules are defined once in **S0.4** and the Section 2 auth note. For this section: the load and scenario harness is Qt-free and speaks only MLLP + the HTTP API against an already-running engine, so the two placements apply per test —

- **(a) Drive remotely from a dev PC** (preferred for 4.1–4.8): the box runs `serve`, the dev PC runs `python -m harness ... --engine http://<box-ip>:8765 --token <T>`. Latency includes the LAN hop — note it, prefer (b) for pure host latency.
- **(b) Copy the standalone `harness/` directory onto the box** and run it there (the wheel satisfies imports; no PySide6 for `--load`/`--failover`/`--scenario`). This eliminates the LAN hop and is **required** for 4.9 failover (the failover harness *spawns* the two `serve` nodes from the cwd-relative `harness/config/load`, so it must run on the box from a cwd containing `harness/`).

Nothing in this section requires an engine *source* checkout on the box; it requires only the installed wheel (to `serve`) plus the harness via (a) or (b). The acceptance runner and its `tests/` tree are out of scope for Section 4. **All headless harness runs pass `--token <T>`** (the failover orchestrator excepted — it disables auth on its spawned nodes).

**Validate custom profiles before use.** The four new profiles in Appendix D are pure data but use the real `harness/load/profile.py` schema (`[load]` / `[[load.target]]` / `[load.mix]` / `[load.slo]` / `[[load.phase]]` with `rate_start`). The parser fails loud on any schema error → exit 2 before traffic. **Preflight each with `python -m harness --load <path> …` (or `--list-profiles`) and confirm it loads** before relying on it.

**The load SUT.** All load profiles drive the synthetic high-fan-out graph at `harness/config/load` (`graph.py`). It defines three inbound MLLP hubs, each fanning **every** received message to a full Handler set into the harness correlation sink:

| Inbound (Connection) | Port | Fan-out knob (default) |
|---|---|---|
| `IB_Load_ADT` | 2600 | `MEFOR_LOAD_FANOUT` (20) |
| `IB_Load_Results` | 2601 | `MEFOR_LOAD_RESULTS_FANOUT` (4) |
| `IB_Load_Other` | 2602 | `MEFOR_LOAD_RESULTS_FANOUT` (4) — **shared with the Results lane** |

> **Fan-out knob correction:** in `harness/config/load/graph.py` **both** the Results (`_RES_HANDLERS`) and Other (`_OTH_HANDLERS`) lanes use `_SHAPE.results_fanout`. So `MEFOR_LOAD_RESULTS_FANOUT` governs the Other lane's write volume too; only the ADT lane has its own `MEFOR_LOAD_FANOUT`. There is **no** separate Other knob — to scale Other-hub write volume, raise `MEFOR_LOAD_RESULTS_FANOUT`.

Serve it on the box (pick the backend per test via `MEFOR_STORE_*`; `--db` is the SQLite file path):

```powershell
# SQLite (anchor)
python -m messagefoundry serve --config C:\srv\mefor\src\harness\config\load --db C:\srv\mefor\load.db --env dev

# SQL Server / PostgreSQL: set the store env, then serve
$env:MEFOR_STORE_BACKEND="sqlserver"; $env:MEFOR_STORE_SERVER="localhost"; $env:MEFOR_STORE_DATABASE="mefor_load"
$env:MEFOR_STORE_AUTH="sql"; $env:MEFOR_STORE_USERNAME="mefor_load"; $env:MEFOR_STORE_PASSWORD="<from MEFOR_*>"
python -m messagefoundry serve --config C:\srv\mefor\src\harness\config\load --env dev
```

**SUT knobs** (set on the **serve** side — profiles are pure data and carry no engine-side config): `MEFOR_LOAD_FANOUT` (20, ADT lane), `MEFOR_LOAD_RESULTS_FANOUT` (4, Results **and** Other lanes), `MEFOR_LOAD_TRANSFORM` (`cheap`|`edit`|`slow`), `MEFOR_LOAD_TRANSFORM_MS` (1.0), `MEFOR_LOAD_SINK_HOST`/`_SINK_PORT` (2700)/`_SINK_PORTS` (1), `MEFOR_LOAD_ADT_PORT` (2600)/`_RESULTS_PORT` (2601)/`_OTHER_PORT` (2602). **Restart `serve` after changing any `MEFOR_LOAD_*`** — they bind at graph load.

**Measurement model (applies to every 4.x verdict).** Only `sustained`/`soak` phases are scored; `warmup`/`ramp`/`spike` are transient and excluded from the verdict (but their backlog/recovery are watched). Three channels: sender ACK/intake latency, the **correlation sink** true E2E (DB-free, fan-out-aware), and the engine `/stats` poller (throughput / backlog / `in_pipeline` / drain). No-loss reconciliation is fan-out-agnostic: `read>=sent`, `sink_received>=written`, `backlog==0`; any excess is benign `at_least_once_redeliveries`, **never** loss. Every `--load` run must end `backlog==0` (drained) to be valid.

**Output convention.** All reports land under an **absolute** dir outside the source checkout, e.g. `C:\srv\mefor\reports\load\`, as `--report-json` (+ optional `--report-csv`). (Relative `out\…` would resolve against the harness cwd, i.e. inside the checkout — avoid, both to keep evidence findable and to keep load reports out of git.) Set the **first host baseline** from 4.1 and feed it to later runs with `--baseline <run.json> --tolerance 0.1`. Per-DB applicability is called out per test (**once** / **x3** / **x2**).

---

### S4.1 — Per-DB throughput baseline (wiring → realistic mix)

| | |
|---|---|
| **ID** | S4.1 |
| **Objective** | Establish the box's **first throughput baseline** per backend: prove wiring with `smoke`, then measure the realistic-mix latency-at-load with `fanout-baseline`. Persist the JSON as the canonical baseline for all later comparison. |
| **Tool** | Load harness (`python -m harness --load`) over MLLP+HTTP against the running `serve`. |
| **Applicability** | **x3** — SQLite, SQL Server, PostgreSQL. |
| **Where** | Engine on the box; harness from dev PC (a) **or** on the box (b). Prefer (b) for pure-host latency. |
| **Est.** | ~25 min total (3 backends × [smoke ~2 min + fanout-baseline ~6 min] + setup). |
| **Maps to** | Real-host ceiling; matrix throughput rows (H1 satisfied here, not by the stale `steady`). |

**Commands** (repeat per backend; serve the matching `MEFOR_STORE_*` first; `--token <T>` on every run):

```powershell
# 1) Wiring sanity (zero-loss only — NOT a perf number)
python -m harness --load smoke --engine http://127.0.0.1:8765 --token <T> `
  --db-backend sqlite --report-json C:\srv\mefor\reports\load\smoke-sqlite.json

# 2) Realistic-mix baseline (ADT-dominant; ships a 2000 msg/s 20s spike + ACK SLO)
python -m harness --load fanout-baseline --engine http://127.0.0.1:8765 --token <T> `
  --db-backend sqlite --report-json C:\srv\mefor\reports\load\baseline-sqlite.json --report-csv C:\srv\mefor\reports\load\baseline-sqlite.csv
```

For SQL Server use `--db-backend sqlserver --report-json …\baseline-mssql.json`; for PostgreSQL `--db-backend postgres … baseline-pg.json`. The `--db-backend` flag only **tags** the report — the actual store is whatever `serve` was started against, so keep them aligned.

**Cross-backend comparison** (after all three baselines exist, anchor on SQLite):

```powershell
python -m harness --load fanout-baseline --engine http://127.0.0.1:8765 --token <T> `
  --db-backend postgres --baseline C:\srv\mefor\reports\load\baseline-sqlite.json --tolerance 0.1 `
  --report-json C:\srv\mefor\reports\load\baseline-pg-vs-sqlite.json
```

**PASS:**
- `smoke`: exit 0, `zero_loss=true`, `backlog==0`. (Wiring proven; no throughput assertion.)
- `fanout-baseline`: exit 0 — meets shipped SLO `min_sustained_msg_s>=200`, `max_e2e_p99_ms<=5000`, `max_ack_p99_ms<=50` (spike-phase ACK), `zero_loss=true`, drained.
- A persisted `baseline-<backend>.json` exists for all three backends.
- Comparison run does not regress beyond `--tolerance 0.1` vs the SQLite anchor (or the regression is explained — e.g. server-DB network/ODBC overhead).

**Watch:** SQLite's single-writer WAL is the **anchor ceiling** — expect it to bound sustained write-amplified throughput; SQL Server / PostgreSQL should meet or exceed it on real storage but pay ODBC/round-trip latency on E2E p99. Record achieved `sustained_msg_s`, `e2e_p99_ms`, `ack_p99_ms`, drain time per backend.

---

### S4.2 — Max sustainable throughput (closed-loop ceiling)

| | |
|---|---|
| **ID** | S4.2 |
| **Objective** | Find the **maximum sustainable throughput** per backend with no local-backlog inflation, by holding a fixed number of messages in flight (closed loop) rather than a fixed offered rate. This is the real-host ceiling number CI cannot produce. |
| **Tool** | Load harness, built-in `closed-loop` profile (concurrency sweep; conformance-only SLO, **no throughput floor** — reported as-observed). |
| **Applicability** | **x3**. |
| **Where** | Engine on box; harness (a) or (b). Prefer (b) — closed-loop measures the engine ceiling, so remove the LAN hop. |
| **Est.** | ~12 min/backend → ~35 min x3. |
| **Maps to** | Closed-loop ceiling on real storage. |

**Commands:**

```powershell
python -m harness --load closed-loop --engine http://127.0.0.1:8765 --token <T> `
  --db-backend sqlserver --report-json C:\srv\mefor\reports\load\ceiling-mssql.json --report-csv C:\srv\mefor\reports\load\ceiling-mssql.csv
```

(Repeat with `--db-backend sqlite` / `postgres` against the matching `serve`.)

**PASS:**
- exit 0 (conformance invariants hold: `zero_loss=true`, FIFO preserved, drained `backlog==0`).
- A monotonic-then-plateau curve is captured: record the **achieved `sustained_msg_s` at each concurrency step**, the `e2e_p99_ms` at the knee, and the step where throughput stops rising (the ceiling).
- The report's "harness-was-the-limit" flag is **NOT** set at the plateau step (so the plateau is the engine's, not the sender's — see S4.7).

**Watch:** the concurrency step at which `sustained_msg_s` flattens while `e2e_p99_ms` climbs = the ceiling. Compare ceilings across backends; SQLite should plateau earliest (single-writer). If the plateau coincides with the limit flag, re-run with a larger pool / from the box to confirm it's the engine.

---

### S4.3 — Spike / burst stress

| | |
|---|---|
| **ID** | S4.3 |
| **Objective** | Drive a short burst **above** the S4.2 sustained ceiling and confirm the engine absorbs it: backlog grows then **drains to zero**, no loss, ACK SLO honored during the burst. |
| **Tool** | Load harness. First try the shipped `fanout-baseline` spike phase (2000 msg/s, 20 s). If that burst is below this host's ceiling (likely on real hardware), use the **new `spike-burst` profile** below run as a single burst. |
| **Applicability** | **once** (backend-independent stress shape; optionally x3 if you want per-backend burst absorption). Run on SQLite first, then the slowest backend. |
| **Where** | Engine on box; harness (a) or (b). |
| **Est.** | ~5 min. |
| **Maps to** | Stress-gap (spike); §4 robustness. |

**Command (shipped):**

```powershell
python -m harness --load fanout-baseline --engine http://127.0.0.1:8765 --token <T> `
  --db-backend sqlite --report-json C:\srv\mefor\reports\load\spike-sqlite.json
```

If you need a burst clearly above the measured ceiling and a measured recovery window, drop in the **new `spike-burst.toml`** profile (real schema; full contents in Appendix D; place under the laid-down `harness\load\profiles\` or run via `--load <path>`). It models warmup → `spike` (above-ceiling, excluded from the verdict) → a `sustained` **recovery** phase (under ceiling, measured) so the drain is the signal:

```powershell
python -m harness --load harness\load\profiles\spike-burst.toml --engine http://127.0.0.1:8765 --token <T> `
  --db-backend sqlite --report-json C:\srv\mefor\reports\load\spike-burst-sqlite.json
```

**PASS:** exit 0; during the spike phase backlog rises but the subsequent `sustained` recovery phase drains `backlog` to 0; `zero_loss=true`; `max_ack_p99_ms<=50` honored. The recovery phase reaches steady state (no permanent backlog).

**Watch:** peak `backlog`, time from spike-end to `backlog==0`, ACK p99 during vs after the burst, any dead-letters (must be 0 for well-formed traffic).

---

### S4.4 — Transform-cost ceiling (CPU wall)

| | |
|---|---|
| **ID** | S4.4 |
| **Objective** | Demonstrate the **"transform, not framing, dominates throughput"** finding on this host's real CPU: hold framing constant and inflate per-message transform cost to find the single-core transform ceiling. |
| **Tool** | Load harness `closed-loop` (low concurrency, single ADT hub) **with** `MEFOR_LOAD_TRANSFORM=slow` + `MEFOR_LOAD_TRANSFORM_MS` swept on the **serve** side (CPU `_spin` on the event loop). |
| **Applicability** | **once** (CPU-bound, store-independent — use SQLite to keep store cost out of the picture). |
| **Where** | Engine on box; harness (a) or (b). Must restart `serve` for each `_MS` value. |
| **Est.** | ~15 min (3–4 `_MS` points × ~3 min). |
| **Maps to** | Stress dimension "transform-cost ceiling"; "transform dominates". |

**Setup — restart serve per sweep point** (example for 5 ms, fan-out 20):

```powershell
$env:MEFOR_LOAD_TRANSFORM="slow"; $env:MEFOR_LOAD_TRANSFORM_MS="5"; $env:MEFOR_LOAD_FANOUT="20"
python -m messagefoundry serve --config C:\srv\mefor\src\harness\config\load --db C:\srv\mefor\load.db --env dev
```

**Drive (constrain to the single ADT hub via low concurrency):**

```powershell
python -m harness --load closed-loop --engine http://127.0.0.1:8765 --token <T> `
  --db-backend sqlite --report-json C:\srv\mefor\reports\load\transform-5ms.json
```

Sweep `MEFOR_LOAD_TRANSFORM_MS` over e.g. `1, 2, 5, 10` (restart serve each time; report `transform-1ms.json` … `transform-10ms.json`).

**PASS / expected curve:** measured `sustained_msg_s` plateaus near the analytic single-core wall **≈ 1000 / (fan-out × `_MS`) msg/s** for each `_MS` (e.g. 20 × 5 ms → ≈ 10 msg/s), confirming throughput scales **inversely with transform cost**, not with framing. Record the achieved plateau vs the predicted wall per `_MS` point. exit 0, `zero_loss=true`, drained.

**Watch:** the `_spin` runs on the asyncio **event loop (single-threaded)**, so raising `_MS` throttles the **whole engine**, not one of several cores in parallel — the figure is **single-core-bound** (the "msg/s/core" label means single-core; the transform runs on the single asyncio event-loop thread, so even the **free-threaded `python3.14t` (no-GIL) build does not parallelize one event loop** — record which 3.14 build the box runs, standard or `3.14t`, since it bounds how to read this number). The transform runs **per handler** (one routed row per handler = fan-out times per inbound message), which the formula captures, but the spin also blocks intake. Attribute the gap between predicted and achieved to event-loop + store overhead. This isolates the host CPU clock as the transform ceiling.

---

### S4.5 — Fan-out write-amplification

| | |
|---|---|
| **ID** | S4.5 |
| **Objective** | Stress outbound + store **write volume** by amplifying fan-out (each message → N outbound rows + N deliveries) and observe DB/WAL growth and drain per backend. |
| **Tool** | Load harness `closed-loop` (or `reference`) with `MEFOR_LOAD_FANOUT` (ADT lane) swept on the serve side, or the **new `writeamp.toml`** thin-lane profile. |
| **Applicability** | **x3** (write amplification is a store-pressure test — the whole point is to compare backends). |
| **Where** | Engine on box; harness (a) or (b). Restart serve per fan-out value. |
| **Est.** | ~20 min/backend across the sweep → run SQLite + the two server DBs (~50 min). |
| **Maps to** | "fan-out amplification" + stress-gap (high write-amplification). |

**Setup — sweep `MEFOR_LOAD_FANOUT` = 1, 10, 50, 100, restart serve each time, raise drain timeout as fan-out climbs:**

```powershell
$env:MEFOR_LOAD_FANOUT="50"
python -m messagefoundry serve --config C:\srv\mefor\src\harness\config\load --db C:\srv\mefor\load.db --env dev
```

For very high fan-out, run with the **new `writeamp.toml`** profile (single thin open lane so you isolate write volume, generous drain — full contents in Appendix D):

```powershell
python -m harness --load harness\load\profiles\writeamp.toml --engine http://127.0.0.1:8765 --token <T> `
  --db-backend postgres --report-json C:\srv\mefor\reports\load\writeamp-fanout50-pg.json
```

**PASS:** exit 0, `zero_loss=true`, **`backlog` drains to 0 within `drain_timeout_s`** at every fan-out level. Capture, per fan-out × backend: peak `in_pipeline`, peak `backlog`, drain time, and on-disk growth (SQLite `.db`+`-wal` size; SQL Server / PostgreSQL DB size).

**Watch:** SQLite `-wal` growth + checkpoint behavior under high fan-out; SQL Server / PostgreSQL store-write latency and connection-pool saturation; the drain time scaling roughly linearly with fan-out. If a backend can't drain at fan-out 100 within the timeout, that is the host's write-amplification ceiling for that store — record it.

---

### S4.6 — Soak

| | |
|---|---|
| **ID** | S4.6 |
| **Objective** | Prove steady-state stability over a long run: no DB/WAL creep, no dead-letter accumulation, no memory growth, drain-to-zero at end. |
| **Tool** | Load harness `soak` profile (ships 1 h @ 300 msg/s; `min_sustained_msg_s=100`). |
| **Applicability** | **Resolved (S0.7 A1): 8 h overnight on SQL Server** (production-target store) **+ 1 h each on SQLite (anchor) and PostgreSQL (parity)**. If the box can't hold 8 h, do ≥2 h on SQL Server and record the shortfall. |
| **Where** | Engine on box; harness (a) or (b). Run engine **under the NSSM service identity** if coordinating with the production-posture story (otherwise foreground is acceptable for the soak shape). |
| **Est.** | SQL Server **8 h** (overnight, the cloned 28800 s soak below); SQLite + PostgreSQL **1 h** each (the shipped `soak`). |
| **Maps to** | `soak` (DB/WAL growth + dead-letter accumulation watch); stress dimension "soak". |

**Command:**

```powershell
python -m harness --load soak --engine http://127.0.0.1:8765 --token <T> `
  --db-backend sqlserver --report-json C:\srv\mefor\reports\load\soak-mssql.json --report-csv C:\srv\mefor\reports\load\soak-mssql.csv
```

For an extended overnight soak, clone `soak.toml` and raise the **single `[[load.phase]]` whose `kind = "soak"`** `duration_s` to `28800` (8 h) — the shipped soak profile has **no `sustained` phase**, so edit the `soak`-kind phase, not a `sustained` one. **Preflight the clone** (`python -m harness --load <path> --token <T> …` loads it) before the overnight run, and run it from the box (b) to avoid a multi-hour dev-PC LAN dependency.

**PASS:** exit 0, `zero_loss=true`, `backlog==0` at end (drains cleanly), **dead_letters==0** for well-formed traffic, throughput stays within tolerance of the run's own early steady-state (no decay), and DB/WAL footprint stabilizes (checkpoint keeps WAL bounded; SQL Server / PostgreSQL DB size grows only with retained rows, not unboundedly). Engine process RSS does not creep across the run.

**Watch:** sample `…\load\*.csv` over time for throughput decay; periodically size the store (`.db`/`-wal`, or `sp_spaceused` / `pg_database_size`); watch `dead_letters` and engine RSS (Task Manager / `Get-Process`). Any monotonic growth in WAL/dead-letters/RSS = fail.

---

### S4.7 — Overload / backpressure (the number is the engine's, not the sender's)

| | |
|---|---|
| **ID** | S4.7 |
| **Objective** | Offer **beyond** the measured ceiling for minutes and assert graceful backpressure: backlog inflates under load but **drains to zero after load stops**, `zero_loss` holds, and the report's **"harness-was-the-limit" flag is NOT set** — so the ceiling from S4.2 is provably the engine's, not the load generator's. |
| **Tool** | Load harness with the **new `sustained-overload.toml`** profile (no shipped profile *holds* offered rate above the delivery ceiling for minutes — `reference` drains and `fanout-baseline`'s spike is 20 s). Full contents in Appendix D. |
| **Applicability** | **once** (validate the ceiling is real); optionally **x3** if you want per-backend backpressure behavior. |
| **Where** | Engine on box; harness **on the box (b)** strongly preferred — driving overload over a LAN hop risks the *dev PC's* NIC being the limit. |
| **Est.** | ~10 min. |
| **Maps to** | Stress-gap (sustained overload / backpressure); validates S4.2. |

Set the overload phase `rate_start` ≈ 3–5× the S4.2 knee for this host (the Appendix D template uses 4000).

```powershell
python -m harness --load harness\load\profiles\sustained-overload.toml --engine http://127.0.0.1:8765 --token <T> `
  --db-backend sqlite --report-json C:\srv\mefor\reports\load\overload-sqlite.json
```

**PASS:**
- exit 0; `zero_loss=true`; final `backlog==0` (the drain phase clears the inflated backlog within `drain_timeout_s`).
- The report's **"harness-was-the-limit" / sender-limited flag is FALSE** during the overload phase (offers the pool couldn't take show as `deferred`, confirming the engine — not the sender — set the rate).
- During overload, `backlog` and E2E p99 climb (expected) while ACK intake stays bounded; after load stops they recover.

**Watch:** the `deferred` count (offers the pool refused) — its presence with the limit-flag false is exactly the proof the engine is the bottleneck. If the limit-flag is **true**, the sender saturated first — re-run from the box / increase the pool and repeat before trusting any ceiling number.

---

### S4.8 — Robustness under load (malformed / oversized / mid-frame disconnect, while sustained)

| | |
|---|---|
| **ID** | S4.8 |
| **Objective** | Confirm the Connection **stays up and dead-letters cleanly under sustained throughput** when malformed / oversized / mid-frame-disconnect traffic is mixed in — the **S2.7** robustness path, but **under load** (a slow/failing transform or a bad message must not stall intake or crash the lane). **Cross-reference: S2.7 covers the idle/functional case; this is the under-load case — both are kept, neither repeats the other.** |
| **Tool** | Load harness with the **new `malformed-load.toml`** profile carrying **well-formed traffic only**; bad input (malformed/oversized/mid-frame) is driven **concurrently** from the **harness GUI Compose/Send fault-injection tab** (desktop session). |
| **Applicability** | **once** (robustness shape; run on SQLite, then re-confirm on SQL Server since the dead-letter persistence path differs). |
| **Where** | `--load` from box/dev PC; the **fault-injection GUI must run on a desktop session on the box** (PySide6). All three bad-input cases are GUI-driven; the profile supplies only the well-formed background load. |
| **Est.** | ~12 min. |
| **Maps to** | Stress-gap (malformed-under-load); gap-map **#7** (robustness) — **under load** here (idle case = **S2.7**). |

> **Why bad input is NOT in the profile mix:** the harness corpus is built by `generators._core.generate_message`, which only emits **hl7apy-conformant** messages and **raises** on an unknown trigger (e.g. an `ADT^BAD` mix key → `KeyError: unknown ADT trigger(s): BAD`), failing corpus build at preflight (exit 2). A malformed/oversized message therefore **cannot** be expressed as a profile mix entry. The `malformed-load.toml` profile carries only well-formed ADT (background throughput); the malformed/oversized/torn-frame inputs are injected from the **GUI Compose presets (no-MSH / wrong-version / oversized) and the Send/Receive fault "close mid-frame"**, fired against `IB_Load_ADT` :2600 **while** the sustained phase runs. (The malformed- and oversized-corpus generators are the same flagged **engineering dependency** if a repeatable, fully-automated version is wanted later.)

```powershell
# Well-formed background load (Appendix D profile — preflight it first):
python -m harness --load harness\load\profiles\malformed-load.toml --engine http://127.0.0.1:8765 --token <T> `
  --db-backend sqlite --report-json C:\srv\mefor\reports\load\malformed-load-sqlite.json
# CONCURRENTLY, from the box's desktop GUI: Compose no-MSH/wrong-version/oversized + Send/Receive "close mid-frame" to :2600.
```

**PASS:** exit 0 with the well-formed SLO honored; the inbound lane **never stops** (well-formed `sustained_msg_s` holds through the GUI fault injections); each malformed/oversized/torn message is recorded `ERROR`/dead-letter, **never** silently dropped; `zero_loss=true` for well-formed messages; engine and the `serve` process stay up. The Connection is not killed by any bad input (count-and-log invariant holds under load).

**Watch:** that throughput for the good fraction does not dip when bad messages arrive (no head-of-line stall — the staged pipeline should isolate the failing transform/parse); the dead-letter / ERROR rows accumulate exactly to the injected bad-message count; no Connection restart in the engine log.

---

### S4.9 — Failover under load (Gate #3) — and the Windows recovery-time number

| | |
|---|---|
| **ID** | S4.9 |
| **Objective** | Two-node, primary-killed-under-load failover: assert the **hard-gated conformance invariants** AND **report the Windows recovery TIME** — the number CI structurally cannot produce because of the Windows port-rebind lag. |
| **Tool** | Failover harness (`python -m harness --failover failover`). It **owns and spawns both `serve` nodes** (with `MEFOR_AUTH_ENABLED=false` on them, so **no `--token`**) against a shared **server** DB, kills the primary under load, and scores recovery + invariants. **Lease timings come from the profile's `[load.failover]` table** (heartbeat/fence/ttl in seconds), which the orchestrator propagates to both nodes as `MEFOR_CLUSTER_*_SECONDS` — do **not** set them in the operator env (see S5.3). |
| **Applicability** | **SQL Server and PostgreSQL only (x2)**. **SQLite EXCLUDED** — it can't cluster (no shared server store). |
| **Where** | **ON the box only (placement b)** — the harness launches two `serve` processes (spawning `serve --config harness/config/load` resolved against the cwd) and binds the node/sink ports; it cannot do that against a remote engine. **cwd must contain `harness/config/load`.** |
| **Prereq** | `MEFOR_STORE_BACKEND=postgres|sqlserver` **+** the `MEFOR_STORE_*` connection env for the shared server DB. **`MEFOR_TEST_SQLSERVER`/`MEFOR_TEST_POSTGRES` are NOT consulted by the failover harness** (they gate the S1.7 pytest suites only); the orchestrator refuses to run (exit 2) if `MEFOR_STORE_BACKEND` is unset/`sqlite`. |
| **Est.** | ~10 min/backend → ~20 min x2. |
| **Maps to** | §4 Gate #3 capstone; Windows failover-recovery timing; host trap "Windows port-rebind recovery lag". |

**Commands:**

```powershell
# PostgreSQL (set the STORE backend + connection env; NOT MEFOR_TEST_*):
$env:MEFOR_STORE_BACKEND="postgres"
$env:MEFOR_STORE_SERVER="W2025"; $env:MEFOR_STORE_DATABASE="mefor_store"
$env:MEFOR_STORE_AUTH="sql"; $env:MEFOR_STORE_USERNAME="mefor_svc"; $env:MEFOR_STORE_PASSWORD="<from secret store>"
python -m harness --failover failover --db-backend postgres `
  --inbound-base-port 2600 --sink-port 2700 --report-json C:\srv\mefor\reports\load\failover-pg.json

# SQL Server:
$env:MEFOR_STORE_BACKEND="sqlserver"
# (+ the MEFOR_STORE_* connection env for the shared SQL Server DB)
python -m harness --failover failover --db-backend sqlserver `
  --inbound-base-port 2600 --sink-port 2700 --report-json C:\srv\mefor\reports\load\failover-mssql.json
```

**PASS (exit 0; all hard-gated invariants):**
- **No acknowledged loss** — every ACKed message is ultimately delivered (`read>=sent`, `sink_received>=written`).
- **No split-brain** — leadership lease is self-fencing; never two leaders.
- **Bounded duplicates** — any redeliveries are benign `at_least_once_redeliveries`, within the profile's `max_dup_rate`.
- **Promotion observed** — the surviving node takes leadership; `/cluster` reflects the new leader.
- **Per-lane FIFO** — `lane_inversions == 0`.
- Pipeline **drains** (`backlog==0`) after recovery.

**REPORT (the unique deliverable):** extract and record the **recovery time** from `…\load\failover-*.json` (kill → new-leader-promoted → first message processed by the survivor). **Explicitly call out** that on Windows the killed primary's inbound-port rebind can lag **tens of seconds** (socket release) vs near-instant on Linux — so this recovery-time figure is **host-specific and only obtainable on this box**. CI asserts recovery *occurred*; it cannot assert *how fast* on Windows. Capture the number per backend.

**Watch:** the port-rebind interval specifically (gap between kill and the survivor accepting on the inbound port); lease timing is governed by the profile's `[load.failover]` table (invariant `heartbeat_seconds < leader_fence_timeout_seconds < leader_lease_ttl_seconds`, enforced at parse); any `lane_inversions>0` (immediate fail). Exit codes: 0 pass / 1 invariant-violation / 2 setup / 3 interrupted. To retune lease timings, edit `[load.failover]` in `failover.toml` and re-run.

---

### S4.10 — Host/infra stress (DB restart & service bounce under load)

| | |
|---|---|
| **ID** | S4.10 |
| **Objective** | Real-host fault stress that CI can't reach: bounce the **store** (and separately the **NSSM service**) mid-run and confirm reconnect + no-loss + drain; note connection-pool behavior and storage pressure. |
| **Tool** | Load harness `reference` (or `soak`) providing sustained traffic, **plus** an out-of-band DB restart / service bounce performed on the box. |
| **Applicability** | **SQL Server + PostgreSQL** for the DB-restart variant (server stores with reconnect logic); **all three** for the service-bounce variant. |
| **Where** | **ON the box** — restarting the DB service and bouncing NSSM are OS-level; harness (b) on box or (a) from dev PC for the traffic. |
| **Est.** | ~15 min. |
| **Maps to** | Matrix **B6** (live DB-restart reconnect drill); pool behavior; ties to **S2.4** (crash/restart durability) but here **under sustained load**. |

**Procedure — DB-restart variant (SQL Server example):**

```powershell
# Terminal 1 (box or dev PC): sustained traffic
python -m harness --load reference --engine http://127.0.0.1:8765 --token <T> `
  --db-backend sqlserver --report-json C:\srv\mefor\reports\load\dbrestart-mssql.json

# Terminal 2 (ON the box), mid-run: bounce the store service
Restart-Service -Name "MSSQLSERVER" -Force        # SQL Server
# PostgreSQL: Restart-Service -Name "postgresql-x64-17"
```

**Service-bounce variant (matrix B6 / durability):** mid-run, restart the engine's NSSM service (`Restart-Service -Name "MessageFoundry"` — exact NSSM service name per runbook §4) and confirm the durable `queue` recovers `pending` rows after restart (overlaps **S2.4**; here the value-add is **mid-load**).

**PASS:**
- After the DB comes back, the engine **reconnects** without operator action; the run completes `zero_loss=true` and **`backlog` drains to 0**; any in-flight rows are recovered (`reset_stale_inflight` on the survivor / restart) — at-least-once holds, dups bounded.
- For the service bounce: after restart the durable `queue` `pending` rows are reprocessed; no acknowledged loss.
- No connection-pool deadlock or exhaustion (engine log shows reconnect, not a stuck pool).

**Watch:** reconnect latency (DB-down → first successful store write after recovery); whether the engine dead-letters vs retries during the outage (D19 says retries treat transient like AE — expect retry+recover, **not** permanent dead-letter, for a brief restart); pool re-establishment; on SQLite the service-bounce-only case (no DB to restart). Note storage pressure if the box's disk is shared with the DB.

---

### Throughput & stress reporting

**Where reports land.** All runs write `--report-json C:\srv\mefor\reports\load\<name>-<backend>.json` (and `--report-csv` where a time series is useful — S4.1, S4.2, S4.6). Failover writes `…\load\failover-<backend>.json`. Use **absolute paths outside the source checkout** so the harness cwd doesn't determine where evidence lands, and **never commit** load reports, captures, or generated corpora (they may carry synthetic bodies; treat as the same class as dryrun output — see the header note).

**Baselines.** The S4.1 `baseline-<backend>.json` files are the **canonical host baselines**. Re-runs and cross-backend comparisons pass `--baseline …\baseline-<anchor>.json --tolerance 0.1`; a run that regresses past tolerance exits 1. Re-baseline (and date-stamp the file) only on an intentional host/storage/version change, and record why. SQLite is the standing anchor (single-writer WAL ceiling).

**Per-backend comparison table to fill in** (from S4.1/S4.2/S4.6/S4.9 — these are the host's first real ceilings):

| Metric | SQLite | SQL Server | PostgreSQL | Source test |
|---|---|---|---|---|
| Realistic-mix sustained (msg/s) | _fill_ | _fill_ | _fill_ | S4.1 |
| Realistic-mix E2E p99 (ms) | _fill_ | _fill_ | _fill_ | S4.1 |
| ACK p99 under spike (ms) | _fill_ | _fill_ | _fill_ | S4.1 |
| Closed-loop ceiling (msg/s) + knee concurrency | _fill_ | _fill_ | _fill_ | S4.2 |
| Closed-loop E2E p99 at knee (ms) | _fill_ | _fill_ | _fill_ | S4.2 |
| Transform ceiling (msg/s single-core @ fan-out 20, 5 ms) | _fill_ (store-independent) | — | — | S4.4 |
| Drain time @ fan-out 50 (s) | _fill_ | _fill_ | _fill_ | S4.5 |
| Soak: WAL/DB growth + dead-letters over 1 h | _fill_ | _fill_ | _fill_ | S4.6 |
| Overload backlog peak / drain-to-zero (s); sender-limited? | _fill_ | _fill_ | _fill_ | S4.7 |
| **Failover recovery time (s) — Windows** | n/a (no cluster) | _fill_ | _fill_ | S4.9 |
| DB-restart reconnect latency (s) | n/a | _fill_ | _fill_ | S4.10 |

**Validity gate for every row:** the run exited 0, ended `backlog==0` (drained), `zero_loss=true`, and (for ceiling rows) the "harness-was-the-limit" flag was **false**. A number obtained with the sender saturated (limit-flag true) is not a host ceiling — re-run from the box / with a larger pool first.

> **New data-only artifacts introduced by Section 4** (full contents in Appendix D; place under the laid-down `harness\load\profiles\`): `spike-burst.toml` (S4.3), `writeamp.toml` (S4.5), `sustained-overload.toml` (S4.7), `malformed-load.toml` (S4.8). All use the real `[load]`/`[[load.target]]`/`[load.mix]`/`[load.slo]`/`[[load.phase]]` schema — **preflight each with `python -m harness --load <path>` before relying on it**. Flagged engineering dependency (not pure-data): the malformed- and oversized-body corpus generators for S4.8 (the generator only emits conformant messages).

---

## Section 5 — Per-DB execution matrix & sequencing

### S5.1 Recommended run order (numbered)

Run as a sequence; later phases assume earlier ones are green. Phases (2)–(8) repeat per backend where the matrix (S5.4) says `x3`.

0. **Clean 0.2.1 env + service-identity setup** — upgrade the wheel with **both** server-DB extras (`pip install --upgrade "messagefoundry[sqlserver,postgres]==0.2.1"`, **S1.1**) + `pip install openpyxl`; install Python **machine-wide** (per-user Python blocks non-admin service launch, exit 103); create the dedicated **AD service account / gMSA** (preferred over LocalSystem); grant SQL Server login + DB user (`db_ddladmin`+`db_datawriter`+`db_datareader`) and least-priv Clarity read; one-time DBA `ALTER DATABASE … SET READ_COMMITTED_SNAPSHOT ON`; confirm **ODBC Driver 18** installed at OS level; if running `harness.acceptance`, lay down the pinned `0.2.1` source checkout + seed `WIN2025-TEST-MATRIX.xlsx` (S0.4 / S1.7).
1. **Host smoke** — `verify --section host` (**S1.2**). Confirms ODBC discoverability (A3), MLLP/API/DICOM local bindability, no-flash grep (F7-partial). Gate before anything else.
2. **Acceptance probes** — `python -m harness.acceptance --no-pytest` (**S1.6**, fast probe-only on the laid-down source checkout), then the full `python -m harness.acceptance` with the `--xlsx` write-back (**S1.7**).
3. **Functional disposition coverage** — `python -m harness --scenario {processed,filtered,unrouted,error,dead_letter} --token <T>` against the running engine (**S3.1–S3.5**), plus the reconcile spot-check (**S3.10**).
4. **Gap-closure T1→T3** — **S2.1**→**S2.8** in tier order: T1 (**S2.1** healthy→processed under service, **S2.2** DPAPI boundary) → T2 (**S2.3** outbound MLLP, **S2.4** crash/restart durability, **S2.5** NSSM lifecycle) → T3 (**S2.6** real `encrypt=true`+trusted-cert, **S2.7** malformed/oversized/mid-frame, **S2.8** API auth/bind).
5. **Throughput baseline** — `python -m harness --load smoke` then `--load fanout-baseline` then `--load closed-loop` against the load graph; capture per-backend baseline JSON (**S4.1/S4.2**).
6. **Stress** — spike-burst / sustained-overload / transform-ceiling / write-amplification / malformed-under-load profiles (**S4.3–S4.5, S4.7, S4.8**). Preflight each custom profile first.
7. **Soak** — `python -m harness --load soak` (1 h @ 300 msg/s); watch DB/WAL growth + dead-letter accumulation (**S4.6**).
8. **Failover** — `python -m harness --failover failover --db-backend {postgres|sqlserver}` (set `MEFOR_STORE_BACKEND` + `MEFOR_STORE_*`); record Windows recovery-time (**S4.9**); host/infra stress (**S4.10**).

### S5.2 Per-backend PowerShell env blocks

> Set per-line in PowerShell (`$env:NAME="value"`). `MEFOR_LOAD_*` knobs go on the **`serve` side** (the SUT); profiles are data and carry no backend identity (use `--db-backend` to *tag* the report).

**SQLite (run-once baseline; no server creds):**
```powershell
$env:MEFOR_STORE_BACKEND = "sqlite"
# store path is the serve --db argument, e.g. C:\srv\mefor\data\messagefoundry.db
# Load SUT knobs (only when serving the load graph)
$env:MEFOR_LOAD_FANOUT         = "20"
$env:MEFOR_LOAD_RESULTS_FANOUT = "4"     # governs BOTH the Results and Other lanes
$env:MEFOR_LOAD_TRANSFORM      = "cheap"
$env:MEFOR_LOAD_SINK_PORT      = "2700"
```

**SQL Server (x3 backend):**
```powershell
$env:MEFOR_STORE_BACKEND  = "sqlserver"
$env:MEFOR_STORE_SERVER    = "W2025\SQLEXPRESS"          # or the prod instance
$env:MEFOR_STORE_DATABASE  = "MEFOR_Store"
$env:MEFOR_STORE_AUTH      = "sql"                        # or "integrated" for the AD svc acct
$env:MEFOR_STORE_USERNAME  = "mefor_svc"                  # omit for integrated
$env:MEFOR_STORE_PASSWORD  = $env:MEFOR_STORE_PASSWORD    # from secret store, never inline
# Production posture: encrypt=true + trusted cert in [store]; do NOT set MEFOR_ALLOW_INSECURE_TLS
# Acceptance/pytest server-DB suite gate (S1.7 ONLY — NOT the failover harness):
$env:MEFOR_TEST_SQLSERVER  = "1"
# Load SUT knobs as above
```

**PostgreSQL (x3 backend):**
```powershell
$env:MEFOR_STORE_BACKEND  = "postgres"
$env:MEFOR_STORE_SERVER    = "W2025"
$env:MEFOR_STORE_DATABASE  = "mefor_store"
$env:MEFOR_STORE_AUTH      = "sql"
$env:MEFOR_STORE_USERNAME  = "mefor_svc"
$env:MEFOR_STORE_PASSWORD  = $env:MEFOR_STORE_PASSWORD
# Production posture: libpq sslmode via [store] (sslmode ignored if MEFOR_ALLOW_INSECURE_TLS set — don't)
# Acceptance/pytest server-DB suite gate (S1.7 ONLY):
$env:MEFOR_TEST_POSTGRES   = "1"
# Load SUT knobs as above
```

> **Weakened-TLS only for the dev-cert lane (never the S2.6 production-posture test):** `$env:MEFOR_ALLOW_INSECURE_TLS="1"` **paired** with `encrypt=false`/`trust_server_certificate` in `[store]`. The common first mistake — secure-default `encrypt=true` against a non-TLS dev server — yields a cryptic "rejected SSL upgrade" that does **not** name the fix.

### S5.3 Failover / cluster timing (configured in the profile, NOT operator env)

The failover orchestrator (`harness/load/failover.py`) **sets the spawned nodes' cluster env itself** from the profile's `[load.failover]` table, using **seconds-suffixed** names (`MEFOR_CLUSTER_HEARTBEAT_SECONDS`, `MEFOR_CLUSTER_LEADER_FENCE_TIMEOUT_SECONDS`, `MEFOR_CLUSTER_LEADER_LEASE_TTL_SECONDS`) and `MEFOR_AUTH_ENABLED=false`. **Do NOT export `MEFOR_CLUSTER_*` yourself** — operator values are inert here (and the `*_MS` names the older draft used do not exist). To retune lease timings, edit `failover.toml`'s `[load.failover]` table (the parser enforces `heartbeat_seconds < leader_fence_timeout_seconds < leader_lease_ttl_seconds`):

```toml
# in harness/load/profiles/failover.toml — the orchestrator propagates these to BOTH nodes
[load.failover]
kill_at_fraction             = 0.5
heartbeat_seconds            = 2.0
leader_fence_timeout_seconds = 4.0
leader_lease_ttl_seconds     = 6.0
max_dup_rate                 = 0.05
```

The only env the operator sets for failover is the shared **store** block (`MEFOR_STORE_BACKEND=postgres|sqlserver` + `MEFOR_STORE_*`); SQLite is n-a (no shared server store).

### S5.4 Test-group × backend matrix

| Test group (IDs) | SQLite | SQL Server | PostgreSQL |
|---|---|---|---|
| **S1.2** host smoke (`verify --section host`) | run-once† | x3 (store section per backend) | x3 (store section per backend) |
| **S1.6/S1.7** acceptance probes + full (`harness.acceptance`) | run-once | run-once‡ | run-once‡ |
| **S3.1–S3.7** functional disposition scenarios | run-once | n-a (logic is backend-agnostic) | n-a |
| **S3.10** reconcile output-parity spot-check | run-once | n-a | n-a |
| **S2.1** healthy→PROCESSED under service | run-once§ | **x3** | **x3** |
| **S2.2** DPAPI admin→service key boundary | run-once | n-a (key boundary is identity, not store) | n-a |
| **S2.3** real outbound MLLP delivery | run-once | n-a | n-a |
| **S2.4** crash/restart queue durability | run-once | **x3** | **x3** |
| **S2.5** NSSM lifecycle (autostart/crash-restart) | run-once | n-a | n-a |
| **S2.6** real `encrypt=true` + trusted-cert connect | n-a | **x2 (SQL Server)** | **x2 (PostgreSQL)** |
| **S2.7** malformed / oversized / mid-frame | run-once | n-a | n-a |
| **S2.8** API auth + loopback bind | run-once | n-a | n-a |
| **S4.1/S4.2** throughput baseline + ceiling | **x3** | **x3** | **x3** |
| **S4.3–S4.5, S4.7, S4.8** stress (spike/overload/transform/write-amp/malformed) | run-once¶ | x3 (multi-backend ceiling sweep) | x3 |
| **S4.6** soak (1 h) | run-once | run-once‖ | run-once‖ |
| **S4.9** failover | n-a (single-node) | **x2 (SQL Server)** | **x2 (PostgreSQL)** |
| **S4.10** host/infra stress (DB restart / service bounce) | run-once (service-bounce only) | **x2** | **x2** |

† host section is store-agnostic; the **store** sub-section runs per backend.  ‡ pytest server-DB suites self-skip without `MEFOR_TEST_*`; run once per backend with the gate set.  § proves the path on the simplest store first, then x3.  ¶ stress *shape* validated once on SQLite, then the **multi-backend ceiling sweep** is the x3 part.  ‖ soak run on each backend that is a production candidate.

### S5.5 Rough time budget

| Phase | Est. duration |
|---|---|
| (0) clean env + service-identity setup | 60–120 min (one-time) |
| (1) host smoke | 5 min per backend |
| (2) acceptance probes (`--no-pytest` then full) | 10 min probes + 30–60 min full pytest |
| (3) functional disposition coverage + reconcile | 15 min (5 scenarios) + 20 min (S3.10) |
| (4) gap-closure T1→T3 | 3–4 h (S2.2 DPAPI + S2.5/S2.6 setup-heavy) |
| (5) throughput baseline | 30 min per backend (×3 ≈ 90 min) |
| (6) stress | 60–90 min per backend lane |
| (7) soak | 60 min run + ~15 min teardown/analysis per backend |
| (8) failover + infra stress | 30 min per server backend (×2) |
| **Total (happy path)** | **~2–2.5 full working days** |

---

## Section 6 — Reporting, baselines & sign-off

### S6.1 Artifacts each tool emits

| Tool | Report flags | What it produces | Where archived |
|---|---|---|---|
| `verify` | `--report-md r.md --report-json r.json` | Per-section/per-check PASS/FAIL/SKIP/MANUAL/ERROR; gates exit code on FAIL/ERROR | `C:\srv\mefor\reports\verify\<backend>-<phase>.{md,json}` |
| `check` | `--json` | validate + dryrun + posture; exit 0 iff no required check failed | `C:\srv\mefor\reports\check\<rev>.json` |
| `graph` | `--json` | Wired graph snapshot (wiring diff/sanity) | `C:\srv\mefor\reports\graph\<rev>.json` |
| `audit-verify` | (`--db`/`--service-config`) | Hash-chain verdict — **exits 0 even on FAIL**; must **string-parse** stdout for `FAIL` (D17) | `C:\srv\mefor\reports\audit\<ts>.txt` |
| `harness.acceptance` | `--report-md o.md --report-csv o.csv --xlsx WIN2025-TEST-MATRIX.xlsx` | Stamps the **`Status` column** of the **pre-existing** 54-row matrix workbook (keyed by the matrix's native A/F/G… row IDs), PASS/FAIL/SKIP/MANUAL/ERROR; `--xlsx` needs `openpyxl` + a seed workbook with `ID`/`Status` headers (else exit 2) | `C:\srv\mefor\reports\acceptance\WIN2025-TEST-MATRIX.xlsx` (the signed matrix) |
| `harness --scenario` | (exit code; `--token`) | Per-disposition pass/fail (0 pass / 1 fail / 2 bad-scenario or engine setup) | log captured to `C:\srv\mefor\reports\functional\<scenario>.log` |
| `harness --load` | `--report-json p.json --report-csv p.csv`; `--baseline run.json --tolerance 0.1`; `--token` | Throughput/latency/no-loss/SLO verdict + regression vs baseline | `C:\srv\mefor\reports\load\<backend>-<profile>.{json,csv}` |
| `harness --failover` | `--report-json p.json` (no `--token`; nodes auth-off) | Recovery time, no-loss, bounded dups, FIFO, no split-brain | `C:\srv\mefor\reports\load\failover-<backend>.json` |
| `harness.reconcile` | `capture …` / `compare …` | Per-connection HL7-aware output diff + gating exit code | `C:\srv\mefor\reports\reconcile\<connection>.{json,txt}` |

> Per the header note and S0.6: every report carries **metrics/metadata only — never message bodies**. Load reports, captures, and generated corpora are **never committed** (same class as `dryrun` output) — and they live under `C:\srv\mefor\reports\`, outside any git checkout.

> **Note on the matrix ID space:** the signed `WIN2025-TEST-MATRIX.xlsx` is keyed by the matrix's **native** row IDs (A1/A3/A5/F1/F7/G1/H1/…), which differ from this plan's `S<n>.<n>` IDs. The Appendix master index and the per-test "Maps to" rows are the crosswalk between the two. Matrix **H1**'s printed `--load steady` command is **stale** (no such profile) — satisfy H1 from S4.1/S4.2 (`fanout-baseline`/`closed-loop`) and note the substitution when stamping.

### S6.2 Baselines & trend

- **First good run per backend is the baseline.** Capture `…\load\baseline-<backend>.json` (S4.1) and the closed-loop ceiling JSON (S4.2); archive immutably (these are the **host throughput ceiling** numbers, the deliberate box-owned signal from S0.5).
- **Regression on re-run:** pass the prior run as `--baseline …\baseline-<backend>.json --tolerance 0.1`; a >10% degradation or any zero-loss violation exits non-zero (`1`).
- **Cross-backend comparison:** same profile, swap only the store; `--db-backend <name>` tags each report so the three JSONs compare apples-to-apples (SQLite is the anchor).
- **Soak trend:** archive the `soak` report + a note on DB/WAL growth and dead-letter accumulation slope.

### S6.3 Sign-off GATE (exact green set required to declare the box accepted)

All of the following must hold on a clean `0.2.1` install (both server-DB extras) under the production service identity:

1. **`verify`** across SQLite + SQL Server + PostgreSQL: **FAIL = 0 and ERROR = 0** (MANUAL/SKIP do not block). Archived `verify` reports per backend.
2. **`harness.acceptance`** (or the equivalent S1–S4 coverage): **no FAIL, no ERROR** (MANUAL + SKIP never fail). Signed `WIN2025-TEST-MATRIX.xlsx` with every `Status` stamped (D3 RemoteFile and H1 `steady` consciously deferred/substituted per S0.3).
3. **All 8 gaps (S2.1–S2.8) closed or documented** — each is PASS, **or** has a written finding with a supported remedy. **S2.2 (DPAPI boundary) is the likely real bug:** "closed" means either PHI encrypts/stores under the service identity with no decrypt failure, **or** the boundary failure is documented with the chosen remedy (machine-scope DPAPI / env-var key / mint-as-service).
4. **Throughput-ceiling baseline captured per backend** (S4.1 baseline + S4.2 closed-loop JSON archived for SQLite, SQL Server, PostgreSQL).
5. **Failover conformance invariants hold** on both server backends (zero acked loss, per-lane FIFO, no split-brain, bounded dups, drained pipeline) **and** the Windows host recovery-time number is recorded (S4.9).

### S6.4 Filing a finding when something fails

For any FAIL/ERROR (or a non-zero harness exit), file a finding with: the **test ID** (`S<section>.<n>`) + matrix/gap-map row; the exact **command + PowerShell env block**; the **identity** it ran under (`[Admin]` / `[Svc]` / svc-account name); the **backend** + `--db-backend` tag; the captured **report artifact path**; expected vs observed (e.g. store status, exit code, recovery time); and a **PHI-safety note** confirming synthetic-only data and that no body/`--show-phi`/`dryrun` output was redirected to a committed/CI file. For `audit-verify` FAILs, attach the string-parsed stdout (it exits 0). For a harness exit-2, note whether it was a **profile schema** error (custom TOML), a **missing driver** (asyncpg/aioodbc), a **missing/absent xlsx** seed, or an **auth/token** rejection — the four most likely setup traps. Reference the relevant **host trap** (DPAPI, ODBC 18, weakened-vs-trusted TLS, service grants, port-rebind lag, 0.2.1 clean-env) so the remedy is obvious to the next operator.

---

## Appendix

### A. Master TEST INDEX

> All IDs below are defined in the body sections above (no placeholders). **S1.x** = host/service-identity (§1), **S2.x** = gap-closure #1–#8 (§2), **S3.x** = functional disposition (§3), **S4.x** = throughput/stress (§4); **S0/S5/S6** are narrative sections. (Total executed/observed tests: **49** — counted below.)

| ID | Name | Tool | On-box / remote | Per-DB | Maps-to |
|---|---|---|---|---|---|
| S1.1 | 0.2.1 clean-env prerequisite (both DB extras) | `pip install --upgrade` + `verify --help` + driver probe | on-box | once | host trap (clean env) |
| S1.2 | Host readiness smoke (incl. OS-level ODBC 18) | `verify --section host` | on-box | once† | A3; matrix A |
| S1.3 | Per-DB store + smoke (live ACK) | `verify --section store,smoke --smoke live` | on-box | x3 | matrix A |
| S1.4 | `smoke self` pre-service gate | `verify --section smoke --smoke self` | on-box | once | matrix A |
| S1.5 | Full saved-report acceptance run | `verify --section host,store,smoke,manual` | on-box | once | matrix A–H roll-up |
| S1.6 | Acceptance probes (fast) | `harness.acceptance --no-pytest` | on-box | once | matrix probes |
| S1.7 | Acceptance full (54-row matrix + xlsx write-back) | `harness.acceptance --xlsx ...` | on-box | once‡ | 54-row matrix |
| S1.AC-AD | AD / Kerberos domain login (MANUAL) | console / API auth | on-box | once | F1 |
| S1.AC-MFA | Native TOTP MFA local account (MANUAL) | console enroll/login | on-box | once | F (MFA) |
| S1.AC-API | API loopback + unauth reject (MANUAL checklist) | `Invoke-WebRequest :8765` | on-box | once | #8 (executed = S2.8) |
| S1.AC-NSSM | NSSM lifecycle (MANUAL checklist) | NSSM `AppExit` / reboot | on-box | once | G1 (executed = S2.5) |
| S1.AC-FLASH | No console-flash on Status poll (MANUAL) | watch desktop | on-box | once | F7 |
| S1.AC-DISPO | Console disposition walk (MANUAL) | console + harness inject | on-box | once | console ops (ties §3) |
| S1.AC-FW | Firewall external-listener admit (MANUAL) | `Test-NetConnection <box> 2575` | dev PC→box | once | A5 |
| S1.AC-ACL | Service-account file ACLs (MANUAL) | inspect ACLs | on-box | once | A6 |
| S2.1 | Healthy → PROCESSED **under service** | harness `--scenario processed` (svc identity) | on-box | x3 | gap #1 / T1 |
| S2.2 | DPAPI admin→service key boundary | `protect-key` + serve as svc | on-box | once | gap #2 / T2 |
| S2.3 | Real outbound MLLP delivery (engine as client) | GUI Send A01 + harness Receive 2576 | remote+on-box | once | gap #3 / T2 |
| S2.4 | Crash/restart queue durability | kill svc (by-port PID) + restart | on-box | x3 | gap #4 / T2 |
| S2.5 | NSSM lifecycle (autostart/crash-restart) | NSSM `AppExit` | on-box | once | gap #5 / T2 / G1 |
| S2.6 | Real `encrypt=true` + trusted-cert store connect | `verify --section store,smoke` | on-box | x2 | gap #6 / T3 |
| S2.7 | Malformed / oversized / mid-frame robustness (idle) | harness `--scenario error` + GUI fault inject | remote+on-box | once | gap #7 / T3 (under-load = S4.8) |
| S2.8 | API auth + loopback bind (executed) | `Invoke-WebRequest` to `:8765` | on-box | once | gap #8 / T3 / #8 |
| S3.0 | Serve disposition-coverage graph | `serve --config harness/config` | on-box | per-DB | prereq for S3 |
| S3.1 | Disposition: processed (ADT^A05 → file) | `harness --scenario processed` | remote | once | functional (new) |
| S3.1b | Disposition: processed fan-out (A01 → echo+file) | GUI Send A01 + Receive 2576 | on-box | once | functional (new) |
| S3.2 | Disposition: filtered (ADT^A02) | `harness --scenario filtered` | remote | once | functional (new) |
| S3.3 | Disposition: unrouted (ORU^R01) | `harness --scenario unrouted` | remote | once | functional (new) |
| S3.4 | Disposition: error (ADT^A03 → AE NAK) | `harness --scenario error` | remote | once | functional; ties S2.7 |
| S3.5 | Disposition: dead_letter → replay (A01, 2576 down) | `harness --scenario dead_letter` | remote | once | functional; ties D19 |
| S3.6 | Independent draining (echo dead / file delivered) | GUI A01 + Receive fault | on-box/remote | once | reliability invariant (new) |
| S3.7 | Retry highlight (AE → recover → delivered) | GUI A01 + Receive `fail-N` | on-box/remote | once | D19 (showcase) |
| S3.9 | Per-backend disposition smoke | `--scenario {processed,filtered,error}` ×3 | on-box | x3 | store parity (new) |
| S3.10 | Reconcile output-parity spot-check | `harness.reconcile capture`+`compare` | on-box | once | reconcile capability (new) |
| S4.1 | Per-DB throughput baseline | `harness --load smoke`+`fanout-baseline` | remote/on-box | x3 | real-host ceiling (new); H1 |
| S4.2 | Closed-loop throughput ceiling | `harness --load closed-loop` | remote/on-box | x3 | ceiling (new); H1 |
| S4.3 | Spike / burst | `harness --load fanout-baseline` / `spike-burst.toml` | remote/on-box | once | stress (new) |
| S4.4 | Transform-cost ceiling (CPU wall) | `closed-loop` + `MEFOR_LOAD_TRANSFORM=slow` | remote/on-box | once | stress (new) |
| S4.5 | Fan-out write-amplification | `closed-loop` / `writeamp.toml` | remote/on-box | x3 | stress (new) |
| S4.6 | Soak (1 h) | `harness --load soak` | remote/on-box | x3/once‖ | stress (new) |
| S4.7 | Sustained overload / backpressure | `sustained-overload.toml` | on-box | once | validates S4.2 (new) |
| S4.8 | Robustness under load | `malformed-load.toml` + GUI fault inject | on-box | once | gap #7 under-load (new) |
| S4.9 | Failover recovery (Windows timing) | `harness --failover failover` | on-box | x2 (server) | Gate #3 / G1 |
| S4.10 | Host/infra stress (DB restart / svc bounce) | `--load reference` + `Restart-Service` | on-box | x2 (+SQLite svc-bounce) | B6; ties S2.4 |

### B. Env-var quick reference (copy-paste)

```powershell
# ---- Store / connection ----
$env:MEFOR_STORE_BACKEND   = "sqlite" | "sqlserver" | "postgres"
$env:MEFOR_STORE_SERVER    = "W2025\SQLEXPRESS"
$env:MEFOR_STORE_DATABASE  = "MEFOR_Store"
$env:MEFOR_STORE_AUTH      = "sql"            # or "integrated"
$env:MEFOR_STORE_USERNAME  = "mefor_svc"
$env:MEFOR_STORE_PASSWORD  = "<from secret store, never inline>"
$env:MEFOR_ALLOW_INSECURE_TLS = "1"           # ONLY the weakened dev-cert lane; pair with encrypt=false. NOT for S2.6.

# ---- pytest server-DB suite gates (S1.7 acceptance ONLY — NOT the --failover harness) ----
$env:MEFOR_TEST_SQLSERVER  = "1"
$env:MEFOR_TEST_POSTGRES   = "1"

# ---- Config secrets (fail-closed on first missing — D8) ----
$env:MEFOR_VALUE_<NAME>    = "<value>"

# ---- Cluster / failover lease timings: DO NOT set in operator env. ----
# They are configured in failover.toml [load.failover] (heartbeat_seconds < leader_fence_timeout_seconds
# < leader_lease_ttl_seconds) and the orchestrator propagates them to both nodes as MEFOR_CLUSTER_*_SECONDS.

# ---- Load SUT knobs (set on the serve side; profiles are data) ----
$env:MEFOR_LOAD_FANOUT         = "20"         # ADT lane only
$env:MEFOR_LOAD_RESULTS_FANOUT = "4"          # BOTH the Results AND Other lanes
$env:MEFOR_LOAD_TRANSFORM      = "cheap"      # cheap | edit | slow
$env:MEFOR_LOAD_TRANSFORM_MS   = "5"          # with slow: single-core CPU spin on the event loop
$env:MEFOR_LOAD_ADT_PORT       = "2600"
$env:MEFOR_LOAD_RESULTS_PORT   = "2601"
$env:MEFOR_LOAD_OTHER_PORT     = "2602"
$env:MEFOR_LOAD_SINK_PORT      = "2700"

# ---- 0.2.0 ONLY (retired on 0.2.1 — do not set on the upgraded box) ----
# $env:PYTHONUTF8 = "1"
```

### C. Command quick-reference (copy-paste)

```powershell
# === Clean-env prerequisite (DO FIRST — S1.1) ===
python --version                                                    # MUST be 3.14.x (engine requires Python >=3.14)
pip install --upgrade "messagefoundry[sqlserver,postgres]==0.2.1"   # BOTH server DB drivers
pip install openpyxl                                                # for S1.7 --xlsx write-back
python -c "import asyncpg, aioodbc"                                 # confirm drivers present

# === Wheel-native gates (on the box, against the config repo) ===
messagefoundry verify --section host
messagefoundry verify --section store,smoke --smoke live --service-config <toml>     # once per backend (S1.3)
messagefoundry verify --section host,store,smoke,manual --report-md C:\srv\mefor\reports\verify\all.md --report-json C:\srv\mefor\reports\verify\all.json  # S1.5
messagefoundry check  --config C:\srv\mefor\adopter-config\config --messages sample-messages --json
messagefoundry dryrun --config C:\srv\mefor\adopter-config\config --messages <files>    # bodies redacted unless --show-phi; never redirect to a committed/CI file
messagefoundry graph  --config C:\srv\mefor\adopter-config\config --json
messagefoundry audit-verify --service-config <toml>                                   # string-parse stdout for FAIL (exits 0 anyway)
messagefoundry generate --type ADT --triggers --count 50 --out C:\temp\fix --seed 1   # synthetic only; never redirect to a committed/CI file

# === Serve the matching graph so the harness lines up (absolute --config) ===
python -m messagefoundry serve --config C:\srv\mefor\src\harness\config      --db .\messagefoundry.db --env dev   # scenarios (S3)
python -m messagefoundry serve --config C:\srv\mefor\src\harness\config\load --db .\load.db           --env dev   # load (S4)

# === Functional scenarios (headless; remote or on-box; AUTH-ON needs --token) ===
python -m harness --list-scenarios
python -m harness --scenario processed --engine http://<box-ip>:8765 --token <T> --timeout 30

# === Reconcile output-parity (S3.10) ===
python -m harness.reconcile capture  --connection <name> --engine http://127.0.0.1:8765 --token <T> --out C:\srv\mefor\reports\reconcile\cap
python -m harness.reconcile compare  --captured C:\srv\mefor\reports\reconcile\cap --golden <synthetic-golden-dir>

# === Throughput / stress (headless; running engine; --token; PREFLIGHT custom profiles) ===
python -m harness --load <path>          --engine http://127.0.0.1:8765 --token <T>   # preflight: loads or exits 2 on schema error
python -m harness --load smoke           --engine http://127.0.0.1:8765 --token <T> --db-backend sqlite    --report-json C:\srv\mefor\reports\load\smoke-sqlite.json
python -m harness --load fanout-baseline --engine http://127.0.0.1:8765 --token <T> --db-backend sqlserver --report-json C:\srv\mefor\reports\load\baseline-mssql.json
python -m harness --load closed-loop     --engine http://127.0.0.1:8765 --token <T> --db-backend postgres  --report-json C:\srv\mefor\reports\load\ceiling-pg.json
python -m harness --load fanout-baseline --engine http://127.0.0.1:8765 --token <T> --baseline C:\srv\mefor\reports\load\baseline-sqlite.json --tolerance 0.1 --report-json C:\srv\mefor\reports\load\baseline-pg-vs-sqlite.json

# === Failover (spawns two nodes; shared SERVER DB; ON THE BOX; cwd contains harness/config/load; NO --token) ===
$env:MEFOR_STORE_BACKEND="postgres"   # + MEFOR_STORE_* ; NOT MEFOR_TEST_*
python -m harness --failover failover --db-backend postgres  --inbound-base-port 2600 --sink-port 2700 --report-json C:\srv\mefor\reports\load\failover-pg.json
$env:MEFOR_STORE_BACKEND="sqlserver"  # + MEFOR_STORE_*
python -m harness --failover failover --db-backend sqlserver --inbound-base-port 2600 --sink-port 2700 --report-json C:\srv\mefor\reports\load\failover-mssql.json

# === Acceptance matrix (needs full 0.2.1 source checkout + tests/ + dev deps + SEED xlsx on the box) ===
Copy-Item C:\srv\mefor\src\harness\acceptance\WIN2025-TEST-MATRIX.xlsx C:\srv\mefor\reports\acceptance\   # seed first
python -m harness.acceptance --no-pytest
python -m harness.acceptance --report-md C:\srv\mefor\reports\acceptance\o.md --report-csv C:\srv\mefor\reports\acceptance\o.csv --xlsx C:\srv\mefor\reports\acceptance\WIN2025-TEST-MATRIX.xlsx
```

### D. New stress-profile `.toml` contents (data-only artifacts for S4.3, S4.5, S4.7, S4.8)

> **These four profiles now SHIP in the repo** (`harness/load/profiles/`) — so on a copied-`harness/` box they are **built-ins**: run them by name (`--load spike-burst` / `writeamp` / `sustained-overload` / `malformed-load`) or by path. The contents below are reproduced for reference/tuning. They use the **real** `harness/load/profile.py` schema (single `[load]` table; ≥1 `[[load.target]]`; `[load.mix]` with type CODES the corpus covers; `[load.slo]`; `[[load.phase]]` with `name`/`kind`/`loop`/`duration_s`/`rate_start`). `kind` ∈ {warmup,ramp,sustained,spike,soak}; only `sustained`/`soak` are measured. **Preflight each (`python -m harness --load <path> --token <T> …` loads it) before relying on it.** No engineering dependency **except** the malformed/oversized corpus generators (S4.8 bad input is GUI-injected, not in any mix).

**`spike-burst.toml`** (S4.3 — single hard burst above ceiling, then a measured recovery):
```toml
[load]
name = "spike-burst"
description = "single hard burst above ceiling, then a measured recovery window"
pool_size = 160
corpus_count_per_trigger = 20
drain_timeout_s = 600.0
correlator_capacity = 2000000

[[load.target]]
name = "adt_hub"
port = 2600
types = ["ADT"]

[load.mix]
"ADT^A01" = 70.0
"ADT^A08" = 30.0

[load.slo]
max_ack_p99_ms = 50.0
zero_loss = true
# no min_sustained_msg_s — recovery (drain), not a floor, is the signal

[[load.phase]]
name = "warmup"
kind = "warmup"
loop = "open"
rate_start = 100.0
duration_s = 10.0

[[load.phase]]
name = "spike"            # transient, EXCLUDED from the verdict
kind = "spike"
loop = "open"
rate_start = 3000.0       # set ABOVE the S4.2 ceiling for this host
duration_s = 30.0

[[load.phase]]
name = "recovery"         # MEASURED: backlog must drain here
kind = "sustained"
loop = "open"
rate_start = 300.0        # well under ceiling so backlog can drain
duration_s = 60.0
```

**`writeamp.toml`** (S4.5 — single thin open lane; vary `MEFOR_LOAD_FANOUT` on the serve side):
```toml
[load]
name = "writeamp"
description = "single thin open lane; the FAN-OUT (serve-side) is the write-volume stress"
pool_size = 64
corpus_count_per_trigger = 20
drain_timeout_s = 600.0    # raise as MEFOR_LOAD_FANOUT climbs (100x => lots to drain)
correlator_capacity = 2000000

[[load.target]]
name = "adt_hub"
port = 2600
types = ["ADT"]

[load.mix]
"ADT^A01" = 100.0

[load.slo]
zero_loss = true
max_drain_seconds = 600.0

[[load.phase]]
name = "warmup"
kind = "warmup"
loop = "open"
rate_start = 20.0
duration_s = 10.0

[[load.phase]]
name = "sustained"
kind = "sustained"
loop = "open"
rate_start = 60.0          # low offered rate; fan-out is the write stress
duration_s = 120.0
```

**`sustained-overload.toml`** (S4.7 — hold offered rate above the delivery ceiling, then drain):
```toml
[load]
name = "sustained-overload"
description = "hold offered rate above the delivery ceiling for minutes, then drain"
pool_size = 160
corpus_count_per_trigger = 20
drain_timeout_s = 600.0
correlator_capacity = 2000000

[[load.target]]
name = "adt_hub"
port = 2600
types = ["ADT"]

[load.mix]
"ADT^A01" = 70.0
"ADT^A08" = 30.0

[load.slo]
zero_loss = true
max_drain_seconds = 600.0

[[load.phase]]
name = "warmup"
kind = "warmup"
loop = "open"
rate_start = 200.0
duration_s = 15.0

[[load.phase]]
name = "overload"          # MEASURED overload: held above ceiling for 5 min
kind = "sustained"
loop = "open"
rate_start = 4000.0        # >> the S4.2 closed-loop knee; backlog SHOULD grow
duration_s = 300.0
# no min_sustained_msg_s floor — backlog growth + ACK/E2E divergence is the signal

[[load.phase]]
name = "drain"             # long low-rate DRAIN phase
kind = "sustained"
loop = "open"
rate_start = 50.0
duration_s = 180.0
```

**`malformed-load.toml`** (S4.8 — well-formed background throughput; bad input is GUI-injected concurrently, NOT in the mix):
```toml
[load]
name = "malformed-load"
description = "well-formed background throughput; malformed/oversized/torn frames injected via the GUI"
pool_size = 64
corpus_count_per_trigger = 20
drain_timeout_s = 300.0
correlator_capacity = 2000000

[[load.target]]
name = "adt_hub"
port = 2600
types = ["ADT"]

[load.mix]
"ADT^A01" = 70.0           # all CONFORMANT triggers — the corpus only emits valid messages.
"ADT^A08" = 30.0           # (An 'ADT^BAD' key would raise at corpus build → exit 2.)

[load.slo]
max_error_rate = 0.001     # for the well-formed background; GUI-injected bad msgs are expected ERRORs, not loss
max_dead_letters = 0       # for the well-formed remainder
zero_loss = true           # applies to the well-formed messages

[[load.phase]]
name = "warmup"
kind = "warmup"
loop = "open"
rate_start = 100.0
duration_s = 10.0

[[load.phase]]
name = "sustained"
kind = "sustained"
loop = "open"
rate_start = 400.0
duration_s = 180.0
```

### E. MANUAL checklist (human-only rows — cannot be automated)

These have no runnable PASS gate the harness can assert; a human observes and stamps `Status=MANUAL→PASS/FAIL` into the matrix. They are the human-closed half of `verify`/acceptance (see §1, S1.AC-*).

| ID | Item | What to observe | Maps-to |
|---|---|---|---|
| S1.AC-AD | AD / Kerberos login against the real domain | Service authenticates as the AD svc account / gMSA; integrated-auth store connect works | F1 |
| S1.AC-FLASH | No-console-flash on Status poll | No console window flashes when the console polls service status (`verify` only greps `CREATE_NO_WINDOW`) | F7 |
| S1.AC-NSSM (a) | NSSM autostart-on-reboot | Service comes up automatically after a real reboot; ingest→processed without intervention | S2.5 / G1 |
| S1.AC-NSSM (b) | NSSM restart-after-crash | Kill the process (by-port PID); NSSM `AppExit` restarts it; pipeline resumes | S2.5 / G1 |
| S1.AC-ACL | Service-account file ACLs | Store/config/log dirs writable by the svc account, not world-readable | A6 |
| S1.AC-FW | Windows Firewall external admit | External MLLP client reaches `:2575` from another host | A5 |
| M-DESKTOP | Real desktop session (Desktop Experience) | Console GUI / harness GUI launches (not Server Core) | A7 |
| D3 | RemoteFile SFTP/FTP in+out | **Consciously deferred — no SFTP/FTP endpoint provisioned on the box** (covered by `tests/` in CI). Stamp `MANUAL → deferred`. | matrix D3 |
| H1 | Throughput harness row | `--load steady` is **stale** (no such profile). Satisfy from S4.1/S4.2 (`fanout-baseline`/`closed-loop`) and note the substitution. | matrix H1 |
| S4.10 (manual half) | Live DB-restart drill | Bounce the SQL Server/PostgreSQL service mid-flight; engine recovers, no loss | B6 |
| S2.2 (remedy) | DPAPI boundary remedy confirmation | Chosen remedy (machine-scope DPAPI / env-var key / mint-as-service) lets the svc identity decrypt the key | S2.2 |
| S4.9 (timing) | Windows port-rebind recovery timing | Record seconds for a killed listener to rebind `:2600` (host-variable; the box-owned number) | S4.9 |
| M-BOOTSTRAP | `bootstrap-admin.txt` handling | One-time admin password written to repo root on first `serve`; rotate + secure/delete after capture (D11) | runbook |

### F. Phase-2 (customer-network) backlog

> The open decisions are now **resolved in S0.7** (with on-box criteria). **B3** (key rotation) and **B6** (strict-validation 2577) were **promoted into Phase 1**, and **B1** (`db_lookup`) is conditional on a reachable test Clarity. The items below are what remains **deferred to Phase 2** — they need the real graph, real Clarity, real certs, real feeds, or the off-box collector that only exist on the customer network (≈ mid-July 2026).

- **`db_lookup` live enrichment under the service identity** against the REAL Clarity read-only DB (ADR-0010 off-event-loop read, least-priv grant) — correctness is D22/CI-covered, but the constrained-identity live read on this box is a host-specific path not in S2.x. **Add a targeted row if the box carries the Clarity feed.**
- **TLS MLLP transport round trip on the real host** (real-cert listener+sender) — the S2.6 weakened-vs-trusted-TLS trap applied to the *transport*, not just the store; CI covers MLLP TLS, the real-cert host round trip is not exercised here.
- **Encryption key rotation under the service identity** (`rotate-key` with `require_encryption=true`, both old+new key decryptable by the svc account) — S2.2 covers minting/decrypting one key, not rotation under the constrained identity.
- **Off-box audit/log shipping reachability** (matrix B5/H4) — marked MANUAL; the box→collector reachability check is a host-only network signal not scheduled here.
- **Config reload under the service identity** confined to `[api].config_reload_roots` with the svc-account ACLs (matrix F5) — deferred to CI pytest; the IDE-promote-then-reload path under the constrained identity is host-specific.
- **Strict-validation inbound (`IB_Coverage_Strict`, 2577)** end-to-end on the box — no S3 scenario drives a version mismatch into 2577 (only the tolerant 2575 path via `--scenario error`); add a GUI/Compose wrong-version send to 2577 if strict-AE-under-service is wanted.
