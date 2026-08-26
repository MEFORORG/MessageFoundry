[← Master Test Plan index](../MASTER-TEST-PLAN.md) · *Part I — Strategy, environments & tooling*

---

## 0.11 The environment matrix

Every test in this plan executes somewhere. This section enumerates **every environment the plan
needs**, what each one proves that no other environment can, and whether it exists today. An
environment that is "must be built" is a **procurement or provisioning dependency** for the chapters
that need it — those dependencies are priced in §0.17.

Vocabulary reminder for this table: **engine shard** = N `serve --shard` processes over one unified
store ([`__main__.py:98`](../../../messagefoundry/__main__.py) `--shard`, [`:115`](../../../messagefoundry/__main__.py)
the supervisor that spawns one per engine shard); **database shard** is the shelved store-splitting
axis and appears nowhere in this matrix.

**Cross-document ID prefixes** (§0.1 "The ID scheme", rule 3 — restated because this chapter cites two
foreign documents heavily): a coverage-plan gap ID is written **`FCP:<ID>`**, a WIN2025 plan/matrix row
**`W25:<row>`**. A bare ID always means a row of this plan. Two further identifiers below are neither:
`SEC-005` is the IDE's own ADR 0035 non-loopback-credential control, and the AD-lab cell IDs `L0`–`L18`
belong to the lab runbook — both are named with their owner in place.

| ID | Environment | What it is | What it proves that nothing else can | Cost / effort to stand up | Status |
|---|---|---|---|---|---|
| **E1** | Developer PC (Windows 11) + per-worktree `.venv` | The authoring box. Isolated checkout + branch + venv per parallel session via [`scripts/worktree/new.ps1`](../../../scripts/worktree/new.ps1) (`-Sqlserver`, `-Ide`, `-NoInstall`); see [`docs/WORKTREES.md`](../../WORKTREES.md) | Interactive debugging, the PySide6 harness GUI tabs (Send/Receive/File/Compose/Monitor), and anything needing a human in the loop. It is also the only place the *mutation* and *diff-coverage* gates were ever verified by hand ([`docs/quality-gates/HANDOFF-mutation-coverage.md`](../../quality-gates/HANDOFF-mutation-coverage.md) §1) | None — already provisioned | **Exists** |
| **E2** | Linux container CI (GitHub-hosted `ubuntu-latest`) | The cheap-breadth leg. Carries `ruff check`, `ruff format --check`, both `mypy --strict` passes, the ledger gate, the full `pytest` suite, the web-console suite, and every service-container leg | Volume. It is the only environment that runs on **every** PR at 1× minutes, and the only one that hosts the SQL Server / PostgreSQL service containers | $0 (hosted minutes are free on this public repo) | **Exists** |
| **E3** | Windows CI legs (hosted `windows-2022`, `windows-2025`) | Two Server SKUs running the same `pytest` suite + the web-console suite; plus the nightly NSSM `windows-service-smoke` on both SKUs | Real Windows sockets, `ProactorEventLoop`, Windows service paths, and the real NSSM install → start → `/health` → MLLP → uninstall path. These are the *deployment* OSes | $0 here (2×-billed, free on a public repo) | **Exists** |
| **E4** | Self-hosted Windows Server 2025 box, all three backends | Two distinct things, deliberately not crossed: (a) the **dispatch-only SQL Server VM** behind [`selfhosted-win2025-sql.yml`](../../../.github/workflows/selfhosted-win2025-sql.yml) (label `mefor-win2025-sql`); (b) the **acceptance box** `WIN-NAFGLU5SH1J` that [`docs/testing/WIN2025-TEST-PLAN.md`](../WIN2025-TEST-PLAN.md) owns | OS-level **ODBC Driver 18** discoverability, the NSSM **service identity**, the per-user **DPAPI** key boundary, file ACLs, Windows Firewall, Windows **port-rebind lag**, and the real-host **throughput ceiling** on real storage. WIN2025-TEST-PLAN §S0.2 is the authoritative CI-owned / box-owned split | Hardware exists; the CI runner service is **de-registered** ([`docs/CI-SELFHOSTED-RUNNER.md`](../../CI-SELFHOSTED-RUNNER.md) — "currently runner-less") | **Partial** — workflow + label exist, no runner registered |
| **E5** | Domain-joined AD / federation lab (AWS) | Three EC2 boxes per `docs/releases/HANDOFF-AD-LAB-aws.md`: **A** = DC for the throwaway `mefor.lab` forest + the AD FS farm; **B** = domain-joined engine host under NSSM; **C** = domain-joined client with Chrome *and* Firefox (may be B for pass 1) | The **entire AD acceptor path**, which the handoff records as *mock-seam only* today (`kerberos_principal` is `# pragma: no cover`; every serve-path TLS/proxy assertion monkeypatches `uvicorn.run`). Kerberos SPN/EPA, gMSA logon, integrated SQL auth, OIDC/AD FS SSO, the MFA-claim gate, and the L18 username-collision privilege-escalation refusal | An EC2 booking window; the runbook insists the four items are planned **"as one window, or not at all"** | **Must be built** |
| **E6** | Browser matrix host | Real browsers driving the web console at `/ui` (`messagefoundry_webconsole`, mounted same-origin via `mount_ui`) | Anything that only a browser engine can execute: the WebAuthn/passkey ceremony against a real authenticator, CSP enforcement as the browser applies it (not as the header asserts it), the session watchdog and logout affordance as rendered, and the two-browser AD FS landing assertion (AD-lab cell L7) | Needs at minimum one Windows host with Chrome + Firefox; Safari needs macOS or a cross-browser service | **Must be built** |
| **E7** | VS Code extension test host | The `ide` job in [`ci.yml`](../../../.github/workflows/ci.yml): `ubuntu-latest` + `windows-latest`. `npm run typecheck` → `npm run compile` (esbuild) → `npm run test:unit` (mocha, vscode-free) on **both** legs; `npm test` (`@vscode/test-electron`, a real headless VS Code) on the **Windows** leg only | Extension activation + command registration in a real Extension Host, and the vscode-free model layer (engine link state, the two frozen ADR 0110 boundary allowlists, settings-scope `SEC-005` (ADR 0035's non-loopback credential guard — an IDE control ID, not a row of this plan's SEC chapter), graph/steps/HL7 models, `promoteTarget` resolution) | $0 — already wired | **Exists** |
| **E8** | Partner / DICOM / FHIR interop endpoint set | Real peers for the non-HL7 connectors: a DICOM C-STORE SCP/SCU peer and DICOMweb STOW-RS receiver, a FHIR server for the SMART Backend Services token + `fhir_lookup` path, an SFTP/FTPS endpoint for `RemoteFile`, and an X12 trading-partner TCP peer | Wire-level interop with a foreign implementation. Everything today terminates in a loopback sink or an in-process fake. WIN2025-TEST-PLAN §S0.3 already records matrix row **`W25:D3` (RemoteFile SFTP/FTP)** as *deferred — no SFTP endpoint provisioned on the box* | Containerized peers (HAPI FHIR, a pynetdicom SCP, an SFTP container) are near-free; a real modality/PACS or an EHR sandbox is a registration + relationship cost | **Must be built** (loopback substitutes exist) |
| **E9** | Two-box HA / failover rig | Two engine hosts sharing one externalized store (SQL Server AOAG per [`docs/AOAG-DEPLOYMENT.md`](../../AOAG-DEPLOYMENT.md), or PostgreSQL), exercising the leader lease + graph supervisor | Failover across a **machine** boundary: real network partition, real NIC/host loss, VIP behaviour, and the Windows-host recovery *time*. CI already proves the *conformance invariants* (zero acknowledged loss, per-lane FIFO, no split-brain, bounded duplicates) with two `serve` processes on one runner via `tests/test_load_failover_sqlserver.py` / `tests/test_load_failover_postgres.py` — that is a different signal | 2 VMs + a shared server DB | **Partial** — single-host two-process is in CI; two-box is not |
| **E10** | Non-production engine + production-like engine (PUB) | A pair of engines the IDE's **Stage → Promote** can target, wired to a config repo remote. Target resolution is already unit-tested pure ([`ide/src/promoteTarget.ts`](../../../ide/src/promoteTarget.ts), `promote-target.test.ts`) | The promotion chapter's whole subject: a config change moving non-prod → prod-like through `messagefoundry check` (validate / dryrun / posture / build-check / reference-backend), a dry-run POST, then an apply — against two engines with **different derived security postures**. A single dev engine cannot show a posture-divergent promotion | 2 hosts (VMs are fine) + a git remote (a bare repo on a share suffices) | **Must be built** |
| **E11** | Cloud / Kubernetes target (ADR 0047) | The manifests under [`docker/k8s/`](../../../docker/k8s) (`statefulset.yaml`, `ha-postgres.yaml`, `secret.example.yaml`), guided by [`docs/CLOUD-DEPLOYMENT.md`](../../CLOUD-DEPLOYMENT.md) | That the multi-replica active-passive manifest actually elects a leader, that only the leader binds listeners, and that the L4 MLLP load balancer follows failover. Today [`manifest-lint.yml`](../../../.github/workflows/manifest-lint.yml) proves only that the YAML **schema-validates** (kubeconform) and satisfies grep-level HA policy assertions — nothing applies it | `kind`/`k3d` in CI is ~free; a managed EKS/AKS/GKE cluster is billed and needs a cloud account | **Partial** — manifests + lint exist, no cluster |
| **E12** | Air-gapped / offline install target | A network-isolated host installing from a local wheelhouse, with the config repo as a **bare repo on a network share** — the shape [`docs/INSTALL-GUIDE.md`](../../INSTALL-GUIDE.md) §5 names for air-gapped sites | That the engine installs, wires, and serves with **no egress**: no PyPI, no `mcr.microsoft.com`, no `packages.microsoft.com` for ODBC 18, no OCSP/CRL fetch, no update check ([ADR 0026](../../adr/0026-off-box-egress-update-check.md)). A CI runner has egress by construction and can never prove this | One isolated VM + a mirrored wheelhouse + an offline ODBC 18 installer | **Must be built** |

### Notes that change how an environment is used

- **E5 is hand-run, by standing instruction.** `HANDOFF-AD-LAB-aws.md`
  states: *"Do not wire any of this to CI. A domain-joined self-hosted runner executing repo code is a
  much larger blast radius than the existing mirror-gated `windows-service-smoke`. Hand-run it; commit
  the scrubbed record."* It also forbids stopping/terminating any EC2 instance without the owner's
  say-so, requires every artifact to be written **off** instance-store, and requires RFC 2606/5737
  placeholders in anything committed — the blocking `forbidden-content` context enforces the last one.
  **On the runbook, precisely.** The authority for E5's test cells is
  `docs/security/AD-FEDERATION-LAB-RUNBOOK.md` (cells L0–L18). It is **not missing** — `/docs/security/`
  is deliberately git-ignored in the public repo ([`.gitignore:144`](../../../.gitignore), alongside
  `docs/reviews/` at `:145` and `docs/marketing/` at `:146`, withheld as ~32 files of posture and
  risk-register detail that would read as an attacker roadmap). The document exists and the owner
  confirms it is available to whoever builds the lab; it simply is not readable from this worktree. No
  plan row should describe it as absent, and its unreadability here is **not** a coverage defect — it is
  a publishing boundary. What this chapter cites from it is sound evidence that lives outside the public
  tree by design.
  **The countable exit condition for the environment phase is standing the lab up**, not locating a
  document: a domain controller promoted for the throwaway `mefor.lab` forest, test accounts and groups
  created (including the L18 collision pair), the engine's **SPN registered and a keytab issued**, and a
  **reachable LDAPS endpoint** the engine host can bind against. Those four are observable, so they can
  be tracked to done; "find the runbook" cannot.
- **E4 must stay non-required.** `selfhosted-win2025-sql.yml` is `workflow_dispatch`-only with no
  schedule, precisely so the VM never has to be powered on; it is not a required check and cannot
  wedge a PR. Any proposal to promote it to a gate re-introduces the SPOF that retired the previous
  self-hosted runners.
- **E1 is not a test environment of record.** It runs the same commands as E2/E3 but with an
  uncontrolled interpreter, an uncontrolled SQLite build, and no lock enforcement. Results from E1 are
  evidence for *triage*, never for sign-off.

---

## 0.12 Store-backend matrix

Three store backends are supported and all three are in scope for this plan. They differ in how they
are provisioned, which is why the plan needs both CI service containers and the E4 box.

| | **SQLite** | **SQL Server** | **PostgreSQL** |
|---|---|---|---|
| Role | Default / single-node store; the WAL staged queue | Promoted production server store | Supported production server store |
| Versions under test | Whatever CPython 3.14 links on the host (CI stamps `sqlite3.sqlite_version` in the benchmark job) | **2022 (16.x)** and **2025 (17.x)** — matrixed in `sqlserver-store` and `load-test-sqlserver` | **16** (`postgres:16` service container) |
| Python driver | `aiosqlite` (base dep) | `aioodbc` → `pyodbc` — the `[sqlserver]` extra | `asyncpg` — the `[postgres]` extra |
| OS-level driver | none | **Microsoft ODBC Driver 18 for SQL Server** — *not* pip-installable. CI installs `msodbcsql18` + `mssql-tools18` + `unixodbc-dev` from `packages.microsoft.com`; the self-hosted leg asserts it with `Get-OdbcDriver -Name "ODBC Driver 18 for SQL Server"` and throws if absent | none — asyncpg speaks the wire protocol directly |
| CI provisioning | none (file on the runner) | `mcr.microsoft.com/mssql/server:{2022,2025}-latest` service container, `ACCEPT_EULA=Y`, port 1433; DB created via `sqlcmd` with a ~120 s readiness loop; the load leg additionally sets `READ_COMMITTED_SNAPSHOT ON` | `postgres:16` service container with a `pg_isready` health-check gate |
| On-box (E4) provisioning | file on the box's largest non-OS volume | a real local SQL Server 2025 instance; credentials come from the **runner's machine environment** (`MEFOR_STORE_PASSWORD` is never in the repo) | a real local PostgreSQL instance |
| Test gate env var | (always on) | `MEFOR_TEST_SQLSERVER=1` — 82 references across `tests/` | `MEFOR_TEST_POSTGRES=1` — 57 references across `tests/` |
| Connection env | `--db <path>` | `MEFOR_STORE_BACKEND/SERVER/PORT/DATABASE/AUTH/USERNAME/PASSWORD`, `MEFOR_STORE_TRUST_SERVER_CERTIFICATE` | same `MEFOR_STORE_*` set, plus `MEFOR_STORE_ENCRYPT=false` for the plaintext container |
| TLS escape needed in CI | n/a | `MEFOR_ALLOW_INSECURE_TLS=1` — the container's self-signed cert forces `trust_server_certificate=true`, which the store's TLS-hardening guard refuses without this trusted-network dev/test escape | `MEFOR_ALLOW_INSECURE_TLS=1` for the same reason (plaintext container) |
| Known live defect | — | **pyodbc 5.3.0 + py3.14 native segfault** in the C parameter-binding path against the 2025 container (upstream `mkleehammer/pyodbc#1459`, unfixed; 5.3.0 is the newest and the first with py3.14 wheels). Worked around by [`scripts/ci/retry-native-crash.sh`](../../../scripts/ci/retry-native-crash.sh), which retries the whole step **only** on exit 139/134 and never on exit 1 — so it cannot mask a regression | — |

**Backend-specific behaviours the plan must keep distinct** (they are deliberate divergences, not
bugs): SQL Server carries a response-column cipher pass and the batching path (`FCP:SCALE-9` in
[`FEATURE-COVERAGE-PLAN.md`](../FEATURE-COVERAGE-PLAN.md) is confirmed **SS-only**);
PostgreSQL rejects NUL bytes and uses `SELECT … FOR UPDATE SKIP LOCKED` + advisory locks where SQL
Server uses pooled claim; `body_ref` is inert on both servers; and a `Reference(...)` config against a
SQL Server store is refused at gate time by `messagefoundry check`'s `reference-backend` check.

### The x3 / x2 / once notation

This plan reuses the per-DB notation that [`WIN2025-TEST-MATRIX.md`](../WIN2025-TEST-MATRIX.md)
and [`WIN2025-TEST-PLAN.md`](../WIN2025-TEST-PLAN.md) §"ID scheme" already established. Do
not invent a second notation:

| Notation | Meaning |
|---|---|
| **once** | Backend-independent. Run the test one time; the result does not vary by store. |
| **x3** | Run once per backend — **SQLite, SQL Server, PostgreSQL**. The default for any store-touching assertion. |
| **x2** | Server backends only — **SQL Server + PostgreSQL**. Used where the behaviour has no SQLite analogue (connection pooling, advisory/pooled claim, leader lease, cross-process failover). |
| **n-a** | Not applicable to this backend; state *why* in the row rather than leaving it blank. |

Where an **x3** row is currently satisfied only by a structural assertion (a DDL inspection or a
`dir()` check) rather than an executed round-trip, the plan must say so explicitly — that distinction
is the whole subject of `FCP:P1`, which closed 14 such rows and dropped 8 after
grounding them against live code.

---

## 0.13 Test data strategy

**The hard rule, restated because everything below depends on it: all test traffic is synthetic and
PHI-free. No test in this plan uses real PHI, under any circumstance, in any environment.** Reports
and matrices carry metrics, IDs, counts, dispositions and SQLSTATEs — never a message body, element
value, or search needle. `dryrun`, `generate` and `--show-phi` output is treated as body-bearing and
is never redirected to a committed file, a ticket, or a CI log.

### 0.13.1 Synthetic generators — the primary source

[`messagefoundry/generators/`](../../../messagefoundry/generators) emits **conformant** HL7 v2.x across the
message families the engine handles: `adt`, `oru`, `orm`, `oml`, `orl`, `mdm`, `mfn`, `dft`, `bar`,
`ras`, `rde`, `siu`, `vxu`, `documents`, with `all_types.py` as the registry. Two entry points:

- `messagefoundry generate` — the CLI subcommand ([`__main__.py:350`](../../../messagefoundry/__main__.py) — **RE-POINTED 2026-08-15 (BACKLOG #1100), was `:349`, which is now blank**; the subparser is `generate = sub.add_parser(` at `:350` with the name `"generate"` on `:351`, and its flags follow at `:353-361`).
- `python -m messagefoundry.generators.adt [--triggers A01,A04] [--count N] [--out DIR]` — the ADT
  corpus builder: **57 triggers across 25 message structures** (A01–A62 excluding the A19 query event
  and reserved A56–A59), with segment order and the allowed segment set driven by **hl7apy's own
  2.5.1 reference tree**, and every message gated through `messagefoundry.parsing.validate` before it
  counts.

Conformance is a property of the generator, not of a stored file — which is why the corpus is
disposable (§0.13.3) and why the load corpus can only ever emit valid messages (§0.13.5).

### 0.13.2 Curated corpora — small, committed, provenance-tracked

| Corpus | Contents | Why committed |
|---|---|---|
| [`samples/messages/`](../../../samples/messages) | `adt_a01.hl7`, `adt_batch.hl7`, `x12_270_eligibility.edi` | Fixed inputs for the MLLP sender, the docker smoke, and the X12 path |
| [`samples/messages/hapi-hl7v2/`](../../../samples/messages/hapi-hl7v2) | 7 files + README: ADT^A01 (2.4), ADT^A03 (2.5), OMD^O03 ×2, OML^O21 (2.5.1), a 2.3.1 Z-event ERP^Z99, and an 18-message concatenated batch spanning 2.1–2.4 | **Type and version diversity a generator will not produce.** Vendored verbatim from `hapifhir/hapi-hl7v2` at commit `de1503651040` under **MPL-2.0**; the README carries the full per-file provenance manifest. If any file is ever modified, MPL-2.0 requires that file to carry its source notice |
| [`samples/dicom/generate_sr_sample.py`](../../../samples/dicom/generate_sr_sample.py) | A generator, not a committed binary | Keeps DICOM sample data regenerable and out of git |

### 0.13.3 The git-ignored corpus

`/samples/messages/adt/` is **git-ignored and regenerable** — 2,850 messages are never committed.
`tests/test_generated_adt.py` generates in-process, deterministic and seeded, checking one message per
trigger plus the generator's own units; `MEFOR_FULL_CORPUS=1` expands that to generate and re-validate
all 2,850. The design consequence for this plan: **the corpus needs no storage, no versioning and no
distribution** — the generator module plus the seed *is* the artifact of record.

### 0.13.4 X12 / DICOM / FHIR sample data

- **X12** — `samples/messages/x12_270_eligibility.edi` drives the tolerant `parsing/x12/` codec; the
  opt-in strict validator needs the `[x12]` extra (`pyx12`), installed on the CI full-suite leg so the
  strict tests assert rather than `importorskip`-skip.
- **DICOM** — headers/SR only, no pixel data. Datasets are generated (`samples/dicom/`); the `[dicom]`
  extra (`pynetdicom` + `pydicom`) is installed on the CI full-suite leg and on the
  `windows-service-smoke` leg, because the samples graph binds a DIMSE C-STORE SCP at startup.
- **FHIR** — the `[fhir]` extra is installed in CI specifically so the typed-tier tests, *including the
  PHI-no-leak invariant (ADR 0022)*, execute their assertions instead of skipping.

### 0.13.5 Hostile / malformed corpora — and the honest gap

What exists:

- **Harness Compose tab presets** — `valid`, `no-MSH`, `wrong-version` — sent over MLLP with an explicit
  ACK expectation (Accept / Reject / No ACK), flagged against the actual reply. This is the documented
  route to the ERROR / AR / AE / strict-validation paths the generators cannot reach.
- **Harness Receive tab fault injection** — `delay then AA` (past the engine timeout, to force a
  retry), `close (no reply)`, and `fail N then AA` — driving outbound retry / dead-letter / independent
  draining.
- **[`harness/load/profiles/malformed-load.toml`](../../../harness/load/profiles/malformed-load.toml)** — the
  robustness-under-load profile. Read its header carefully before planning against it: it carries
  **well-formed background throughput only**; the malformed / oversized / torn-frame inputs are
  injected **concurrently from the GUI** while the sustained phase runs. Bad input *cannot* be a
  profile mix key — the corpus generator only emits hl7apy-conformant messages and raises on an unknown
  trigger, so an `ADT^BAD` key fails at preflight with exit 2. Its SLOs (`zero_loss`,
  `max_dead_letters = 0`) apply to the well-formed remainder, not to the injected bad messages.

**The instrument is itself under test — and it is also a product.** The two bullets above are not
neutral infrastructure. The PySide6 harness GUI (`harness/`) is simultaneously (a) this plan's *only*
route to hostile-input and outbound-fault injection and (b) a **shipped distribution** — the separate
`messagefoundry-harness` wheel (`packaging/messagefoundry-harness/`), built and version-checked in
lockstep with the engine by the `release-harness` job ([`release.yml:477`](../../../.github/workflows/release.yml),
PyPI publish gated on the `PUBLISH_HARNESS` repo variable). **The TRAY chapter (§13d) owns testing it**,
and the specific affordances this section leans on are rows there, not assumptions here: the Compose-tab
presets (`harness/compose.py:74-77` — "No MSH segment", "Bad version (2.3)") and the Receive-tab fault
modes (`harness/mllp.py:40` — `REPLY_MODES` = AA/AE/AR/none plus `DELAY_AA`, `CLOSE`, `FAIL_THEN_AA`).
Read the dependency in the honest direction: if a TRAY row shows a preset seeds the wrong string or a
fault mode does not fire, every robustness result this chapter's corpora produced is void until re-run.

**The gap:** there is **no headless hostile corpus and no fuzzer**. Every malformed input in the estate
today is hand-authored and GUI-driven — which means robustness testing is not repeatable in CI, cannot
be regression-gated, and depends on a human driving a GUI that is itself a release artifact. Closing
that is a tooling item (§0.14.2), not a data item.

### 0.13.6 De-identification — the only sanctioned path from real traffic

[ADR 0030](../../adr/0030-anonymization-test-harness-tee.md) built
[`messagefoundry/anon/`](../../../messagefoundry/anon) (`hl7.py` / `keying.py` / `rules.py` / `surrogates.py` /
`leak.py`), vendored **byte-identical** to [`tee/anon/`](../../../tee/anon) so the dependency-free tee carries
the same logic. Its contract:

- **Two-layer rule model.** Field *selection* is data (`load_rules` over an optional `anon.toml`);
  surrogate *production* is code (`surrogates.py`). Rules are centralized — **do not inline ad-hoc
  de-id logic anywhere**, and do not build a second framework beside it.
- **Deterministic, secret-per-dataset.** `keying.Keyer` salts surrogates so the same real value maps to
  the same surrogate *within* a dataset and is re-identification-resistant *across* datasets.
- **Fail-closed, and this is the load-bearing property.** `anonymize_checked()` = `anonymize()` + a
  `leak_check()` against the publish-guard authority; a surviving forbidden token raises `LeakError`
  and **nothing is written**. The exception carries token *categories* only (e.g. `"partner/site
  token"`), never the offending value — so raising or logging it cannot itself leak PHI.
- **The only surface.** `python -m tee anonymize-captures --db <tee.db> --out <file.jsonl>
  [--direction corepoint_copy]` ([`tee/__main__.py:286`](../../../tee/__main__.py)) is the sanctioned way to
  turn captured live traffic into a shareable dataset — plus the harness hooks. There is no other
  approved route, and a hand-written scrub script is a defect.

**Rule for this plan:** a dataset derived from real traffic may be used *only* after passing
`anonymize_checked`, and even then it is a **local** artifact unless the chapter that uses it says
otherwise. De-identified is not the same as publishable.

### 0.13.7 Versioning, and where test data may NOT live

**Versioning model.** Test data is versioned as *code*, not as blobs:

| Kind | Version of record |
|---|---|
| Generated HL7 | the generator module + the seed (deterministic); nothing is stored |
| Vendored third-party corpora | the provenance manifest in the corpus README — upstream repo, commit SHA, licence, per-file upstream path |
| Load profiles | committed `.toml` under `harness/load/profiles/` (`smoke`, `smoke-sqlserver`, `fanout-baseline`, `closed-loop`, `reference`, `soak`, `failover`, `spike-burst`, `sustained-overload`, `malformed-load`, `connscale*`, `estate*`, `writeamp`, the A/B pairs) |
| Reconcile golden pairs | JSONL captures produced by `python -m harness.reconcile capture`, compared by `… compare --mefor … --corepoint …` |
| De-identified datasets | the `anon.toml` rule file + the per-dataset secret salt (the salt is a secret and is never committed) |

**Where test data may NOT be committed** — the `.gitignore` rules are the enforcement, and they are
deliberately fail-closed:

- `*.db`, `*.db-wal`, `*.db-shm`, `*.db*` — the engine store. **Never** read or write it, never commit it.
- `out/`, `harness_io/`, `*.log` — runtime output and harness I/O.
- `/samples/*/` is ignored **by default**, with only the known-good example dirs explicitly re-included
  (`config/`, `consistency/`, `dicom/`, `ech-sidecar/`, `generators/`, `messages/`, `results_relay/`).
  A new unlisted `samples/` subdirectory cannot reach the public repo just because nobody added a rule.
- `/samples/messages/adt/` — the regenerable ADT corpus (listed *after* the re-includes, or the
  re-included parent would drag it back in).
- `/migration-local/` — customer-estate working area. A real-numbers load profile, if one is ever
  built, lives **only** here and is run with `--load <path>`.
- `/_verify_*/` — workflow self-verification temp dirs holding estate-derived config.
- `/harness/load/profiles/hospital-baseline.toml`, `/harness/load/profiles/soak-12h.toml` —
  operator-local profiles tuned to a specific deployment's volume.
- `scripts/security/scan-tokens.local.txt` — the real customer/vendor token list. Only the
  **synthetic** `.example` is ever committed.
- `.env`, `.env.*`, `*.key`, `*.pem`, `*.pfx`, `secrets/`, `/docker/secrets.env`, `/docker/tls/`,
  `bootstrap-admin.txt`.

Two CI contexts back this up: **`forbidden-content (customer/PHI leak guard)`**
([`security.yml:367`](../../../.github/workflows/security.yml), running
[`scripts/security/scan_forbidden.py --path .`](../../../scripts/security/scan_forbidden.py)) is **blocking and
required**, and **`gitleaks`** is blocking. A committed real token list, a routable IP, a real hostname
or a message body turns the build red — which is why the AD-lab handoff makes scrubbing the L17 run
record an explicit sub-step rather than a formality.

---

## 0.14 Tooling inventory

### 0.14.1 What exists

| Tool | Scope | Invocation | Where it runs | Notes for this plan |
|---|---|---|---|---|
| **pytest** | 535 `tests/test_*.py` modules (547 top-level entries) + the web-console package's own **14 `.py` files** (12 `test_*.py` modules, plus `conftest.py` and the `_soft_webauthn.py` authenticator stub) | `pytest -q`; console suite is a **separate** run: `pytest packaging/messagefoundry-webconsole/tests -q` | E1, E2, E3, E4 | `asyncio_mode="auto"`; **one session-scoped loop** for tests *and* fixtures (both keys set, and they must match); `testpaths=["tests"]`; `addopts = "--timeout=60 --timeout-method=thread"` |
| pytest markers / env gates | Selective execution | `win2025_acceptance` is the **only** registered marker (`tests/test_win2025_acceptance.py`). Env gates: `MEFOR_TEST_SQLSERVER`, `MEFOR_TEST_POSTGRES`, `MEFOR_FULL_CORPUS`, `MEFOR_RUN_SLOW`, `MEFOR_TEST_FORCE_AAD_BIND`, `MEFOR_SHARDCERT_DELIVERING` | all | The estate leans on **env gates, not markers**. That is a deliberate observation for the plan: `pytest -m` is not a usable selection axis today |
| Offscreen Qt | PySide6 harness/Qt view tests | `QT_QPA_PLATFORM=offscreen` (set on every CI pytest step; Linux additionally installs `libegl1 libgl1 libxkbcommon0 libdbus-1-3`) | E1–E4 | Required, or Qt-importing tests fail headless |
| Watchdogs | Hang containment (three nested) | `--timeout=60` (per-test) → `PYTHONFAULTHANDLER=1 -o faulthandler_timeout=90` (native stack dump) → step `timeout-minutes` → job `timeout-minutes` | E2, E3 | Windows legs use larger values (`pytest_timeout=120`, `fault_timeout=150`, step 26 / job 30) |
| Flake retry | In-run only | `pytest-rerunfailures>=16.0` | E2, E3 | Self-heals the known harness-monitor timing flake. It **records nothing** — see §0.14.2 |
| **ruff** | Lint + format, **whole repo** | `ruff check .` / `ruff format --check .` | E2 only (platform-independent) | Scope lives in **one place** — `[tool.ruff] extend-exclude` — and `tests/test_lint_scope_parity.py` fails if the hook and CI drift apart. Pinned `>=0.4,<0.16`: 0.16 turns on RUF022/RUF100/BLE001, ~525 findings |
| **mypy (strict)** | Types, both platforms | `mypy messagefoundry messagefoundry_webconsole --exclude 'messagefoundry/tray/'` **and** `mypy --platform win32 messagefoundry` | E2 only | Two passes on Linux so `sys.platform=='win32'` branches (ctypes/DPAPI/service_control/tray) are typed without paying for a Windows mypy |
| Mutation + diff-coverage | Advisory quality signals 6 + 7 | Built in `quality-advisory.yml` (mutmut 3; 2.5.1 crashed on py3.14 and `\|\| true` hid it for months). Local recipe in [`docs/quality-gates/HANDOFF-mutation-coverage.md`](../../quality-gates/HANDOFF-mutation-coverage.md) | E2 (+ E1 to verify) | `pytest-cov`, `diff-cover`, `mutmut` are **CI-only** installs — adding them to `pyproject.toml` without re-running `uv lock`/`uv export` reds the DEP-1 gate |
| **ide** mocha + electron | VS Code extension | `npm run test:unit` (mocha, `--ui tdd`, vscode-free) on both legs; `npm test` → `out/test/runTest.js` (`@vscode/test-electron`) on Windows | E7 | 35 `*.test.ts` modules under `ide/src/test/suite/`. The unit split exists because `npm test` is Windows-only — without it the whole node estate was type-checked and never executed on ubuntu |
| **harness GUI (PySide6)** | The five-tab operator-driven test instrument: Send / Compose / Receive / File / Monitor | `python -m harness` (a separate process; reaches the engine only over the HTTP API via `apiclient/`) | E1, and any host with a display | **Both an instrument and a product.** It is the plan's only route to hostile-input injection (Compose presets) and outbound-fault injection (Receive `REPLY_MODES`), *and* it ships as the separate `messagefoundry-harness` wheel (`packaging/messagefoundry-harness/`, `release-harness` in [`release.yml:477`](../../../.github/workflows/release.yml), publish gated on `PUBLISH_HARNESS`). **Testing it is the TRAY chapter's job (§13d)** — this chapter only consumes it. It needs a human at a display, so nothing it produces is CI-repeatable (§0.13.5) |
| **harness/load** | Throughput, latency, loss, drain, connection scale, engine-shard fan-in | `python -m harness --load <profile\|path> --engine URL [--token T] --sink-port N --report-json --report-csv [--baseline --tolerance] [--db-backend LABEL] [--shard-engine …]`; `--list-profiles` | E2 (smoke), E4 (ceiling) | Three measurement channels (sender / correlation sink / engine poller) answering three different questions — [`docs/LOAD-TESTING.md`](../../LOAD-TESTING.md). Never imports the engine; never touches the store |
| harness failover / connscale / estate | HA, 500–1500 connections, multi-engine estate | `python -m harness --failover …`, `--connscale …`, `--estate …` (each with its own `--list-*-profiles`) | E2 (in `tests/test_load_failover_*`), E4, E9 | The failover orchestrator **spawns** two `serve` nodes and binds ports, so it must run *on* the host under test with a cwd containing `harness/config/load` |
| **harness/acceptance** | The 54-row WIN2025 matrix runner | `python -m harness.acceptance [--report-md] [--report-csv] [--xlsx]` | E4 | **Dev-tree artifact** — it shells out to `python -m pytest` at the repo root and reads source by repo-relative path, so the box needs a full source checkout pinned to the deployed wheel version, plus `openpyxl` for `--xlsx` |
| **harness/reconcile** | Parallel-run output parity (the Corepoint-cutover tool) | `python -m harness.reconcile capture --out <jsonl> [--host --port]`; `… compare --mefor … --corepoint … [--ignore-segment] [--report-json]` | E1, E4 | Exercised on a synthetic golden pair; the real use is a cutover shadow phase |
| **`messagefoundry verify`** | On-box deployment acceptance, **wheel-only** | `verify [--section host,store,smoke,manual,federation] [--smoke self\|live\|none] [--check-disposition] [--report-md] [--report-json]` | E4, E5, E10, E12 | Exit 0 = no FAIL/ERROR (MANUAL/SKIP don't fail), 1 = FAIL/ERROR, 2 = usage. **Do not build a third acceptance framework** — `messagefoundry/verify/` owns the PASS/FAIL/SKIP/MANUAL contract and `--section federation` is how the AD lab extends it |
| **`messagefoundry check`** | Commit/CI config gate | `check` (+ the ADR 0050 anchor flags) | E1, adopter CI, E10 | Required checks: `validate`, `dryrun` (fixtures; honours a sibling `<fixture>.expect`), `posture`, `build-check` (posture-stamped connector construction), `reference-backend`. Advisory: `ruff`, `mypy`, `raise-fstring`, `accepts-candidate` |
| CI security scanners | SAST / SCA / secrets / supply chain | `bandit`, `semgrep`, `gitleaks`, `pip-audit` (+ the DEP-1 lock-sync re-export diff), `npm-audit`, `trivy`, SBOM, `crypto-inventory`, `forbidden-content`; plus `codeql` (python + javascript-typescript), `scorecard`, `zizmor`, `kubeconform` | E2 | Blocking: bandit, pip-audit, gitleaks, semgrep, forbidden-content, zizmor. Advisory: CodeQL, Scorecard (fork tokens lack `security-events: write`) |

### 0.14.2 What is missing and should be added

Each of these was checked against the tree, not assumed. The first seven are **absent outright** — none
of the named tools appears anywhere in the repo (excluding `.venv`). The last four are subtler and are
the more dangerous kind: a *capability* is missing even though something adjacent exists (a licence-
complete SBOM that never refuses a licence; an `RLIMIT_AS` that is a no-op on the deployment OS; a
single hand-rolled ENOSPC raise at one call site; a deliberately session-scoped event loop with no
order-randomisation to test the coupling it invites). Each row names the adjacent thing so the
distinction is auditable rather than a matter of opinion.

| Gap | Evidence it is missing | What to build | Where it would run |
|---|---|---|---|
| **Browser automation for `/ui`** | No `playwright`, `selenium`, or `puppeteer` in any `.py`, `.md`, `.json`, `.yml` or `.toml` in the tree. The web-console suite (14 `.py` files: 12 test modules — `test_ui_csp_canary.py`, `test_ui_origin_guard.py`, `test_ui_mfa_gate.py`, `test_ui_session_watchdog.py`, `test_ui_hardening.py`, `test_golden_surface.py`, … — plus `conftest.py` and the `_soft_webauthn.py` **software** authenticator stub) is entirely **server-side ASGI assertions over rendered HTML** — it proves the header/markup contract, and a WebAuthn ceremony against a *software* authenticator, not browser behaviour | A headless-browser smoke over the real `/ui`: sign-in, MFA/passkey ceremony, CSP as *enforced*, session expiry, the message list and dead-letter replay affordances | E2 (headless Chromium leg) + E6 (real browser matrix) |
| **Fuzzing rig** | No `atheris`, no `hypothesis`, no libFuzzer harness. Hostile input is GUI-injected only (§0.13.5) | Structure-aware fuzzing of the parse boundary: MLLP framing, `parsing/peek.py`, the X12 splitter, the DICOM dataset reader, and the `mfb64:v1:` binary carriage decoder. Corpus seeded from the generators; crashes captured as regression fixtures | Scheduled CI (its own workflow, never a required check) |
| **DAST** | Every security job is SAST or SCA. Nothing exercises a **running** engine | An authenticated scan against a locally-served engine + `/ui` — the API surface, the auth routes, CSRF/CSP, and the deny-by-default per-route permission map | Scheduled CI, against a container-served engine |
| **Coverage measurement / enforcement** | `diff-cover` is advisory, **PR-only** (it needs a base ref to diff), and reports at `--fail-under=0`. There is no repo-wide figure, no committed baseline, and no per-package floor | A recorded baseline + a ratchet on *new* code. Keep the rubric's rule — surface, never gate on a single gameable number — but make the number exist and trend | E2 |
| **Flake detection / quarantine** | `pytest-rerunfailures` self-heals a flake *in-run* and reports nothing; no JUnit XML is collected, no history, no quarantine list | Emit JUnit XML per leg, store it, trend rerun events, and quarantine a test only with a linked issue and an expiry | E2, E3 |
| **Accessibility checker** | No `axe-core`, `pa11y`, or `lighthouse` anywhere | An automated a11y pass over the web console's main pages, riding the same browser harness | E2 (headless) |
| **Web-console seam matrix** | Recorded as a **known gap in `ci.yml` itself**: the console declares a *range* of supported engine seams (`SUPPORTED_ENGINE_SEAMS`) but its suite runs against exactly one installed engine, so the back-compat claim is not exercised anywhere | Install the MIN and MAX supported engine builds and run the console package suite against each | E2 |
| **Randomized test-order leg** | No `pytest-randomly` / `pytest-random-order` in `[project.optional-dependencies] dev` or any workflow; the suite has only ever run in collection order. The exposure is structural, not hypothetical: `pyproject.toml:221-222` sets **`asyncio_default_test_loop_scope = "session"` *and* `asyncio_default_fixture_loop_scope = "session"`** — one shared event loop for tests **and** fixtures, deliberately (BACKLOG #17, to kill cross-loop aiosqlite teardown), which is also a textbook inter-test coupling surface: shared loop state, module-level registries, `MEFOR_*` env mutation and store files can leak forward and a passing suite can be order-dependent without anyone knowing | A **non-required, scheduled** leg running the suite under a randomized order with a printed seed, plus a seed-replay recipe. Treat every failure as a real coupling defect to fix at the fixture, never as a reason to pin the order. Do **not** make it a required check and do **not** weaken the session-scoped loop to satisfy it — the loop scope is a decided design, so the fix for an order failure is isolation in the test | Scheduled CI (E2), its own workflow |
| **Disk-full / ENOSPC injection** | Nothing can make the store's volume run out of space. One hand-rolled `OSError(28, "No space left on device")` exists at a single call site (`tests/test_asvs_gcm_invocation_bound.py:462`); there is no reusable injector, no small-loopback-filesystem fixture, and no coverage of ENOSPC on the WAL, the `.mfbak` archive write, the retention/purge archive stage, the file connector's output dir, or the rotating logs. The engine's durability claim is a **write** claim, so the failure mode it is least tested against is *the write not landing* | A reusable full-volume fixture — a small loopback/VHDX filesystem on the CI runner, or a fault-injecting path shim — plus rows asserting the disposition on ENOSPC: no acknowledged message lost, no half-written archive kept, a `storage_threshold` alert raised, and clean recovery once space returns | E2 (loopback FS on Linux), E4 (a real small volume on the box) |
| **OOM / memory-pressure harness** | The sandbox child gets a POSIX `RLIMIT_AS` cap (`messagefoundry/pipeline/_sandbox_worker.py:73`, a **no-op on Windows** — the deployment OS) and `/metrics` exports host/process memory gauges via `psutil` (`messagefoundry/api/metrics.py:151`), but nothing *applies* pressure: no test runs the engine under a constrained memory budget, and the large-payload paths (base64 `mfb64:v1:` carriage, DICOM datasets, the X12 interchange splitter, a batch file read) have no memory-ceiling assertion | A bounded-memory leg — a container with a hard memory limit, or a `RLIMIT_AS`-wrapped run — driving the large-payload and sustained-queue paths, asserting graceful degradation (bounded RSS, backpressure, a logged `ERROR`/dead-letter) rather than an OOM-killed process. Pair it with the Windows gap: state explicitly that `RLIMIT_AS` buys nothing on the deployment OS | E2 (cgroup-limited container), E4 (Windows job-object equivalent) |
| **Licence / SBOM policy gate** | SBOMs are generated (`security.yml` `sbom`: CycloneDX, licence-complete, scored by `sbomqs`) but the job is **`continue-on-error: true`, cron/dispatch-only, and not a required check** — it *records* licences, it never *refuses* one. No `pip-licenses`, `reuse`, or Trivy licence policy anywhere. The project ships **AGPL-3.0-or-later** (`pyproject.toml:29`) with an **LGPL** GUI dependency (PySide6, chosen deliberately over PyQt for OSS distribution) and vendored **MPL-2.0** corpora (`samples/messages/hapi-hl7v2/`) whose per-file source notices are a standing licence obligation — so a GPL-incompatible transitive licence (proprietary, SSPL, a 4-clause-BSD advertising clause) arriving via a Dependabot bump is a **distribution** defect that no gate would catch | An allow/deny licence policy evaluated against the generated SBOM on every dependency change (ride the existing blocking `pip-audit` job rather than adding a required context — see §0.15's structural rule), plus an assertion that the MPL-2.0 vendored files still carry their notices | E2 |

Every added tool has a **DEP-1 consequence**: a new dependency in `pyproject.toml` requires re-running
`uv lock` and all four `uv export`s (`requirements.lock`, `docker/locks/requirements-core.lock`,
`docker/locks/requirements-sqlserver.lock`, `constraints.lock`) or the blocking `pip-audit` job's
lock-sync step reds the PR. CI-only tools installed at job runtime avoid this — which is exactly how
the mutation and diff-coverage gates are structured.

---

## 0.15 CI topology

Sixteen workflows. This is the complete list; the plan cites these rather than restating what they do.

| Workflow | Legs / jobs | Trigger | Environment | Gates? | Role in this plan |
|---|---|---|---|---|---|
| [`ci.yml`](../../../.github/workflows/ci.yml) · `test` | `ubuntu-latest`, `windows-2022`, `windows-2025` — all py3.14. Ledger gate (ungated, Linux); ruff + both mypy passes (Linux only); pytest; web-console pytest | PR, push→main, dispatch. **Not** the nightly cron | E2 + E3 | **Required** ×3 contexts | The functional spine. Docs-only PRs short-circuit the expensive steps via `changes.code` while the required context still reports green |
| `ci.yml` · `changes` | Path filters → `serverdb`, `docker`, `code`, `ide`, plus the per-repo `matrix` / `ide_matrix` JSON | every `ci.yml` run | E2 | no | Decides which heavy legs run. On a **fork** it emits the ubuntu-only matrices |
| `ci.yml` · `ide` | build + typecheck + `test:unit` on ubuntu **and** windows-latest; `@vscode/test-electron` on Windows | dispatch, or PR touching `ide/**` / this workflow | E7 | no | The VS Code extension chapter's CI home |
| `ci.yml` · `sqlserver-store` | SQL Server **2022** and **2025** containers. Steps: store suite · coordinator (leader election) · failover (real TTL takeover, 2-node) · DATABASE-connector round-trip · **failover-LOAD** (SIGKILL the primary mid-load) · 10 throughput-lever invariant files · X12 RTE capture/re-ingress | nightly `17 3 * * *`, dispatch, or a PR touching the server-DB surface | E2 + containers | rolled up by `CI gate` | The **x2** server-backend leg for SQL Server. Every step is wrapped in `retry-native-crash.sh` |
| `ci.yml` · `postgres-store` | `postgres:16`. Store suite · failover-LOAD · the same 10 throughput-lever files · **connscale pool-wait smoke** (forced `MEFOR_STORE_POOL_SIZE=4`) · X12 RTE | same as above | E2 + container | rolled up | The **x2** leg for PostgreSQL, and the only place the advisory-lock / `SKIP LOCKED` concurrency is exercised |
| `ci.yml` · `load-test` | `smoke` profile on SQLite, serving `harness/config/load` under the **secure PHI posture** (runtime-minted store key, bounded retention, deny-by-default egress) | nightly + dispatch | E2 | rolled up | The zero-loss / SLO regression gate at smoke size. The **PR-time** gate is the in-process `tests/test_load_runner.py` |
| `ci.yml` · `load-test-sqlserver` | `smoke-sqlserver` on SQL Server **2022** and **2025**, RCSI on | nightly + dispatch | E2 + container | rolled up | End-to-end store path per stage; this leg caught the routed-stage `handler_name`-drop |
| `ci.yml` · `windows-service-smoke` | `windows-2022` + `windows-2025`. NSSM install (virtual account `NT SERVICE\MessageFoundry`, `-LockConfigDir`, `--env prod`) → start → `/health` → MLLP → `/messages` → stop → uninstall | nightly + dispatch, this repo only | E3 | rolled up | The only automated proof of the real Windows service path. It runs `prod`, so it also proves the fail-closed prod guards (store key, bounded PHI retention, deny-by-default egress) |
| `ci.yml` · `docker-smoke` | Builds slim + `runtime-sqlserver` + the baked smoke image; asserts an ADT reaches **PROCESSED** (not merely RECEIVED); verifies graceful `docker stop` (tini → SIGTERM → lifespan) | nightly, dispatch, or a PR touching image/locks/packaging | E2 | **not** in `CI gate` | The container-runtime leg and the seed for E11 |
| `ci.yml` · `ci-gate` | `if: always()`; fails iff a gated leg failed or was cancelled — a **skipped** leg passes | every run | E2 | **Required** | The one stable required context standing in for the conditional/matrix legs, which report unexpanded names when skipped |
| [`security.yml`](../../../.github/workflows/security.yml) | `pip-audit` (+ DEP-1 lock-sync), `npm-audit`, `sbom`, `trivy`, `bandit`, `gitleaks`, `semgrep`, `crypto-inventory`, `forbidden-content` | PR, push→main, daily `0 6 * * *`, dispatch | E2 | **Required:** `bandit`, `pip-audit`, `forbidden-content` | The PHI/customer leak guard and the supply-chain floor. The daily cron bounds CVE exposure on an unchanged tree at ~24 h |
| [`codeql.yml`](../../../.github/workflows/codeql.yml) | python + javascript-typescript | push→main, PR, weekly `0 7 * * 1`, dispatch | E2 | advisory | Taint/data-flow SAST — untrusted HL7/config reaching a sink across function boundaries |
| [`scorecard.yml`](../../../.github/workflows/scorecard.yml) | OpenSSF Scorecard → SARIF + public badge | `branch_protection_rule`, weekly `0 8 * * 1`, push→main, dispatch | E2 | advisory | Supply-chain hygiene regression detector |
| [`zizmor.yml`](../../../.github/workflows/zizmor.yml) | Actions static analysis (`zizmor==1.5.2`) | PR touching `.github/**`, daily `0 6 * * *`, dispatch | E2 | **Blocking** (not in required set) | Guards the CI substrate itself: template injection, over-broad tokens, dangerous triggers |
| [`quality-advisory.yml`](../../../.github/workflows/quality-advisory.yml) | `complexity` (ruff C901 **delta**), `clone` (jscpd), `coverage` (diff-cover, PR-only), `mutation` (mutmut 3), and a `liveness` job that **can** go red when a gate stops measuring | PR, dispatch, nightly `23 4 * * *` | E2 | **Never** required; `tests/test_quality_advisory_invariants.py` pins that | The quality-measurement chapter's home. Deliberately uses workflow-command annotations, **not** SARIF — the reasons are measured and recorded in its header |
| [`benchmark.yml`](../../../.github/workflows/benchmark.yml) | Reference sustainable-rate steps per backend + the active-passive failover profile; metrics-only JSON uploaded | **dispatch only** | E2 + containers | no | Produces the numbers transcribed into `docs/benchmarks/TUNING-BASELINE.md` |
| [`selfhosted-win2025-sql.yml`](../../../.github/workflows/selfhosted-win2025-sql.yml) | The SQL Server store / coordinator / failover / connector suites on **real** Windows Server 2025 + real ODBC 18 | **dispatch only**, label `[self-hosted, windows, mefor-win2025-sql]`; concurrency queues (one shared DB) | E4 | no, and never | The one production-shaped combination hosted runners cannot reach. Dispatch-only *is* the security control — no fork code ever reaches the runner |
| [`freethread-smoke.yml`](../../../.github/workflows/freethread-smoke.yml) | Install + import + smoke subset on cp314t (free-threaded) | weekly `0 6 * * 1`, dispatch | E2 | must never be required | Informational tripwire for [`docs/design/freethread.md`](../../design/freethread.md). Its header records why belt-and-braces `continue-on-error` made the canary *incapable of reporting a problem* — a useful precedent for every advisory gate in this plan |
| [`manifest-lint.yml`](../../../.github/workflows/manifest-lint.yml) | kubeconform + ADR-0047 HA-policy grep assertions on `docker/k8s/*.yaml` | push/PR touching manifests or `docker/README.md`, dispatch | E2 | additive, not required | The only automated signal on E11 today — and it is schema/policy lint, **not** an applied deployment |
| [`backlog-hygiene.yml`](../../../.github/workflows/backlog-hygiene.yml) | A PR claiming `BACKLOG #N` and touching engine/IDE code must also update `docs/BACKLOG.md` | PR→main | E2 | not required | Keeps the status ledger honest. The structural half rides `tests/test_backlog_status_check.py` in the `test` matrix |
| [`cla.yml`](../../../.github/workflows/cla.yml) | CLA Assistant, signatures on the `cla-signatures` branch | `issue_comment`, `pull_request_target` (opened/synchronize) | E2 | **Required** (`CLA Assistant`) | Contribution gate |
| [`dependabot-auto-merge.yml`](../../../.github/workflows/dependabot-auto-merge.yml) | Scoped auto-merge: patches + dev-only minors, each held unless EVERY named dependency sits on its ecosystem's **allow-set** row (hold-unless-named, whole-group denial), plus a published-GHSA gate and a release-age gate on the security track — all **failing closed** | `pull_request` | E2 | n/a | Why the required-check set is load-bearing: it is the only thing standing between a dependency bump and `main` |
| [`dependabot-lock-resync.yml`](../../../.github/workflows/dependabot-lock-resync.yml) | Re-exports the four lock artifacts onto the Dependabot branch | PR touching `uv.lock` / `pyproject.toml` | E2 | n/a | Must stay in lockstep with security.yml's DEP-1 step — a file the gate diffs but this job does not export is un-fixable by the bot |
| [`vuln-metrics.yml`](../../../.github/workflows/vuln-metrics.yml) | NIST SSDF RV.2 KPIs from real Dependabot PRs + CISA KEV + FIRST EPSS | weekly `0 8 * * 1`, dispatch | E2 | no | Evidence artifact, not a detector |
| [`release.yml`](../../../.github/workflows/release.yml) | Build + SBOM + Sigstore sign + GitHub release + PyPI Trusted Publishing; separate `release-harness` (gated on the `PUBLISH_HARNESS` repo variable) and a `webconsole-v*` tag namespace | tag `v*` / `webconsole-v*`, dispatch (dry-run: builds/signs, never publishes) | E2 | n/a | The release chapter's substrate |

**Required contexts on `main`** (per [`docs/CI.md`](../../CI.md); branch protection is the source of
truth): `CI gate`, `test (ubuntu-latest, py3.14)`, `test (windows-2022, py3.14)`,
`test (windows-2025, py3.14)`, `bandit (Python SAST)`, `pip-audit (dependency vulnerabilities)`,
`forbidden-content (customer/PHI leak guard)`, `CLA Assistant`.

**Two structural rules this plan inherits and must not break.** (1) A new required check **wedges every
PR opened before it existed** — that is why the ledger gate rides *inside* the already-required `test`
leg rather than becoming its own context, and why any gate this plan adds should ride an existing
required job or stay behind `CI gate`. (2) A matrix or conditional leg reports an **unexpanded** name
when skipped and an expanded one when it runs, so no single context string matches both states — hence
`ci-gate`.

---

## 0.16 Which planned tests can join CI, and which cannot

### Can join CI (work required, but no blocker)

| Candidate | How | Where |
|---|---|---|
| Headless-browser smoke of `/ui` | New job installing a headless browser, serving the engine loopback with auth on, driving sign-in → message list → dead-letter replay | `ubuntu-latest` |
| Accessibility pass | Rides the same browser job | `ubuntu-latest` |
| Fuzzing the parse boundary | Its own scheduled workflow, corpus seeded from the generators, crashes minimized into `tests/` fixtures | `ubuntu-latest`, nightly/weekly |
| DAST against a running engine | Serve the container image, scan authenticated | `ubuntu-latest`, scheduled |
| Coverage baseline + trend | Extend the existing advisory `coverage` job; add a stored baseline | `ubuntu-latest` |
| Flake trending | JUnit XML emission on every pytest step + an aggregation job | all pytest legs |
| k8s manifests **applied** (not just linted) | `kind`/`k3d` cluster in-job, apply `docker/k8s/`, assert leader election and single-binder | `ubuntu-latest`, path-gated like `manifest-lint` |
| Web-console seam matrix | Install MIN and MAX supported engine builds; run the console suite against each | `ubuntu-latest` |
| DICOM / FHIR / SFTP interop against **containerized** peers | Service containers (HAPI FHIR, an SFTP image, a pynetdicom SCP) | `ubuntu-latest`, path-gated |

### Cannot join CI

| Candidate | Why not | Where it runs instead |
|---|---|---|
| **AD / Kerberos / EPA / OIDC federation cells (L0–L18)** | Standing prohibition in `HANDOFF-AD-LAB-aws.md`: a domain-joined self-hosted runner executing repo code is a far larger blast radius than `windows-service-smoke`. A Domain Controller is also *a VM role, never a container* | E5, hand-run as one booked window; commit the **scrubbed** L17 run record |
| **Service identity, DPAPI boundary, file ACLs, Windows Firewall, no-console-flash, port-rebind lag** | Structurally unreachable: CI runs as a root-equivalent user in a container or on an ephemeral hosted VM. WIN2025-TEST-PLAN §S0.2 assigns these to the box by design | E4, `messagefoundry verify` + `harness.acceptance` |
| **Real-host throughput ceiling** | CI throughput is smoke-sized, containerized and shared-runner: it gates *regression*, not *capacity*. Explicitly recorded as a **distinct, non-duplicate** signal | E4, `--load closed-loop` / `reference` |
| **Real-hardware SQL Server 2025 on real Windows Server 2025** | Hosted runners reach SQL Server only through a Linux service container | E4 via `selfhosted-win2025-sql.yml`, dispatch-only, never required |
| **Real certificates, real partner endpoints, real Clarity `db_lookup`** | Phase 2 of the WIN2025 plan: no production config repo and no customer-network access exist yet | E8 / customer network, Phase 2 |
| **8-hour soak** | Wall-clock. The nightly cron cannot hold a runner that long, and doing so would collide with the whole nightly budget | E4 overnight (8 h on SQL Server; 1 h each on SQLite/PostgreSQL) |
| **Two-box failover across a machine boundary** | Requires two hosts and a real network partition. CI's two-`serve`-process rig on one runner proves the invariants, not the topology | E9 |
| **Air-gapped install** | A CI runner has egress by construction; removing it removes the runner's ability to check out and install | E12 |
| **Real browser matrix (Safari, older Edge, real WebAuthn authenticators)** | Hosted runners give one browser family per OS image and no hardware authenticator | E6 |
| **Promotion between two posture-divergent engines** | Needs two long-lived engines with different derived postures and a config repo remote; an ephemeral runner can fake neither the posture divergence nor the operator's approval step | E10 |

---

## 0.17 Cost, procurement & lead time

Nothing in this section is a purchase recommendation; it is the dependency list the plan cannot run
end-to-end without. **Lead time**, not price, is the binding constraint on most rows.

| # | Item | Why the plan needs it | Cost shape | Lead time | Blocks |
|---|---|---|---|---|---|
| **C1** | GitHub-hosted Actions minutes | Every CI leg, including the 2×-billed Windows and electron legs | **$0** — free on a public repo. This is *why* the self-hosted NucBox runners were retired and the matrix went hosted-everywhere | none | nothing |
| **C2** | Re-register the `mefor-win2025-sql` self-hosted runner | `selfhosted-win2025-sql.yml` exists, is dispatch-only, and is **runner-less** | Hardware exists; install the runner service as a dedicated non-admin local user, set `MEFOR_STORE_PASSWORD` in the machine env, install ODBC 18 | **days** | the real-hardware SQL Server rows |
| **C3** | SQL Server licensing | Two majors under test (2022, 2025) | Container images are free to pull for CI; on-box use is **Developer Edition** (free, non-production only). A production-licensed instance is a Phase-2 customer-side item | none for test | nothing in Phase 1 |
| **C4** | Windows Server licences / evals | E3 is hosted (free); E4, E5-B/C, E9, E10 are self-provisioned | Eval or existing licences | days | E4/E5/E9/E10 |
| **C5** | **AD / federation lab (AWS)** | Boxes A (DC + AD FS), B (engine, domain-joined, NSSM), C (Chrome + Firefox client; may be B for pass 1). Optional pass-2: AD CS, IIS+ARR mTLS front, an Entra tenant | Hourly EC2 for three Windows instances **plus EBS** (artifacts must be written off instance-store — a STOP/START wipes it). Owner approval required before stopping or terminating anything | **book one window**; the runbook is explicit that the four items are planned *as one window, or not at all* | every federation / Kerberos / EPA / gMSA / OIDC row |
| **C6** | **Stand the AD lab up** (the forest itself) | `docs/security/AD-FEDERATION-LAB-RUNBOOK.md` (cells L0–L18) is the named authority; it is **withheld from the public repo**, not missing (`/docs/security/` is git-ignored at [`.gitignore:144`](../../../.gitignore)) and the owner confirms it is available to whoever builds the lab. The countable work is the build itself: DC promoted for `mefor.lab`, test accounts + groups created (incl. the L18 collision pair), the engine **SPN registered and a keytab issued**, and a **reachable LDAPS endpoint** | Owner/admin time inside the C5 window; no purchase | hours-to-days **inside** the booked C5 window | every federation / Kerberos / EPA / gMSA / OIDC row (jointly with C5) |
| **C7** | Browser matrix host(s) | Real Chrome + Firefox on Windows (AD-lab cell L7 needs two browsers on a domain-joined client); Safari needs macOS | One Windows VM covers Chrome+Firefox. Safari = a Mac or a paid cross-browser service. A hardware security key for the passkey path is a small one-off | days (Windows) / weeks (Mac or a service contract) | the web-console browser chapter, WebAuthn end-to-end |
| **C8** | Interop endpoints | DICOM SCP/SCU peer, DICOMweb STOW-RS receiver, FHIR server, **SFTP/FTPS** (matrix row `W25:D3` is deferred today for exactly this reason), X12 partner TCP | Containerized peers ≈ free and should be the default. A real modality/PACS or EHR sandbox is a **relationship + registration** cost, not a purchase | days (containers) / weeks–months (real peers) | the interop chapter's "foreign implementation" rows |
| **C9** | Two-box HA rig (E9) | Machine-boundary failover, VIP behaviour, Windows recovery *time* | 2 VMs + a shared server DB (can reuse C2/C4 capacity) | days | the HA chapter's topology rows |
| **C10** | PUB engine pair (E10) | A non-production and a production-like engine with **different derived postures**, plus a config-repo remote | 2 VMs + a git remote (a bare repo on a share is sufficient and is the documented air-gapped shape) | days | the whole publish/promotion chapter |
| **C11** | Kubernetes target (E11) | Prove the multi-replica manifest elects a leader and the L4 LB follows failover | `kind`/`k3d` in CI ≈ free and should be tried first. A managed EKS/AKS/GKE cluster is billed hourly and needs a cloud account | days (kind) / weeks (managed + account) | the cloud/k8s chapter beyond schema lint |
| **C12** | Air-gapped target (E12) | No-egress install and operation | One isolated VM + a mirrored wheelhouse + the **offline ODBC 18 installer** (normally fetched from `packages.microsoft.com`) | days, but the wheelhouse must be built deliberately | the offline-install chapter |
| **C13** | PyPI Trusted Publishing + `PUBLISH_HARNESS` | `release.yml` requires a **one-time owner** action: claim the `messagefoundry` project and configure a Trusted Publisher (a pending publisher works before the first upload) for `MEFORORG/MessageFoundry` + `release.yml`; the harness wheel needs its own pending publisher **and** the `PUBLISH_HARNESS` repo variable set to `true`; the web console has its own `webconsole-v*` tag namespace bound to the same workflow | $0 | **owner-gated** | the release chapter's live publish rows |
| **C14** | New test tooling (browser driver, fuzzer, DAST, coverage, a11y) | §0.14.2 | $0 in licence for the obvious open-source choices; the real cost is **CI minutes** and the DEP-1 lock discipline if any of them lands in `pyproject.toml` | days each | the corresponding gaps |
| **C15** | `openpyxl` on the acceptance box | `harness.acceptance --xlsx` write-back into the 54-row matrix. It is **not** a project dependency | $0 | minutes | the WIN2025 matrix write-back |

**Sequencing consequence.** Only three rows have long lead times — **C5 + C6** (booking the AD-lab
window and building the forest inside it), **C7** (a Mac or cross-browser contract, if Safari is in
scope), and **C8** (real interop peers). Everything else is days of provisioning. C6 is not a
prerequisite *before* C5 and never was a document hunt: the runbook exists and is available to the
builder, so the two are **one piece of work** — book the window, then stand up DC → accounts/groups →
SPN/keytab → LDAPS inside it, and hold the window open until an LDAPS bind from the engine host
succeeds. Run the container-substitutable interop work (C8, containers) in parallel, and treat C7's
Safari leg as an explicit scope decision rather than an assumption.
