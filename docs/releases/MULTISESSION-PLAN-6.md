# MessageFoundry — Multisession Execution Plan 6 (2026-06-28)

**Scope.** The post-`0.2.10` *buildable* backlog: the four **actionable-now** items (**#33** config-UX
consolidation, **#39** frozen console installer Phase B, **#40** self-hosted Win Server 2025 + SQL Server
2025 CI leg, **#41** cloud / Kubernetes HA packaging) plus the three **owner-decision** items (**#52**
Corepoint-parity roadmap synthesis, **#60** turnkey DR backup + restore-verify, **#61** third-tier DR
standby). Everything else on the board is on-trigger / demand-gated or declined-by-design (see
[`docs/BACKLOG.md`](../BACKLOG.md) "Next up" + the per-item ✅ banners) and is **out of scope here**.

**This is a plan, not a build.** Per the project convention, nothing is built until the owner gives an
explicit "go". And per the user's directive, **the plan starts with ADRs** — every lane that needs a
decision record is gated behind its **Wave 0** ADR being authored and **owner-ratified** (Proposed →
Accepted) before any product code is written.

**Lineage.** Supersedes-forward [`MULTISESSION-PLAN-5.md`](MULTISESSION-PLAN-5.md) (the v0.3-candidate
wave, shipped as `0.2.10`). The BACKLOG / ADR-index / FEATURE-MAP **stale-claim reconciliation** that
PLAN-5 carried as its §I lane is **already done** in this same PR's first commit — so PLAN-6 needs no
reconciliation lane (see §I).

**Autonomy: L1** — workers build + verify (full quartet) + commit **local**; the **owner** opens/merges
PRs and **ratifies ADRs**. Single-writer coordination ledger in AI memory. Worktree-per-lane off
`origin/main` @ `301a2b5`.

---

## A. Wave items (all verified OPEN on `origin/main` @ 301a2b5)

### Wave 0 — ADRs + roadmap decision (Lane 0; coordinator-authored, **owner-ratified**)

Nothing in Wave 1 / Wave 2 builds until its ADR is **Accepted**. See §G for the full ADR registry.

| Output | For item | New / existing |
|---|---|---|
| **ADR 0047** Cloud / Kubernetes HA deployment packaging | #41 | **NEW** (ratifies the cloud research doc into a decision record) |
| **ADR 0032 amendment** Frozen console installer Phase B — freeze tool + Authenticode + LGPL | #39 | **Amend existing** (Phase B was deferred in 0032) |
| **ADR 0050** Single project-root config anchoring | #33 (follow-up A) | **NEW** (the review flagged A as "likely an ADR output") |
| **ADR 0049** Turnkey DR — scheduled config/store backup + restore-verify | #60 | **NEW** |
| **ADR 0048** Third-tier DR standby | #61 | **Existing — Proposed → finalize + EARS + Accept** |
| **#52 roadmap synthesis** — promote the agreed Corepoint-gap rows into numbered items | #52 | No ADR — owner decision + BACKLOG promotions |

### Wave 1 — actionable, independent builds (parallel lanes, each gated on its Wave-0 ADR)

| # | Item | ADR | Lane | Notes |
|---|---|---|---|---|
| **#41** | Cloud / Kubernetes HA deployment packaging — multi-replica reference manifest + managed-Postgres cloud docs + MLLP L4 LB guidance + edge-relay topology + PHI/HIPAA cloud arch + raw-TCP/X12 startup-TLS guard | **ADR 0047** | **L1 cloud-k8s-ha** | HA tier is **code-complete but unpackaged** (PR #480 shipped the image + single-node). Mostly **docs + manifests**; the one code touch is the small TLS guard. Research: [`research/cloud-deployment-research-2026-06.md`](../research/cloud-deployment-research-2026-06.md). |
| **#39** | Frozen, zero-Python console installer (Phase B) — freeze `messagefoundry.console` + Windows installer + Authenticode signing + CI build/sign leg + LGPL notice | **ADR 0032 (amend)** | **L2 frozen-installer** | Layers on the built Phase A `gui-script`. Heavyweight (PySide6 freeze ~150 MB); the freeze-tool + signing decision is the ADR amendment. |
| **#40** | Self-hosted CI leg vs real **Win Server 2025 + SQL Server 2025** box — NSSM service smoke + SQL Server store/coordinator/`db_lookup` suites + recurring #28/#29 load/throughput | none (infra; needs a self-hosted-runner **security note**) | **L3 selfhosted-ci** | **Hardware-gated:** the owner provisions + isolates the self-hosted runner first. Gate to push / `workflow_dispatch` on `main` only; `concurrency` group on the shared box. |
| **#33** | Config-UX consolidation **build** — the review's ranked follow-ups: **A** single project-root anchor (+ extend `--project-root`/`--env`/`--service-config` to `validate`/`graph`/`dryrun`/`check`), **B** total + section-complete env-settings parser, **C** enforce `connections.toml` secret discipline at load, **D** unify env list separators, **E** docs-only catalog consolidation | **ADR 0050** (A only); B/C/D/E from the review | **L4 config-ux** | Review already delivered (31 findings): [`research/config-ux-review.md`](../research/config-ux-review.md). A is the ADR; B/C/D are bounded code; E is docs. **Heavy `config/` toucher — coordinate with #61's priority overlay (Wave 2).** |

### Wave 2 — DR tier (owner-gated; **sequential #60 → #61**)

| # | Item | ADR | Lane | Notes |
|---|---|---|---|---|
| **#60** | Turnkey DR — engine-managed scheduled **config-bundle + SQLite-store backup** + **restore-verify** pass (config-tier slice first) | **ADR 0049** | **L5 dr-backup** | **Server-DB backup stays DBA-delegated** (declined per #52); #60 owns config + SQLite store + the restore-verify mechanic. Backup integrity likely imports `hashlib` → **crypto-inventory gate** (§F). |
| **#61** | Third-tier DR standby — a per-connection **priority tier** (global-default + per-connection-override) + a startup **DR run-profile** (`status:"filtered"`) that runs only high-priority feeds in degraded mode; acquire-VIP-or-abort fencing; consumes #60's cold-seed backups | **ADR 0048** | **L6 dr-standby** | Leans on **ADR 0031** (selective startup / fault isolation) + the #34/#47 per-connection-override plumbing. **Needs #60's backup format** (cold seed) → land after L5. Touches `config/models.py` ConnectionSpec — coordinate with L4. |

---

## B. Lane assignment (worktree per lane off `origin/main` @ 301a2b5)

> `scripts/worktree/new.ps1 -Name <lane>` (isolated checkout + branch + `.venv`); docs-only lanes can use a
> plain `git worktree add` off `origin/main` to skip venv provisioning. Cleanup: `remove.ps1`.

### Lane 0 — COORD / ADR (pure docs; builds no product code)
- Author **ADR 0047 / 0049 / 0050**, **finalize ADR 0048** (Proposed → Accepted, add EARS acceptance
  criteria), **amend ADR 0032** (Phase B). Flip `docs/adr/README.md` rows as each is Accepted.
- **#52 roadmap synthesis:** from [`marketing/corepoint-gap-analysis.md`](../../marketing/corepoint-gap-analysis.md)
  (local-only), bring the owner the **NEW-candidate gap rows** worth promoting (DR is #60/#61; alert-escalation,
  declarative-modeling, correlation-UX, web-monitor/host-metrics, PKCS#12/cert-inventory, generic OAuth2/Digest/NTLM,
  Oracle/MySQL/ODBC-DSN) and **promote the agreed ones into numbered BACKLOG items** with triggers. Owner decision;
  no code.
- Re-check `origin/main`'s highest ADR number **before** authoring (a sibling worktree may have claimed
  0047+); the numbers below are reserved as of `301a2b5`.

### Lane L1 — CLOUD-K8S-HA (#41) — *Wave 1, ADR 0047*
- Multi-replica HA reference manifest (Postgres-backed `replicas: 3`, `[cluster].enabled=true`, PDB
  `maxUnavailable: 1`, lease-TTL-aware `terminationGracePeriodSeconds`) + a Postgres service in `compose`.
- Cloud docs led by **managed Postgres** (RDS / Cloud SQL / Azure DB); SQLite/single-node framed POC/edge.
- MLLP **L4 load-balancer** guidance (one NLB listener/port, primary-only TCP health check, drain via
  `deregistration_delay`; explicit **no L7/HPA for MLLP**). Hybrid **edge-relay** topology template.
  Cloud **PHI/HIPAA** secure-architecture doc (BAA, HIPAA-eligible services, KMS CMEK, PrivateLink).
- **Code (small):** a startup **TLS guard for raw-TCP / X12 listeners** (parallel to `check_mllp_tls_exposure`).
- Files: `docker/`, new `deploy/k8s/` manifests, `docs/DEPLOYMENT.md` / a new cloud doc, `transports/` (TLS guard).

### Lane L2 — FROZEN-INSTALLER (#39) — *Wave 1, ADR 0032 amendment*
- Freeze `messagefoundry.console` (PyInstaller / Nuitka / briefcase — the ADR-amendment decision) to a
  single-folder exe; reuse `app.ico`. Inno Setup / MSIX installer (Desktop + Start-Menu shortcuts, ARP
  uninstall). **Authenticode** sign the exe + installer. CI **build + sign** leg producing the installer as
  a release asset. PySide6 **LGPL** compliance (relinking notice).
- Files: new `packaging/console-installer/`, `.github/workflows/` (build+sign leg), `docs/SERVICE.md` /
  console install docs. **Signing cert from CI secrets — never in the repo.**

### Lane L3 — SELFHOSTED-CI (#40) — *Wave 1, no ADR; hardware-gated*
- Self-hosted GitHub Actions runner on the Win Server 2025 + SQL Server 2025 box (**owner provisions +
  isolates**). A leg that installs the wheel + `[sqlserver]` + ODBC Driver 18, registers/starts the engine
  as a Windows service (`scripts/service/`), hits `/health`, runs the SQL Server store/coordinator/`db_lookup`
  suites against the local instance, and hosts the recurring **#28/#29** load/throughput runs.
- Security: gate to **push / `workflow_dispatch` on `main` only** (never fork PRs); `concurrency` group;
  runner-local `MEFOR_*` creds. A short **self-hosted-runner security note** under `docs/` (not an ADR).
- Files: `.github/workflows/` (new self-hosted job), `docs/CI-*.md`. No product code.

### Lane L4 — CONFIG-UX (#33) — *Wave 1, ADR 0050 for A; B/C/D/E from the review*
- **A (ADR 0050):** anchor the whole config bundle to one project root; extend `--project-root` / `--env` /
  `--service-config` to `validate` / `graph` / `dryrun` / `check`. Root-causes the NSSM non-repo-CWD silent
  miss. Contends `config/environments.py` + `config/settings.py` + `__main__.py`.
- **B:** make the env-settings parser **total + section-complete** (`MEFOR_<multi_word>_*`, dotted/nested
  sections, `[pipeline]`/`[cert_monitor]`) — `config/settings.py`.
- **C:** enforce `connections.toml` secret discipline **at load** (not just redact in the API view) —
  `config/connections_file.py` + `config/wiring.py`.
- **D:** unify env list separators — `config/settings.py`. **E:** docs-only catalog consolidation —
  `docs/CONFIGURATION.md`.
- **Circulation already honored:** the review's two named consumers (#34 retention overlay, the future
  `[secrets]` provider) already shipped / are tracked; B (dotted-section reachability) is the one that affects
  any future nested `MEFOR_*` surface.

### Lane L5 — DR-BACKUP (#60) — *Wave 2, ADR 0049; owner-gated*
- Engine-managed scheduled (+ on-demand) backup of the **config bundle + SQLite store**, with a
  **restore-verify** pass (open the backup, integrity-check, count rows). Cadence / retention / restore-verify
  posture are **owner-set** (gate). **Server-DB store backup stays DBA-delegated** — do not reimplement
  Postgres/SQL Server backup.
- Files: new `pipeline/dr_backup.py` (or `ops/`), a `messagefoundry backup` / `restore-verify` CLI,
  `config/settings.py` `[dr]`/`[backup]` block, `docs/`. **`hashlib` for backup integrity → register in
  `scripts/security/crypto_inventory_check.py` (§F).**

### Lane L6 — DR-STANDBY (#61) — *Wave 2, ADR 0048; after L5*
- New per-connection **`priority`** tier (`critical|normal|low` or `dr_profile`), global-default +
  per-connection-override (the #34/#47/`RetryPolicy` idiom), authored on `ConnectionSpec` + `connections.toml`.
- Startup **DR run-profile** = "start only connections at tier ≥ X", on the ADR 0031 selective-startup path;
  a new `status:"filtered"` distinct from 0031's `failed`. `[dr]` activation `manual` (default) / `auto`
  (probe the HA pair `/healthz`); **acquire-VIP-or-abort** fencing + tier-2-lease quorum vs split-brain;
  drain-then-hand-back fail-back. Cold seed **consumes #60's backups**; warm seed = DB replica (DBA).
- Files: `config/models.py` (ConnectionSpec `priority`), `config/wiring.py`/`connections.toml` parse,
  `pipeline/` (DR run-profile + startup selection), `transports/`/`api/` (VIP/health probe hook), `docs/`.
  **Coordinate `config/models.py` + `connections.toml` parsing with L4 (config surface).**

---

## C. Land-order / wave sequence

1. **Wave 0 (Lane 0) — ADRs + #52.** Author 0047/0049/0050, finalize 0048, amend 0032; bring the owner the
   #52 promotions. **Owner ratifies.** *No build starts until the relevant ADR is Accepted.*
2. **Wave 1 — parallel** once their ADRs are Accepted: **L1 (#41)**, **L2 (#39)**, **L3 (#40)**, **L4 (#33)**.
   These are largely independent (docs/manifests, packaging/CI, CI-infra, config). The shared collisions are
   the **`.github/workflows/` files** (L1/L2/L3) and the **`config/` surface** (L4 now vs L6 later) — see §D.
   **L3 may stall** on owner-provisioning the self-hosted runner; that does not block L1/L2/L4.
3. **Wave 2 — sequential, owner-gated:** **L5 (#60)** lands first (defines the backup/cold-seed format),
   then **L6 (#61)** builds on it. L6 rebases its `config/models.py` + `connections.toml` edits over L4.
4. Each lane: full quartet green (`ruff format --check` + `ruff check` + `mypy` strict + `pytest`
   offscreen) **before** the owner PRs it; store-touching work (L5/L6) runs the 3-backend parity suite.

---

## D. Contention matrix

| File(s) | Lanes | Resolution |
|---|---|---|
| **`.github/workflows/ci.yml` + `release.yml`** | **L2 (#39 build+sign leg)** · **L3 (#40 self-hosted job)** · **L1 (#41 prod-posture manifest CI, if any)** | **Serialize the workflow-file edits** (additive job blocks), or put each new job in its **own** workflow file to decouple. Last-writer rebases. |
| **`config/settings.py`** | **L4 (#33 A/B/D)** · **L5 (#60 `[dr]`/`[backup]` block)** · **L6 (#61 `[dr]` activation)** | L4 is the heavy toucher (Wave 1, lands first). L5/L6 add **new `[dr]`/`[backup]` sections** (additive) and rebase over L4. **L5 and L6 must agree on one `[dr]` block shape** (backup vs standby keys) — coordinate. |
| **`config/models.py` (ConnectionSpec) + `connections.toml` parse** (`config/wiring.py`, `config/connections_file.py`) | **L4 (#33 C secret-discipline)** · **L6 (#61 per-connection `priority`)** | Different concerns, same files. **L6 rebases over L4.** The `priority` override reuses the #34/#47 per-connection-override plumbing already in these files. |
| **`__main__.py` (CLI flags)** | **L4 (#33 A — `--project-root`/`--env`/`--service-config` on more subcommands)** · **L5 (#60 `backup`/`restore-verify` subcommands)** | L4 sole heavy toucher; L5 adds new subcommands (additive). Sequence; both register via the existing subcommand pattern. |
| **`transports/` startup TLS guards** | **L1 (#41 raw-TCP/X12 guard)** | L1 sole toucher; mirror `check_mllp_tls_exposure`. |
| **`pipeline/` startup + `wiring_runner.py`** | **L6 (#61 DR run-profile selective startup)** | L6 sole toucher; rides the ADR 0031 selective-startup path. Re-verify count-and-log + at-least-once across the DR handoff. |
| **`store/{store,base,postgres,sqlserver}.py`** | **L5 (#60 SQLite backup read path)** | L5 reads the SQLite store for backup; **additive, no schema change** (server-DB backup is DBA-delegated). Parity suite if any read method is added. |
| `docs/` (DEPLOYMENT, SERVICE, CONFIGURATION, CI, a new cloud + DR doc) | all lanes | Disjoint files — no real collision; E (#33) owns CONFIGURATION.md. |
| `docs/adr/` — NEW 0047/0049/0050, finalize 0048, amend 0032; `docs/adr/README.md` row flips | **Lane 0** | Coordinator-owned, single-writer. |

---

## E. Coordination rules

1. **Worktree per lane**, branched off `origin/main` @ `301a2b5`. Never edit a sibling worktree. Use the
   lane's own `.venv`.
2. **ADR-gated:** a Wave-1/2 lane does not write product code until its Wave-0 ADR is **Accepted** by the
   owner. (L3/#40 needs no ADR but **is** gated on the owner provisioning the runner.)
3. **Single-writer coord ledger** in AI memory (one session writes the live status; others read). One
   logical lane per session.
4. **L1 autonomy:** build + verify + commit **local**; the owner opens/merges PRs and ratifies ADRs. Don't
   push/PR or merge without an explicit owner "go".
5. **Land-order:** Wave 0 → Wave 1 (parallel) → Wave 2 (L5 then L6). The DR lanes are owner-gated on posture
   decisions (§H) — they do not start on ADR-Accept alone.
6. **`git add` explicit paths** (the repo guard blocks `git add -A`/`.`). Commits end with the
   `Co-Authored-By` trailer.

---

## F. Build gotchas (checklist — apply on every lane)

1. **SPDX header** on every **new** `.py` (the #350 sweep only covered existing files). L1 (TLS guard), L5
   (`dr_backup.py`), L6 (DR-profile module) all add new `.py`.
2. **Crypto-inventory gate:** a new `.py` importing `hashlib`/`hmac`/`secrets`/`ssl`/`cryptography`/`argon2`
   trips the ASVS 11.1.3 gate (a **required CI leg AND a pytest test**) until registered in
   `scripts/security/crypto_inventory_check.py` INVENTORY. **L5 (#60 backup integrity → `hashlib`)** and
   possibly **L2 (#39 signing helper)** hit this.
3. **DEP-1 re-lock:** if a lane adds a **runtime** dependency (unlikely here — #41 manifests, #39 freeze
   tools, and #40 runner are build/infra, not runtime deps), add it to `pyproject.toml` then re-lock from
   the **repo root** with the lock header's relative `uv export` command — **never** `uv export --directory`
   (it bakes into the lock header and reds DEP-1). `uv` is not installed by default (`pip install uv`).
4. **New optional extra → CI install line:** if a lane adds a `[extra]` whose tests use `importorskip`, add
   it to `.github/workflows/ci.yml`'s `.[dev,console,...]` install line or the tests **silently skip** in CI.
   (#39 freeze tools belong in a CI build step, not a runtime extra.)
5. **Self-hosted runner (L3):** repo code executes on owner hardware — **push / `workflow_dispatch` on `main`
   only**, never fork `pull_request`; tight runner token; `concurrency` group on the shared box.
6. **Secrets:** Authenticode signing cert (L2), SQL Server SA / DSN (L3), backup-target creds (L5) come from
   CI/runner-local env (`MEFOR_*`), **never** the repo. Never log full bodies / PHI.
7. **Store parity:** L5/L6 store-touching work runs the SQLite + Postgres + SQL Server suites; preserve the
   count-and-log + at-least-once invariants (esp. L6's DR handoff / fail-back).

---

## G. ADRs (Lane 0; coordinator-authored, owner-ratified)

> Numbers reserved as of `origin/main` @ `301a2b5` (highest existing ADR = **0048**; **0047** is the open
> gap). **Re-check the highest ADR on `origin/main` before authoring** — a sibling worktree may have claimed
> 0047/0049/0050.

| ADR | Title (working) | For item | State / target |
|---|---|---|---|
| **0047** | Cloud / Kubernetes HA deployment packaging — multi-replica reference manifest, managed-Postgres-led cloud docs, MLLP L4 LB (no L7/HPA), hybrid edge-relay, cloud PHI/HIPAA arch; ratifies the cloud research into a decision record | #41 | **NEW** — Proposed → ratified before L1 builds |
| **0032 (amend)** | Frozen console installer Phase B — freeze toolchain choice (PyInstaller / Nuitka / briefcase), Authenticode signing, installer (Inno/MSIX), CI build+sign leg, PySide6-LGPL-for-a-frozen-binary compliance | #39 | **Amend existing (Accepted)** — add the Phase-B decision section; ratified before L2 builds |
| **0050** | Single project-root config anchoring — one root for `--config` + `environments/` + `messagefoundry.toml`/DB; extend `--project-root`/`--env`/`--service-config` to `validate`/`graph`/`dryrun`/`check`; fixes the NSSM non-repo-CWD silent miss | #33 (A) | **NEW** — Proposed → ratified before L4's A slice builds (B/C/D/E need no ADR) |
| **0049** | Turnkey DR — scheduled config-bundle + **SQLite-store** backup + restore-verify; **server-DB backup explicitly DBA-delegated** (declined for the engine); cadence/retention/restore-verify posture owner-set | #60 | **NEW** — Proposed → ratified + posture set before L5 builds |
| **0048** | Third-tier DR standby — per-connection priority tier + DR run-profile (`status:"filtered"`) + acquire-VIP-or-abort fencing + cold-seed-from-#60 / warm-from-DB-replica + drain-then-hand-back fail-back | #61 | **EXISTS (Proposed)** → finalize, add **EARS** acceptance criteria, **Accept**; posture set before L6 builds |

**No ADR:** **#40** (CI infra — a `docs/` self-hosted-runner **security note** instead) · **#52** (roadmap
synthesis — an owner decision that **promotes** gap rows into numbered BACKLOG items; no decision record of
its own).

---

## H. Owner / hardware-gated callout (decisions that gate their lanes — not agent-buildable on ADR-Accept alone)

- **#40 (L3)** — **hardware-gated:** owner provisions + isolates the self-hosted Win Server 2025 + SQL Server
  2025 runner and reviews its exposure before the leg can run. The lane's CI wiring can be authored against a
  not-yet-online runner, but it is not "done" until the box is up.
- **#60 (L5)** — **owner-gated:** backup **cadence**, **retention**, and **restore-verify posture** (and the
  backup target / encryption) before build. ADR 0049 presents the options.
- **#61 (L6)** — **owner-gated:** the DR **posture** — warm (DB-replica) vs cold (#60 backups), activation
  trigger (manual runbook vs `/healthz` auto-probe), the **feed-priority tiers**, and fail-back behavior.
  ADR 0048 presents these for ratification.
- **#52 (Lane 0)** — **owner decision:** which NEW Corepoint-gap rows to **promote** into the scheduled
  backlog (vs leave as demand-gated). The synthesis is agent-prepared; the promotion is the owner's call.

---

## I. BACKLOG / ADR-index / FEATURE-MAP reconciliation — DONE (this PR)

Unlike PLAN-5 (which carried reconciliation as a §I lane), PLAN-6 needs none: the **first commit of this
same PR** already reconciled the stale doc state against the CHANGELOG + code —

- **`docs/BACKLOG.md`** — flipped the per-item banners for the items that shipped in `0.2.3` / `0.2.9` /
  `0.2.10` but still read open (#7, #16, #23, #30, #31, #32, #34, #46, #47, #49, #50, #53, #54, #55),
  de-duplicated #39, reframed "Next up" to post-`0.2.10`, and refreshed the Value-analysis rows.
- **`docs/adr/README.md`** — 0027 / 0033 / 0041 / 0042 statuses Proposed → Accepted (built).
- **`docs/FEATURE-MAP.md`** — #2 (off-thread polling) + #6 (IDE test harness) markers → done.

So PLAN-6's board (§A) is already verified against an accurate BACKLOG. The remaining residual is purely
forward-looking: the **#52 synthesis** (Lane 0) will add the agreed Corepoint-gap rows as **new** numbered
items the owner chooses to schedule.
