[← Master Test Plan index](../MASTER-TEST-PLAN.md) · *Part III — Execution, phasing & sign-off*

---

## Part III — Execution, phasing & sign-off

Part II is 17 chapters and **1,186 matrix rows** — 1,087 class **T**, 95 class **C**, 4 class **A**.
Thirty-nine of the T rows are **pointer rows** (Method `—`): they name another chapter's owner row and
scope no separate effort, so the executable body of the plan is **1,147 rows**. Nobody executes 1,147
rows by reading them in order. Part III is how the plan actually gets run by the team that exists:
**one to two engineers with heavy AI assistance, not a QA department.** It sequences the work by risk
retired per unit of effort, pulls everything with procurement or lab lead time to the front so it is
never the critical path, states the cadence that keeps the per-commit gate usable, and defines a
countable go/no-go.

Three conventions before anything else, because mixing them is the single easiest way to corrupt this
plan:

- **Phase IDs here are `E0`–`E7`** (*execution*). [`docs/testing/FEATURE-COVERAGE-PLAN.md`](../FEATURE-COVERAGE-PLAN.md)
  already owns `P0`–`P7` for its own phase roadmap and `FCP:CRIT-n`/`FCP:STORE-n`/`FCP:PIPE-14`-style
  **gap** IDs in a *different* ID space from this plan's row IDs. Never write "P2" meaning a phase of
  this plan, and never assume `STORE-10` means the same row in both documents — it does not.
- **Foreign IDs are always prefixed** (plan-wide, applies to every chapter). A FEATURE-COVERAGE-PLAN
  gap ID is written `FCP:HA-20`; a WIN2025 test or matrix ID is written `W25:S6.3` / `W25:D3`. **A
  bare `HA-20` always means this plan's own row.** The ID spaces genuinely collide — `HA-20`, `API-13`
  and `STORE-10` each exist in both spaces meaning different things — so an unprefixed foreign ID is a
  defect, not a shorthand.
- **Row IDs are the chapter prefixes reported in Part II and nothing else.** No ID appears in Part III
  that a chapter did not report. Where a whole block is meant, it is written as a range that the
  chapter actually emitted (e.g. `PARSE-01..11`).

### Aggregate scale (the number the phasing has to absorb)

Rows are broken out by **row class** (the plan-wide `Cls` column): **T** = *Test*, a falsifiable
assertion with an observable pass criterion — **only T rows count toward the release gate**; **C** =
*Characterisation*, a recorded measurement, finding or dated decision with no threshold yet, which
**cannot fail and therefore never gates a release**; **A** = *Assurance*, an external engagement
(penetration test, third-party review, DAST), blocking **only for an off-loopback / production-exposure
release** and excluded from the ordinary P0 count.

Two further columns matter to the arithmetic. **Ptr** counts **pointer rows** — T rows whose Method is
`—` because another chapter owns the deliverable; they go green when their owner does and carry no
separate effort. And the P0 count is split: **P0 (block)** is the per-release countable gate — class-T
P0 rows executable in an environment that exists or that this plan builds — while **P0 (camp)** is
class-T P0 work that cannot run until a lab is procured (§21.1, tier 2).

Every figure below was derived by parsing the chapter matrices themselves, not by reading any chapter's
prose. Where the two disagreed, the table won.

| § | Chapter | Prefix | Rows | T | C | A | Ptr | P0 (block) | P0 (camp) | OQ |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | Pipeline & Reliability Core | `PIPE` | 59 | 53 | 6 | 0 | 4 | 13 | 0 | 12 |
| 2 | Message Store, Backends & Data Lifecycle | `STORE` | 73 | 66 | 7 | 0 | 9 | 11 | 0 | 15 |
| 3 | High Availability, Failover & DR | `HA` | 63 | 56 | 7 | 0 | 2 | 10 | 1 | 13 |
| 4 | Connections & Transports | `CONN` | 67 | 63 | 4 | 0 | 4 | 9 | 0 | 12 |
| 5 | Parsing, Codecs, Validation & Message Data | `PARSE` | 64 | 60 | 4 | 0 | 0 | 10 | 0 | 14 |
| 6 | Configuration, Wiring & CLI | `CFG` | 60 | 56 | 4 | 0 | 2 | 11 | 0 | 12 |
| 7 | Publishing & Promotion | `PUB` | 70 | 63 | 7 | 0 | 1 | 11 | 1 | 16 |
| 8 | Engine HTTP/WebSocket API | `API` | 73 | 66 | 6 | 1 | 3 | 7 | 0 | 12 |
| 9 | Authentication, RBAC & AD | `AUTH` | 65 | 59 | 6 | 0 | 0 | 9 | 7 | 13 |
| 10 | Web Console (`/ui`) | `WEB` | 72 | 69 | 3 | 0 | 3 | 16 | 0 | 14 |
| 11 | VS Code IDE Extension | `IDE` | 71 | 65 | 6 | 0 | 1 | 17 | 0 | 14 |
| 12 | Steps Editor | `STEPS` | 80 | 78 | 2 | 0 | 0 | 12 | 0 | 13 |
| 13 | Windows Tray, Service & Packaging | `TRAY` | 78 | 72 | 6 | 0 | 0 | 12 | 0 | 14 |
| 14 | Alerting & Observability | `ALERT` | 68 | 64 | 4 | 0 | 1 | 12 | 0 | 13 |
| 15 | Security Posture, PHI & Supply Chain | `SEC` | 79 | 66 | 10 | 3 | 2 | 8 | 0 | 14 |
| 16 | Performance, Throughput & Capacity | `PERF` | 66 | 60 | 6 | 0 | 3 | 15 | 0 | 12 |
| 17 | Interoperability, Migration, Upgrade & UAT | `MIG` | 78 | 71 | 7 | 0 | 4 | 13 | 0 | 12 |
| — | **Total** | — | **1,186** | **1,087** | **95** | **4** | **39** | **196** | **9** | **225** |

**The gate number is 196, not 205.** 211 rows across the plan carry a P0 marking. They decompose
exactly once, with no row counted twice:

| P0 rows by tier | Count | Which |
|---|---|---|
| **Blocking** — class T, environment exists or this plan builds it | **196** | the `P0 (block)` column |
| **Campaign** — class T, P0, but needs a lab that does not exist | **9** | `AUTH-08`, `AUTH-11`, `AUTH-12`, `AUTH-17`, `AUTH-19`, `AUTH-20`, `AUTH-28` (AD lab); `HA-52` (VIP / machine-boundary failover, carried in its chapter as `P0 (campaign)`); `PUB-11` (the two-engine publishing rig) |
| **Characterisation at P0** — class C, cannot pass or fail | **3** | `AUTH-10`, `AUTH-18`, `PERF-14` |
| **Assurance at P0** — class A, exposure-only | **3** | `SEC-64`, `SEC-65`, `SEC-66` (carried as `P0 (exposure)`) |
| **Total P0-marked rows** | **211** | 196 + 9 + 3 + 3 |

Two refinements on the 196. **Seven of them are pointer rows** — `PIPE-35`, `PIPE-39`, `STORE-44`,
`STORE-46`, `CONN-37`, `PERF-07`, `PERF-09` — which go green with their owner row and scope no separate
work, so the distinct P0 build is **189 rows**. And 196 is **16.5% of the plan**, not the 17% the
earlier draft claimed off an inflated count.

The 95 **C** rows and 4 **A** rows are real, funded work — they are simply not gate conditions. A
chapter that quietly re-classes a C row to T without recording its threshold has moved the gate, which
§22 treats as a reportable change; the converse (re-classing a T row to C to dodge a red) is the same
offence in the other direction. The phasing below is built so that **E1 alone retires the largest share
of *silent* regression risk in the whole document** — because E1 does not write new assertions at all,
it makes the ones that already exist execute.

**One inherited discrepancy, recorded not fixed.** §3 (`HA`) states in its own preamble that it has
"10 P0 rows among the T rows" and carries `HA-52` separately as a campaign gate; the previous version
of the table above folded `HA-52` into an `HA` P0 count of 11 and so reported a 205 total that mixed
the two tiers. The table above adopts the chapter's split. No chapter's prose disagrees with its own
matrix on rows, T/C/A or P0; the only other presentation drift is cosmetic — `TRAY` bolds four of its
Pri cells (`**P0**` for `TRAY-19`, `TRAY-20`, `TRAY-22`, `TRAY-27`) and `SEC` writes `P0 (exposure)` —
both parse correctly and neither changes a count.

---

## 18. Phasing

### 18.1 The ordering rule

Phases are ordered by **risk retired per unit of effort**, with two overrides:

1. **Procurement and lab lead time is pulled to E0**, whatever its risk ranking. A lab that is
   ordered in month four makes month four the critical path; a lab ordered in week one costs nothing
   but a purchase order. Nothing in E0 requires the lab to *exist* — only for it to be *started*.
2. **A decision that blocks a P0 row's content outranks the row.** 225 open questions were reported
   across Part II, and Part II is explicit that many of them block the *assertion text*, not merely
   the scheduling — you cannot write `PIPE-08`'s assertion before the owner rules on bounded
   dead-letter vs bounded STOP, and you cannot write `PARSE-01`'s before the owner rules on parity
   vs correctness for blank segments. Those decisions are E0 work, not E2 work.

### 18.2 Phase summary

| Phase | Theme | Entry | Exit (headline) | Rough effort |
|---|---|---|---|---|
| **E0** | Decisions + procurement kickoff | Part II accepted | Every P0-blocking open question answered; every long-lead item ordered | ~1 week owner time, ≈0 engineering |
| **E1** | Make the existing gates honest | E0 CI-budget rulings | No `MEFOR_TEST_*`-gated suite unnamed by a workflow; `ci-gate` cannot pass by skipping | 3–4 engineer-weeks |
| **E2** | P0 correctness & count-and-log | E1 + the E0 rulings on PIPE/PARSE/CONN semantics | Every clinical-safety P0 has a red-then-green assertion with a falsifier | 5–7 engineer-weeks |
| **E3** | Contracts, security & auth (lab-free half) | E1 | Wire contracts pinned; the containerised directory acceptor runs; attestation is not blind | 6–8 engineer-weeks |
| **E4** | Operator & authoring surfaces | E0 rulings on the browser leg and Windows PR minutes | `app.js` executes; the Steps/IDE cross-language contracts are pinned; the tray's shipped launch path is tested | 8–10 engineer-weeks |
| **E5** | Boxes & labs | Labs delivered from E0 procurement | Real-directory, two-box HA, promotion-pipeline and vintage/upgrade rows executed | 5–7 engineer-weeks + lab calendar |
| **E6** | Performance & capacity campaigns | E1 (engine-shard suites in CI) + E5 (hosts) | The filling term exists on every path that publishes a number; the retracted claims are retracted | 4–6 engineer-weeks of campaign time |
| **E7** | Detectability, UAT & external assurance | E2–E6 fault-injection helpers landed | Detectability sweep run; UAT signed; the standing risk acceptances re-confirmed or retired | 3–4 engineer-weeks + vendor calendar |

**Total ≈ 34–46 engineer-weeks.** That is a re-derivation, not the earlier figure: the previous estimate
read "38–48" while its own phase column summed to 36–48, and it was sized against a row count that
double-counted work now owned by a single chapter. Three corrections bring it down:

- **39 pointer rows carry no effort.** They are duplicate coverage claims that became references to an
  owner row. The concentration is in `STORE` (9), `PIPE` (4), `CONN` (4) and `MIG` (4) — which is why
  **E2 drops to 5–7** and **E5 to 5–7**. No coverage was removed; the same assertion is now written and
  paid for once.
- **95 C rows and 4 A rows are not assertion-building.** A C row's deliverable is a recorded number,
  finding or dated decision, and the four A rows are vendor calendar, not engineering. They stay in the
  phase content; they do not scale like test authoring.
- **9 campaign P0 rows are lab-calendar work**, already inside E5's "+ lab calendar" and not inside the
  engineer-week total.

For one engineer with heavy AI assistance that is roughly eight to eleven months; for two, four and a
half to six. The plan is deliberately not all-or-nothing: E1 is standalone and valuable on its own, and
§24 exists for a team that can only do a fraction.

### 18.3 E0 — Decisions & procurement kickoff

**Goal.** Remove the two things that cannot be parallelised later: unanswered owner questions and
unordered hardware.

**Entry.** Part II accepted as the working plan.

**Content.**

- Answer the open questions Part II flagged as blocking **P0 row content** (not merely scheduling).
  The load-bearing set, by chapter: `PIPE` OQ-3 (terminal shape for `PIPE-08`/`PIPE-09`);
  `STORE` OQ-1/OQ-3/OQ-5/OQ-6; `HA` #1/#3/#4/#5/#6; `CONN` Q1/Q2/Q4/Q7/Q10; `PARSE` OQ1/OQ2/OQ4/OQ6;
  `CFG` Q1/Q3/Q4/Q5/Q9; `PUB` (the eight decision-gated rows `PUB-02`, `PUB-05`, `PUB-06`, `PUB-10`,
  `PUB-47`, `PUB-58`, `PUB-59`, `PUB-65`); `API` Q1/Q3/Q6/Q10; `AUTH` Q1/Q3/Q5/Q8; `WEB` Q1/Q2/Q3/Q4/Q5/Q8;
  `IDE` (required-check status, VS Code version pin, publish bar); `STEPS` Q1/Q3/Q4; `TRAY` Q1/Q3/Q5/Q6;
  `ALERT` (the six that block P0 rows); `SEC` (FCP extend-or-freeze, external-assurance trigger);
  `PERF` Q1/Q4/Q7; `MIG` Q4/Q5/Q6/Q7.
- **Budget rulings** that shape every later CI decision: Windows minutes per PR (`TRAY` Q3),
  server-DB CI runtime (`STORE` OQ-3, `API` Q3), whether a headless-browser leg is accepted
  (`WEB` Q3 — blocks 18 rows), whether a containerised LDAP leg is accepted (`AUTH` Q5 — blocks five
  rows, four of them P0).
- **Raise every procurement item now** (see §18.10). None of them blocks E1–E4.
- **Fix the doc defects that later criteria would otherwise cite** — Part II found a large set of
  shipped documents making claims nothing backs. `CFG` Q9 states this explicitly as a precondition:
  stale `FEATURE-MAP` §10/§12, the ADR 0007 header and the ADR 0036 links must be corrected *before*
  the master plan cites them.

**Exit (countable).**

1. Every open question tagged in Part II as gating a **P0** row has a written, dated owner answer.
2. Purchase orders / build tickets exist for: AD lab, second HA host, the **two-engine publishing
   rig** (`PUB2` — a non-production *and* a production-like engine, separately administered), and
   (if commissioned) the external assurance engagement.
2a. The **AD-lab runbook is released to the named lab builder**. `docs/security/AD-FEDERATION-LAB-RUNBOOK.md`
   is owner-held and withheld from the public repo (`docs/security/` is gitignored, `.gitignore:144`);
   handing it over is a dated E0 action with a named recipient, and it gates the lab build (§18.10).
3. The four budget rulings above are recorded, each as "accepted / declined / deferred with a date".
4. The doc-defect list is triaged into fix-now vs pin-with-a-test.

**Effort.** ~1 week of owner time. Near-zero engineering. **Do not let this phase slip** — it is the
only phase whose delay directly delays every other phase.

### 18.4 E1 — Make the existing gates honest

**Goal.** Every suite that already exists actually executes, and a red leg can actually block. This
is the cheapest risk retirement in the plan because the tests are already written.

**Entry.** E0's CI-runtime and Windows-minutes rulings.

**Content (by chapter).**

| Work | Rows | Why it is first |
|---|---|---|
| Six `MEFOR_TEST_*`-gated pipeline suites (36 tests) execute in no CI leg; add the meta-test that fails when a gated file is unnamed by any workflow | `PIPE-01`, `PIPE-02`, `PIPE-03` | 36 written tests currently protect nothing |
| Extend the `serverdb` path-gate alternation so it lists every file the SQL Server / PostgreSQL steps run (its own comment says it must) | `PIPE-01`..`PIPE-03`, `STORE-01`..`STORE-04` | The gate silently under-selects today |
| Per-connection purge `CASE` onto PostgreSQL + SQL Server | `STORE-01`..`STORE-04` | Zero occurrences on either server suite |
| Never-run live cluster/DR suites wired into a leg | `HA-01`, `HA-02`, `HA-48` (the `HA-56`/`STORE-44`/`STORE-46` pointers resolve with them) | Six live server-DB DR/backup files run nowhere |
| `config-gate` leg + frozen `messagefoundry check` roster | `CFG-01`..`CFG-05` | No workflow invokes `messagefoundry check` at all |
| API executed on server DBs | `API-09`..`API-13` | `create_app` appears in zero server-DB-gated test |
| Engine-shard suites in CI | `PERF-06`..`PERF-10` | No workflow contains the word "shard" |
| Liveness guards for the seven blocking `security.yml` jobs + an advisory-job register | `SEC-02`, `SEC-03`, `SEC-05`, `SEC-72` | The pattern exists for `freethread-smoke.yml`; it was never extended |
| `ide` into `ci-gate`'s `needs:`; widen the `ide` path filter beyond `ide/**` | `IDE-34`, `STEPS-13`, `STEPS-14` | A pure-Python rename breaks the IDE with both suites green |
| Re-gate `windows-service-smoke` path-wise per PR (today `(schedule \|\| workflow_dispatch)` only) | `TRAY-01` | The privileged install path merges ungated |
| ALERT vocabulary binding guard as a CI invariant | `ALERT-01`, `ALERT-02`, `ALERT-03`, `ALERT-07` | Drift has already fired twice |
| Coverage-ownership guard for the post-2026-07-14 security wave | `SEC-01` | Zero FCP references to ADRs 0135, 0138–0153 |

**The non-negotiable E1 discipline: an anti-vacuity receipt per newly wired leg.** Every leg that E1
turns on must be demonstrated red by a deliberately planted defect before it is accepted as green.
`TRAY` §13 makes the point concretely — a grep over empty `icacls` output is exactly how a posture
assertion silently dies. This is the same principle the repo already applies in
`.github/workflows/quality-advisory.yml`'s `liveness` job, whose header records three signals that
reported success for months while measuring nothing.

**Exit (countable).**

1. The `PIPE-03` meta-test is green: **zero** `MEFOR_TEST_*`-gated suite files are unnamed by any
   workflow or script.
2. `ci-gate`'s `needs:` covers every leg that can go red under the E0 budget ruling; a skipped leg
   still counts as a pass *only* where the path-gate provably could not have selected it.
3. An anti-vacuity receipt is filed for each newly wired leg (planted defect → red → removed → green),
   with the run ID.
4. `sqlserver-store` and `postgres-store` execute the purge, cluster/DR and API rows above — not
   structurally, but as executed assertions on a live server DB.

**Effort.** 3–4 engineer-weeks. **Risk retired: the largest per unit effort in the plan.**

### 18.5 E2 — P0 correctness & count-and-log

**Goal.** The defects where a clinical message is lost, merged, or mis-dispositioned and nothing
tells anyone.

**Entry.** E1 (a CI that can go red on SQL Server / PostgreSQL) plus the E0 rulings on `PIPE` OQ-3,
`PARSE` OQ1/OQ2 and `CONN` Q1.

**Content.** `CONN-01`..`CONN-05` (the MLLP frame-merge defect — two clinical messages merge and
count-and-log records one received where two arrived); `PARSE-01`..`PARSE-05` and `PARSE-14`
(blank-segment `IndexError` unwinding out of the inbound path before any row is written, before any
ACK); `PARSE-06`..`PARSE-11` (`\X00\` NUL reaching a pre-ACK ingress enqueue, with the gated
PostgreSQL and SQL Server twins); `PIPE-04`..`PIPE-06` (the AE-NAK doc defect, preserving the genuine
pre-ACK strict-inbound `AE`); `PIPE-08`..`PIPE-10` (the poison-crash attempts ceiling on the default
split path, with the subprocess hard-abort harness); `PIPE-12` (the live-runner `committed_txns`
ceiling); `CONN-06`..`CONN-10` (acceptance-matrix false greens, including the `W25:D10` count-and-log cell
that points at a cross-field consistency suite asserting no disposition at all);
`STORE-07`..`STORE-09` (the shipped `mfenc:v2` at-rest writer, essentially untested);
`STORE-13`..`STORE-15` (the PHI serve gate bypassable by ordinary Connection config).

Four of E2's P0 rows — `PIPE-35`, `PIPE-39`, `STORE-44`, `STORE-46` — are **pointer rows**. They are
listed because the phase is not exited while their owner is red, but they scope no separate work and
must not be estimated twice.

**Exit (countable).**

1. Every row above has an assertion that **fails on today's code** and passes after the fix — the
   red baseline is recorded with a run ID, not asserted from memory.
2. Every one of them carries a falsifier in one of the two sanctioned forms (§23.4): an
   inverted-predicate mutation proof or a planted-gate self-test.
3. The count-and-log invariant is executed — not structurally asserted — on all three backends for
   the ingress path.
4. `harness/config/coverage.py`'s AE-NAK line and its five WIN2025 repetitions are corrected **and** a
   test pins the corrected semantic so the doc cannot drift back. The correction alone does not exit
   the phase — see B6.

**Effort.** 5–7 engineer-weeks.

### 18.6 E3 — Contracts, security & auth (the lab-free half)

**Goal.** Pin the machine-readable contracts, close the blind spots in attestation and audit, and get
the *containerised* directory acceptor running — deliberately separated from the AD-lab rows so this
phase never waits on hardware.

**Entry.** E1. Explicitly **not** the AD lab.

**Content.** `API-01`..`API-08` (OpenAPI golden over path/method/status/field+type+required,
`apiclient` parity, IDE TS-mirror drift, tray `/health` key contract); `API-14`..`API-26` (real-wire
framing on a uvicorn subprocess plus the executed tokenless / under-privileged sweep with a planted
gate); `AUTH-01`..`AUTH-05` (the new gated `directory-ldap` container leg driving the real
`LdapAuthenticator`); `AUTH-14`, `AUTH-25`, `AUTH-54` (the NULL-client reject-audit rows — audit blind
on precisely the unauthenticated attack path); `AUTH-37`, `AUTH-55`, `AUTH-63`;
`PUB-01`..`PUB-09` (attestation blind on copy-files + service restart and on the tray Restart; the
fingerprint globs missing the sibling `environments/` layout; a promote that cannot prove what went
live and renders a dual-control hold as success); `PUB-56` (approvers approve blind — the TOCTOU on
the one preventive control); `CFG-11`..`CFG-18` (settings-surface parity: 23 reachable sections vs 28
model fields); `SEC-04` (the customer/PHI leak gate's detector floor); `ALERT-06`/`ALERT-07`/`ALERT-10`
and `ALERT-32`/`ALERT-33` (the permanently-open `connection_started` instance and startup-only
`[alerts]`); `ALERT-08`/`ALERT-09`/`ALERT-58`/`ALERT-67` (the unauthenticated SMTP hop, and forcing
one of the two contradicting documents to be corrected).

**Exit (countable).** The OpenAPI golden is in place with the E0-ruled gating status; the
`directory-ldap` leg executes the real acceptor and is red on a planted regression; every route-level
directory reject audits a non-NULL client; a promote returns the fingerprint that went live and a 202
hold never prints as success; the alert vocabulary guard and the SMTP posture assertion are green.

**Effort.** 6–8 engineer-weeks.

### 18.7 E4 — Operator & authoring surfaces

**Goal.** The three surfaces a human actually touches — web console, IDE/Steps, tray — none of which
has an execution path for its most load-bearing code today.

**Entry.** E0's rulings on the headless-browser leg (`WEB` Q3) and Windows PR minutes (`TRAY` Q3);
E1 for `ide` in the gate.

**Content.** `WEB-01`..`WEB-07`, `WEB-09`, `WEB-10`, `WEB-15`, `WEB-17`..`WEB-22`, `WEB-34` (the P0
set: `app.js` is 1,506 lines carrying the ASVS 14.3.1 watchdog, both WebAuthn ceremonies and the
`redirect:"manual"` PHI guard, and it is never executed; there is no real TLS, proxy or browser
cookie jar anywhere; dual-control dead-ends in the sole operator console); `WEB-56` (the exposure
runbook printed to operators six times that ships nowhere); `STEPS-01`..`STEPS-05` (all seven
committed lens fixtures are stale) and `STEPS-06`..`STEPS-12` (the webview mirror re-implements ten
model functions which, when this phasing was written, were "verified manually" — **that half closed
2026-08-04 with BACKLOG #233**: `ide/src/test/suite/steps-mirror.test.ts` gates all ten on every `ide`
leg, leaving only the STEPS-01..05 fixture half of this P0 group open);
`STEPS-23`..`STEPS-27` (the verbatim `expr` splice that
produces output failing both `ruff format --check` and `ruff check --select F`);
`IDE-09`..`IDE-22` (every credential and PHI path lives in a zero-test shell);
`IDE-41`..`IDE-44` (the delivery vehicle — `vsce package` exists but appears in no workflow);
`IDE-01`, `IDE-17`, `IDE-29`, `IDE-45`, `IDE-47`; `TRAY-02`..`TRAY-08` (the post-install posture
assertions the privileged leg has never made), `TRAY-10`..`TRAY-14`, `TRAY-16`, `TRAY-17`,
`TRAY-19`..`TRAY-23`, `TRAY-27`, `TRAY-70`.

**`TRAY-19`, `TRAY-20`, `TRAY-22` and `TRAY-27` were promoted to P0 in this revision** — the `TrayApp`
state→icon/tooltip map, the action-routing table, the Win32 message-pump dispatch table and the
"lying tray" (a standard user on a hardened box seeing `WEDGED` because TLS discovery failed silently).
Until this revision the tray application itself held **zero** P0 rows while eight sat on the install
scripts. Three of the four are plain `pytest` on `any` and the fourth is `win32`-guarded on `dev-PC`:
no Windows minutes, no lab, no procurement. They are the cheapest P0 rows in the plan and §24 now
front-loads them.

**Exit (countable).** `app.js` executes in CI under the E0-ruled browser posture (or, if the browser
leg was declined, `WEB` Q3's declination is recorded against every one of the 18 rows it blocks and
`FEATURE-COVERAGE-PLAN`'s `FCP:UI-32` accept-by-design is re-confirmed in writing); the lens fixtures are
regenerated and guarded by a key manifest; the tray's shipped launch path resolves all 18 `.ico`
files from `site-packages` and launches under `pythonw` with no `tray crashed` line; the privileged
install leg asserts ObjectName / Start / ACLs with an anti-vacuity receipt.

**Effort.** 8–10 engineer-weeks. This is the largest phase and the one most sensitive to the E0
browser ruling.

### 18.8 E5 — Boxes & labs

**Goal.** Everything that needs hardware someone had to acquire. **This phase's content is fixed at
E0; only its start date depends on delivery.**

**Entry.** The relevant lab exists. Each work item below can start independently as its lab lands —
this phase is a *set of parallel tracks*, not a serial block.

| Track | Needs | Rows | Note |
|---|---|---|---|
| Real directory | AD DS domain: writable DC + DNS + Kerberos SPN + a real OIDC IdP — **plus the owner-held lab runbook released to whoever builds it** (see §18.10) | 27 `AUTH` rows: `AUTH-07`, `AUTH-08`, `AUTH-10`..`AUTH-13`, `AUTH-15`..`AUTH-24`, `AUTH-28`, `AUTH-33`, `AUTH-34`, `AUTH-36`, `AUTH-38`..`AUTH-40`, `AUTH-51`, `AUTH-52`, `AUTH-58`, `AUTH-64` | **7 are campaign-gate P0s** — `AUTH-08`, `AUTH-11`, `AUTH-12`, `AUTH-17`, `AUTH-19`, `AUTH-20`, `AUTH-28`. ADR 0142 status is literally "code COMPLETE, awaiting lab validation". `AUTH-09`, `AUTH-26`, `AUTH-27` and `AUTH-29` are P0 but run on `dev-PC` — do **not** park them here |
| Two-box HA / domain | A second Windows host; optionally an AlwaysOn AG lab and a k8s cluster | `HA-36`..`HA-40`, `HA-51`, `HA-52` | **`HA-52` is the campaign-gate P0** (floating VIP / L4 LB, real-sender reconnect through a VIP move). The DB-restart-under-load drill is already owned manually by **`W25:S4.10`** — build only the automated arm. `HA-03`, `HA-04`, `HA-06`, `HA-22` and `HA-45` were previously parked here in error: they run on `container-CI` / `dev-PC` and belong in E1/E2 |
| Promotion pipeline (the **two-engine publishing rig**) | A non-production **and** a production-like engine, separately administered (`PUB2`) | `PUB-11`, `PUB-46`, `PUB-69` | **`PUB-11` is the campaign-gate P0.** Cross-node fingerprint divergence needs two real nodes, and a promote against localhost cannot exercise the remote `config_dir: null` path. `PUB-10`, `PUB-18`, `PUB-20`, `PUB-21`, `PUB-32`, `PUB-33` and `PUB-53` run on `container-CI` and belong in E3 |
| Host acceptance | The W2025 box | Owned by [`WIN2025-TEST-PLAN`](../WIN2025-TEST-PLAN.md) — **do not restate** | This plan contributes only the automated arms it converts |
| Upgrade & vintage | A store written by a prior engine vintage; both wheels | `MIG-01`, `MIG-02`, `MIG-06`..`MIG-17`, `MIG-47`, `MIG-49` | Console seam bump bricks the whole engine, not just `/ui`. `MIG-18` is a pointer row — no separate work |
| Reconcile PHI fix | none (prerequisite, do in E3/E4) | `MIG-36`, `MIG-37`, `MIG-38` | **Blocking prerequisite for `W25:S3.10`** — the reconcile harness leaks field values by default |
| Real-hardware SQL Server | The existing self-hosted `mefor-win2025-sql` VM | `STORE`, `HA`, `PIPE` server-DB rows re-run on real Windows + real ODBC | No procurement: the runner exists, dispatch-only; just turn the VM on |

**Exit (countable).** Each track's rows executed and stamped, or the track's absence recorded as a
dated deferral naming which rows remain unexecuted. `MIG-36`..`MIG-38` land **before** any reconcile
report is archived anywhere. The three lab tracks carry the plan's **9 campaign-gate P0 rows**; a
release that claims AD/SSO, HA or promotion is blocked on the corresponding track (§21.1, tier 2).

**Effort.** 5–7 engineer-weeks of engineering, spread across the lab calendar.

### 18.9 E6 — Performance & capacity campaigns · E7 — Detectability, UAT & assurance

**E6.** Entry: E1 (engine-shard suites executing) and E5 (a second host for failover-under-load).
Content: `PERF-01`..`PERF-03` (the sustainable-rate verdict has no filling term on the paths that
publish numbers — build the red baseline first, per scenario S-PERF-B); `PERF-11`..`PERF-14` (the
published sizing and scale-out claims are unreproducible with shipped code — the η ≈ 0.85 engine-shard
speedup was measured on per-engine-shard SQLite files four days before ADR 0063 made that topology
fail-closed);
`PERF-47`, `PERF-48`, `PERF-60` (the reference floor enforced nowhere). Exit: every path that
publishes a rate has a filling term; the retraction from `PERF` Q1/Q4 is signed; `benchmark.yml`'s
`set +e` discard of the harness SLO exit code is fixed or documented as deliberate.
**Note the shape of this phase: its first deliverable is a retraction, not a test.** That is an owner
and communications action, and it should not be scheduled as engineering.

**E7.** Entry: the fault-injection helpers from E2–E6 have landed. Content: `ALERT-55` (the
detectability sweep — Part II explicitly schedules it last because it depends on every other
chapter's fault injection); `MIG` UAT and interop rows; `SEC` external assurance if commissioned;
the escaped-defect review (§23.5); mutation-scope rotation review (§23.2). Exit: §21's go/no-go
checklist is answerable.

### 18.10 The dependency chain, stated explicitly

Nothing below is a soft preference; each is a hard "cannot start before".

```
E0 decisions ──┬─> E1 CI honesty ──┬─> E2 P0 correctness ──┐
               │                   ├─> E3 contracts/auth ──┤
               │                   └─> E6 engine-shard perf┤
               ├─> E4 surfaces  (also needs the E0 browser + Windows-minutes rulings)
               │                                            │
E0 procurement ┤                                            │
               ├> AD-lab RUNBOOK released to the builder ──> AD lab exists ──> E5 AUTH
               │  (owner-held: docs/security/AD-FEDERATION-       │            real-directory
               │   LAB-RUNBOOK.md, withheld from the public repo) │            track  ──┐
               │                                                  └──────────> HA-52 VIP arm
               ├> 2nd host exists ───> E5 two-box HA / domain track ──> E6 failover-under-load
               ├> TWO-ENGINE PUBLISHING RIG (PUB2: a non-production engine AND a
               │  production-like engine, separately administered) ──> E5 promotion track
               │                                                        (PUB-11, PUB-46, PUB-69)
               ├> vendor sandboxes / partner lab ──────────> E5 interop, E7 UAT
               └> assurance vendor contracted ─────────────> E7 pentest/DAST (SEC-64..66)
                                                             │
                          E2..E6 fault-injection helpers ────┴─> E7 ALERT-55 detectability sweep

  E5 AUTH track + HA-52 + PUB-11  ──> the 9 campaign-gate P0 rows (§21.1 tier 2)
```

Four chains deserve calling out because getting them wrong wastes a quarter:

- **The AD-lab build has a predecessor of its own: the runbook.** The lab's build procedure lives in
  `docs/security/AD-FEDERATION-LAB-RUNBOOK.md`, which is **withheld from the public repo** —
  `docs/security/` is gitignored post-cutover (`.gitignore:144`) as a deliberate attacker-roadmap
  decision. The document exists and is owner-readable; it is simply not in a public checkout. So the
  first task on this chain is not "write a runbook", it is **release the owner-held runbook to whoever
  builds the lab**, and E0 must name that person. Treating the runbook as absent would restart work
  that is already done.
- **The AD-lab work cannot start before the lab exists** — and the lab is the longest-lead internal
  item. `AUTH-01`..`AUTH-05` were deliberately scoped to a *containerised* LDAP leg precisely so that
  four P0 rows do not sit behind it. Seven P0 rows genuinely need a domain (`AUTH-08`, `AUTH-11`,
  `AUTH-12`, `AUTH-17`, `AUTH-19`, `AUTH-20`, `AUTH-28`); `AUTH-09`, `AUTH-26`, `AUTH-27` and `AUTH-29`
  are P0 on `dev-PC` and must not be parked behind the lab.
- **Two-box HA needs a second host.** `W25:S4.9` already runs two nodes against one shared server
  DB *on one box*; that is not the same test. `HA-03` (the engine-shard × `[cluster]` lease collision)
  is testable without a second host and should not wait for one — nor should `HA-04`, `HA-06`, `HA-22`
  or `HA-45`, all of which run on `container-CI` or `dev-PC`.
- **The two-engine publishing rig (`PUB2`) is a first-class procurement item, not an afterthought.**
  `PUB-11` is a P0 that cannot execute anywhere else: a single engine cannot exhibit cross-node
  fingerprint divergence, and a promote against localhost cannot demonstrate the remote
  `config_dir: null` path. `PUB-46` and `PUB-69` ride the same rig. Order it in E0 alongside the AD lab
  and the second host, or promotion stays unverified through every release that ships a promote button.

---

## 19. Execution matrix — area × environment

### 19.1 Environment register

| Env | What it is | Exists today? | Reached via | Lead time |
|---|---|---|---|---|
| `DEV` | Developer box, SQLite, `pytest -q` (Qt tests need `QT_QPA_PLATFORM=offscreen`) | Yes | local | — |
| `CI-LX` | `ubuntu-latest` hosted runner, the `test` leg (1x minutes, free on this public repo) | Yes | `ci.yml` `test` | — |
| `CI-WIN` | `windows-2022` + `windows-2025` hosted runners, the `test` leg (2x-billed, free here) | Yes | `ci.yml` `test` matrix | — |
| `CI-DB` | SQL Server + PostgreSQL **Linux service containers** | Yes | `ci.yml` `sqlserver-store`, `postgres-store`, `load-test-sqlserver` | — |
| `CI-SVC` | Real NSSM install → serve → MLLP on Server 2022 + 2025 | Yes, but schedule/dispatch-only | `ci.yml` `windows-service-smoke` | re-gating = `TRAY-01` |
| `CI-IDE` | `tsc` + mocha unit + `@vscode/test-electron`, ubuntu + windows-latest | Yes; not required, path-gated to `ide/**` | `ci.yml` `ide` | — |
| `SH-SQL` | Self-hosted `mefor-win2025-sql` VM: **real** SQL Server 2025 on **real** Windows Server 2025 | Yes — `workflow_dispatch` only, VM off by default, never a required check | `selfhosted-win2025-sql.yml` | turn the VM on |
| `W2025` | The acceptance box: Windows Server 2025, all three backends, NSSM service identity | Yes | `WIN2025-TEST-PLAN` / `harness.acceptance` | scheduling only |
| `BROWSER` | Headless-browser leg. **No Playwright / Puppeteer / Selenium exists anywhere in the repo** | **No** | to be built | build decision (`WEB` Q3) |
| `LDAP` | Containerised LDAP driving the real `LdapAuthenticator` | **No** | to be built | build decision (`AUTH` Q5) |
| `ADLAB` | Real AD DS domain: writable DC + DNS + Kerberos SPN + a real OIDC IdP | **No** | procurement, **after** the owner-held runbook (`docs/security/AD-FEDERATION-LAB-RUNBOOK.md`, withheld from the public repo) is released to the builder | **long** |
| `HA2` | Second Windows host; optional AlwaysOn AG lab / k8s cluster | **No** | procurement | **long** |
| `PUB2` | The **two-engine publishing rig**: a non-production engine **and** a production-like engine, separately administered | **No** | procurement | medium |
| `EXT` | Partner lab, vendor sandboxes, external assurance vendor | **No** | procurement / contract | **longest** |

### 19.2 Notation

`x3` = the row set runs once per store backend (SQLite / SQL Server / PostgreSQL) · `x2` = server DBs
only (SQL Server / PostgreSQL) · `1` = once, backend-independent · `M` = manual / human-closed ·
`—` = not applicable · `(new)` = the leg itself is a deliverable of this plan.

### 19.3 CI and developer environments

| Area | `DEV` | `CI-LX` | `CI-WIN` | `CI-DB` | `CI-SVC` | `CI-IDE` | New CI legs this plan adds |
|---|---|---|---|---|---|---|---|
| `PIPE` | x3 | 1 | 1 | x2 | — | — | gated-suite meta-test; `serverdb` alternation fix |
| `STORE` | x3 | 1 | 1 | x2 | — | — | purge/at-rest rows onto the server legs |
| `HA` | 1 | 1 | — | x2 | — | — | cluster/DR suites named by a step |
| `CONN` | x3 | 1 | 1 | x2 | 1 | — | headless partner-fault peer |
| `PARSE` | x3 | 1 | 1 | x2 | — | — | NUL twins on the gated legs |
| `CFG` | 1 | 1 | 1 | — | 1 | — | **`config-gate` (new)** |
| `PUB` | 1 | 1 | 1 | — | 1 | — | promotion rig (partly `PUB2`) |
| `API` | x3 | 1 | 1 | x2 | — | — | server-DB API leg; real-wire uvicorn leg |
| `AUTH` | 1 | 1 | 1 | x2 | — | — | **`directory-ldap` (new)** |
| `WEB` | 1 | 1 | — | — | — | — | **browser leg (new)** |
| `IDE` | — | 1 | 1 | — | — | 1 | `ide` into `ci-gate`; VSIX packaging leg |
| `STEPS` | 1 | 1 | — | — | — | 1 | **`steps-contract` dual-runtime (new)** |
| `TRAY` | 1 | — | 1 | — | 1 | — | Windows **wheel** leg; `TRAY-01` re-gate |
| `ALERT` | x3 | 1 | 1 | x2 | — | — | vocabulary binding guard |
| `SEC` | 1 | 1 | 1 | — | — | 1 | liveness guards on `security.yml` |
| `PERF` | 1 | 1 | — | x2 | — | — | engine-shard suites; filling-term gate |
| `MIG` | x3 | 1 | 1 | x2 | 1 | — | vintage/upgrade legs |

### 19.4 Boxes and labs

| Area | `SH-SQL` | `W2025` | `BROWSER` | `LDAP` | `ADLAB` | `HA2` | `PUB2` | `EXT` |
|---|---|---|---|---|---|---|---|---|
| `PIPE` | 1 | x3 | — | — | 1 | — | — | — |
| `STORE` | 1 | x3 | — | — | — | — | — | — |
| `HA` | 1 | x2 | — | — | 1 | x2 | — | — |
| `CONN` | — | x3 | — | — | 1 | — | — | 1 |
| `PARSE` | 1 | x3 | — | — | — | — | — | — |
| `CFG` | — | 1 | — | — | 1 | — | 1 | — |
| `PUB` | — | 1 | — | — | — | — | 1 | — |
| `API` | 1 | x3 | — | — | — | — | — | 1 |
| `AUTH` | — | M | 1 | 1 | 1 | — | — | — |
| `WEB` | — | M | 1 | — | 1 | — | — | — |
| `IDE` | — | M | — | — | 1 | — | 1 | 1 |
| `STEPS` | — | — | — | — | — | — | — | — |
| `TRAY` | — | M | — | — | 1 | — | — | — |
| `ALERT` | — | x3 | — | — | — | x2 | — | — |
| `SEC` | — | M | 1 | 1 | 1 | — | — | 1 |
| `PERF` | x2 | x3 | — | — | — | x2 | — | — |
| `MIG` | 1 | x3 | — | — | — | — | 1 | 1 |

### 19.5 Read-offs

**What runs on the W2025 box.** `PIPE`, `STORE`, `PARSE`, `API`, `ALERT`, `PERF` and `MIG` at `x3`
(once per backend, under the NSSM service identity); `HA` at `x2`; `CONN` at `x3` for the transports;
`CFG` and `PUB` once; `AUTH`, `WEB`, `IDE`, `TRAY` and `SEC` as manual human-closed rows.
**The box's own acceptance content is owned by [`WIN2025-TEST-PLAN`](../WIN2025-TEST-PLAN.md)
and stamped through [`WIN2025-TEST-MATRIX`](../WIN2025-TEST-MATRIX.md) via
`python -m harness.acceptance` — this plan adds the automated arms and does not re-run `W25:S0.5`'s
"do NOT re-run on the box" list.**

**What needs the AD lab.** 41 rows across nine chapters, concentrated in two: `AUTH` (27 rows) and
`HA` (7 — `HA-36`..`HA-40`, `HA-51`, `HA-52`), plus one row each in `PIPE`, `CONN`, `CFG`, `IDE`,
`TRAY`, `WEB` and `SEC`. **Eight of the 41 are P0** — the seven `AUTH` campaign gates
(`AUTH-08`, `AUTH-11`, `AUTH-12`, `AUTH-17`, `AUTH-19`, `AUTH-20`, `AUTH-28`) and `HA-52` — plus two
class-**C** P0 rows (`AUTH-10`, `AUTH-18`) that record a finding and cannot fail. Everything else in
`AUTH` — including four of its P0 rows — was deliberately scoped to the containerised `LDAP` leg so it
does not wait. **The lab build itself waits on the owner-held runbook, not on writing one** (§18.10).

**What needs a second host.** `HA` two-box rows and `PERF` failover-under-load. `HA-03` (engine-shard
× `[cluster]` lease collision) does **not** — it is reproducible with N `serve --shard` processes over
one unified store on a single box; neither do `HA-04`, `HA-06`, `HA-22` or `HA-45`.

**What needs the two-engine publishing rig.** `PUB-11` (P0, campaign gate), `PUB-46` and `PUB-69` — and
nothing else. Every other `PUB` row, including the other eleven P0s, runs on `container-CI` or
`dev-PC`.

**What needs a real partner or vendor.** `CONN`'s eight `external` rows (`CONN` Q10), `MIG`'s vendor
sandboxes (`MIG` Q7), `API` Q10's pentest/DAST question, and `SEC`'s external assurance.

---

## 20. Regression cadence

### 20.1 The tiers

| Tier | Trigger | What runs | Wall-clock target |
|---|---|---|---|
| **Per-commit** | local `pre-commit` | ledger gate (`scripts/hooks/ledger_check.py`), `ruff format`, `ruff check --fix`, the forbidden-content leak guard (`--require-tokens`, fail-closed), secret scanning | **< 10 s on a normal diff** |
| **Per-PR (required)** | `pull_request` | `test (ubuntu-latest / windows-2022 / windows-2025, py3.14)` — ruff + mypy strict + pytest; `security.yml`'s blocking jobs; the E1-added `config-gate` and (if E0 rules them required) `directory-ldap` / `steps-contract` | within the shipped caps (§20.2) |
| **Per-PR (path-gated)** | `changes` outputs | `sqlserver-store`, `postgres-store`, `docker-smoke`, `ide`, and (after `TRAY-01`) `windows-service-smoke` | gate must select correctly |
| **Per-PR (advisory)** | `pull_request` | `quality-advisory`: `complexity`, `clone`, `coverage` (diff-coverage), `mutation`, `liveness` | ≤ 20–30 min, never blocking |
| **Nightly** | `ci.yml` cron `17 3 * * *`; `quality-advisory` cron `23 4 * * *`; `security.yml` cron `0 6 * * *` | the heavy post-merge legs — `load-test`, `load-test-sqlserver`, `sqlserver-store` ×2 majors, `postgres-store`, `windows-service-smoke` ×2 SKUs, `docker-smoke`; the advisory sweep; the daily CVE re-scan | unbounded (off the PR path) |
| **Nightly (randomized order)** — *new, this plan* | a second nightly `ci.yml` job on the same cron | the ubuntu `test` suite re-run under a **shuffled test order** with the seed printed in the job summary and pinned in the failure report | same as `test` (≈ one extra 1x-billed ubuntu run) |
| **Weekly** | `freethread-smoke.yml` cron `0 6 * * 1`; `selfhosted-win2025-sql.yml` on demand when the VM is up | cp314t readiness tripwire; the real-hardware SQL Server suites | unbounded |
| **Per-release** | `release.yml` (`release`, `release-webconsole`, `release-harness`) + a manual box pass | `messagefoundry verify` per backend, `messagefoundry check --json`, `python -m harness.acceptance` full pass, the `MIG` vintage/upgrade matrix, the `TRAY` wheel leg | a day, planned |
| **Per-campaign** | `workflow_dispatch` | `benchmark.yml` (`baseline-sqlite` / `baseline-postgres` / `baseline-sqlserver`), the load/soak/failover campaigns, the shardcert ladder, `ALERT-55`'s detectability sweep | days, scheduled |

### 20.2 The rule that keeps the fast tiers fast

**A new required per-PR leg must fit inside the caps the repo already ships, or it arrives with a
path-gate, or it is nightly. There is no fourth option.** The shipped caps, from the `test` matrix
that `changes` computes: job timeout 15 min (ubuntu) / 30 min (Windows); pytest **step** timeout
13 / 26 min; per-test `pytest-timeout` 60 s (ubuntu) / 120 s (Windows); faulthandler 90 / 150 s.
Three nested watchdogs (#55) exist so a hang is named in minutes rather than burning the 6-hour
default — a new leg that needs a cap raised is a leg that needs redesigning.

Two corollaries, both already load-bearing in the repo and both easy to break:

- **The docs-only short-circuit must keep working.** `changes.code` is a conservative detector: any
  path outside the docs allowlist runs the full suite. A new required leg that ignores `changes.code`
  turns every documentation PR into a full CI run.
- **`ci-gate` treats a skipped leg as a pass.** That is correct — and it is exactly why the E1
  meta-test (`PIPE-03`) and the `serverdb` alternation fix matter: a leg that skips because its
  path-gate under-selects is indistinguishable from a leg that skips because nothing relevant
  changed. The gate cannot tell; the meta-test can.

### 20.2a The randomized-test-order nightly leg (and why the suite needs one)

The suite runs on **one shared asyncio event loop for its entire session** — `pyproject.toml`
sets both `asyncio_default_test_loop_scope = "session"` and `asyncio_default_fixture_loop_scope =
"session"` (`[tool.pytest.ini_options]`), and `tests/conftest.py` documents the reason: a fresh loop
per test put a function-scoped async fixture's `aiosqlite` connection on one loop while the test ran on
another. The shared loop is the **right** call — it also matches production topology, where the engine
runs on one long-lived `asyncio.run()` loop — but it has a cost that nothing in CI currently measures:

> **One shared loop is one shared mutable object.** A test that leaves a task pending, a callback
> scheduled, a signal handler installed, a `default_executor` swapped, or a lingering transport open
> hands that state to every test after it. Under `pytest`'s fixed collection order the coupling is
> invisible — the suite is green because the tests always run in the same sequence.

Nothing detects this today. There is **no `pytest-randomly` and no `pytest-random-order`** anywhere in
`pyproject.toml`, `requirements.lock` or `.github/workflows/`, so no run has ever perturbed the order.
The failure mode is the one this plan is most concerned with: a suite that is green for a reason other
than the code being correct.

**The leg.** A second nightly ubuntu job runs the same `test` suite with the order shuffled and the
seed printed. Rules, so it stays useful rather than becoming a flake generator:

1. **Advisory, never blocking on the PR path.** It cannot gate a commit — an order-dependent failure is
   a real defect, but diagnosing it is not a merge-blocking activity.
2. **A failure opens a quarantine entry with a named owner and a deadline** (§23.6), and the entry
   records the **seed**, so the order is reproducible on a developer box with one flag.
3. **The seed is printed to `$GITHUB_STEP_SUMMARY` on every run, pass or fail.** A leg that cannot show
   the seed it used did not measure anything — the §23.3 liveness rule applies here as it does
   everywhere else, and this leg records a receipt through `scripts/quality/liveness.py`.
4. **Any fix is a test fix, never a re-ordering.** Pinning an order to keep it green re-hides the
   coupling and is explicitly out of bounds; the fix is the leaked task, fixture or handler.

Cost is one extra 1x-billed ubuntu run per night — the cheapest new leg in the plan, against a hazard
class no other leg can see.

### 20.3 Cadence for the new content

| Chapter block | Cadence | Why |
|---|---|---|
| `PIPE`, `PARSE`, `CONN`, `CFG`, `STEPS` P0 rows | per-PR required | fast, deterministic, clinical-safety |
| `STORE`, `HA`, `API`, `ALERT` server-DB rows | per-PR path-gated + nightly | container startup cost; the gate must name every file |
| `AUTH` `directory-ldap` | per-PR if E0 funds it, else nightly | one container, seconds of runtime, but four P0 rows depend on it |
| `WEB` browser rows | per-PR path-gated on the console package | a browser leg is the single most cost-sensitive addition |
| `TRAY` privileged-install rows | per-PR path-gated on `scripts/service/**` + packaging | 2x-billed Windows minutes; `TRAY` Q3 |
| `PERF` | per-campaign only | never on the PR path — a perf number on a shared runner is noise |
| `MIG` upgrade/vintage | per-release | it is a release property, not a commit property |
| `SEC` external assurance | per-engagement | §21.5 |
| **The whole ubuntu suite, shuffled** | **nightly, advisory** | one session-scoped event loop is shared by every test and fixture; nothing perturbs the order today (§20.2a) |
| The 9 **campaign-gate** P0 rows | per-lab, then per-release *for a release that claims the capability* | they cannot run in CI at all until the AD lab / second host / two-engine publishing rig exists (§21.1, tier 2) |

---

## 21. Release readiness — the go/no-go gate

The gate is **countable**: every item is a number or a yes/no, and every "yes" is backed by a named
artifact. A criterion that can only be satisfied by someone's judgement belongs in the advisory list —
and so does a criterion that can be satisfied by *editing a document*.

### 21.1 The three tiers of the gate

The gate has three tiers because the plan's rows have three classes and two of the classes cannot
carry a per-release release decision. Every P0-marked row lands in exactly one tier.

| Tier | What it is | Count | Blocks what |
|---|---|---|---|
| **1 — Blocking** | class-**T** P0 rows executable in an environment that exists or that this plan builds | **196** rows (7 of them pointers → **189** distinct builds) | **every** release. This is the countable per-release gate |
| **2 — Campaign gates** | class-**T** P0 rows that cannot run until a lab is procured | **9** rows | only a release that **claims the capability**; never counted in the per-release automated total |
| **3 — Assurance** | class-**A** rows: third-party assessment, penetration test, DAST | **4** rows, **3** of them P0 | only an **off-loopback / production-exposure** release; advisory otherwise |

And, standing outside all three: **the 95 class-C rows are tracked but cannot block.** A C row has no
threshold — its deliverable is a recorded number, a written finding or a dated owner decision — so it
can be *incomplete*, but it can never be red. Three C rows carry a P0 marking (`AUTH-10`, `AUTH-18`,
`PERF-14`); they must be **complete** at sign-off, and completeness is a yes/no about whether the
measurement or decision was recorded, not a pass/fail about its content. A C row converts to T — and
enters tier 1 — on the day its threshold or decision is written down, and that conversion is a
reportable change under §22, in both directions.

#### Tier 1 — Blocking (the per-release gate)

| # | Criterion | Count / condition | Source |
|---|---|---|---|
| **B1** | P0 rows resolved | All **196** tier-1 (class **T**) P0 rows PASS, or carry a written, dated owner deferral naming the residual risk. Seven are pointer rows (`PIPE-35`, `PIPE-39`, `STORE-44`, `STORE-46`, `CONN-37`, `PERF-07`, `PERF-09`) and go green with their owner. The 9 tier-2 and 3 tier-3 P0 rows are **not** in this count | every chapter's matrix |
| **B2** | No dead gated suite | `PIPE-03` meta-test green: **0** `MEFOR_TEST_*`-gated suite files unnamed by a workflow or script | `PIPE-01`..`PIPE-03` |
| **B3** | Gates can go red | An anti-vacuity receipt (planted defect → red run ID) on file for **every** leg E1 wired and every new leg E2–E6 added | §18.4 |
| **B4** | Box acceptance | The **`W25:S6.3`** sign-off gate is green in full — `verify` FAIL=0/ERROR=0 across all three backends, `harness.acceptance` no FAIL/no ERROR, all eight `W25:S2` gaps closed-or-documented, per-backend throughput baselines archived, failover invariants + the Windows recovery-time number recorded | `WIN2025-TEST-PLAN` §`W25:S6.3` — cited, not restated |
| **B5** | Measurement liveness | Every liveness receipt across `quality-advisory.yml` and `security.yml` reads `measured` or `not-applicable` **with evidence** — never `failed`. The §20.2a shuffled-order leg files a receipt carrying its seed | `scripts/quality/liveness.py`; `SEC-02`/`SEC-03`/`SEC-05`/`SEC-72` |
| **B6** | Doc drift **pinned by a test** | **Every** enumerated shipped-document defect is pinned by a test that fails if the document drifts back, and each pinning test has an anti-vacuity receipt proving it was red against the pre-fix text. **Correcting the document does not satisfy B6** — see the note below | `PIPE`, `STORE`, `API`, `HA`, `ALERT`, `SEC`, `MIG`, `WEB` |
| **B7** | PHI clean | **0** message bodies, element values or search needles in any report, CI log, artifact or committed file; the leak guard green with its detector floor asserted; `MIG-36`..`MIG-38` landed so the reconcile harness no longer emits field values by default | `SEC-04`, `MIG-36`..`MIG-38`, §22.3 |
| **B8** | Risk acceptances current | All three standing acceptances (§21.5) re-confirmed with a date, or retired | `FEATURE-MAP.md:136`; `docs/SECURITY.md:1692` |
| **B9** | Blocking questions answered | **0** unanswered open questions that a chapter tagged as gating a P0 row | §18.3 register |
| **B10** | Flake quarantine empty | **0** tests in quarantine past their owner's deadline | §23.6 |

**Why B6 was rewritten: a criterion satisfiable by an editorial edit is not a gate.** The previous
wording read "either fixed **or** pinned by a test", which let every doc-drift item close by editing
the document — the cheapest possible action, with no mechanism preventing the next refactor from
re-introducing the same drift, and no way for the criterion to ever go red again. That is the exact
failure §25.3 warns about ("a go/no-go criterion must rest on a test, never on a citation"). B6 now
requires the pinning test, and the editorial correction is the *precondition* for writing it, not a
substitute. The enumerated set is unchanged: the AE-NAK line in `harness/config/coverage.py` and its
five WIN2025 repetitions, `aad_bind` in ADR 0019 vs `settings.py`, the `SECURITY.md` route counts, the
`FEATURE-MAP` §6/§10/§11/§12 rows, the self-inconsistent `FCP:DEPLOY-26`, `PHI.md` row 11 vs
`BACKLOG.md`, `WEBCONSOLE-PACKAGE.md` §2 layer 1, and `verify/checks.py`'s instruction to install a
`[console]` extra that does not exist.

Two scoping notes on B6, both about not manufacturing false drift:

- A `BACKLOG` citation is drift **only at or below the published #231 baseline**. `docs/BACKLOG.md` in
  this repo is a *published baseline* that stops at `## 231.` and says so itself
  (`docs/BACKLOG.md:6041`); numbers **above** it are valid evidence from the fuller ledger, not dangling
  references. A drift-pinning test must therefore bound its check at #231, or it will fail on sound
  citations.
- A document under `docs/security/`, `docs/reviews/` or `docs/marketing/` is **withheld from the public
  repo**, not missing (`.gitignore:144-146`). A pinning test cannot assert on a file it cannot read, and
  its unreadability is never itself a B6 item.

Where a doc-drift item genuinely has no testable surface, it is re-classed **C** in its owning chapter
and tracked to completion — it does not stay in B6 as an editorial to-do wearing a gate's clothes.

#### Tier 2 — Campaign gates (blocking only for a release that claims the capability)

Nine class-T P0 rows depend on an environment that does not exist yet. They are **not** part of the
per-release automated count — a release cannot be held hostage to a purchase order — but they **are**
blocking for any release that advertises the capability they cover. Three chapters contribute.

| # | Campaign gate | Rows | Environment | Blocking for a release that claims… |
|---|---|---|---|---|
| **CG1** | Real-directory authentication | `AUTH-08`, `AUTH-11`, `AUTH-12`, `AUTH-17`, `AUTH-19`, `AUTH-20`, `AUTH-28` (7) | `ADLAB` — AD DS domain: writable DC + DNS + Kerberos SPN + a real OIDC IdP. Predecessor: the owner-held lab runbook released to the builder (§18.10) | AD / LDAP / Kerberos / SSO authentication. ADR 0142 cannot leave "code COMPLETE, awaiting lab validation" until CG1 is green |
| **CG2** | Machine-boundary HA failover | `HA-52` (1) | `HA2` + `ADLAB` — a second Windows host and a floating VIP / L4 LB in front of it | high availability or automatic failover. `W25:S4.9`'s two-nodes-on-one-box run is **not** a substitute |
| **CG3** | Two-engine publishing rig | `PUB-11` (1) | `PUB2` — a non-production **and** a production-like engine, separately administered | promotion between environments. A single engine cannot exhibit cross-node fingerprint divergence, nor the remote `config_dir: null` path |

**How a campaign gate is answered at sign-off.** Each is one of exactly three states, dated and named:
**green** (the campaign ran, rows stamped against a named artifact); **not claimed** (the release notes
do not advertise the capability, and the gap is stated in them — not merely in this plan); or
**deferred** (the capability *is* claimed and the campaign has not run, which requires a written owner
deferral naming the residual clinical or security risk). "The lab is not ready" is not a fourth state;
it is the reason attached to one of the three.

#### Tier 3 — Assurance (blocking only on exposure)

Four class-**A** rows exist, all in `SEC`; three are P0-marked as `P0 (exposure)`.

| # | Assurance gate | Rows | Blocking for |
|---|---|---|---|
| **AS1** | Independent third-party ASVS L2/L3 source review + penetration test of the off-loopback topology | `SEC-64`, `SEC-65` (both `P0 (exposure)`) | any off-loopback bind or production exposure |
| **AS2** | Authenticated DAST against a running engine | `SEC-66` (`P0 (exposure)`) and `API-71` (P1, the same engagement seen from the API chapter) | the same |

**The standing risk acceptance, and the condition that voids it.** The project today carries a signed,
dated (2026-06-12) acceptance that there has been **no third-party assessment, no penetration test and
no DAST** — the ASVS 5.0 L3 work is an explicitly point-in-time, AI-assisted **self-assessment, not a
certification, not an audit, not an independent review** (§21.5, row 1). That acceptance is valid
**only while the engine stays on loopback.** It is **void the moment the default bind posture changes
or the engine is exposed off-loopback or to production traffic** — at which point AS1 and AS2 become
tier-1 blocking and the release cannot ship without them. The mechanism that keeps the acceptance's
precondition true is itself a set of tier-1 rows: the loopback-default and exposure-ladder tests
(`WEB-17`..`WEB-21`, the `API` bind rows). If those go red, the acceptance is not merely stale — its
premise is false.

Advisory otherwise. An assurance engagement that has not been commissioned is reported as
"not commissioned, acceptance current as of `<date>`", never as a red gate on a loopback release.

### 21.2 Advisory (recorded, never blocking)

- Diff-coverage percentage, mutation score, cyclomatic-complexity counts, clone counts. The repo's own
  rubric calls these weak and gameable as single numbers; they surface, they never gate.
- P2 rows across all chapters (**426** of the 1,186), and P1 rows (**549**) except where a chapter has
  named one as an exit criterion for its phase.
- **All 95 class-C rows**, including the three at P0. They are reported as complete / incomplete with
  the recorded number, finding or dated decision attached — never as PASS / FAIL.
- The nightly shuffled-order leg (§20.2a). An order-dependent failure opens a quarantine entry with its
  seed; it does not hold a release.
- Performance numbers that are not a declared floor. A *declared* floor — e.g. the TUNING-BASELINE
  "≥ 200 msg/s, ACK p99 ≤ 50 ms, e2e p99 ≤ 5 s" reference performance floor that `PERF-60` found is
  enforced nowhere — becomes blocking the moment it is wired to an assertion, and not before.
- `IDE`/`STEPS` legs, unless E0 promotes them to required.

### 21.3 What "SKIP" and "MANUAL" mean at the gate

Aligned with the vocabulary the box tooling already uses: **MANUAL and SKIP never fail a run.** But
a SKIP is only acceptable at the gate when the skip is *explained by a path-gate or an absent,
documented environment* — a SKIP caused by a mis-selecting gate is a **B2/B3 failure**, not a skip.
This distinction is the entire reason `PIPE-03` exists.

### 21.4 The blocking-question register

E0 produces it, E7 closes it. Format: one row per question — chapter, question number, the row IDs it
gates, the exit criterion it blocks, owner, answer, date. **225** questions were raised; only the
subset gating P0 rows is blocking (§18.3 enumerates them). The rest are tracked but advisory.

### 21.5 Standing risk acceptances the project already carries

These are pre-existing and must be re-confirmed or retired at every sign-off. **They are not
introduced by this plan; they constrain it.**

| Acceptance | Where recorded | Condition | When it must be re-confirmed or retired |
|---|---|---|---|
| **No third-party assessment, no penetration test, no DAST.** The ASVS 5.0 L3 work is an explicitly point-in-time, AI-assisted **self-assessment — not a certification, not an audit, not an independent review** | `docs/FEATURE-MAP.md:136`, restated in `docs/Secure_Build_Scorecard_MEFOR.md:40`/`:63`/`:113`; the signed, dated (2026-06-12) acceptance itself lives in `docs/security/RELEASE-GATE.md:73-90` | **Void on any off-loopback or production exposure** | At **every** release sign-off, and **immediately** on any change to the default bind posture. The bind guard is the mechanism keeping the acceptance's precondition true — so the loopback-default and exposure-ladder tests (`WEB-17`..`WEB-21`, the `API` bind rows) *are* the control. Retire by commissioning the engagement + DAST (`SEC` §15.5 scenario F; `API` Q10) |
| **ECH (Encrypted Client Hello) for outbound SNI — infeasible** | `docs/SECURITY.md:1692` | documented infeasibility, not a deferral | At each release; retire only if the ecosystem changes |
| **Program controls not yet in place**: recurring vulnerability scans on a ≤6-month cadence, an annual penetration test, and a tested 72-hour DR / backup-restore drill | `docs/PHI.md:1192-1196` | §164.308/§164.310 program controls, not §164.312 code changes | At each release. The DR drill is *partly* addressable by the `HA` DR/backup rows plus `W25:S4.10` — but a **tested 72-hour** drill is an operational exercise this plan does not substitute for |

**A verification caveat that is itself a sign-off item.** `docs/security/RELEASE-GATE.md` is
**withheld from the public repo** — `docs/security/` is gitignored post-cutover (`.gitignore:144`) as
a deliberate attacker-roadmap decision, so the acceptance text at `RELEASE-GATE.md:73-90` **exists and
is owner-readable, but cannot be read from a public checkout**. That is a publishing boundary, not a
missing document, and it is never counted as a coverage defect. Three chapters touch it independently
(`AUTH` Q1, `SEC`, and `WEB-56` — where the real defect is the *dangling operator-facing path*: the
engine prints `docs/security/OFF-LOOPBACK-DEPLOYMENT.md` to operators six times, and that path
resolves in no distributed tree). Confirming from the owner-held copy that the acceptance is still
current, and deciding what an operator is supposed to read instead, is a named go/no-go action, not a
footnote.

---

## 22. Reporting

### 22.1 Artifacts

The per-tool artifact table is already written and correct — see
[`WIN2025-TEST-PLAN` §`W25:S6.1`](../WIN2025-TEST-PLAN.md). **Do not restate it.** It covers
`verify --report-md/--report-json`, `check --json`, `graph --json`, `audit-verify` (which **exits 0
even on FAIL** — its output must be string-parsed), `harness.acceptance --report-md/--report-csv/--xlsx`,
`harness --scenario`, `harness --load --report-json/--report-csv` with `--baseline`/`--tolerance`,
`harness --failover --report-json`, and `harness.reconcile capture`/`compare`.

What Part III adds on top, for the CI-side and campaign-side work this plan creates:

| Artifact | Produced by | Lives |
|---|---|---|
| Per-leg PASS/FAIL/SKIP summary tables | `$GITHUB_STEP_SUMMARY` in each new leg | the run |
| Uploaded raw outputs (e.g. `mutmut-results`) | `actions/upload-artifact` | the run's artifacts |
| **Liveness receipts** — `measured` / `not-applicable` / `failed` + units + evidence | `scripts/quality/liveness.py record` | the run, aggregated by the `liveness` meta-job |
| **Anti-vacuity receipts** — planted defect, red run ID, removal commit | the phase report | the phase report (§22.4) |
| Campaign handbacks — per-cell JSON + CPU/DMV CSVs | the load/bench harness | `docs/benchmarks/results/<date>-<campaign>/` (precedent: `2026-07-12-throughput-c4-c7`) — **metrics only** |
| Box reports | `verify`, `harness.*` | `C:\srv\mefor\reports\…` — **outside any git checkout**, per `W25:S6.1` |

### 22.2 Per-phase deliverables

Each phase produces exactly three things, and no more:

1. **A phase report** — one Markdown file: which rows moved to PASS/FAIL/SKIP/MANUAL, the run IDs, the
   anti-vacuity receipts, the falsifier notes, the open questions the phase answered, and the ones it
   discovered.
2. **The stamped matrices** — the chapter matrices with their `Status` and `Evidence` columns filled
   (§22.4).
3. **The register delta** — which blocking questions closed, which risk acceptances were touched.

### 22.3 The PHI rule for reports (hard)

**Reports carry metrics and metadata only — never message bodies, element values, or search needles.**
This is the same rule `FEATURE-COVERAGE-PLAN` and `WIN2025-TEST-PLAN` already state, and it is
restated here because Part III's artifacts are the ones most likely to be pasted into a ticket.

Concretely:

- `messagefoundry dryrun` and `messagefoundry generate` output is body-bearing. Never redirect it to a
  committed file, a ticket, or a CI log.
- The IDE Test Bench's `--show-phi` path and `tee`'s `--show-diffs` path are body-bearing by
  construction. Same rule.
- **The reconcile harness is body-bearing *by default* today** — `MIG-36`/`MIG-37`/`MIG-38` are
  blocking prerequisites before any reconcile output is archived at all, anywhere, including on the
  box. Until they land, reconcile runs are read on screen and not saved.
- All traffic in every phase is **synthetic and PHI-free** — generated corpora and the anonymized
  harness corpus (ADR 0030). No exceptions, in any environment, including the labs.
- Load reports, captures and generated corpora are **never committed**; the campaign handbacks under
  `docs/benchmarks/results/` are metrics and metadata only, which is why that precedent is safe.

### 22.4 Stamping results back into the matrices

Each chapter matrix gains two columns at execution time: **`Status`** and **`Evidence`**.

- `Status` uses the vocabulary the box tooling already emits: `PASS` / `FAIL` / `SKIP` / `MANUAL` /
  `ERROR`. Using the same five words means a reader never has to translate between this plan and the
  signed `WIN2025-TEST-MATRIX.xlsx`.
- `Evidence` is a **named artifact**: a pytest node ID, a CI run ID + job name, a report path under
  `C:\srv\mefor\reports\…`, or a campaign handback directory. **A row goes green only against a named
  artifact.** "Looks right" is not evidence, and neither is a line-number citation (§25.3).
- The box's 54-row matrix keeps its own native row IDs (A1/B3/F7/G1/H1…) and is stamped by
  `python -m harness.acceptance --xlsx`; this plan's rows keep their chapter prefixes. The two ID
  spaces are crosswalked, never merged.

---

## 23. Coverage & effectiveness measurement — how we know the plan works

A test plan that measures only its own completion measures nothing. Five signals, four of which
already exist in the repo and are extended rather than reinvented.

### 23.1 Coverage — two different numbers, only one of them useful as a target

- **Diff-coverage** (the shipped `coverage` job in `quality-advisory.yml`, PR-only, `--fail-under=0`)
  answers "did the lines this PR changed get executed". It stays advisory, permanently. A whole-repo
  coverage percentage is explicitly rejected as a gate by the project's own rubric, and nothing in
  this plan reintroduces one.
- **Execution coverage of the plan itself** is the number to actually track: *the fraction of the
  **1,147 executable rows** whose method is executing, versus planned* — 1,186 total less the 39
  pointer rows, which execute vicariously through their owner and would otherwise inflate the
  numerator and denominator alike. Report it per chapter, per phase, **split by class**: T rows
  executing, C rows recorded, A rows commissioned. It is the only coverage metric that distinguishes
  "we wrote 1,186 rows" from "1,147 rows run", and the class split is what stops a chapter from
  reporting progress by completing characterisation work while its assertions stay unwritten.

### 23.2 Mutation testing

The shipped `mutation` job runs mutmut 3.6.0 over a deliberately bounded scope —
`messagefoundry/parsing/binary.py` driven by `tests/test_binary_carriage.py` — and measured 461
mutants in about three seconds, so the "one suite run per mutant" cost model does not apply.

**The plan's extension: rotate the bounded scope with the phase.** E2 points it at the parsing and
staged-handoff modules it is hardening; E3 at the auth and API contract modules; E4 at the lens/steps
model. Keep it advisory and keep the scope bounded — the deliverable per phase is a **survivor triage
note in the phase report**, not a score threshold. A survivor is a hint to strengthen an assertion.

### 23.3 Liveness — the anti-vacuity meta-gate

The `liveness` job in `quality-advisory.yml` is the model, and its header records why: three separate
signals reported success for months while measuring nothing (a shallow fetch destroyed diff-cover's
merge base; mutmut 2.5.1 crashed before generating a mutant; the killed count grepped for a line
mutmut never prints). The rule generalises to every gate this plan adds:

> **A gate that cannot prove it measured something is `failed`, not green.**

Every new leg records a receipt via `scripts/quality/liveness.py record` with a status, units, and
evidence. `SEC-02`/`SEC-03`/`SEC-05`/`SEC-72` extend the same pattern to `security.yml`'s seven
blocking jobs, which have no liveness guard today.

### 23.4 Falsifier discipline

The repo already practises this on the performance side — `harness/load/shardcert_ladder.py:538`
names `utilization` as the falsifier for the "lanes do not bind" branch, `harness/load/enginepoll.py:208-212`
refuses to print a baseline it cannot anchor, and ADRs 0069/0098/0107 record levers that were
*killed* by their own falsifiers. Part III makes it a test-plan rule:

- **Every P0 row names the observation that would prove the test vacuous.** Two sanctioned forms,
  both already used in Part II: the **inverted-predicate mutation proof** (`STORE-01`..`STORE-04`) and
  the **planted-gate self-test** (`API-14`..`API-26`).
- **Every performance or capacity claim ships with its falsifier and the measurement that could kill
  it.** `PERF-01`..`PERF-03` exist because a ceiling verdict with no filling term cannot be falsified —
  and the honest response, per `PERF-11`..`PERF-14`, is sometimes a retraction rather than a test.

### 23.5 Escaped-defect tracking

An **escaped defect** is any defect found outside this plan: in review, on the box, by an adopter, or
by a later chapter re-auditing an earlier one. Each gets three things:

1. a row in the owning chapter (append-only, new ID);
2. a regression test that fails on the pre-fix code;
3. a note naming **which of the six coverage dimensions missed it** (functional / security /
   performance / HA / PHI / cross-backend — the dimensions
   [`FEATURE-COVERAGE-PLAN`](../FEATURE-COVERAGE-PLAN.md) already defines).

Track the count per chapter per phase. A chapter whose escape count is rising is a chapter whose
audit was wrong, and it gets re-audited — **not** a chapter that needs more rows.

The precedent is this plan's own construction: **every one of the 17 Part II chapters corrected its
own recon**, several of them materially (a "missing" guard that existed, a "closed" ADR residual that
was open, counts off by three to ten, a whole finding the recon never saw). Recon is not verification.

### 23.6 Flake rate and quarantine

The watchdogs are already tiered — per-test `pytest-timeout` 60 s (ubuntu) / 120 s (Windows),
faulthandler at 90 / 150 s, pytest step caps at 13 / 26 min, job caps at 15 / 30 min. The plan adds
the policy layer:

- A test that fails intermittently is **quarantined with a named owner and a dated deadline** — never
  re-run until green, never `-k`-excluded silently.
- The quarantine list is a **countable go/no-go item** (B10): zero entries past deadline.
- Flake rate is reported per phase as *quarantine entries opened / closed*, not as a percentage —
  with a suite this size a percentage rounds to zero and hides everything.

---

## 24. The first ten things to build

For a team that can only start with a fraction. Ordered, and re-ranked against the corrected tier-1
count: **every item on this list closes tier-1 (blocking) P0 rows only** — nothing here waits on a lab,
and nothing here is a campaign or assurance gate. Items 1–2 are one to two weeks of work and are worth
more than the rest of the list combined, because they convert already-written tests from decoration
into protection.

| # | Build this | Closes (tier-1 P0s) | Why here |
|---|---|---|---|
| 1 | The gated-suite **meta-test** (fails when a `MEFOR_TEST_*`-gated suite file is named by no workflow or script) + the `serverdb` path-gate alternation fix its own comment already demands + **`ci-gate` completeness with anti-vacuity receipts** — every leg that can go red is in `needs:`, `ide` included, and each newly wired leg is proven red once | `PIPE-01`, `PIPE-02`, `PIPE-03`, `TRAY-01`, `IDE-34`, `STEPS-13`, `STEPS-14` | One test file and one regex turn **36 already-written tests** from dormant into executing — the highest ratio in the plan — and the receipt discipline is what makes "green" mean something. Without this half, items 2–10 can all land and still protect nothing. Formerly two items; they are one PR series and were never separable |
| 2 | **`config-gate` CI leg + the frozen `check` roster** | `CFG-01`..`CFG-05` | `messagefoundry check` — the project's own commit/CI gate — is invoked by **no workflow**, and `.pre-commit-config.yaml` owns the pre-commit hook so `.mefor-hooks/pre-commit` never runs. The gate exists and is not wired |
| 3 | **MLLP frame-merge** | `CONN-01`..`CONN-05` | An SB inside an open frame is appended as payload: two clinical messages merge into one, and count-and-log records 1 received where 2 arrived. Silent, clinical, and the reproduction is already pinned |
| 4 | **Blank-segment `IndexError` + `\X00\` NUL in derived values** | `PARSE-01`..`PARSE-10` (`PARSE-11`/`PARSE-14` ride along at P1) | The `IndexError` unwinds out of the inbound path before any row is written: 0 message rows, 0 queue rows, no ACK, socket dropped. The NUL rides a derived value past the ingest guard into a pre-ACK enqueue |
| 5 | **The AE-NAK correction — *and its pinning test*** | `PIPE-04`, `PIPE-05`, `PIPE-06` | Cheap, and today the harness config and five WIN2025 passages teach every operator the wrong ACK semantics under ACK-on-receipt. Preserve the genuine pre-ACK strict-inbound `AE`. Note B6: correcting the six passages does **not** close this — the pinning test does |
| 6 | **The four newly-promoted `TrayApp` P0 rows** — state→icon/tooltip map, action routing, the Win32 message-pump dispatch table, and the "lying tray" (TLS discovery failure rendered as `WEDGED` for a standard user on a hardened box) | `TRAY-19`, `TRAY-20`, `TRAY-22`, `TRAY-27` | **Four P0s for four `pytest` files.** Three run on `any`, one is `win32`-guarded on `dev-PC`: no Windows minutes, no NSSM, no box, no lab. Until this revision the tray application held **zero** P0 rows while eight sat on the install scripts, even though ADR 0113 names the untested Win32/`TrayApp` layer as the design's main risk. Cheapest P0s in the plan — they were absent from this list only because they were absent from P0 |
| 7 | **Per-connection purge on SQL Server + PostgreSQL, and the shipped at-rest writer** | `STORE-01`..`STORE-04`, `STORE-07`..`STORE-09` (+ the `STORE-44`/`STORE-46` pointers) | `connection_cutoffs` appears zero times in either server suite, and the `mfenc:v2` cipher the engine actually builds at startup is essentially untested |
| 8 | **Cluster/DR live suites wired into a leg, *plus the four live failover P0s*** | `HA-01`, `HA-02`, `HA-48`, `HA-03`, **`HA-10`, `HA-11`, `HA-18`, `HA-23`** | Six live server-DB DR/backup files run nowhere; only the SQL Server failover twin runs at all. The four added rows are the **failover behaviour** itself — DB-restart-under-load fence/re-elect/rebind with `acked_not_delivered == 0`, the outage-duration matrix around the fence boundary, SQL Server stranded-in-flight re-pend on promotion, and the live two-node `/cluster/nodes` projection. **All four run on `container-CI` with a service container — none needs a second host**, which is why they belong here and not in E5. (`HA-56` was listed here previously in error: it is a P1 **pointer** to `STORE-45` and closes nothing on its own, though its files reach CI through `HA-02`'s wiring) |
| 9 | **OpenAPI golden + the API executed on server DBs** | `API-01`, `API-02`, `API-03`, `API-09`..`API-12` (the `API-04`..`API-08` and `API-13` blocks ride along at P1) | 121 models behind 105 route objects with only 49 field-name snapshots, and `create_app` appears in **zero** server-DB-gated test. This is the contract the console, `apiclient`, IDE and tray all depend on |
| 10 | **The containerised `directory-ldap` leg** | `AUTH-01`, `AUTH-02`, `AUTH-03`, `AUTH-05` | No procurement, one container. The entire real-directory acceptor path is `pragma: no cover` today; this closes four P0 rows **without waiting for the AD lab** — the seven AD-lab P0s are campaign gate CG1 and are deliberately not on this list |

**Deliberately not in the first ten**, and why:

- **Everything behind a lab** — the seven CG1 AD-lab P0s, `HA-52` (CG2), `PUB-11` (CG3). They are
  blocking for a release that claims the capability, but no amount of engineering starts them before
  E0's procurement lands. Item 10 exists precisely to get four of `AUTH`'s P0s out from behind CG1.
- **The `WEB`/`IDE`/`STEPS` surface block.** Large, and gated on the E0 headless-browser ruling. It
  holds 45 tier-1 P0 rows — the single biggest concentration in the plan — so it is the first thing to
  add when the team grows past two engineers, not the first thing to attempt with one.
- **`PERF`.** Its first deliverable is a **retraction** of a published scaling claim, which is an owner
  and communications action rather than an engineering one.
- **The class-A assurance rows.** Procurement and vendor calendar; advisory until the bind posture
  changes (§21.1 tier 3).

**Suggested grouping.** Items 1–2 as one PR series ("make the gates honest") in weeks 1–2; items 3–6 as
the clinical-safety-and-visibility series (item 6 is the odd one out thematically but is two days of
work and closes four P0s, so it rides along rather than waiting for E4); items 7–10 as the
backend-and-contract series. Each series ends with a phase report (§22.2).

**What this list is worth, counted.** Items 1–10 name **62 distinct tier-1 P0 rows of the 196 — 32%** —
for roughly the first third of the engineering budget, and they do it without a single purchase order.
(Two of the 62 are the `STORE-44` / `STORE-46` pointers, which go green with `HA-02` / `HA-48` in item 8;
they are counted once each as rows, not twice as work.)

---

## 25. Maintenance — how this plan stays true

Part II corrected its own recon 17 times out of 17. That is the maintenance problem in one sentence:
**the facts in this document decay faster than the document gets read.** Four rules keep it honest.

### 25.1 The ADR-ships-with-test-IDs rule

This is not new machinery — it is an extension of what the repo already enforces.
[`docs/adr/TEMPLATE.md`](../../adr/TEMPLATE.md) already requires behavioural acceptance criteria
in EARS form, each linked with `→` to the test or fixture that verifies it, and `messagefoundry
adr-analyze` already checks that each `→` link resolves to a real file.

The extension: **an ADR that lands must also name the master-plan row ID it closes or creates**, and
the chapter matrix must gain that row **in the same commit**. Same discipline, same commit boundary,
as the ledger gate that already blocks an unallocated ADR or BACKLOG number
(`scripts/hooks/ledger_check.py`, wired through `.pre-commit-config.yaml`; see
[`docs/LEDGER-GATE.md`](../../LEDGER-GATE.md)).

Three consequences worth stating plainly:

- A feature that ships with no row is a coverage gap **by construction**, and `SEC-01`'s ownership
  guard is the machine enforcement — it fails today for ADRs 0135 and 0138–0153, which have **zero**
  references in `FEATURE-COVERAGE-PLAN`.
- An ADR whose status is "Proposed — code COMPLETE, awaiting lab validation" (ADR 0142's literal
  status) names the lab row that would flip it. It cannot flip to Accepted on a green unit suite.
- A `→` link that resolves to a file but not to a *test that can fail* is the vacuity case; §23.4's
  falsifier forms apply to ADR acceptance criteria exactly as they apply to plan rows.

### 25.2 Row IDs: allocated, append-only, never renumbered

Row IDs follow the same rule as ADR and BACKLOG numbers, for the same reason — the ledger corruption
that motivated `scripts/coord/alloc.ps1` fired three times because two sessions each grepped for the
next free number, picked the same one, and merged clean.

- **Never grep for the next free row ID.** Allocate within the chapter, and add the row in the same
  commit as the code or ADR that motivated it.
- **Append-only.** A retired row keeps its ID and is marked `RETIRED` with a reason. Renumbering
  breaks every phase report, every stamped matrix, and every ADR `→` link that cited it.
- **One owner per chapter.** The chapter owner answers its open questions and is on the hook when its
  escaped-defect count rises (§23.5).

### 25.3 Citations decay; tests do not

Every chapter in Part II cites file paths and line numbers. Those citations were evidence **at the
time of writing** and several will be wrong within a month.

> **A go/no-go criterion must rest on a test, never on a citation.**

Where a chapter's finding is currently held only by a citation (a doc defect, a stale ADR line, a
`pragma: no cover`), B6 requires it to be converted into a pinning test or fixed. That conversion is
what makes the finding survive the next refactor. A quarterly re-audit re-runs each chapter's recon
and diffs it; the diff, not the original text, is the maintenance signal.

### 25.4 Relationship to the artifacts this plan sits on top of

This is the **umbrella**. The documents below keep their own identity, ID spaces and ownership, and
this plan cites them rather than absorbing them:

| Artifact | Owns | This plan's relationship |
|---|---|---|
| [`FEATURE-COVERAGE-PLAN.md`](../FEATURE-COVERAGE-PLAN.md) | The subsystem coverage-gap audit across six dimensions, phases `P0`–`P7`, gap IDs in its own space | Chapters cite it and re-grade stale rows **in the same commit** as the re-grading. `SEC`'s open question — extend it, or freeze it with this plan as standing owner — must be answered in E0 |
| [`WIN2025-TEST-PLAN.md`](../WIN2025-TEST-PLAN.md) + [`WIN2025-TEST-MATRIX.md`](../WIN2025-TEST-MATRIX.md) + [`WIN2025-ACCEPTANCE.md`](../WIN2025-ACCEPTANCE.md) | Host and service-identity acceptance on the box; the 54-row signed matrix; the `W25:S6.3` sign-off gate | **B4 cites `W25:S6.3` verbatim.** This plan adds only the automated arms and respects `W25:S0.5`'s do-not-re-run list |
| [`VERIFY.md`](../VERIFY.md) | On-box deployment acceptance across the five `verify` sections | Cited as a per-release and per-backend tool; `CFG-40` covers only its untested report writers |
| [`LOAD-TESTING.md`](../../LOAD-TESTING.md) + `harness/load/` | Throughput, connection-scale, failover-under-load, the profiles, GO/NO-GO verdicts and the falsifier practice | `PERF` adds gates and a filling term **around** the rig; it does not reimplement it |
| [`CI-QUALITY.md`](../../CI-QUALITY.md) + [`docs/quality-gates/`](../../quality-gates) | The two-checkpoint story and the advisory-gate build handoff | §23 extends the shipped signals (coverage, mutation, liveness); it does not add a new gate framework |
| [`FEATURE-MAP.md`](../../FEATURE-MAP.md) | The capability status catalog and the published posture claims | B6 pins the drifted rows; B8 re-confirms the risk acceptance it records |

### 25.5 Review cadence for the plan itself

- **Per phase**: the phase report closes rows, opens rows, and records the questions the phase
  discovered. Non-negotiable — a phase without a report has not exited.
- **Per release**: B1–B10 answered; the risk-acceptance table re-dated.
- **Quarterly**: re-audit one to three chapters (rotating), diff against the original recon, and file
  the drift as escaped-plan-defects. Prioritise the chapters with the highest escaped-defect counts
  and the ones whose subsystems changed most.
- **On any change to the default bind posture**: re-confirm the no-pentest/no-DAST acceptance
  immediately, out of cycle. It voids on off-loopback exposure, and the tests that keep its
  precondition true are in `WEB` and `API` — not in a document.
