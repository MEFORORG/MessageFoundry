# 0203 -- The engine repository holds what an install needs, and the test harness moves to its own repository

- **Status:** Proposed. No code moves under this ADR. It is research and a recommendation for the
  owner to rule on. The only owner rulings in it are the two quoted sentences under *Context*.
- **Date:** 2026-10-01
- **Related:** vault BACKLOG #2684 (this ADR); #2672 to #2683 (the harness coverage wave); #1585 and
  #1697 (both closed: the harness's engine pin, and the client import rule);
  [ADR 0201](0201-a-messagefoundry-toolkit-distribution-carries-the-authoring-and-development-tooling-out-of-the-engine-wheel.md)
  (the toolkit distribution); [ADR 0088](0088-apiclient-service-cli-extraction.md) (the client
  library); [ADR 0030](0030-anonymization-test-harness-tee.md) (the tee relay and `anon/`);
  [ADR 0191](0191-coverage-guided-fuzzing-of-the-tolerant-parsers.md) (fuzzing);
  [`CLAUDE.md`](../../CLAUDE.md) sections 0, 4 and 5;
  [`tests/test_dependency_boundaries.py`](../../tests/test_dependency_boundaries.py)

---

## Context

### What the owner said

Two sentences, given on 2026-10-01 in a Manager's chat and relayed in that Manager's brief:

> "also, I think we should move the harness to a separate repo"

> "my thought is that the mefor repo should hold only that which is required for a mefor install."

### The Manager's reading, and where the evidence lands

The Manager read the second sentence as a test and drew two conclusions. It marked both as a
reading. The table says what this ADR found for each.

| The reading | Finding |
|---|---|
| The whole of `harness/` leaves, the load rig included | Holds, on one condition. The engine's merge gate runs the load rig today, so the gate needs decision D below first. |
| Rows #2672 to #2683 are built in the new repository after the move | Holds for #2672 to #2682. It does not hold for #2683, which touches only `fuzz/` and one engine test, and `fuzz/` stays. |

### Every number below names its instrument

Unless a line says otherwise, a number here was read at engine `origin/main` `612689f797` on
2026-10-01 with `git grep` or `git ls-files` in a worktree of this repository. The working clones
are shallow (`git rev-parse --is-shallow-repository` prints `true`), so no number here comes from
history older than the 707 commits the clone can see.

The brief carried readings taken at `2578c72819`. They were re-measured. Where the two differ, the
right-hand column is the one this ADR uses.

| Reading | Brief, at `2578c72819` | Here, at `612689f797` |
|---|---|---|
| `harness` import statements in `tests/`, at column 0 | 228 | 231 |
| The same, counting imports inside function bodies | not taken | 301 |
| Test files importing `harness`, at column 0 | 75 | 76 |
| The same, counting imports inside function bodies | not taken | 82 |
| Workflow files that run or import it | 3 | 3, and that pattern misses most of the gate. See D. |
| Engine modules the harness imports | 13 named | 19, counted by distinct dotted name. See G. |

The column-0 pattern is `^(from|import) harness[a-zA-Z0-9_.]*`. The wider one allows leading
white space. The wider count is the one that matters for a move: an import inside a test body
breaks the same way when the package is gone.

## Decision

**Recommended, for the owner to rule on:** move the whole of `harness/` and its distribution to one
new repository, keep the engine's load, failover and engine-shard certification legs in the
engine's merge gate by running that repository's code at a pinned commit, and move nothing else in
the same step.

The ten sections below each answer one question the row asked. Each gives the evidence and a
recommendation.

### A. The test keeps two things: what a site installs, and what proves it

**What the engine wheel ships.** `pyproject.toml` sets `packages = ["messagefoundry"]` for the
wheel. The sdist is `only-include = ["messagefoundry", "README.md", "CHANGELOG.md", "LICENSE",
"NOTICE"]`. So an installed engine is that one package, and the sdist adds four top-level files.

**Neither literal reading of the sentence works.**

| Reading of "required for a mefor install" | What it removes | Why it fails |
|---|---|---|
| Ships in an installed distribution | `tests/`, `.github/`, `docs/`, all of `scripts/` | The gate that makes an install safe would leave. And one install path needs a file no wheel carries: `messagefoundry service install` finds `scripts/service/install-service.ps1` by walking up from the package to a source checkout (`messagefoundry/service.py`, `install_script_path`). |
| Needed to build, gate and release one | Nothing, for the harness | The gate runs the harness today. This reading keeps it. |

**The test this ADR proposes.** A path stays in the engine repository when either answer is yes.

1. **Does a site need it to install, run or operate an engine?** The package source, its
   packaging, the container build, the service installer, the operator documents.
2. **Is its subject the installed product?** The tests, the workflows, the release pipeline and
   the design records that test, build, release or explain that product.

A path whose subject is something else leaves. That covers a separate tool with its own command
and its own users, and the working method of the sessions that build the product.

**One more rule, and the split rests on it: a tool the gate uses can be used at a pin.** The gate
needs pytest, ruff, hatchling and NSSM, and hosts none of them. Needing a tool is a reason to pin
it. It is no reason to keep its source here.

**Where that leaves the three things an install never carries.** `tests/`, `.github/` and `docs/`
stay under question 2. They are the proof and the explanation of the installed product.

### B. The inventory: the harness leaves now, three more trees fail the test, and the rest stay

File counts are `git ls-files -- <path>`. "Co-change" is the count of commits, in the 707-commit
visible window, that touch the path, and how many of those also touch `messagefoundry/`. It is a
measure of how often a move would turn one change into two.

| Path | Files | Verdict | Reason |
|---|---|---|---|
| `messagefoundry/` | 334 | IN | The engine wheel's one package. It carries at least two measurement hooks that exist for the load rig. See G. |
| `messagefoundry/generators/` | 19 | IN for now | It ships in the engine wheel and backs `messagefoundry generate`. ADR 0201 slice 7 moves it to the toolkit. The harness imports it in 6 statements, and five of them import the private `_core`. |
| `messagefoundry_webconsole/`, `packaging/messagefoundry-webconsole/` | 40, 47 | IN | The operator console a site installs. |
| `messagefoundry_toolkit/`, `packaging/messagefoundry-toolkit/` | 3, 4 | IN, and an owner question | `docs/INSTALL-GUIDE.md` names it for authoring commands. ADR 0201 placed it here two days before this ADR, in lockstep, because it calls engine internals. The owner's sentence may reach it. This ADR does not reopen 0201's layout. It does change slice 7; see I. |
| `harness/`, `packaging/messagefoundry-harness/` | 99, 4 | **OUT, now** | A separate tool with its own command and its own distribution. The engine wheel does not carry it. No tree outside `tests/` imports it (0 files). Co-change: 36, of which 20. |
| `tee/` | 18 | OUT, later | A standalone relay for a parallel-run cutover. Its docstring says it imports nothing from the engine. It vendors `anon/`, which ADR 0201 slices 5 and 6 are moving, so it waits for them. 13 test files import it. Co-change: 6, of which 6. |
| `fuzz/` | 4 | IN | Its subject is the engine's own parsers. One engine test and `scripts/security/dast_ingress_sweep.py` import it. It is a test of the product, like `tests/`. |
| `ide/` | 180 | OUT in principle, not in this move | An authoring extension. A site does not need it to install. Its coupling was only partly measured: 25 test files name `ide/`, and co-change is 28, of which 17. It needs its own decision. |
| `samples/` | 38 | IN | `serve` defaults to `--config samples/config`, and 25 test files name it. It is the worked example the install documents use. |
| `environments/` | 2 | IN | `docs/INSTALL-GUIDE.md` names these files. |
| `scripts/service/` | 6 | IN | The Windows service installer. See A. |
| `scripts/ci/`, `release/`, `security/`, `quality/`, `docs/` | 16, 6, 22, 11, 5 | IN | The gate and the release. Workflows name four of the five. |
| `scripts/asvs/` | 6 | IN | The verifier for the engine's own evidence. Two workflows run it. The record it checks is already elsewhere. |
| `scripts/coord/`, `worktree/`, `hooks/` | 31, 16, 21 | OUT in principle, not in this move | Their subject is the working method, not the product, and korus is their upstream home. Co-change: 64 touches, of which 2. They are also the commit gate, so they leave only by being vendored back from korus. That is its own decision. |
| `scripts/connscale_harvest.py` | 1 | OUT, with the harness | It harvests the harness's connscale readings from this repository's CI artifacts. Four test files import it. One, `tests/test_connscale_harvest.py`, imports nothing from `harness`, so it is outside the 82 in E and must be moved by name. The script imports `messagefoundry.spreadsheet`. |
| `scripts/dev/`, `bench/`, `telemetry/`, `codex/`, `tray/`, and four more top-level scripts | 15 | unmeasured | Not read for this ADR. |
| `docs/` outside the four rows below | 82 | IN | Operator and design documents. |
| `docs/adr/` | 193 | IN | Design records of the product. |
| `docs/benchmarks/` | 216 | IN | The harness produced these records, and the engine's design rests on them: 29 files under `docs/` outside this tree cite it, 19 of them under `docs/adr/`. Moving it breaks that evidence chain and the link check. |
| `docs/roles/` | 7 | OUT in principle, with the coordination scripts | Seat cards. Same reason, same later decision. |
| `docs/backlog-proposals/` | 10 | unmeasured | Not read for this ADR. |
| `docker/` | 12 | IN | The container install. |
| `net-helper/` | 10 | IN | A helper a site installs with `scripts/service/install-net-helper.ps1`. |
| `security/`, `ci/`, `changelog.d/` | 6, 3, 6 | IN | Release records, tool locks and changelog fragments for the shipped artifact. |
| `.github/` | 45 | IN | The gate. |
| `tests/` | 1086 | IN, less the harness's own tests | Question 2. See E for which files leave. |
| `.agents/`, `.claude/`, `.codex/`, `AGENTS.md`, `CLAUDE.md` | 27 | unmeasured against the test | Session configuration for whoever works here. They stay with the repository they configure. |

### C. One new repository now, named for the harness

**Recommendation: one repository, `messagefoundry-harness`, in the same organisation, public, under
the same licence.**

| Name | Recommended value | Why |
|---|---|---|
| Repository | `messagefoundry-harness` | It matches the owner's words and the PyPI name. |
| Distribution | `messagefoundry-harness`, unchanged | PyPI already holds 17 releases of it, the latest 0.5.1 (PyPI JSON API, 2026-10-02 02:48 UTC). |
| Import package | `harness`, unchanged for the move | A move that also renames is two changes. `python -m harness` appears on 108 lines in 47 tracked files. A rename is a later, separate choice. |

**Why one and not one per tool.** Every repository needs its own gates, its own branch protection
and its own coordination install (section H). `tee/` is 18 files. When it leaves, it can enter the
same repository as a second package with its own distribution. A later rename is possible but
not free: the PyPI Trusted Publisher and the engine's pin checkout both name the repository.

**The toolkit is not a candidate for it.** ADR 0201 keeps the toolkit in lockstep with engine
internals and found no stable seam between them.

### D. The engine's gate keeps its load legs by running the harness at a pinned commit

**The three-file reading undercounts.** The pattern `^(from|import) harness|python -m harness`
finds `benchmark.yml`, `ci.yml` and `ingress-rate-probe.yml`. It cannot see a job that reaches the
harness through `pytest`. The table reads each job's non-comment lines.

| Workflow and job | What it does with the harness | Runs on a pull request | Feeds a required context |
|---|---|---|---|
| `ci.yml` `test` | Runs `pytest -m 'not tooling'` over `tests/`, which collects the 80 test files in E. Installs the `harness` extra, which is PySide6. | Yes, on Linux and two Windows legs. | Yes, directly. Its matrix legs are required by name. |
| `ci.yml` `load-test` | `serve --config harness/config/load`, then `python -m harness --load smoke`. Linux only. | No. Queue, nightly and dispatch. | Through `CI gate`. |
| `ci.yml` `load-test-sqlserver` | The same with the `smoke-sqlserver` profile. | No. The same three events. | Through `CI gate`. |
| `ci.yml` `sqlserver-store` | Runs `tests/test_load_failover_sqlserver.py` and `tests/test_shard_cert_sqlserver.py`. | Only when the server-database paths change. Always in the queue. | Through `CI gate`. |
| `ci.yml` `postgres-store` | Runs `tests/test_load_failover_postgres.py` and `tests/test_connscale_postgres.py`. | The same. | Through `CI gate`. |
| `ci.yml` `packaging-build` | Builds the harness wheel and runs the member gate over it. | Only when the packaging paths change. | Through `CI gate`. |
| `ci.yml` `webconsole`, `tooling` | Install the `harness` extra. No harness code was found in their steps. | Yes; `tooling` only when its paths change. | Through `CI gate`. |
| `benchmark.yml`, three `baseline-*` jobs | `python -m harness --load reference` and `--failover failover`. | No. `workflow_dispatch` only. | No. |
| `ingress-rate-probe.yml` `probe` | `python -m harness.load.ingress_probe`. | No. `workflow_dispatch` only. | No. |
| `quality-advisory.yml` `coverage`, `mutation` | Install the `harness` extra. | Not read. | No. Advisory. |
| `release.yml` `release-harness` | Builds, checks and publishes the harness wheel. | No. | No. A release job. |

**The pull-request gate for load is the `test` job, not `load-test`.** `ci.yml` says so in the
comment above `load-test`: the in-process `tests/test_load_runner.py` "is the PR gate". So the
harness tests inside `test` carry more of the gate than the job names suggest.

**How `CI gate` rolls legs up.** It is one job with `if: always()` and a `needs:` list. It fails
when any needed job failed or was cancelled, and a skipped job is not a failure. `CI gate` is a
required context; the live set is in `.github/required-contexts.txt` and in branch protection.

**A name collision to avoid.** The `tooling` job's display name is `repo harness tests`. It runs
the coordination and workflow tests. It is not a test of `harness/`.

**The options.**

| Option | What it costs | What it keeps |
|---|---|---|
| 1. Engine CI checks out the harness repository at a pinned commit and runs it | One pin to move. An engine change that breaks the pinned harness needs a harness change first, so one change becomes two in order (section F). A second repository's code runs in the job that gates merges, so the pin must be a full commit SHA. | Every leg, before merge, against the engine under test. |
| 2. The legs move to the new repository's CI and run against an engine ref on a schedule | The engine's merge gate loses its load, failover-under-load and engine-shard certification legs. A regression is found after it merges. | Nothing in the engine gate. |
| 3. The engine keeps a small in-tree driver | A second sender, sink and no-loss reconcile to maintain. The tree already shows what copies do: `tests/test_harness_reconcile.py` opens by saying its three reconcile copies "NO LONGER SHARE ONE INVARIANT". Failover and engine-shard certification are not small. And it leaves test-rig code in the engine repository. | The SQLite smoke only. |

**Recommendation: option 1.** Option 2 weakens a control, and `CLAUDE.md` section 0 says zero
deployments may never be cited to relax one. Option 3 buys a copy that drifts.

**The shape of option 1.**

- A new file, `ci/harness.pin`, holds one full commit SHA of the harness repository.
- Each job that uses the harness checks that commit out beside the engine and puts it on
  `PYTHONPATH`. It installs nothing from it, so the harness's own engine pin is never resolved
  and no dependency cycle forms. The two load legs install no `harness` extra today, so they need
  no PySide6.
- **Every run keeps the job, the events and the operating systems it has today.** The class 3
  test files in section E move with the harness. Each engine job then runs the same files, by
  path, from the pinned checkout, in a separate `pytest` run started in that checkout. The four
  SQLite ones stay in the `test` job, on every pull request and on all three legs. The four
  database ones stay in their database jobs. The two load legs keep their `python -m harness
  --load` command.
- **A narrower contract is a later step, not this one.** It would be cleaner for the engine to use
  only `python -m harness` and its exit code. The command cannot carry the gate yet.
  `tests/test_shard_cert_sqlserver.py` runs a kill leg and asserts per-lane results that
  `python -m harness shardcert` does not expose. The failover tests use a profile from
  `tests/_failover_load_support.py`. And `benchmark.yml` runs `--failover` under `set +e`, so no
  job gates on that exit code today.

### E. The 82 test files: 62 move as the harness's own, 9 move and stay in the gate, 11 are split

Two helper modules are counted among the 82. Classes were assigned by reading each file's
docstring and its imports.

| Class | Files | Disposition |
|---|---|---|
| 1. Tests of the harness | 61 test files and `tests/_connscale_ports.py` | Move with it. The engine gate stops running them. |
| 2. Engine tests that use the harness | 11 test files | Split first, inside the engine repository. Listed below. |
| 3. Runs that certify the engine through the harness | 8 test files and `tests/_failover_load_support.py` | Move with it. The engine gate keeps running them at the pin (section D). |

**Class 3, by name.** Database-gated: `test_load_failover_postgres.py`,
`test_load_failover_sqlserver.py`, `test_shard_cert_sqlserver.py`, `test_connscale_postgres.py`.
On SQLite, inside the `test` legs: `test_connscale_smoke.py`, `test_multishard_smoke.py`,
`test_load_runner.py` and `test_harness_scenarios.py`, which starts a managed app and asserts the
engine's disposition through the API.

**One class 1 file is a named exception.** `test_harness_monitor.py` also starts a managed app. It
is a Qt panel test, so keeping it in the engine gate would keep PySide6 there. This ADR lets it
leave. Whether the engine's own API tests cover the same ground was not measured.

**Not measured file by file:** which other class 1 files start a real engine. A text search finds
`EngineNode(` or a `run_*` entry point in at least ten more, several of them behind stubs. Step 3
of the migration must read each before it leaves the gate.

**The moved tests need two fixtures from `tests/conftest.py`.** They are session-wide and
automatic: `_allow_insecure_config_source_in_tests` and `_warn_posture_for_the_server_db_legs`.
The database runs open a store under the posture the second one sets. The new repository's own
`conftest.py` must carry both.

**Class 2, by name.** Each is an engine test today. Each has a part that is really a harness test.

| File | What it tests | Proposed disposition |
|---|---|---|
| `test_adr0157_inc0_margin.py` | The cluster fence margin, proved against the harness's failover profile and `_node_env`. | The margin tests stay, on a hand-built settings object. The profile and `_node_env` checks move. |
| `test_bytes_per_message_amplification.py` | The store's body-copy model, welded to the harness report's copies-per-message figure. | The model stays. The report weld moves and reads the engine at the pin. |
| `test_txn_per_message_cost_model.py` | The durable-write cost model, with late imports of the engine-shard bench shape and the report summary. | The same split. |
| `test_live_cost_counters.py` | Live `committed_txns` and `body_copies`, with one test feeding the harness report. | The counter tests stay. That one test moves. |
| `test_claim_phase_timing.py` | Claim phase timing. One test checks the harness's `_PHASE_RE` does not match the new log line. | The engine keeps the log line as a pinned string. The regex test moves. |
| `test_delivery_phase_timing.py` | Delivery phase timing. One test checks `_EPISODE_RE` and the line it must match. | The same. |
| `test_mllp_tcp_nodelay.py` | `TCP_NODELAY` on engine sockets and on the harness sink. | Engine sockets stay. The sink test moves. |
| `test_monitoring_reason_reveal.py` | API reason masking. Two tests import `harness.load.multishard`. | Those two move. The rest stay. |
| `test_csv_formula_consistency.py` | One formula-injection rule across every writer, engine and harness. | Engine writers stay. Harness writers move, with a test that compares `harness/_spreadsheet.py` to the pinned engine's `spreadsheet.py`. |
| `test_console_streams.py` | The engine's console hardening, proved by driving the `harness.reconcile` command. | Stay, driving an engine command instead. The harness keeps its own copy for its command. |
| `test_anon_integration.py` | `anon/`, the tee subcommand and the harness capture sink. | Follows ADR 0201 slices 5 and 6. The capture-sink and corpus parts move. |

**Three more files name the harness by path and import nothing from it.**

| File | What it loads | Proposed disposition |
|---|---|---|
| `test_harness_config.py` | The `harness/config` coverage graph. | Moves. |
| `test_passthrough_graph.py` | `harness/config/passthrough`. | Moves with its graph. The graph imports `harness.config.load._shape`, and `tests/test_load_config.py` pairs it with a harness load profile, so it cannot become an engine fixture as it stands. `docs/CONNECTIONS.md` links to it as a runnable example and needs a new target. |
| `test_store_once_graph.py` | `harness/config/store_once`. | Moves, for the same two reasons. |

**Not measured:** whether the engine has equal tests of pass-through re-ingress and of
store-once delivery elsewhere. Step 3 must check before those two files leave.

**The engine's own gates walk the harness tree.** At least 32 test files name `harness/`, a quoted
`"harness"` or the distribution name without importing it, and 29 of those do so outside a comment
line. They include `test_dependency_boundaries.py`, `test_packaging.py`,
`test_release_member_gate.py`, `test_cp1252_console_safety.py`, `test_security_static.py` and
`test_lint_scope_parity.py`. Each needs an edit in the pull request that removes the tree, because
several refuse a walk target that is not there.

### F. The harness depends on the engine, and each side pins a commit the other has already passed

**Direction.** The harness imports the engine. The engine imports nothing from the harness. That
does not change.

| Repository | What it pins | What its required CI runs |
|---|---|---|
| Harness | `ENGINE_REF`, a file naming one engine commit. Its package metadata keeps an exact engine version, as #1585 set. | Its own tests, and the class 3 runs, against the engine at `ENGINE_REF`. |
| Engine | `ci/harness.pin`, one harness commit. | The load, failover and engine-shard legs, from that commit, against the engine under test. |

**Why no cycle blocks a merge.** Each pin names a commit that exists and has passed its own gate.
No required leg in either repository reads the other's `main`. Moving a pin is an ordinary pull
request in one repository.

**An engine change that breaks the harness takes three steps.**

1. Harness pull request: accept both the old and the new engine behaviour. Its CI passes against
   the old `ENGINE_REF`. Merge it.
2. Engine pull request: make the change and move `ci/harness.pin` to the step 1 commit.
3. Harness pull request: move `ENGINE_REF` to the step 2 commit and drop the old behaviour.

**What that costs here.** A Builder gets one turn in one worktree of one repository. So steps 1 and
2 are two briefs, in order, with a merge between them. Today they are one pull request.

**How often.** In the 707 visible commits, 2026-09-16 to 2026-10-02, 36 touch `harness/` and 20 of
those also touch `messagefoundry/`. That is the upper bound for this window, since some of the 20
are repository-wide sweeps that would not have broken a leg. It is not a small number.

**Releases stop being lockstep.** The harness takes its own version line. An engine release goes
first. A harness pull request then moves `ENGINE_REF` and the metadata pin, and a harness release
follows. Between the two, the newest harness on PyPI names the previous engine, and installing
both newest versions fails at resolution. That is loud, and section 0 says nobody is running
either.

**The `harness` extra leaves the engine.** `messagefoundry[harness]` is PySide6 and nothing else.
It becomes the harness's own dependency, and the engine wheel's metadata stops naming a test tool.

### G. Six engine modules are a deliberate client surface, and the split would freeze seven internal imports by accident

Counts are import statements under `harness/`, imports inside function bodies included. 36 of
the 77 Python files there import the engine, under 19 distinct dotted module names. The brief
named 13. It did not name the root package, `config.settings`, the three `store` modules or `api`.

**How the 19 divide.** Six are a deliberate client surface: the first four rows below. Seven need
a declaration or a small fix: the other rows. Six are internals, in the second table. `pki` is
imported through the root name, so it adds a row and no dotted name. `config.wiring` is in both
tables, because the harness uses it two ways.

| Engine module | Statements | Standing today | Before the move |
|---|---|---|---|
| `messagefoundry` (root: `inbound`, `outbound`, `router`, `handler`, `Send`, `MLLP`, `File`, `PassThrough`, `SetMeta`, `SetState`) | 8 | The authoring surface. Public by design. | Nothing. |
| `messagefoundry.apiclient` | 16 | The client library ADR 0088 extracted. | Nothing. |
| `messagefoundry.mllpcodec` | 6 | The client-importable codec #1697 made. | Nothing. |
| `messagefoundry.parsing`, `.message`, `.peek` | 22 | The carve-out in `CLAUDE.md` section 4. | Nothing. |
| `messagefoundry.generators` | 6 | In the engine wheel today. Moving to the toolkit, ADR 0201 slice 7. Five of the six statements import the private `_core`. | Give the five files a public generator surface. Settle the order against slice 7. |
| `messagefoundry.api.models` | 4 | The API's response models. Not a forbidden package, and not a declared client surface. | Re-export the models from `apiclient`, or declare `api.models` supported. |
| `messagefoundry.console_streams` | 3 | A 46-line helper. Undeclared. | Declare it supported. |
| `messagefoundry.api_tls_source` | 2 | Passes the client rule. Undeclared. | Declare, or expose what is needed through `apiclient`. |
| `messagefoundry.pki`, through the root name | 1 | The same. | The same. |
| `messagefoundry.config.models` (`RetryPolicy`) | 8 | Excused for `harness/config/`. `RetryPolicy` is already a root export. | Import it from the root. |
| `messagefoundry.config.wiring` (`HandlerFn`, `RouterFn`) | 4 | Excused for `harness/config/`. The two types are not root exports. | Export the two types. |
| `messagefoundry.api` (`create_managed_app`) | 1 | Runs the engine in-process, in `ingress_probe.py`. | Start a `serve` subprocess, as `failover.py` and `shardcert.py` do. |

**The seven internal imports.** `tests/test_dependency_boundaries.py` forbids a client from
importing `config`, `pipeline`, `store` and `transports`. Its `_CLIENT_ALLOWED` list excuses one
harness directory and two harness files by name. These seven, in those two files, are what a split
would freeze by accident.

| Engine module | Statements | Used by | What it is used for |
|---|---|---|---|
| `messagefoundry.config.settings` | 6 | `shardcert.py`, `connscale/runner.py` | `load_settings`, `StoreSettings`. |
| `messagefoundry.config.tls_policy` | 3 | the same two | `HopPosture`. |
| `messagefoundry.config.wiring` (`load_config`) | 1 | `shardcert.py` | Runs the config loader. |
| `messagefoundry.store.base` | 2 | the same two | `open_store`, two pool-size constants. |
| `messagefoundry.store.sqlserver` | 3 | the same two | Opens the store to reset and count it. |
| `messagefoundry.store.postgres` | 1 | `connscale/runner.py` | The same. |
| `messagefoundry.pipeline.sharding` | 1 | `shardcert.py` | The engine-shard planner. |

**Recommendation for the seven: give them a home in the toolkit, never in the production
command.** The harness needs to reset and count a test store, read a few effective settings, and
compute an engine-shard plan. `messagefoundry/cli_surface.py` gives every command a tier, and a
command that wipes a store must not ship as a production row: ASVS 15.2.3 and ADR 0201 point the
other way. The toolkit is the development tier, it is in lockstep with the engine, and ADR 0201
already makes the harness depend on it. This ADR does not design that surface. If the work is
declined, name the seven as "tracked, not supported", and accept that a pin move can break those
two files.

**Five contracts an import scan cannot see.** Each needs the same choice.

- Raw SQL against `messages`, `queue`, `message_events`, `response` and `delivered_keys`, and a
  read of the private `store._pool`, in the same two files.
- Three regular expressions over engine log lines in `harness/load/shardcert_ladder.py`:
  `_PHASE_RE`, `_CLAIM_RE` and `_EPISODE_RE`.
- Fields of the `/stats` response, at least `committed_txns` and `body_copies`.
- `serve` flags and `MEFOR_*` settings passed to engine subprocesses. Not counted for this ADR.
- **Hooks inside the engine wheel that exist for the rig.** At least
  `messagefoundry/pipeline/connscale_shim.py`, which calls itself "a harness-only, env-gated
  measurement hook", and `messagefoundry/pipeline/phase_timing.py`. They are off unless an
  environment setting turns them on. They stay where they are under this ADR. Whether measurement
  hooks pass the owner's test is a question for the owner.

**The harness's tests reach further than the harness.** At least 18 of the test files that move
import one of the four forbidden packages. The client rule does not walk `tests/` today. The new
repository must decide whether its tests may.

### H. A new repository needs the leak gate, a commit gate, CI and a coordination install on day one

**The two precedents, read with `git ls-tree` at their `origin/main` on 2026-10-01**: the vault
at `2aa32ceb33` and korus at `f779ef279d`.

| Carries | Vault (private) | korus (public) |
|---|---|---|
| `CLAUDE.md` | yes | yes, with a template |
| Role playbooks | `roles/`, an older copy that korus says differs from its own | `roles/`, the source of record |
| `.pre-commit-config.yaml` | yes | not found at the root |
| Leak gate | `.gitleaks.toml`, `.semgrep` | `scripts/security/scan_forbidden.py`, `branch-leak-scan.yml` |
| `scripts/coord/`, `hooks/`, `worktree/` | 20, 9 and 12 files | 13, 16 and 11 files, driven by `ccx.config.json` |
| Workflows | 19 | 5 |
| Required contexts (`gh api .../branches/main/protection`) | `ledger structure`, `publish leak gate` | `gates (ubuntu-latest)`, `gates (windows-latest)` |
| Merge queue | unmeasured | none found: the rulesets API returned no ruleset, where the engine's returned `protect-main` |

korus `docs/INSTALL.md` says how a repository adopts the kit: vendor the scripts, place
`ccx.config.json` at the root, and run four installers from a plain terminal. The installers
refuse to run inside a session.

**Day one.**

| Need | Why it cannot wait |
|---|---|
| `LICENSE`, `NOTICE`, SPDX headers, and the contributor and commercial licence terms | It is a public repository that publishes a wheel. The headers already exist on the files. |
| `CLAUDE.md`, with the deployment-status section, the synthetic-data-only rule and the client import rule | Every session reads it first. The harness handles captures, so the PHI rule is not optional. |
| The leak gate: forbidden-content scan, secret scan and the branch scan on push | The repository is public from its first push. |
| A commit gate: ruff, licence header, control characters, workflow lint | Otherwise a defect first shows in CI, after a one-turn Builder has gone. |
| CI: lint, types, the class 1 tests on Linux and Windows, the class 3 runs against `ENGINE_REF` | It is the gate. |
| Branch protection with required contexts | Otherwise CI gates nothing. |
| The coordination kit from korus, a worktree gate that covers the new clone, and seat cards | Sessions collide without it. |
| The harness's own test for the client import rule | The engine's copy stops seeing the tree. |
| The crypto inventory gate, and the ASVS file-surface and absence-proof coverage, for the harness's files | `scripts/security/crypto_inventory_check.py` registers harness files and runs in a required leg. `scripts/asvs/scorecard.py` walks `harness` as a shipped root, because it ships on PyPI. If the cut removes those entries and the new repository has no such gate, coverage narrows while the wheel still ships. |
| A `conftest.py` with the two fixtures section E names | The database runs fail closed without them. |
| A check that `import harness` resolves to this checkout | Until the cut, every engine commit still holds `harness/`, and it is a namespace package. If the engine checkout is on the import path, the old copy can win and the runs pass against the wrong code. Install the engine as a built wheel, and assert the path. |

**Can wait.**

| Item | Until |
|---|---|
| A merge queue | Merge volume asks for one. korus runs without. |
| An ADR ledger and its gate | The repository writes its first ADR. Backlog rows stay in the one vault ledger. |
| CodeQL, Scorecard and the other scheduled scanners | Soon after the first release. A dependency audit should not wait that long. |
| The release workflow, with signing and an SBOM | The first release from the new repository. |

**Unmeasured:** how the engine's leak-gate token list would be shared with a second public
repository.

### I. Migration, in order

Steps marked **OWNER** are the owner's alone.

1. **OWNER.** Rule on this ADR, on gate option 1, and on the names in C.
2. Narrow the import surface in the engine repository, one pull request per row of G. This is
   worth doing even if the move is declined.
3. Split the 11 class 2 files (section E), in the engine repository. Read each class 1 file
   that starts an engine, and check the two graph tests have engine equivalents. After this
   every test file is wholly engine or wholly harness. `tests/conftest.py` is the one shared
   file: both repositories end with their own.
4. Give the class 3 files their own directory and their own `pytest` step in each job that
   runs them (section D), with the harness still in tree. The events and the operating
   systems do not change. The gate is now shaped for a pin.
5. Land or close every open pull request that touches `harness/`. At 2026-10-02 02:50 UTC,
   `gh pr list` showed 7 open pull requests and none touched it.
6. **OWNER.** Create the repository: name, public visibility, licence.
7. Extract the history on a fresh **full** clone, since the working clones are shallow. Use
   `git filter-repo` with a path list: `harness/`, `packaging/messagefoundry-harness/`, the class 1
   and class 3 test files, the three graph tests, `scripts/connscale_harvest.py` with
   `tests/test_connscale_harvest.py`, and `docs/LOAD-TESTING.md`.
   `git subtree split` takes one prefix and the move has many paths. Commit subjects keep their
   `(#N)` suffix, which names an engine pull request; the new README says so. Run the leak gate
   over the whole extracted history before the first push.
8. Add the day-one tooling (section H) as the first new commit. `pyproject.toml` becomes an
   ordinary package table: the force-include map and its hatchling traps are no longer needed.
   The SPDX headers and the `LICENSE` and `NOTICE` copies travel with the files.
9. **OWNER.** Set branch protection and its required contexts, run the coordination installers,
   add the new clone to the worktree gate, and extend the Lander's standing authority to it.
10. One engine pull request, "the cut", on its own. It must be one pull request, because the
    gates that walk the tree refuse one that is half gone. It does at least this:
    - deletes `harness/`, its packaging directory and the moved tests;
    - adds `ci/harness.pin`, its checkout step and the test for AC-2 and AC-3;
    - removes the `harness` extra and the `release-harness` job;
    - edits the test gates that walk the tree, at least 32 files;
    - edits the gates that are not tests: at least `scripts/security/crypto_inventory_check.py`,
      `scripts/asvs/scorecard.py`, `scripts/release/harness_resolution_check.py`,
      `.pre-commit-config.yaml`, `.dockerignore` and `.gitattributes`;
    - repoints `benchmark.yml` and `ingress-rate-probe.yml`, which run the harness and serve
      `harness/config/load`;
    - updates `CLAUDE.md` and the documents that name `python -m harness`;
    - **amends ADR 0201.** Its slice 7 edits five `harness/` files and the harness packaging
      table, and its AC-7 keeps the harness's toolkit pin under an engine test. After the cut
      both live in the other repository, so the amendment is recorded here, not left implied.
11. **OWNER.** Point the PyPI Trusted Publisher for `messagefoundry-harness` at the new
    repository's release workflow. The first release from there starts the harness's own version
    line. Between steps 10 and 11 no harness release can be cut, which costs nothing today.
12. Build #2672, then #2673 to #2682, in the new repository.

**Order against the harness wave.**

| Row | Where it is built | Why |
|---|---|---|
| #2672 (driver and sink seam, coverage report) | New repository, after step 10 | It blocks #2673 to #2682, and it only adds files under `harness/`. If steps 6, 9 and 11 will take more than a few days, build it in the engine first: the extraction carries it. |
| #2673 to #2680 (scenario sets and connector coverage) | New repository | Each new driver needs a client-side codec for its transport. That widens section G, so decide the surface with the row. |
| #2681 (the coverage gate) | New repository | It reads the engine's connector registry at `ENGINE_REF`. A new engine connector then shows as uncovered when the pin moves, not at the engine's merge. That is a weaker gate than the row describes, and the row should say so. |
| #2682 (fuzz mode) | New repository | It is a harness mode. |
| #2683 (Atheris targets) | **Engine repository, any time** | It touches `fuzz/` and `tests/test_fuzz_targets.py` only, and the row says it is independent of #2672. |

### J. What gets worse, and what would change this recommendation

**Worse after the split.**

- One change becomes two pull requests in order whenever the engine and the harness must change
  together. The upper bound was 20 in the visible window.
- The engine's boundary test stops seeing the harness. Today a new harness import of an engine
  internal is refused at the engine's merge. Afterwards an engine refactor breaks the harness only
  when a pin moves.
- Repository-wide sweeps, such as licence headers, console encoding and lint scope, need a second
  run in a second repository.
- A second set of gates and a second coordination install must be kept current. korus
  `docs/INSTALL.md` warns that an uninstalled control shows no error.
- A benchmark record now needs two commit names to be reproduced: the engine's and the harness's.

**Better after the split.**

- The engine repository sheds 34,719 lines of harness Python and most of the 33,273 lines in
  the 82 test files (newline counts over tracked files). The 11 class 2 files hold 5,052 of
  those lines and mostly stay. How much CI time that saves was not measured.
- The harness gets a type gate. `ci.yml` says `harness/` is outside every mypy step today.
- The force-include map and the `harness` extra go away. The namespace-package trap goes away
  only after the cut; section H names the check that covers the weeks before it.
- The harness uses only what the engine publishes, which is what a site's own tools would use.

**What would change the recommendation.**

| Evidence | Then |
|---|---|
| The owner means the narrow reading: only what a wheel ships | `tests/`, `docs/` and `.github/` would leave too. This ADR recommends against that reading. |
| Step 2 shows `shardcert.py` and `connscale/runner.py` cannot work through a toolkit surface | Keep those two, and what they need, in the engine as test fixtures. That is the withdrawn "keep the load rig" idea, for two files and not for `harness/load/`. |
| The owner will not accept two ordered pull requests for a coupled change | Option 3 in D, with its copy and its smaller gate. |
| The co-change rate stays near 20 of 36 after step 2 narrows the surface | The seam is not real yet. Stop after step 4 and leave the harness in tree until it is. |

**What this ADR must not break.** The reliability and count-and-log invariants in `CLAUDE.md`
section 2 are certified by the load, failover and engine-shard legs. No step above may remove one
of those legs from the engine's merge gate, even for one pull request.

## Acceptance Criteria

These hold after the move. No test for them exists yet, except where one is named.

- **AC-1** -- THE engine repository SHALL contain no `harness/` directory and no
  `packaging/messagefoundry-harness/` directory.
  Verified by: `tests/test_dependency_boundaries.py` and `tests/test_packaging.py`, edited in step 10
- **AC-2** -- WHEN an engine job runs a class 3 file or a load leg, THE SYSTEM SHALL run it
  against the engine under test, from the harness commit named in `ci/harness.pin`, on the same
  events and operating systems as before the move.
  Verified by: a new workflow test, step 10, beside `tests/test_required_contexts.py`
- **AC-3** -- IF `ci/harness.pin` does not hold a full 40-character commit SHA, THEN THE SYSTEM
  SHALL fail the leg before it runs any harness code.
  Verified by: the same new workflow test
- **AC-4** -- THE engine SHALL import nothing from the harness.
  Verified by: `tests/test_dependency_boundaries.py`, a new arm with a planted control. The arm
  reads import statements only: 28 files under `messagefoundry/` use the word "harness" in
  prose today, and `harness` is an ordinary word.
- **AC-5** -- THE harness SHALL import no engine module outside the supported list section G
  settles.
  Verified by: the harness repository's own copy of the client import walk, step 8
- **AC-7** -- WHILE an engine commit still holds `harness/`, THE harness repository's CI SHALL
  fail a run in which `import harness` resolves outside its own checkout.
  Verified by: a new test in the harness repository, step 8
- **AC-6** -- THE engine wheel's metadata SHALL declare no `harness` extra.
  Verified by: `tests/test_packaging.py`, edited in step 10

## Options considered

1. **Move the whole harness to one new repository, and keep the gate legs at a pin.** **CHOSEN
   (recommended).** It applies the owner's test to the one tree that clearly fails it, and it
   keeps every leg in the merge gate.
2. **Keep `harness/load/` and move the rest.** The Manager's first reading, later withdrawn. It
   keeps the tightly coupled half in the engine, which is cheaper. Rejected because a load rig is
   not needed for an install, and "the gate needs it" is answered by a pin.
3. **Move the harness and everything else that fails the test at once**: `tee/`, `ide/`, the
   coordination scripts. Rejected for now. Each has its own coupling, and only the harness's was
   measured well enough to plan.
4. **Move the legs out of the engine gate with the harness** (option 2 in D). Rejected: it weakens
   a control.
5. **Leave the harness in place and only narrow its imports** (steps 2 to 4 alone). Not rejected.
   It is the fallback if the owner declines the move, and it is the first third of the move
   anyway.

## Consequences

**Positive** -- the engine repository holds the product and its proof. The harness becomes an
ordinary client of the engine, with its own gate. Steps 2 to 4 are worth their cost on their own.

**Negative / risks** -- section J lists them. The largest is that a coupled change takes two
ordered pull requests, and one-turn Builders cannot do both.

**Out of scope** -- moving `tee/`, `ide/`, the coordination scripts or `docs/roles/`; renaming the
`harness` import package; ADR 0201's layout and its slices 3 to 6; the design of the toolkit
surface section G asks for; any change to what the engine wheel ships.

## To resolve on acceptance

- [ ] The owner confirms the test in section A, or states the one intended.
- [ ] The owner chooses gate option 1, 2 or 3 in section D.
- [ ] The owner confirms the repository name, its visibility and its licence (section C).
- [ ] The owner says whether the test reaches `messagefoundry_toolkit/` (section B).
- [ ] The owner says whether `docs/benchmarks/` stays, as recommended, or moves with the harness.
- [ ] Section G's seven internal imports: a toolkit surface, or "tracked, not supported".
- [ ] Whether the two measurement hooks inside the engine wheel pass the owner's test.
- [ ] The harness's version line and how its metadata pins the engine (section F).
- [ ] Whether the new repository's tests may import the four forbidden engine packages.
- [ ] How the leak-gate token list is shared with a second public repository.
- [ ] The order of this move against ADR 0201 slices 5 to 7, and the wording of the amendment
      to its slice 7 and its AC-7.
