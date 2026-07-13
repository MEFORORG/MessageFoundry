# ENGINE-BOX RIG HANDOFF — STEP 2 (instrumented soak) + STEP 3 (RUN-A)

**Date:** 2026-07-13 · **Programme:** MessageFoundry throughput · **Discipline:** ADR 0101 (binding)
**Runs:** `S2` — the per-stage residency decomposition · `RUN-A` — the store-causality sign test
**Spec (in-repo):** `docs/benchmarks/PLAN-ENGINE-ATTRIBUTION.md` · **Tool:** `scripts/bench/stage_residency.py`

**Read this top to bottom before you touch the rig.** Every `<ANGLE BRACKET>` value is yours to fill (§3.7 lists them all and where they come from). Anything marked **VERIFY ON THE BOX** must be checked, not copied.

---

## 0. WHAT THESE TWO RUNS ARE FOR

The 45M/day target is **520.83 events/s**. We sustain **90.0 events/s raw** on the shipped default and **144.0 events/s raw** on the best deployable configuration.

**Seven runs have now failed to find a lever** — C1, C3, C5, C6, C7, P0, and the tempdb work. Two more are on the books but are **not clean negatives** and must not be counted as such:

- **C4's verdict is WITHHELD.** It handed back **zero JSON**; every C4 figure is prose-only and unauditable; it was measured on the **N=16 COLLAPSED arm** (26.2% delivered on C6's repro) on the **old 8-vCPU engine box**, and **the CPU attribution was never re-run after the upsize.** (`docs/benchmarks/THROUGHPUT-STATUS-2026-07-10.md:273`.)
- **C2 was RETRACTED.**

**The wall is UNNAMED.** P0's finding reframes the programme: **at the measured ceiling, nothing on the per-message path is saturated.** The engine burns ≤0.36 cores per shard of the 1.0 available. The claim loop's claimers are ~**17% busy** (4 shards × 3 stage-dispatchers × K=1 = **12 claimer tasks**; §4.6 tells you how to confirm the dispatcher count on the box — if it differs, recompute, and note that a *higher* claimer count only makes them *less* busy and strengthens the conclusion).

And the outbound lane: a 250 ms per-lane delivery episode contains **≥23.8 ms of accounted work, leaving ≤226 ms of residual.**

> ⚠️ **That 226 ms is an UPPER BOUND, not a measurement.** It was built by treating c6-n4x2's `claim_mean_ms = 13.316` as the *outbound* claim. **It is not.** I opened the artifact: `soak.claim_timing` in `c6-n4x2.json` has **no `by_stage` key** — it predates PR #1008 and is the n-weighted **multi-stage blend**. **The outbound claim has never been measured. `by_stage.outbound.claim_mean_ms` in STEP 2 is the first time it will be.** Do not quote "90.5%" as a figure. The qualitative claim survives any plausible outbound claim: **a large majority of the episode is unaccounted for.**

Meanwhile the store box runs hot — but **every store-CPU number this programme quotes is unattributed or inadmissible.** The frequently-cited "80–94% CPU, roughly half of it the 0.25 s clock-driven scan" derives from **C4's N=16 COLLAPSED arm on the 8-vCPU box (VERDICT WITHHELD)**. The scan's share **at N=4 on the current 16-vCPU rig is UNKNOWN.** The C1 controls in RUN-A are the first admissible reading of it, and **this run will measure it.**

So: **the single load-bearing assumption underneath four consecutive failed runs — that the store's CPU saturation is CAUSAL — has never once been tested.**

**STEP 2 says WHERE the residual actually lives. STEP 3 tests WHETHER the store's CPU matters at all.**

We are not proposing a lever, and **neither run is expected to raise throughput.** **We are measuring.** A null is the most likely outcome of RUN-A, it is pre-registered as such, and it is a **successful run**.

---

## 1. ⛔ THE TRAP — READ THIS TWICE

> ### 🚨 `stage_residency.py` IS NOT RETROACTIVE, AND `message_events` IS NOT CLEAN
>
> **`shardcert._reset_store` (`harness/load/shardcert.py:476`, called at `:702` and `:1564`) `DELETE`s the pipeline tables at the START of every run — and once per LADDER RUNG.** Anything you did not capture before the next run starts is gone.
>
> **➡️ RULE 1: run `scripts/bench/stage_residency.py` IMMEDIATELY after the STEP 2 soak, BEFORE any other shardcert run starts.** Not at the end of the session. Not "after the next arm." Immediately.
>
> **AND — a contradiction, now settled by reading the merged code:**
> The source docs (including `stage_residency.py`'s own module docstring and PR #1008's commit message) say `_reset_store` wipes `message_events`. **IT DOES NOT.** Its `DELETE` list is exactly nine tables — `queue, outbox, response, delivered_keys, state, leader_lease, nodes, cluster_config, messages` (`shardcert.py:491-501`) — `message_events` is **not among them** and has **no foreign key to `messages`** (`store/sqlserver.py:722`), so nothing cascades into it.
>
> **Consequence: `message_events` ACCUMULATES across every rung, every arm, every run.** And `stage_residency.py`'s SQL has **no run filter and no time filter** — so it will not exit 1, it will **silently print a decomposition that BLENDS your soak with everything that came before it.** A wrong number that looks completely right.
>
> **This was reproduced, not reasoned.** Two soaks seeded into one store — an old one at 500 ms/stage and a new one at 50 ms/stage — and the tool reported a confident `mean = 242.9 ms`, a number belonging to neither, with the two runs sitting side by side as `p50 = 50 ms` / `p95 = 500 ms`. After the RULE 2 clear it reported the true `50.0 ms`. **Nothing about the contaminated output looks wrong.**
>
> ⚠️ **Do NOT "check" this on a local SQLite box and conclude it is false.** SQLite and Postgres declare `message_id ... REFERENCES messages(id)` (`store/store.py:1158`, `store/postgres.py:270`); **SQL Server declares NO foreign key** (`store/sqlserver.py:722-724`). **The rig is SQL Server**, and `_reset_store` only ever opens a `SqlServerStore` (`shardcert.py:481`) — so on the rig the `messages` delete succeeds and leaves the `message_events` rows behind as orphans. The backends genuinely differ here.
>
> **➡️ RULE 2: `SELECT COUNT(*) FROM message_events;` then `DELETE FROM message_events;` — BEFORE the STEP 2 soak, and BEFORE EVERY RUN-A ARM AND EVERY DISCOVERY CLIMB (§5.4).** Record the pre-clear count each time. Both rules are correct and harmless under either reading. Do both, every time.
>
> ⛔ **Do NOT "solve" this by setting `message_events` to `off`.** That changes the store write path and would make RUN-A a different configuration from STEP 2 and from C5/C6/C7/P0.

---

## 2. ADR 0101 — THE OPERATOR CHECKLIST

This programme has **published and retracted two performance results.** Every rule below exists because one of them cost us. Apply them mechanically.

| # | Rule |
|---|---|
| **1** | **Gate on the harness `result` field. NEVER `exit_code`.** Every collapsed arm serializes `exit_code = 0`. The engine box's process returns `0` *unconditionally* and carries no verdict at all. `result` ∈ `PASS` / `SOAK_NOT_SUSTAINED` / `SOAK_UNCONFIRMED` / `FAIL` / `SETUP_DEGRADED`. |
| **2** | **Never quote `ceiling.sustained_events_per_s` from a COLLAPSED or UNBRACKETED arm.** It is populated even on a 27%-delivered arm, and on a single-rung ladder it is just `offered_rate × events_per_message`. |
| **3** | **Never name a wall from a wait's RANK, SHARE, or GROWTH RATE.** On a collapsing system almost everything grows. |
| **4** | **Same-session controls ONLY.** Never A/B an arm against a historical number (c6-n4x2, the 90, the 144). Historical numbers are context for the QUESTION, never a control. |
| **5** | **A NULL is a SUCCESSFUL RUN.** Report it as a result, in full, with the same confidence as a positive. |
| **6** | **A failed manipulation check is VOID, not a refutation.** If the knob did not demonstrably engage, **nothing else in that arm means anything.** Re-run it. Do not write it up as a null. |
| **7** | **RAW ≠ PUBLISHABLE.** Publishable = ½ the measured ceiling (Phase-5 D4 derate). **Never mix the two currencies in one sentence, or in one table column.** |

**Where the numbers actually are** (orientation only — **not controls, and not to be reproduced by this run**):

| configuration | raw sustained | publishable (D4 ×0.5) | gap to 520.83 RAW | gap to 520.83 PUBLISHABLE |
|---|--:|--:|--:|--:|
| **Shipped default** (pooled, tempdb feature OFF) | **90.0** | 45.0 | **5.79×** | **11.57×** |
| **Best deployable** (`MEMORY_OPTIMIZED TEMPDB_METADATA = ON` — a SQL Server config, not code) | **144.0** | **72.0** | **3.62×** | **7.23×** |
| `per_lane` claim mode | ≥252 | ≥126 | — | **NOT USABLE — ships OFF.** Storms the store at 1,500 lanes; engine CPU 88% p95. **Do not enable it in any arm.** |

*(Two columns, two currencies, never one. "7.23× short" is a PUBLISHABLE statement about the best deployable configuration; "5.79×" is a RAW statement about the shipped default. They are not comparable.)*

---

## 3. PRECONDITIONS — BLOCKING, BOTH STEPS

### 3.0 The rig is THREE boxes

- **ENGINE box** — `m7i.4xlarge`, 16 vCPU. Runs `shardcert-engine-ladder` + the `serve --shard` subprocesses. **Every `MEFOR_*` export in this document goes here.** Writes: per-shard node logs, `s2-residency.json`, `status_poll.jsonl`, `cpu_soak.csv`. **Writes NO report JSON.**
- **STORE box** — `i4i.2xlarge`, SQL Server, `n_sched = 8`. Local NVMe. All T-SQL below runs here. Writes: the DMV/CPU captures.
- **LOAD-GEN box** — runs `shardcert-drive-ladder` and its K+M children, **from its OWN git checkout**. **It writes the ONLY consolidated report JSON.**

> ⚠️ **VERIFY ON THE BOX:** confirm the engine box is actually `m7i.4xlarge` before the first arm. P0's pre-flight found it had been silently downsized to 2× while idle. **Only the owner may resize it.**

### 3.0a ⬅️ STEP 0 — TAKE THE INSTRUMENTS FROM THE **PRIVATE** REPO

**The instruments do not exist on the pinned rig build.** They landed in **PR #1008** (`93155489`) and **PR #1015** (this document + the `stage_residency.py` corrections), both on **private `main`** — strictly newer than the `28f860e` build C5/C6/C7/P0 ran on.

**The rig boxes now have direct read access to the PRIVATE repo** (`MEFORORG/MessageFoundry`). **No `publish.ps1` is required, and you must not wait on one** — the public mirror is a separate, independently-maintained snapshot and may be mid-update by another session.

> ### 🚨 `28f860e` DOES NOT EXIST IN THE PRIVATE REPO. DO NOT TRY TO CHECK IT OUT.
> The public mirror is a **regenerated snapshot with unrelated history** — its hashes have **no counterpart** in the private repo (`git cat-file -t 28f860e` there returns **`Not a valid object name`**). **There is no private commit you can check out to "stay on the pinned build."**
>
> ⛔ **So: do NOT re-clone from private. Do NOT repoint `origin`. Do NOT `git pull`.** Any of those silently lands you on today's `main` — and **today's `main` is a DIFFERENT ENGINE** (BACKLOG #149 rewrote `store/sqlserver.py` +353 and added an ingress detach path in the pipeline — exactly the code these runs exercise). Every number the programme has ever produced came from `28f860e`.
>
> **The existing mirror-based checkout STAYS. You add private as a SECOND remote and take only the files you need.** Git fetches blobs across unrelated histories without complaint.

### 3.1 BUILD — take the instruments, then PIN

**PR #1008 is harness-only: it touches five files and ZERO files under `messagefoundry/`** (#1015 likewise touches only `scripts/bench/` and `docs/`). Every ENGINE-side emitter the cherry-picked harness consumes **already exists on `28f860e`**: the `claim phase timing (stage=…)` log line landed 2026-07-09 in #845 (`messagefoundry/pipeline/phase_timing.py:210`), and `pool.acquire_wait` landed 2026-06-30 in #675 (`messagefoundry/api/app.py:2505`). **So the pinned engine + these harness files is a COMPLETE instrument set** — and because nothing under `messagefoundry/` moves, **there is no reinstall and the engine under test is untouched.**

**THE ONLY SUPPORTED PATH — on BOTH the ENGINE box AND the LOAD-GEN box:**
```powershell
# HEAD stays on the pinned build. No pull. No branch change.
git remote add private https://github.com/MEFORORG/MessageFoundry.git   # once per box
git fetch private

git checkout private/main -- `
  harness/load/enginepoll.py `
  harness/load/shardcert.py `
  harness/load/shardcert_ladder.py `
  scripts/bench/stage_residency.py `
  tests/test_shardcert_ladder.py `
  docs/benchmarks/HANDOFF-enginebox-step2-step3.md
```
This leaves `HEAD` on the pinned build and **six modified/added paths in `git status --short`. That dirty tree IS the provenance of the cherry-pick — do not clean it, and record it (§8).**

**➡️ IMMEDIATELY CONFIRM THE TREE DID NOT MOVE:**
```powershell
git log --oneline -1        # MUST still be the pinned build (28f860e). Anything else ⇒ STOP.
git status --short          # exactly the six paths above, nothing else
```
> ⛔ **If `git log` shows anything but the pinned build, STOP and re-establish it before running a single arm.** A moved tree does not announce itself — the ladder runs happily on the wrong engine and every number is a measurement of something else.

⛔ **There is no "take the whole tip" fallback any more.** With #149 merged, the tip is a materially different engine on the exact path under test. If the pinned tree is ever lost, **stop and escalate to the owner** — do not proceed on the tip and caveat it.

**VERIFY BY CAPABILITY, on BOTH boxes** — the hash is not self-verifying:
```powershell
.\.venv\Scripts\python.exe -c "from harness.load.shardcert_ladder import ClaimTiming; from harness.load.shardcert import ShardCertReport; import pathlib; print('claim by_stage    :', 'by_stage' in ClaimTiming.__dataclass_fields__); print('report e2e fields :', [f for f in ShardCertReport.__dataclass_fields__ if 'e2e' in f]); print('stage_residency   :', pathlib.Path('scripts/bench/stage_residency.py').is_file())"
```
**Required output on BOTH boxes:**
```
claim by_stage    : True
report e2e fields : ['e2e_count', 'e2e_p50_ms', 'e2e_p99_ms']
stage_residency   : True
```

> 🚨 **THE LOAD-GEN BOX IS NOT OPTIONAL HERE.** The engine computes `claim_timing` and posts it over the coord dir; the **drive half deserializes it** via `ClaimTiming.from_json_dict`. A stale load-gen checkout **silently drops `by_stage`** and you get a report that looks complete and is missing the one number STEP 2 exists to produce. **This exact bug ate P0's first pass.**

> ### ⛔ THE BUILD IS NOW PINNED FOR THE WHOLE SESSION.
> **After the capability check passes: NO `git fetch`, NO `git pull`, NO `git checkout` on either box — not between steps, not between arms.** Every comparison in this document is same-session (ADR 0101 rule 4). A mid-session build change voids all of it. `main` took six PRs in a single day during this arc; **a stray `git pull` would swap the engine underneath you mid-run and you would not be told.**

**Capture provenance NOW, once per box** (this is the §8 handback item, and there is no other source):
```powershell
git rev-parse HEAD    > <OUT_ENGINE>\provenance_engine.txt      # on the ENGINE box
git status --short   >> <OUT_ENGINE>\provenance_engine.txt      # 5 modified files = the cherry-pick
# and the same, on the LOAD-GEN box, into <OUT_LOADGEN>\provenance_loadgen.txt
```
> ⚠️ **`run.commit_sha` in the report JSON is the LOAD-GEN box's HEAD, NOT the engine's.** It is stamped by `_git_commit_sha()` inside the *writing* process (`harness/__main__.py:820-835`, called at `:1717`), which shells `git rev-parse HEAD` in the drive's cwd. The engine box emits no report, so **no engine SHA exists in any artifact unless you capture it by hand.** Proof: `c6-n4x2.json` carries `run.commit_sha = 98bec81d…` while its engine was pinned `28f860e`. Worse, a cherry-pick does not move HEAD, so `run.commit_sha` would print a build state that never ran. **Never report it as "the engine build."**

### 3.2 STORE — tempdb metadata ON, and the restart SEQUENCE

`MEMORY_OPTIMIZED TEMPDB_METADATA = ON` is the **best deployable baseline** (90 → 144 raw, +60%, measured) and it removes C3's tempdb-latch as a confound. It was ON through C5/C6/C7/P0 and is **currently REVERTED on the rig.** The RUN-A spec pre-registers it as **HELD FIXED ON in every arm.**

**Check first:**
```sql
SELECT SERVERPROPERTY('IsTempdbMetadataMemoryOptimized') AS tempdb_memopt;   -- must return 1
```

**If it returns 0, enable it (STORE box). Note the SPACE in `MEMORY_OPTIMIZED TEMPDB_METADATA` — the underscore form is INVALID T-SQL and a previous handoff shipped it wrong:**
```sql
IF NOT EXISTS (SELECT 1 FROM sys.resource_governor_resource_pools WHERE name = 'tempdb_xtp')
    CREATE RESOURCE POOL tempdb_xtp WITH (MAX_MEMORY_PERCENT = 25);
ALTER RESOURCE GOVERNOR RECONFIGURE;
ALTER SERVER CONFIGURATION SET MEMORY_OPTIMIZED TEMPDB_METADATA = ON (RESOURCE_POOL = 'tempdb_xtp');
-- staged? value=1 with value_in_use=0 means "enabled, awaiting restart":
SELECT name, value, value_in_use FROM sys.configurations WHERE name = 'tempdb metadata memory-optimized';
```

**Then RESTART THE SQL SERVER SERVICE (mandatory — the ALTER is not effective until restart).**
```powershell
Get-Service -Name 'MSSQL*'            # VERIFY ON THE BOX: default instance = MSSQLSERVER; named = MSSQL$<NAME>
Restart-Service -Name '<SERVICE_NAME>' -Force
```

> ### 🚨 THE RESTART SEQUENCE IS PART OF THE DESIGN.
> A SQL Server service restart **empties `sys.dm_exec_query_stats` and the plan cache.** Therefore:
> - **Do the tempdb enable + restart BEFORE the STEP 2 soak.** STEP 2 then doubles as the store warm-up.
> - ⛔ **NEVER restart SQL Server between RUN-A arms.** It zeroes the §5.5 check-1 counters mid-session and re-colds the plan cache, and it will make a perfectly good arm unscoreable.
> - ✅ **LEAVE tempdb metadata ON at the end of the session.** The owner has **RULED ADOPT.** Do NOT "restore as-found" — that would revert the +60% baseline.

✅ **A SQL Server SERVICE restart is SAFE and REQUIRED.**
⛔ **An EC2 instance STOP is DESTRUCTIVE and FORBIDDEN** — it wipes the instance-store `mfbench` volume. Do not conflate the two and skip the service restart. See §7.

**Confirm, two signals:**
```sql
SELECT SERVERPROPERTY('IsTempdbMetadataMemoryOptimized');            -- 1
EXEC sys.xp_readerrorlog 0, 1, N'memory-optimized metadata';         -- "Tempdb started with memory-optimized metadata"
```

### 3.3 STORE — MAXDOP is a live landmine

C7 measured `MAXDOP = 1` as **actively HARMFUL** (higher store CPU, *less* delivery — **parallelism is load-bearing**). C7 says it restored the setting, but a stale `MAXDOP = 1` would **silently depress every arm of both runs** and never show in the harness output.

```sql
SELECT name, value_in_use FROM sys.configurations
 WHERE name IN ('max degree of parallelism','cost threshold for parallelism');
SELECT COUNT(*) AS visible_online_schedulers FROM sys.dm_os_schedulers
 WHERE status = 'VISIBLE ONLINE' AND scheduler_id < 255;
USE <BENCH_DB>;
SELECT name, value FROM sys.database_scoped_configurations WHERE name = 'MAXDOP';
```
**Expect:** instance MAXDOP **0**, cost threshold **5** *(the low default — **RECORD it as-found, do NOT "fix" it**)*, schedulers **8**, DB-scoped MAXDOP **0**.

**If DB-scoped MAXDOP reads 1, restore it. Clearing the plan cache is NOT optional — without it SQL Server reuses the cached serial plans and the restore silently does nothing. Do this BEFORE the STEP 2 soak, never mid-RUN-A:**
```sql
USE <BENCH_DB>;
ALTER DATABASE SCOPED CONFIGURATION SET MAXDOP = 0;
ALTER DATABASE SCOPED CONFIGURATION CLEAR PROCEDURE_CACHE;
```

### 3.4 ENGINE box — the two environment gates

```powershell
# MANDATORY. Defaults OFF.
$env:MEFOR_DELIVERY_PHASE_TIMING = "1"

# Windows-console safety for stage_residency.py (see the gotcha in §4.5).
$env:PYTHONUTF8 = "1"
```

> 🚨 **`MEFOR_DELIVERY_PHASE_TIMING=1` IS A HARD PREREQUISITE AND THE HARNESS NEVER SETS IT.** The harness only **parses** the log lines the engine emits when it is on (`shardcert_ladder.py` `_PHASE_RE` / `_claim_lines`). The **RUN-A spec omits it entirely**; the ladder's own `--help` epilog mentions it only in passing ("Set MEFOR_DELIVERY_PHASE_TIMING=1 for the send_ack/mark_done split"). **Unset ⇒ `claim_timing` and `claim_timing.by_stage` come back as the bland string `(none captured — MEFOR_DELIVERY_PHASE_TIMING off or no delivered rows)` — NOT an error.** That silently destroys STEP 2's headline deliverable and RUN-A's claimer check. You would complete the whole session and find the instrument blank.

**Confirm the store env is real, and confirm event verbosity, in the SAME shell that will launch the ladder:**
```powershell
Get-ChildItem Env: | Where-Object Name -like 'MEFOR_STORE_*' | Format-Table Name,Value
$env:MEFOR_ALLOW_INSECURE_TLS
.\.venv\Scripts\python.exe -c "from messagefoundry.config.settings import load_settings; s=load_settings(); print('backend =', s.store.backend); print('message_events =', s.diagnostics.message_events)"
```
**Required:** `backend = sqlserver` (or the `StoreBackend.SQLSERVER` enum) and `message_events = all`.

> 🚨 **THE #1 SESSION-KILLER.** A missing/partial `MEFOR_STORE_*` env does **not** error. `StoreSettings` defaults to **`backend = sqlite`, `path = messagefoundry.db`** — so `stage_residency.py` will happily **create a brand-new empty SQLite file in your cwd**, find nothing, and exit 1 printing *"NO COMPLETE-PATH MESSAGES FOUND — most likely the store was reset by a later run."* It blames the reset trap **while never having contacted SQL Server at all**, and you will believe you were too slow and burn the soak. **Treat any stray `messagefoundry.db` appearing next to you as proof you were pointed at SQLite.**
>
> Likewise, if `message_events` is `errors` or `off`, the `received`/`routed`/`transformed`/`delivered` rows are **never written** — a third distinct way to hit the same misleading error.

Also confirm `MEFOR_ALLOW_INSECURE_TLS`: **shardcert injects it into its own subprocesses**, but `stage_residency.py` does not. If the store hop runs with `trust_server_certificate=true` / `encrypt=false`, the script dies with `ValueError: SQL Server TLS is weakened … set MEFOR_ALLOW_INSECURE_TLS=1`. **VERIFY ON THE BOX** and export it in your shell if so.

### 3.5 🚨 ENGINE box — THE STALE-ENV SWEEP (run this on EVERY arm)

**The harness merges your launching shell's environment as the BASE of the child env** — `node_env = {**os.environ, **store_env, **shape_env, **escapes}` (`harness/load/shardcert.py:1559`; single-box twin at `:700`). **So ANY stale `MEFOR_PIPELINE_*` export silently reconfigures the engine in every arm of both runs, invisibly — it appears in no harness output and in no report JSON.** The immediately preceding session (P0) exported exactly such vars (`MEFOR_PIPELINE_BATCH_HANDOFF_STATEMENTS=false` was its A/B knob). A leftover in a wrapper script or a machine-level env var makes every number in both runs a measurement of an unknown configuration.

**Run this in the SAME shell that launches the ladder, on EVERY arm, and paste the output into the arm's `env_pipeline.txt` (§8):**
```powershell
Get-ChildItem Env: | Where-Object Name -like 'MEFOR_PIPELINE_*'          # ONLY this arm's knob may appear
Get-ChildItem Env: | Where-Object Name -like '*INLINE*'                  # must be EMPTY
$env:MEFOR_DELIVERY_PHASE_TIMING                                          # must be 1
.\.venv\Scripts\python.exe -c "import os; from messagefoundry.config.settings import load_settings; print(load_settings(environ={**os.environ}).pipeline.model_dump())"
git diff --stat HEAD -- harness/config/shardcert/graph.py                 # must be EMPTY
```

**Why the `*INLINE*` and `graph.py` checks:** the **ADR 0057 inline fast-path** emits **no `transformed` event**. If a soak runs with it on, **every message fails the four-event completeness test**, `messages_complete = 0`, and you get exit 1 with the same misleading "store was reset" message. It is **OFF by default** and the merged shardcert graph does not enable it — **but P0 required hand-editing an env-driven `inline=` into `harness/config/shardcert/graph.py:145`.**

### 3.6 Your rig wrapper scripts are NOT in the repo — read them, and dump the env FROM INSIDE them

`ladder_run.ps1` / `p0_ladder_run.ps1` live only on the rig. **P0 recorded that `ladder_run.ps1` HARDCODES `--dests 8` and `--sink-count 8` and never passes `--handlers`/`--delivering`** (they are direct Python kwargs, not env reads, so `MEFOR_SHARDCERT_*` env vars are silently overridden). **Read them before the first arm.**

> 🚨 **If a wrapper launches the ladder with a scrubbed environment** (`Start-Process -UseNewEnvironment`, a scheduled task, a nested shell), **your `$env:MEFOR_PIPELINE_*` export never reaches the child** — and RUN-A silently runs nine C1s. **This is the ONE remaining way the env override can fail.**
>
> **➡️ Add the §3.5 sweep as the LAST LINE INSIDE the wrapper, immediately before it launches the ladder, redirecting to `env_pipeline.txt`.** A dump taken from your interactive shell does not prove what the child saw. **An arm with no in-wrapper env dump is VOID (§8).**

### 3.7 The `<ANGLE BRACKET>` values — you already know these; ECHO THEM BACK

**The engine-box session already holds these rig values from prior sessions — the owner is not supplying them, and you should not ask for them.** They are **not derivable from this document or from the repo**, so they must be **stated explicitly in the handback (§8)**: a number is uninterpretable without knowing which paths, ports and database produced it.

**➡️ Before arm 1, echo the filled-in table into `<OUT_ENGINE>\rig_values.txt`** and re-verify the two starred constraints below — they are the ones that silently ruin a session, and a value that was correct last month may not be correct today.

| placeholder | what it is |
|---|---|
| `<ENGINE_IP>` / `<LOADGEN_IP>` | the two box addresses |
| `<SINK_PORT>` | the sink port band base the drive binds |
| `<COORD_DIR>` | ★ **a directory BOTH boxes can read AND write** (share/UNC). See the warning below. |
| `<KEEP_LOGS_DIR>` | ★ ENGINE-box base for node logs. **Must NOT be on the instance-store volume.** |
| `<OUT_ENGINE>` | ★ ENGINE-box artifact dir. **Must NOT be on the instance-store volume.** |
| `<OUT_LOADGEN>` | LOAD-GEN-box artifact dir (where every `--report-json` lands) |
| `<OUT_STORE>` | STORE-box artifact dir (DMV/CPU captures) |
| `<BENCH_DB>` | the bench database name |
| `<SERVICE_NAME>` | the SQL Server service name (§3.2) |

> ★ 🚨 **`<COORD_DIR>` MUST BE SHARED.** The coord is a **file drop**: `FileDropCoord._path` writes `<dir>/<run_id>.<MSG>.json` (`harness/load/coord.py:155`). **A per-box local path produces a silent rendezvous HANG** that ends in a `CoordTimeout` after `--drive-start-timeout` (300 s) / `--soak-timeout` (900 s). **A hang has TWO causes, not one:** (a) a `--rate-ladder` / `--run-id` / `--hold-seconds` mismatch between the boxes; (b) **`<COORD_DIR>` is not actually shared.** Check both.

> ★ 🚨 **`<KEEP_LOGS_DIR>` AND `<OUT_ENGINE>` MUST NOT SIT ON THE INSTANCE-STORE VOLUME.** The engine box's instance-store (`mfbench`) volume is **wiped on any STOP/START of the instance** — so a stop between arms, or between the session and the handback, **destroys every artifact you produced.** The artifacts ARE the deliverable; the throughput numbers are not reproducible without them. **Verify the drive letter before arm 1**, not after. *(And per §7: you may not stop the instance yourself regardless — that is the owner's call, every time.)*

---

## 4. STEP 2 — THE INSTRUMENTED SOAK (do this first; it is cheap)

### 4.1 What it is for

For the first time ever, decompose a message's wall-clock into **where it actually sits**:

```
A   = ts(routed)      − ts(received)      ingress residency  + ingress claim  + route_only
B   = ts(transformed) − ts(routed)        routed residency   + routed claim   + transform_one
C   = ts(delivered)   − ts(transformed)   outbound residency + outbound claim + send + complete
E2E = ts(delivered)   − ts(received)      the whole life
```
All four timestamps are stamped by the **engine's own clock** — no cross-box skew to correct. **Goal: locate the residual, and — for the first time — compute it against the TRUE per-stage claim.** A term that dwarfs its stage's measured claim/service time is **idle waiting**, and that is the whole question.

### 4.2 Shape — reproduce the c6-n4x2 operating point

| parameter | value | why |
|---|---|---|
| shards (N) | **4** (`a,b,c,d`) | c6-n4x2 |
| `--dests` | **8** | c6-n4x2. **⛔ NEVER `--dests 1` — that was P0's mechanism-test shape (D=1 ⇒ 2 events/msg, not 9) and it is NOT a capacity figure.** |
| `--handlers` / `--delivering` | **leave UNSET** | both default to `--dests` ⇒ H = D = 8 ⇒ **`events_per_message = 1 + D = 9`** |
| `--lanes-per-shard` | **4** | c6-n4x2 ran 16 sender bands = 4 shards × 4 lanes |
| `--driver-count` | **4** | must divide `shards × lanes` = 16 |
| `--sink-count` | **leave UNSET** | derives to `min(8, sink_ports)` = 8, matching c6-n4x2 |
| claim mode | **pooled** (the default) | shipped default |
| rate | **8 ingress/s**, single rung, soak rate PINNED to 8 | see the note below |
| soak hold | **900 s** | matches c6-n4x2; gives ~7,200 complete-path messages |

> ⚠️ **`--persistent` (ADR 0067 W1 fix) — RULING.** It is **not serialized into the report JSON**, so it cannot be proven from the c6-n4x2 artifact. **Cross-check your own C6 invocation in the rig runbook and match it. If the runbook is ambiguous: USE `--persistent`** (the documented recipe). **Whichever way it is settled, hold it IDENTICAL across STEP 2 and every RUN-A arm** — a value that varies between arms voids RUN-A outright. **Record the choice in the handback §7.**

> ⚠️ **`--soak-rate 8` offers ~4% ABOVE the honest rate c6-n4x2 actually proved** (its drain-discounted `ceiling.pinned_ingress_rate = 7.684`). A `SOAK_NOT_SUSTAINED` is therefore plausible. **That does NOT void STEP 2.** STEP 2 is a **decomposition, not a capacity claim**: only `messages_complete` (the §4.7 band) and the four-event completeness gate it. We keep `8` for shape fidelity with c6-n4x2. If you prefer the honest rate, drop `--soak-rate` and accept ~7.7 — either is fine; **say which you did and why.**

### 4.3 Pre-flight — the mandatory clear (STORE box)

```sql
USE <BENCH_DB>;
SELECT COUNT(*) AS rows_before, COUNT(DISTINCT message_id) AS msgs_before,
       MIN(ts) AS first_ts, MAX(ts) AS last_ts
  FROM message_events;              -- ⬅️ RECORD THIS NUMBER IN THE HANDBACK.

DELETE FROM message_events;
SELECT COUNT(*) AS rows_after_clear FROM message_events;   -- must be 0
```
*(`DELETE`, not `TRUNCATE`, is fine — nothing references `message_events`. This is a bench-store data reset, not a rig teardown.)*

### 4.4 Run it

**ENGINE box** (start this first):
```powershell
$env:MEFOR_DELIVERY_PHASE_TIMING = "1"
$env:PYTHONUTF8 = "1"
New-Item -ItemType Directory -Force <OUT_ENGINE> | Out-Null

.\.venv\Scripts\python.exe -m harness shardcert-engine-ladder `
  --shards a,b,c,d --dests 8 --lanes-per-shard 4 --persistent `
  --claim-mode pooled --store sqlserver `
  --rate-ladder 8 --hold-seconds 60 --drain-timeout 150 --soak-hold-seconds 900 `
  --sink-port <SINK_PORT> --sink-host <LOADGEN_IP> --inbound-bind-host 0.0.0.0 `
  --keep-logs-dir <KEEP_LOGS_DIR>\s2 --coord-dir <COORD_DIR> --run-id s2-resid
```

**LOAD-GEN box** (start right after; the two halves rendezvous through the shared coord dir):
```powershell
.\.venv\Scripts\python.exe -m harness shardcert-drive-ladder `
  --engine-host <ENGINE_IP> `
  --rate-ladder 8 --hold-seconds 60 --drain-timeout 150 --soak-hold-seconds 900 `
  --soak-rate 8 --driver-count 4 --sink-host 0.0.0.0 --insecure `
  --coord-dir <COORD_DIR> --run-id s2-resid --report-json <OUT_LOADGEN>\s2-resid.json
```

**Non-negotiables:**
- `--rate-ladder`, `--hold-seconds`, `--drain-timeout`, `--soak-hold-seconds` and `--run-id` must be **byte-identical on both boxes.** A mismatch is a coord-rendezvous **hang** (the other cause is an unshared `<COORD_DIR>` — §3.7).
- **`--keep-logs-dir` is an ENGINE-box flag only.** `--soak-rate` and `--report-json` are **LOAD-GEN-box flags only.**
- **Leave `--soak-drain-timeout` UNSET on both boxes.** It defaults to `None` ⇒ coupled to `--drain-timeout`. The old `--soak-drain-timeout 30` recipe **starves the tail-absorption window and fabricates a FALSE `FROZEN_TAIL` on a healthy soak.**
- The **consolidated report JSON is written on the LOAD-GEN box only.** The engine box writes only per-shard node logs under `--keep-logs-dir`.
- ⚠️ **S2's `ceiling.sustained_events_per_s` will be UNBRACKETED (`ceiling.bracketed == false`) and is NOT QUOTABLE.** A single-rung ladder never collapses, so nothing pins the ceiling from above — the number (~72) is just `offered_rate × 9`, **the offered load.** **Do not carry it into the handback as a throughput result.**
- **Start the `/status` sampler NOW** — §4.6 item 2. It must be running for the whole soak.
- **Capture the store box's usual per-arm artifacts** (`cpu_soak.csv`, `loadgen_cpu_soak.csv`, `storedmv_soak.txt`, `storepage_soak.txt`) exactly as for C5/C6/C7/P0.

### 4.5 🚨 THE DECOMPOSITION — RUN IT NOW, BEFORE ANYTHING ELSE STARTS

> **The moment the drive box prints its report, run this. Do not start another arm. Do not re-run the ladder "to be safe."**

**ENGINE box, SAME shell, SAME cwd, SAME `MEFOR_STORE_*` env as the ladder:**
```powershell
$env:PYTHONUTF8 = "1"
$env:MEFOR_ALLOW_INSECURE_TLS = "1"       # only if the store hop is TLS-weakened — see §3.4
New-Item -ItemType Directory -Force <OUT_ENGINE> | Out-Null     # ⬅️ MANDATORY — see below

.\.venv\Scripts\python.exe scripts\bench\stage_residency.py --json <OUT_ENGINE>\s2-residency.json `
  | Tee-Object -FilePath <OUT_ENGINE>\s2-residency.txt
```

> 🚨 **`stage_residency.py` does NOT create the `--json` parent directory and does NOT guard `OSError`** — it calls `args.json.write_text(...)` bare (`scripts/bench/stage_residency.py:196-197`), *after* printing the table. **So if `<OUT_ENGINE>` does not exist, you get the table on stdout and then a `FileNotFoundError` traceback, and NO JSON.** (This is unlike the harness's own `_write_json_report`, which mkdirs and swallows `OSError` — `harness/__main__.py:838-852`.) **`New-Item -ItemType Directory -Force` first, and `Tee-Object` so the table survives regardless.**
>
> **If the JSON write fails anyway: the data is still in `message_events` and a re-run is SAFE** — `message_events` is not wiped until the next shardcert run starts. Fix the path and re-run the script. **Just do not start another shardcert run first.**

**The tool has exactly TWO flags: `--json PATH` and `--limit N`.** There is **no `--dsn`, no `--db`, no `--config`, no `--since`, no `--run-id`.** It resolves the store from `load_settings()` — the same `MEFOR_STORE_*` env the engine uses.

- **⛔ DO NOT PASS `--limit`.** It does **not** cap the SQL scan (the whole table is fetched anyway) and it does **not** take the newest messages — it breaks out of an **unordered** dict **before** the completeness filter, yielding an arbitrary, biased subset that looks perfectly healthy. Its own docstring's *"cap the scan"* is wrong; the `--help` text is the accurate one.
- **`--help` CRASHES on a Windows console** (`UnicodeEncodeError` — the module docstring contains a U+2212 MINUS SIGN that cp1252 cannot encode). **The tool is not broken.** `$env:PYTHONUTF8 = "1"` fixes it; the normal run path is cp1252-safe either way.
- **Exit codes:** `0` = table printed. `1` = zero complete-path messages **OR a store-open failure (traceback)** — two very different things behind one code. **Gate on the printed table and the JSON file existing, never on the exit code alone** (ADR 0101 rule 1).

### 4.6 What else to capture from the same soak

`stage_residency.py` prints **only** the four residency rows (A / B / C / E2E, with n / mean / p50 / p95 / p99). **It does not print the claim split or the pool queueing-vs-service split.** Capture them or the comparison is impossible.

**1. The TRUE per-stage claim — a LOAD-GEN BOX command.** The consolidated report is written on the load-gen box. **Run this THERE** (or copy `s2-resid.json` to the engine box first):
```powershell
# ⬅️ LOAD-GEN BOX
.\.venv\Scripts\python.exe -c "import json;d=json.load(open(r'<OUT_LOADGEN>\s2-resid.json'));print('result =',d['result']);print('by_stage keys =',list((d['soak']['claim_timing'].get('by_stage') or {}).keys()));print(json.dumps(d['soak']['claim_timing'].get('by_stage'),indent=2));print('flat blend (NOT the outbound claim) =',d['soak']['claim_timing']['claim_mean_ms'])"
```
**Expect THREE stages: `ingress`, `routed`, `outbound`.** The shardcert graph has **no LOOPBACK inbound** (`harness/config/shardcert/graph.py` is MLLP-only), and the RESPONSE dispatcher is built **only** when one exists (`messagefoundry/pipeline/wiring_runner.py:2274-2277`, `_has_loopback_inbound`). **So there is no `response` stage in THIS graph, even though the engine has four stages in general** — the "four-stage blend" language in the source docs describes the engine, not the shardcert bench. **Record whatever keys ACTUALLY appear and report the full set.** If a `response` key shows up, that is itself a finding — report it, and recompute §0's claimer duty cycle from the observed dispatcher count.

> ⚠️ **The flat `claim_mean_ms` is an n-weighted MULTI-STAGE BLEND. It is neither the outbound claim nor any single stage, and THE DIRECTION OF ITS BIAS IS UNKNOWN** until `by_stage` is read — the per-stage `n` and mean have never been measured; that is exactly what `by_stage` exists to produce. **Read `by_stage.outbound.claim_mean_ms`. Report BOTH, and report the ratio — it is a first.** Every `claim_mean` this programme has ever reasoned from is the blend.

**2. The pool queueing-vs-service split — a BACKGROUND SAMPLER, not two point reads.**
⚠️ **These fields are NOT in any report JSON** — PR #1008 wired them into harness dataclasses that nothing serializes. **They must be scraped from the engine's `GET /status`** at `pool.acquire_wait.count` / `.mean_ms` / `.p95_ms` / `.p99_ms`.

> 🚨 **YOU CANNOT SAMPLE "AT THE END" — THE FLEET IS ALREADY DEAD.** The ladder spawns a **FRESH shard fleet per rung** and tears it down when the rung ends (`shardcert_ladder.py:1793-1826` for the soak). **By the time the drive box prints its report, the shard processes are GONE and `/status` is unreachable.**
>
> **Read the ports from the SOAK's OWN coord drop — NOT "the SHARDS_READY file".** There is one drop **per rung**: `FileDropCoord._path` = `<dir>/<run_id>.<MSG>.json` (`coord.py:155`) and the soak's coord is `base.for_run(f"{run_id}.soak")` (`shardcert_ladder.py:1793`). So:
> - **soak:** `<COORD_DIR>\<run-id>.soak.SHARDS_READY.json`  ⬅️ **this one**
> - climb rungs: `<COORD_DIR>\<run-id>.r0.SHARDS_READY.json`, `.r1.`, … — **these carry DEAD api_ports. Do not use them.**
>
> The payload carries `api_ports` (and the per-shard `nodes[].pid`). Ports are **ephemeral** (`bind :0`) — **never hardcode a URL.** Auth is off during a shardcert run, so `/status` and `/stats` are reachable token-free.

**Start a sampler as soon as the soak's drop file appears, and let it run for the whole soak.** Poll every **15 s**, appending one line per sample to `<OUT_ENGINE>\status_poll.jsonl`:
```
{ "t": <epoch>, "port": <p>, "acquire_wait": {count, mean_ms, p95_ms, p99_ms}, "empty_claims_idle_poll": <n>, "empty_claims": <n> }
```
Afterwards, take the **windowed difference between any two IN-SOAK samples** (not the first-vs-last of the whole run):
```
windowed_mean_ms = (mean_b*count_b − mean_a*count_a) / (count_b − count_a)
store_service_ms ≈ by_stage.outbound.claim_mean_ms − windowed_mean_ms      # an ESTIMATE, not an identity
```
- The counters are **cumulative since engine-process start and never reset.** A single reading is meaningless.
- ⚠️ **Semantic caveat, report it:** `record()` fires on **every** pool acquire, not only ones that waited — so `count` is effectively a **total store round-trip counter** and `mean_ms` is **diluted by zero-wait acquires**. A small mean does **not** mean "no queueing". **Read p95/p99 for the tail.** And `acquire_wait` is **one global histogram across ~68 call sites**, so the subtraction above is an **estimate with that caveat attached, not an identity.**

**3. ⚠️ The e2e latency histogram does NOT reach the two-box rig at all.** `e2e_count`/`e2e_p50_ms`/`e2e_p99_ms` exist only on the **single-box** `ShardCertReport` dataclass and are not even in its `to_json_dict()`. **Do not go looking for them in the ladder JSON. The E2E row from `stage_residency.py` IS your end-to-end latency measurement.**

### 4.7 STEP 2 manipulation check — PRE-REGISTERED, BLOCKING

**`messages_complete` from `stage_residency.py` must be consistent with the soak's own message count from the report JSON.**

At 8 ingress/s: `soak.acked ≈ 7,200` over the 900 s soak, plus **~480 from the single 60 s climb rung** (the ladder resets the store per rung — but **not** `message_events`). So:

| observed | verdict |
|---|---|
| `messages_complete` ≈ **7,000–8,200** | ✅ **GREEN.** Proceed. State in the handback that the table blends the 60 s climb rung (~6% of messages) with the 900 s soak — **do not present it as "the soak" without that caveat.** |
| `messages_complete` **≫ 8,200** | ⛔ **VOID.** `message_events` was not cleared. The A/B/C/E2E numbers are a cross-run blend. **Not a result. Clear the table and re-run the soak.** |
| `messages_complete` = **0** (exit 1) | ⛔ **VOID.** Three candidate causes, in order of likelihood: (a) you were pointed at SQLite, not SQL Server (§3.4); (b) `message_events` ≠ `all` (§3.4); (c) the ADR 0057 inline path was enabled, so no `transformed` event was ever written (§3.5). **It is NOT necessarily "you were too slow."** Diagnose before re-running. |

Also confirm the shape from the report JSON (free, pre-registered):
`topology.dests == 8` · `topology.handlers == 8` · `topology.delivering == 8` · `topology.events_per_message == 9` · `soak.sink_received == soak.acked * 8` · `soak.no_loss == true`.

> ⚠️ **`result` for STEP 2 is a DIAGNOSTIC, not a gate.** A `SOAK_NOT_SUSTAINED` (plausible — see §4.2's `--soak-rate 8` note) **does NOT void the A/B/C/E2E table.** Record it, explain it, and keep the decomposition.

### 4.8 What STEP 2's result MEANS

There is **no** pass/fail here — **STEP 2 is a decomposition, not a test.** It has no null band and cannot be "negative." For the first time, compute the residual against the **TRUE per-stage claim** from `claim_timing.by_stage`:

- **If `C` (transformed→delivered) carries the bulk of E2E and dwarfs `by_stage.outbound.claim_mean_ms + mark_done + send_ack`** → the residual is **outbound-stage idle waiting**, located. The next question becomes *what is the lane waiting FOR* — and RUN-A's sweep-clock arms speak directly to one candidate (discovery latency).
- **If `A` or `B` carries it** → the residual is **upstream of outbound entirely**, and the "outbound lane is idle" framing has been pointing at the wrong stage. That would be a major finding on its own.
- **If all three terms are small and E2E is small** → the per-message life is fast and the ceiling is not a per-message-latency phenomenon at all; the constraint is throughput-side (concurrency/admission), not residency.

**Report the numbers. Do not name a mechanism from them.** Mechanism-naming from a table is C4's grave.

---

## 5. STEP 3 — RUN-A, THE STORE-CAUSALITY SIGN TEST

### 5.1 What it is for

`pooled_sweep_interval` (default **0.25 s**) sets the frequency of `list_fifo_lanes` ← `StageDispatcher._sweep_loop` — a **clock-driven, message-rate-independent** store scan. It is **the only exogenous manipulation of store load available to this programme that is orthogonal to message flow.** Slow the clock 4× and you cut the scan's rate 4× **without touching the per-message path at all.**

> ⚠️ **HOW BIG IS THE SCAN? WE DO NOT KNOW.** The often-quoted **"47.5% of store CPU"** is **C4's number: measured on the N=16 COLLAPSED arm, on the 8-vCPU engine box, VERDICT WITHHELD, prose-only, never re-measured after the upsize.** It is **not admissible** and it carries an `at N=16` qualifier the RUN-A spec silently drops. **The scan's share at N=4 on the current 16-vCPU rig is UNKNOWN — and this run will measure it.** **The store-CPU drop you observe is a RECORDED DOSE, not a gate** (§5.5). If the dose turns out to be small, the run still bounds the effect **at that dose** — report it as such. It does **not** void the arm.

**The two live models predict OPPOSITE SIGNS. Read the SIGN, not the magnitude:**

| model | sweep 0.25 → **0.0625 s** (4× faster clock, more scan) | sweep 0.25 → **1.0 s** (4× slower clock, less scan) |
|---|---|---|
| **CLOCK-GATE** — discovery latency binds | throughput **UP** | throughput **DOWN** |
| **SCAN-TAX** — store CPU binds | throughput **DOWN** | throughput **UP** |
| **NEITHER** — null | flat | flat |

**Zero engine code. Zero harness code — verified, with citations, so you do not re-litigate it on the box:**

> ⚠️ **The spec (`PLAN-ENGINE-ATTRIBUTION.md` §6) lists a required harness delta: "`shardcert.py` — pass the two `MEFOR_PIPELINE_*` vars into the `serve --shard` subprocess env (~10 lines)". THAT WORK IS NOT NEEDED. Do not burn rig time building it.**
> - `node_env = {**os.environ, **store_env, **shape_env, **escapes}` — **`os.environ` is the BASE of the merge**, so a var exported in the launching shell already lands in the child (`harness/load/shardcert.py:1559`; single-box twin `:700`).
> - The **only** `MEFOR_PIPELINE_*` key the harness overwrites is `CLAIM_MODE` (`shardcert.py:1562`).
> - `_env_overrides` parses `MEFOR_<SECTION>_<KEY>` with `pipeline` in `_SECTIONS` (`messagefoundry/config/settings.py:116`, `:2604-2612`) → `pooled_sweep_interval` (`:894`); `serve` passes it through (`messagefoundry/__main__.py:1750`).
>
> **THE ONE RESIDUAL EXPOSURE:** a wrapper that launches the ladder with a **scrubbed environment** (`Start-Process -UseNewEnvironment`, a scheduled task, a nested shell). **That is why the env dump must be taken FROM INSIDE the wrapper (§3.6), not from your interactive shell.**

### 5.2 The arms

| # | Arm | N | `sweep` | `K` | Purpose |
|---|---|---|---|---|---|
| **C1** ×3 | control | 4 | 0.25 (unset) | 1 | shipped default — **interleaved: start / middle / end** |
| **S-slow** ×2 | slow clock | 4 | **1.0** | 1 | **★ THE LOAD-BEARING ARM — REPLICATED** |
| **N1-C** | control | **1** | 0.25 (unset) | 1 | N=1 deconfounder baseline |
| **N1-S** | slow clock | **1** | **1.0** | 1 | isolates the pure CPU-tax term |
| **S-fast** | fast clock | 4 | **0.0625** | 1 | opposite-direction confirmation |
| **K4** | claim supply | 4 | 0.25 (unset) | **4** | positive control on the claim path (predicted FLAT) |
| **S-xslow** | extreme | 4 | **4.0** | 1 | dose-response; confirms S-slow's sign or exposes a knee |

**Why S-slow is replicated (a CHANGE from the spec, made BEFORE the run — legitimate; ADR 0101 only forbids moving a threshold AFTER seeing a number):** the null band is ±8% and single-arm run-to-run noise on this rig is **±5–8%**. C1 is replicated 3×, so `mean(C1)` — the **denominator** — is well estimated. But a **singleton** S-slow carries the **full single-arm noise in the numerator**, so `R(S-slow) = 1.08` would sit at roughly **1σ of pure noise**: a true +8% effect and a noise excursion would produce the identical verdict. **That is the exact mechanism behind the two retractions this discipline exists to prevent.** **`R(S-slow)` is therefore taken from the MEAN of its two replicates.**

- **N=16 is EXCLUDED.** It collapses, and ADR 0101 forbids quoting a ceiling from a collapsed arm.
- ⚠️ **The source session handoff says RUN-A moves the knob "in both directions at N=1 and N=4." IT DOES NOT.** Both directions are run **only at N=4**. At N=1 there are exactly two arms: `N1-C` (0.25) and `N1-S` (1.0). **There is no fast-clock arm at N=1.**

### 5.3 ⏱ THE TIME BUDGET — COMPUTE IT BEFORE ARM 1, AND CUT ARMS, NEVER THE LADDER

**A ladder rung is a FULL FLEET CYCLE, not a rate change.** `_run_ladder_step` → `run_shardcert_engine` → `_reset_store` + shards started **strictly one-at-a-time** behind health gates + per-lane inbound port preflight (`shardcert.py:1250-1275`), while the drive box **respawns K+M fresh child processes every rung** (hence `--drive-start-timeout` defaults to **300 s**). Per rung: `hold 60 s` + measured drain (up to `--drain-timeout 150`) + bring-up/teardown.

> ### ➡️ RUNG-0 GIVES YOU THE PER-RUNG WALL CLOCK FOR FREE. TIME IT.
> **Before arm 1, compute:**
> `arm ≈ (rungs run before the early-stop) × (60 s + measured drain + measured bring-up) + 600 s soak + soak drain`
> `session ≈ 2 discovery climbs + (arms × arm)`
>
> A realistic figure is **~40–60 min per arm ⇒ 7–10 hours for ten arms.** **Find out; do not assume.**

**PRE-REGISTERED PRIORITY / CUT ORDER.** Run in this order. **If the clock runs out, you STOP — you do NOT coarsen the ladder** (a coarse ladder manufactures a false null, §5.7):

| order | arm | status |
|--:|---|---|
| 0 | RUNG-0 discovery, N=4 | mandatory |
| 1 | **C1-a** | mandatory |
| 2 | **S-slow (1)** ★ | mandatory |
| 3 | **C1-b** | mandatory |
| 4 | **S-slow (2)** ★ | mandatory |
| 5 | RUNG-0 discovery, N=1 | mandatory |
| 6 | **N1-C** | mandatory |
| 7 | **N1-S** | mandatory |
| 8 | **C1-c** | **MANDATORY AND ALWAYS LAST — it closes the §5.6 session-validity gate. Never cut. If time is short, jump to it.** |
| 9 | S-fast | optional |
| 10 | K4 | optional |
| 11 | S-xslow | optional |

**Arms 0–8 are the MINIMUM VIABLE RUN and they are sufficient.** **S-slow alone discriminates the two models by SIGN** (SCAN-TAX ⇒ UP; CLOCK-GATE ⇒ DOWN; NEITHER ⇒ flat). S-fast is a *confirmation*, not a requirement; K4's own §2(a) arithmetic already predicts FLAT; S-xslow's dose-response is worthless if the primary point is not resolvable. **If S-fast is cut, say so and report the CLOCK-GATE verdict as UNAVAILABLE, not as flat.**

### 5.4 🚨 THE RATE LADDER — the single biggest way this run fakes its own answer

**The spec does not specify a rate ladder. This is the gap that will destroy the session if you improvise it.**

`ceiling.sustained_events_per_s` is derived from the **highest SUSTAINED CLIMB rung**, drain-discounted. The reference artifact c6-n4x2 ran `--rate-ladder 8` — **ONE rung** — and reports `ceiling.bracketed = false`, `first_collapse_ingress_rate = null`, `pinned_ingress_rate = 7.684`: nothing ever collapsed, so **the ceiling was never pinned from above** and 69.16 events/s is just **the offered load**.

> ### ⛔ ON A SINGLE-RUNG LADDER, EVERY ARM RETURNS ≈ offered_rate × 9, EVERY `R` LANDS AT 1.00, AND THE RUN REPORTS THE PRE-REGISTERED "★ NULL" HAVING MEASURED ABSOLUTELY NOTHING.

**RUNG-0 — a DISCOVERY climb, once per N, at the C1 config. Not an arm. `--no-soak` makes it cheap** (the climb early-stops at the first collapse, so a wide ladder is self-limiting):

```powershell
# ENGINE box, N=4 discovery.  Same shape as §4.2, no soak.
.\.venv\Scripts\python.exe -m harness shardcert-engine-ladder `
  --shards a,b,c,d --dests 8 --lanes-per-shard 4 --persistent --claim-mode pooled --store sqlserver `
  --rate-ladder 4:24:2 --hold-seconds 60 --drain-timeout 150 `
  --sink-port <SINK_PORT> --sink-host <LOADGEN_IP> --inbound-bind-host 0.0.0.0 `
  --keep-logs-dir <KEEP_LOGS_DIR>\disc-n4 --coord-dir <COORD_DIR> --run-id disc-n4

# LOAD-GEN box
.\.venv\Scripts\python.exe -m harness shardcert-drive-ladder `
  --engine-host <ENGINE_IP> --rate-ladder 4:24:2 --hold-seconds 60 --drain-timeout 150 `
  --no-soak --driver-count 4 --sink-host 0.0.0.0 --insecure `
  --coord-dir <COORD_DIR> --run-id disc-n4 --report-json <OUT_LOADGEN>\disc-n4.json
```
> ⚠️ **The floor is 4, NOT 8.** The only N=4 operating point this programme has ever measured is `pinned_ingress_rate = 7.684` — **unbracketed**, so the true ceiling under RUN-A's config (tempdb ON, which was already ON for C6 — yet the 90.0 headline is attributed to tempdb OFF; **the configuration is not predictable from any document**) **could be below 8.** A floor at 8 risks collapsing on rung 1. The extra rungs cost ~2 minutes and the climb early-stops anyway.

**Read `ceiling.pinned_ingress_rate` (call it C₄) and `ceiling.first_collapse_ingress_rate`. TWO recovery rules:**
- **If `bracketed == false`** (nothing collapsed) → the ladder never reached the ceiling. **RAISE the top and re-run the discovery.**
- **If the FIRST rung COLLAPSES** → the ladder FLOOR is above the ceiling; there is **no sustained rung**, `pinned_ingress_rate` is `null`, and any number you read is meaningless. **LOWER the floor and re-run the discovery.** **A `bracketed == true` with no sustained rung below the collapse is NOT a ceiling.**

**Repeat for N=1** with `--shards a`. ⚠️ **`--driver-count` must divide `shards × lanes` = 1 × 4 = 4 — so KEEP `--driver-count 4`.** Use a floor **well below** anything you might guess: `--rate-ladder 1:14:1`.

> ⚠️ **The N=1 ceiling has NEVER been measured by this programme.** C5's per-shard `R ∈ [2,3) msg/s` was measured under **8-way store contention, which does not exist at N=1.** Whether one shard sustains 2/s, 8/s or 20/s is **unknown**. **Budget for both recovery re-runs** — the spec's flat "~25 min per arm" does not.

**THE ARM LADDER — a FINE ladder that BRACKETS the discovered ceiling.**

`sustained_events_per_s = pinned_ingress_rate × events_per_message`, and `pinned_ingress_rate` is the **top sustained rung's drain-DISCOUNTED** rate (`offered × hold/(hold+drain)`, `shardcert_ladder.py:1524`). So **`R` moves in ladder-step jumps of `step / C`** — the step size **IS the resolution of your primary metric** — modulated by that rung's measured drain.

> ### ➡️ PRE-REGISTERED RESOLUTION: **effective null band = 8% + (step / C)**. Report it.
> - **Choose `step ≈ 0.03 × C`** (at C₄ ≈ 10 ⇒ **step 0.3**) so quantization stays ≈3% and the effective band stays ≈11%.
> - **Span `0.80 × C` → `1.25 × C`.** Nothing below 0.8×C carries information; the top must still bracket.
> - `--rate-ladder <0.80×C>:<1.25×C>:<0.03×C>` — e.g. C₄ ≈ 10 ⇒ **`8:12.5:0.3`**. *(Fractional steps parse fine — `parse_rate_ladder` uses `float()`, `shardcert.py:1031`.)*
> - **Use the SAME ladder string for every N=4 arm; derive a second from C₁ for the N=1 arms. Both boxes must carry the identical string.**
> - ⛔ **NEVER coarsen the step to save time. Cut an ARM instead (§5.3).** A coarse step manufactures a false null — which is precisely the outcome this run is pre-registered to produce anyway, so it would be undetectable.

**Also report, for EVERY arm:** the top-sustained rung's **RAW offered rate** AND its **measured engine drain**, alongside the discounted `pinned_ingress_rate`. **Drain at the ceiling is long and noisy** (a 20 s vs 60 s drain at the same offered rate is a 0.75× vs 0.50× discount) — **an `R` driven by drain variance must be VISIBLE, not silent.**

**SECONDARY CONTINUOUS COMPARATOR (report it, do not gate on it):** the soak's **`in_pipeline_slope`** at the **common pinned soak rate** (§5.5). It is a backlog-growth slope, not a quoted ceiling, so it does not violate ADR 0101 rule 2 — and because the soak rate is now pinned identically across arms at a given N, it is apples-to-apples and does not quantize.

### 5.5 Running an arm

**PRE-FLIGHT, EVERY ARM (including every discovery climb) — STORE box:**
```sql
USE <BENCH_DB>;
SELECT COUNT(*) AS rows_before FROM message_events;   -- ⬅️ RECORD in the arm's notes
DELETE FROM message_events;
```
> **Why every arm:** `_reset_store` never touches `message_events` (§1). Across two discovery climbs and ten arms it grows monotonically at ~9 rows/message — an indexed, insert-only table — so **every later arm would run against a bigger store than every earlier one.** That is a slow, one-directional store-side drift sitting underneath the ±10% C1 gate that decides whether the **whole session** is valid.

**ENGINE box — export the arm's knob FIRST, in the SAME shell (and see §3.6 if a wrapper launches the ladder):**
```powershell
$env:MEFOR_DELIVERY_PHASE_TIMING = "1"

# ---- pick exactly ONE per arm ----
# C1 / N1-C (control): CLEAR both. Do NOT set "0.25" — unset it, so the control exercises the shipped default path.
Remove-Item Env:\MEFOR_PIPELINE_POOLED_SWEEP_INTERVAL     -ErrorAction SilentlyContinue
Remove-Item Env:\MEFOR_PIPELINE_POOLED_CLAIMERS_PER_STAGE -ErrorAction SilentlyContinue

# S-fast:            $env:MEFOR_PIPELINE_POOLED_SWEEP_INTERVAL = "0.0625"
# S-slow / N1-S:     $env:MEFOR_PIPELINE_POOLED_SWEEP_INTERVAL = "1.0"
# S-xslow:           $env:MEFOR_PIPELINE_POOLED_SWEEP_INTERVAL = "4.0"
# K4 (sweep stays at the DEFAULT — never move both knobs in one arm):
#                    $env:MEFOR_PIPELINE_POOLED_CLAIMERS_PER_STAGE = "4"
```

**Then run the §3.5 stale-env sweep and save it as the arm's `env_pipeline.txt` and `preflight_settings.txt`. An arm without both files is VOID (§8).**

**Then launch both halves** — same shape as §4.4, with these substitutions:

| arm | engine `--shards` | drive `--driver-count` | `--rate-ladder` (both boxes) | `--run-id` (both boxes) | drive `--soak-rate` |
|---|---|---|---|---|---|
| C1-a/b/c, S-slow ×2, S-fast, S-xslow, K4 | `a,b,c,d` | `4` | `<N4_LADDER>` | `runa-<arm>` | **`<0.85 × C₄>`** |
| N1-C, N1-S | `a` | `4` | `<N1_LADDER>` | `runa-<arm>` | **`<0.85 × C₁>`** |

> ### 🚨 `--soak-rate` MUST BE PINNED, AND IDENTICAL FOR EVERY ARM AT A GIVEN N.
> **With `--soak-rate` unset, `pick_soak_rate` (`shardcert_ladder.py:1072`) sets each arm's soak to THAT ARM'S OWN highest drain-discounted sustained rung — i.e. every arm soaks AT ITS OWN CEILING for 600 s.** Two consequences:
> 1. `SOAK_NOT_SUSTAINED` becomes a coin-flip at the ceiling, so the §5.6 `result == PASS` gate would VOID arms at random.
> 2. **Far worse:** the store-CPU and DMV snapshots would bracket soaks that ran at **DIFFERENT OFFERED LOADS per arm** — so a store-CPU drop caused by S-slow simply *soaking at a lower auto-picked rate* would read as a genuine sweep effect. **The dose measurement would be confounded by offered load.**
>
> **Pin it at `0.85 × C_N` (derived from RUNG-0). Record the pinned rate in the handback.** At 0.85×C the soak is below the ceiling, so `PASS` is achievable and the store-CPU / DMV comparison is apples-to-apples.

**Everything else is FIXED and IDENTICAL across every arm:**

`--dests 8` · `--lanes-per-shard 4` · `--persistent` (or the §4.2 ruling, held constant) · `--claim-mode pooled` · `--hold-seconds 60` · `--drain-timeout 150` · `--soak-hold-seconds 600` · `--soak-drain-timeout` **UNSET** · `--handlers` / `--delivering` / `--sink-count` **UNSET** · `--coord-dir <COORD_DIR>` · **ENGINE: `--keep-logs-dir <KEEP_LOGS_DIR>\runa-<arm>`** · **DRIVE: `--report-json <OUT_LOADGEN>\runa-<arm>.json`**

> ### 🚨 `--keep-logs-dir` IS PER-ARM. A FRESH DIRECTORY, EVERY ARM.
> It **defaults to a single shared `./shardcert-ladder-nodelogs`** (`harness/__main__.py:1457`), and the engine writes to **`<base>/<rung_suffix>/shard-<s>.log`** where `rung_suffix` is `r0…rN` or `soak` (`shardcert_ladder.py:426-429, 478-480, 1726-1728, 1797-1799`). **Those names are IDENTICAL across arms** — so nine arms pointed at one base directory **silently overwrite each other's `soak/shard-a.log`.** That destroys the K4 claimer evidence and the §8 `node-logs/` artifact for every arm but the last, and **under ADR 0101 rule 6 an arm with no manipulation-check evidence is VOID.**
> *(The measurement itself survives — `claim_timing` / `by_stage` is attached into the report JSON at run time from the rung's keep_dir, `shardcert_ladder.py:1764`. It is the raw logs and the blocking check that are destroyed.)*
> **`--keep-logs-dir` is an ENGINE-box flag. The drive half has no such flag.**

*(600 s soak, not 900. The soak is the steady-state window in which you take the store-CPU and DMV readings; the primary metric comes from the CLIMB, which is the dominant cost — see §5.3.)*

### 5.6 Manipulation checks — PRE-REGISTERED, BLOCKING. A failure is VOID, not a refutation.

> 🚨 **THE ENGINE NEVER TELLS YOU WHICH ARM IT RAN.** The effective sweep interval is **not logged at startup, not on `/stats`, and not in the report JSON.** There is **no in-band engine signal for the sweep interval.** **A forgotten export produces a silent duplicate C1 that will be scored as a valid S-arm.** The **only** proof of what you measured is: **(a) the store-side `list_fifo_lanes` execution rate (check 1) and (b) the per-arm in-wrapper env artifact (§3.6).** These are not a formality.

---

**★ CHECK 1 — THE STORE-SIDE SWEEP RATE. THE PRIMARY BLOCKING CHECK. PER-ARM.** *(STORE box.)*

Snapshot **BEFORE and AFTER EVERY arm's soak** and **DIFFERENCE**. `sys.dm_exec_query_stats` is cumulative and **evictable** — one reading at session end is a blended number across all arms and is meaningless.

```sql
SELECT SUM(qs.execution_count)   AS sweep_execs,
       SUM(qs.total_worker_time) AS sweep_worker_us,
       SYSUTCDATETIME()          AS at_utc
FROM sys.dm_exec_query_stats qs
CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) st
WHERE st.text LIKE '%SELECT DISTINCT%AS lane FROM queue%';
```
> ⚠️ **The predicate is a trap.** `list_fifo_lanes` is ad-hoc parameterized SQL with no proc name, and it shares its `CROSS APPLY … next_attempt_at FROM queue` shape with `claim_fifo_heads`. A `LIKE` on **that** fragment silently aggregates **both** and the check becomes noise. **Only `list_fifo_lanes` builds a `SELECT DISTINCT … AS lane FROM queue` derived table** (`messagefoundry/store/sqlserver.py:4818-4831`). **Match on the `DISTINCT`.** It has exactly **one caller**: `StageDispatcher._run_sweep_once` (`stage_dispatcher.py:1000`).

**NORMALIZE — a raw cross-arm `execution_count` ratio is confounded:**
```
observed_rate = Δsweep_execs / soak_seconds        [calls/s]
nominal_rate  = (N shards × 3 stage-dispatchers) / sweep_interval
```
*(3 dispatchers: INGRESS/ROUTED/OUTBOUND. The shardcert graph has no loopback inbound ⇒ no RESPONSE dispatcher — §4.6. **Confirm the dispatcher count from the `by_stage` keys** and recompute if it differs.)*

| arm | sweep | nominal (N=4) | nominal (N=1) |
|---|--:|--:|--:|
| C1 / N1-C / K4 | 0.25 s | 48 /s | 12 /s |
| S-slow / N1-S | 1.0 s | 12 /s | 3 /s |
| S-fast | 0.0625 s | 192 /s | — |
| S-xslow | 4.0 s | 3 /s | — |

**PASS BAND: `observed_rate` within `0.6×` – `1.4×` of nominal, on EVERY arm — INCLUDING C1 and N1-C.**
The band is deliberately generous, for two reasons **verified in code**:
- **The interval is a SLEEP FLOOR, not a period** (`stage_dispatcher.py:975-980`): the sweep's own work time is added on top, **and `_sweep_now` can fire the loop EARLY** (`:360, :432, :467`). So the observed rate can run under *or* over nominal.
- **One sweep can issue MULTIPLE `list_fifo_lanes` calls:** `_run_sweep_once` **PAGES** with an after-cursor while `len(page) == limit` (`stage_dispatcher.py:999-1014`), and pages scale with **BACKLOG**, which differs per arm.

**RULES:**
- ⛔ **An arm without a GREEN per-arm sweep-rate check is VOID and gets NO `R`.** *(A pairwise S-fast↔S-slow ratio is NOT sufficient: S-fast may not be run at all (§5.3), and it leaves S-xslow / K4 / N1-C / N1-S with no check. **N1-S is load-bearing** — a forgotten export there produces a silent duplicate of N1-C, `R(N1-S) ≈ 1.00`, and a true N=4 positive gets downgraded to INDETERMINATE.)*
- **SECONDARY (compute only if S-fast ran):** `execution_count` should scale **≥10×** across S-fast → S-slow (a 16× nominal interval range).
- ⚠️ **EVICTION RULE:** if the AFTER snapshot is **LOWER** than the BEFORE snapshot, the plan was **evicted mid-arm** ⇒ the check is **UNKNOWN, not RED**. Re-take the snapshots (re-run the arm). **Never score a non-monotonic pair.**
- ⚠️ **NEVER restart SQL Server or run `CLEAR PROCEDURE_CACHE` between arms** — it zeroes these counters (§3.2).

---

**CHECK 2 — THE CLAIMER CHECK** *(ENGINE box, K4 arm only.)* The engine's phase-timing line reports `claimers=K`. **It must read `4` in K4:**
```powershell
Select-String -Path <KEEP_LOGS_DIR>\runa-k4\*\shard-*.log -Pattern 'claim phase timing \(stage=' | Select-Object -First 20
```
*(The soak's logs land in `<KEEP_LOGS_DIR>\runa-k4\soak\shard-<id>.log`; the climb rungs in `\r<i>\`. This path only exists if you passed `--keep-logs-dir <KEEP_LOGS_DIR>\runa-k4` — §5.5.)*

---

**CHECK 3 — THE IDLE-POLL SIGNAL: DIRECTIONAL ONLY. NOT A PROOF, NOT A GATE.**
Expect `empty_claims_idle_poll` (from `/stats`, via the §4.6 sampler) to **fall on S-slow and rise on S-fast**. **No numeric expectation.**
> ⚠️ **`empty_claims_idle_poll` does NOT count sweep executions.** It counts **EMPTY CLAIMS whose lane was made ready by the sweep**: `StageDispatcher.mark_ready(..., woken=False)` (`stage_dispatcher.py:310-321`) → `record_empty(woken=False)` → `idle_poll` (`:193-198`; `wiring_runner.py:307-323`). And `_run_sweep_once` only readies a lane when its head is **DUE** (`:1005-1011`) — i.e. **when there IS work** — so on a healthy arm most sweep-sourced claims **return rows and increment nothing.** It is a race/backlog artifact and **can sit near zero in every arm.** Do not void an arm against it, and do not wave one through because the number "looked plausible."

---

**CHECK 4 — THE ARM ACTUALLY MEASURED A CEILING.**
`result == "PASS"` **AND** `ceiling.pinned_ingress_rate != null` **AND** `soak.no_loss == true` **AND** `engine.drained == true` **AND** `in_pipeline_final == 0`.
> ⚠️ **`result == PASS` ALONE IS INSUFFICIENT.** If an arm's ceiling falls **below** the ladder start, nothing sustains, the soak is *legitimately SKIPPED*, and `result_label` **still serializes `PASS`** ("correctness held, and the soak either sustained or was legitimately skipped", `shardcert_ladder.py:1332+`) — with `pinned_ingress_rate = null`. **A PASS that measured nothing.**

**CHECK 5 — FIFO INTEGRITY.** `lane_inversions == 0` and `lane_repeats == 0` **at `sweep = 1.0` and `4.0`.** **If a slow sweep breaks FIFO or loses a message, the sweep is on the HOT PATH, not a backstop — and that is itself the finding, stated louder.**

**CHECK 6 — CEILING BRACKETED.** `ceiling.bracketed == true` on every arm.
> ⚠️ **TWO OUT-OF-RANGE CASES ARE NOT VOID AND NOT NULLS — they are re-runs:**
> - **Sustained through the ladder TOP** (`bracketed == false`, nothing collapsed): **the ceiling ROSE above your ladder — this is the SCAN-TAX-LIVE case, the finding you came for.** **Extend that ladder's top and RE-RUN the arm in the same session.** It is **directional evidence (ceiling ≥ top)** — **never score it as flat.**
> - **Collapsed at the ladder BOTTOM** (no sustained rung, `pinned_ingress_rate == null`): **the ceiling FELL below your ladder.** **Lower the floor and RE-RUN the arm.**

**RECORDED DOSE (not a gate):** total store-box CPU during the soak, per arm, from `storedmv_soak.txt` / the CPU capture, plus the `sweep_worker_us` share. **Report the observed store-CPU delta on S-slow as the DOSE ACTUALLY DELIVERED.** If it is small, **the run still bounds the effect AT THAT DOSE — report it as such. DO NOT VOID THE ARM.** *(The old "≥30% CPU drop" gate came from C4's inadmissible N=16 share — see §5.1.)*

### 5.7 The session-validity gate

**C1 runs three times, interleaved (start / middle / end). If their spread exceeds ±10% of their mean, the SESSION IS VOID and NOTHING may be quoted.** That is a methodological kill, not a warning. **C1-c is therefore never cut (§5.3).**

> ⚠️ **There is NO drift control at N=1.** `N1-C` runs once. If the session has room, **run a second `N1-C`**; otherwise **state plainly in the handback that the N=1 leg is DIRECTIONAL ONLY** and carries no variance estimate.

> ⚠️ **The `R` denominator at N=1 is ambiguous in the spec.** It defines `R(arm) = sustained_events_per_s(arm) / mean(interleaved C1 controls)` — and C1 is an **N=4** arm. Taken literally, `R(N1-S)` would be divided by an N=4 control, which is meaningless. **The intent is obviously `R(N1-S) = N1-S / N1-C`. Compute it that way and say so.**

### 5.8 THE PRE-REGISTERED DECISION RULE — fixed before the run, not revisable after seeing data

**Primary metric:** `ceiling.sustained_events_per_s`, gated on **check 4** (`result == PASS` **and** `pinned_ingress_rate != null`) **and check 6** (`bracketed == true`) **and check 1** (per-arm sweep rate GREEN).

**`R(arm) = sustained_events_per_s(arm) / mean(interleaved C1 controls)`** · **`R(S-slow) = mean of its two replicates`** · **`R(N1-S) = N1-S / N1-C`**.

**NULL band: ±8%** *(single-arm run-to-run variance on this rig has been ±5–8%)* **PLUS the ladder's quantization, `step / C`.**
➡️ **Report the EFFECTIVE null band as `8% + step/C`** — at `step = 0.03 × C` that is **≈ ±11%**. **The run cannot detect an effect smaller than that. Say so.**

| Outcome | Condition | Verdict |
|---|---|---|
| **SCAN-TAX LIVE** | `R(S-slow) ≥ 1 + band` **at N=4 AND N=1** (monotone with S-xslow, if run) | **The store's clock-driven fixed cost is causally load-bearing.** The first positive. **Reproduce before publishing.** |
| **CLOCK-GATE LIVE** | `R(S-fast) ≥ 1 + band` **and** `R(S-slow) ≤ 1 − band` at N=4, **and flat at N=1** | Discovery latency gates the message path — T13b is not doing what its docstring says. **Reproduce before publishing.** *(Unavailable if S-fast was cut — report as UNAVAILABLE, not flat.)* |
| **CLAIM SUPPLY LIVE** | `R(K4) ≥ 1 + band` | The serial claim loop binds after all, and the spec's §2(a) arithmetic is wrong. **Reproduce.** |
| **★ NULL — THE STORE IS EXONERATED AS A CPU-BOUND RESOURCE** | **All arms within the effective band of C1, and check 1 GREEN on every arm** | **See below. THIS IS A SUCCESSFUL RUN.** State the **DOSE** (the observed store-CPU delta on S-slow): the exoneration holds **at that dose**. |
| **VOID** | check 1 RED on an arm (the knob did not engage) | **VOID, not a refutation. Re-run the arm.** Do not write it up as a null. |
| **INDETERMINATE** | anything else | **Report INCONCLUSIVE. Name no mechanism. Do not rescue post-hoc.** |

**★ What the NULL means — and why it is the most valuable result available:**

> You cut the store's clock-driven scan rate 4× and bought **nothing.** Combined with the bounds already established — engine ≤0.36 cores/shard, claimers ~17% busy, the outbound-lane residual, P0's txn elasticity of −0.115 — **the store's CPU is NOT causal at the dose delivered, the per-message path is not saturated, and the clock-driven overhead is not the wall.**
>
> That is not a consolation prize. **It retires the interpretation that drove C4, C5, C6 and C7** — four runs that all read "store at high CPU" as "store-bound" and hunted the store. And it forces the next run into the one class never tested: **what the store is WAITING on, not what it is BURNING.**

**And know what RUN-A does NOT do: it does not raise throughput.** Even a positive does not close the gap — the shortfall is measured in multiples, not percent. **This is an ATTRIBUTION run. Anyone reading a throughput number out of it as a deliverable has misread it.** *(Do not compute an illustrative "what if it rose X%" — there is no admissible dose to multiply by, and the 90 / 144 headlines may not be used as controls.)*

---

## 6. ⛔ DO NOT

- **Do NOT `git fetch` / `git pull` / `git checkout` on either box after the §3.1 capability check passes.** The build is **PINNED for the whole session** — both steps, all arms. Every comparison here is same-session.
- **Do NOT gate on `exit_code`.** Ever. The engine box's process returns 0 unconditionally; a collapsed drive run returns 0 too.
- **Do NOT quote a ceiling from a collapsed arm**, and **do not quote an unbracketed one** (`bracketed == false` ⇒ that number is the **offered load**). **Do not quote `sustained_events_per_s` from the STEP 2 soak at all.**
- **Do NOT A/B against C5/C6/C7/P0, or against the 90 / 144 headlines.** They are context, never controls. **C1 will not land on 90 or 144 — that is not a failure.** 90.0 is N=4 with tempdb **OFF**; 144.0 is N=8 × 2/shard with it **ON**. **RUN-A holds tempdb ON at N=4 — a configuration for which no published number exists.**
- **Do NOT reuse a `--keep-logs-dir` across arms.** The per-rung log filenames are fixed; a shared base silently clobbers the previous arm.
- **Do NOT leave `--soak-rate` unset in a RUN-A arm.** It auto-picks each arm's own ceiling and confounds the dose (§5.5).
- **Do NOT set `--dests 1`.** That was P0's mechanism-test shape (2 events/msg, not 9) and it is not a capacity figure.
- **Do NOT set `--claim-mode per_lane`.** It ships OFF and storms the store at 1,500 lanes. *(You cannot enable it by accident: the harness pins `MEFOR_PIPELINE_CLAIM_MODE` into the child env, overwriting anything you exported.)*
- **Do NOT move `pooled_claimers_per_stage` and `pooled_sweep_interval` in the same arm.**
- **Do NOT set `--soak-drain-timeout` explicitly.** Leave it coupled to `--drain-timeout`. A small explicit value fabricates a false `FROZEN_TAIL`.
- **Do NOT pass `--limit` to `stage_residency.py`.** It is a biased, arbitrary subset.
- **Do NOT restart SQL Server, or `CLEAR PROCEDURE_CACHE`, between RUN-A arms.** It zeroes the check-1 counters and re-colds the plan cache mid-session.
- **Do NOT revert tempdb metadata at the end.** The owner has **RULED ADOPT** — leave it **ON**.
- **Do NOT change `cost threshold for parallelism`.** Record it as-found (expected: 5).
- **Do NOT set `message_events` to `off` to "solve" the accumulation problem.** Clear the table instead.
- **Do NOT confuse the two 256s.** `pooled_claim_lane_chunk = 256` (max lanes per claim round-trip — the "chunk of 256" the `lanes_per_claim 1.081` finding refers to) and `pooled_max_processing_lanes = 256` (max concurrently-*processing* lanes) are unrelated settings.
- **Do NOT build the "~10 lines of harness delta" the RUN-A spec asks for.** It is unnecessary (§5.1).
- **Do NOT coarsen a rate ladder to save time. CUT AN ARM.**
- **Do NOT write up a VOID arm as a null.**

---

## 7. ⛔ TEARDOWN — A HARD RULE

> ### **NEVER stop, terminate, or tear down an EC2 instance. That is the OWNER's call, every time.**
>
> The store's `mfbench` database lives on an **instance-store NVMe volume**. An unsanctioned **STOP/START WIPES IT.** *(A plain reboot is safe. A SQL Server **service** restart is safe and is REQUIRED by §3.2.)*
>
> **`<OUT_ENGINE>`, `<OUT_LOADGEN>`, `<OUT_STORE>` and `<KEEP_LOGS_DIR>` must NOT live on the instance-store volume.**
>
> **SQL-side config reverts ARE fine to instruct** (MAXDOP, procedure cache) — **except tempdb metadata, which STAYS ON.**
>
> **When a run is banked: REPORT IT AND HOLD THE RIG.**

---

## 8. HANDBACK — exactly what to send back

**Collect artifacts from all THREE boxes after EVERY arm** (not at the end — a lost box loses everything), to a durable on-rig path, then transfer them over the same channel used for the C5/C6/C7/P0 handbacks.

**Which box writes what:**

| box | files |
|---|---|
| **LOAD-GEN** | `<arm>.json` (**the ONLY consolidated report**), `loadgen_cpu_soak.csv`, `provenance_loadgen.txt` |
| **ENGINE** | `node-logs/` (`<KEEP_LOGS_DIR>\runa-<arm>\`), `cpu_soak.csv`, `status_poll.jsonl`, `env_pipeline.txt`, `preflight_settings.txt`, `provenance_engine.txt`, **STEP 2 only:** `s2-residency.json` + `s2-residency.txt` |
| **STORE** | `storedmv_soak.txt`, `storepage_soak.txt`, `sweep_dmv_before.txt` / `sweep_dmv_after.txt`, the pre-clear `message_events` count |

**Folder** (house style): `OneDrive\Desktop\MEFOR\aws-bench\runa-store-causality-2026-07-13\HANDBACK_<YYYY-MM-DD>\`
**One document at the top: `HANDBACK_RUNA_<YYYY-MM-DD>.md`**, plus **ONE SUBDIRECTORY PER ARM**.

### Per-arm subdirectory (`<arm>/`) — attach all of:

| file | source box | notes |
|---|---|---|
| `<arm>.json` | load-gen | the `--report-json` |
| `env_pipeline.txt` | engine | **MANDATORY — dumped FROM INSIDE the wrapper (§3.6). An arm without it is VOID.** |
| `preflight_settings.txt` | engine | **MANDATORY — the §3.5 `load_settings()` print. An arm without it is VOID.** |
| `node-logs/` | engine | `<KEEP_LOGS_DIR>\runa-<arm>\` — the phase-timing source |
| `sweep_dmv_before.txt` / `sweep_dmv_after.txt` | store | the check-1 snapshots, bracketing the soak |
| `status_poll.jsonl` | engine | the §4.6 background sampler (whole soak) |
| `cpu_soak.csv` / `loadgen_cpu_soak.csv` | engine / load-gen | **report `max_core%`** |
| `storedmv_soak.txt` / `storepage_soak.txt` | store | |
| **STEP 2 only:** `s2-residency.json`, `s2-residency.txt` | engine | |

**Record `max_core%` on ALL THREE boxes.** *(The per-shard PID collector defect is fixed; the shard PIDs are published in the soak's `SHARDS_READY` coord drop if you want a per-PID capture.)*

### The document must state, in this order:

1. **Provenance — BOTH boxes, separately.** `git rev-parse HEAD` + `git status --short` on the **ENGINE** box (**the 5 modified files ARE the cherry-pick — that is the only evidence of it**) and on the **LOAD-GEN** box. State whether you cherry-picked #1008's five files or took the whole tip, **and on which box(es)**. Engine box instance type. Confirmation that the §3.1 capability check passed on **BOTH** boxes. ⚠️ **State plainly: `run.commit_sha` in the report JSON is the LOAD-GEN checkout's HEAD, NOT the engine build, and a cherry-pick is invisible to it.**
2. **Store config as-found and as-run.** `IsTempdbMetadataMemoryOptimized` before and after. Instance MAXDOP, cost threshold, DB-scoped MAXDOP, visible-online schedulers. Whether `tempdb_xtp` already existed. **Whether a SQL Server service restart was performed, and WHEN (it must be BEFORE the STEP 2 soak and never between arms).** **Confirm tempdb metadata was LEFT ON.**
3. **★ The `message_events` pre-clear counts** — the STEP 2 one, and one per RUN-A arm. **Report them even if 0.** This settles §1's contradiction for the whole programme.
4. **STEP 2 result.** The `PER-STAGE RESIDENCY` table as printed, and the A/B/C/E2E terms read **against** `claim_timing.by_stage` — **including the `by_stage` keys that actually appeared** and `by_stage.outbound.claim_mean_ms` vs the flat blend, **and their ratio (a first)**. `messages_seen` / `messages_complete` and the §4.7 verdict. **State that the table blends the 60 s climb rung with the 900 s soak**, and that the S2 `sustained_events_per_s` is **unbracketed and not quotable**. Give the pool acquire-wait windowed split with its "estimate, not identity" caveat.
5. **STEP 3 result.** The arm table: arm · N · sweep · K · **pinned `--soak-rate`** · `result` · `ceiling.bracketed` · `ceiling.pinned_ingress_rate` · **top-sustained rung's RAW offered rate** · **its measured engine drain** · `ceiling.sustained_events_per_s` · `R` · `in_pipeline_slope` · `soak.no_loss` · `lane_inversions` / `lane_repeats`. **The ladder string and the effective null band (`8% + step/C`).** **The C1 spread** (SESSION VOID if >±10%). **Then the pre-registered verdict from §5.8, named exactly** — SCAN-TAX LIVE / CLOCK-GATE LIVE / CLAIM SUPPLY LIVE / **NULL** / VOID / INDETERMINATE. **If S-fast was cut, say CLOCK-GATE is UNAVAILABLE, not flat.**
6. **Manipulation checks, per arm, GREEN / RED / UNKNOWN, with the numbers.** Check 1 (the per-arm sweep rate: observed vs nominal) FIRST. **Any RED ⇒ that arm is VOID — say so and compute NO `R` for it.** **Then the RECORDED DOSE:** the observed store-CPU delta on S-slow. **A small dose is a result, not a failure — state the bound it establishes.**
7. **Anything that did not match this handoff** — a flag that did not exist, a default that had moved, a wrapper script that overrode a shape, a `<COORD_DIR>` that was not shared, the `--persistent` ruling you applied, a value you had to VERIFY ON THE BOX and found different. **This section is as valuable as the numbers.**
8. **Closing disclaimer:** *Read-only DMV / public catalog names only; no secrets, IPs, hostnames, ports, or PHI.*

---

## 9. SOURCES AND NOTES

- **`docs/benchmarks/PLAN-ENGINE-ATTRIBUTION.md`** — the RUN-A spec (arms, decision rule, null band, manipulation checks). **Three things it gets wrong or omits:** it names `harness/load/shardcert.py` as the rig entrypoint (the primary metric comes from the `shardcert-engine-ladder` / `shardcert-drive-ladder` **two-box** pair, report `kind = "shardcert_ladder_two_box"`); it **never mentions `MEFOR_DELIVERY_PHASE_TIMING=1`**, without which half its instruments are blank (the ladder's own `--help` mentions it in passing; **the harness never SETS it — it only parses the log lines the engine emits when it is on**); and it asks for a **~10-line harness delta that is not needed** (§5.1).
- **`docs/adr/0101-*.md`** — the measurement discipline. **Binding.**
- **`scripts/bench/stage_residency.py`** — the STEP 2 tool. **Its module docstring repeats the incorrect "`_reset_store` wipes `message_events`" claim, and repeats the 226 ms / 90.5% figure as if measured.** Trust §1 and §0 of this document, and the `COUNT(*)` you take on the box.
- **`docs/benchmarks/THROUGHPUT-STATUS-2026-07-10.md`** — line 273: **C4's VERDICT IS WITHHELD.** Its 47.5%-scan-share number is prose-only, from an N=16 collapsed arm, on the 8-vCPU box, never re-measured. **Not admissible.**
- **`docs/benchmarks/results/2026-07-12-throughput-c4-c7/…/c6-n4x2/c6-n4x2.json`** — the PASS artifact the residual is derived from. `claim_timing` has **no `by_stage`**; `ceiling.bracketed = false`; `run.commit_sha = 98bec81d…` is the **LOAD-GEN** box. **Context for the question. NOT a control.**
- **Reference numbers, for orientation only:** 45M/day = **520.83 events/s**. Shipped default **90.0 raw** (5.79× short raw) / **45.0 publishable** (11.57× short publishable). Best deployable, tempdb ON: **144.0 raw** (3.62× short raw) / **72.0 publishable** (**7.23× short publishable**). **RAW ≠ PUBLISHABLE — one currency per statement.** `per_lane` **NOT usable, ships OFF.**

*Read-only DMV / public catalog names only; no secrets, IPs, hostnames, ports, or PHI.*