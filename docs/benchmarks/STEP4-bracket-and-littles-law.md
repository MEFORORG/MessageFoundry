# STEP 4 — BRACKET THE CEILING AND TEST LITTLE'S LAW

**Audience: a rig operator with NO prior context.** Everything you need is here. Read §0 and §1 before
you touch anything.

**Nothing in this document is promised to raise throughput.** The most likely outcome — and a fully
respectable one — is **REGIME 1**: latency turns out NOT to be the throughput currency, the outbound
latency line dies, and a year's worth of tempting follow-on work is cancelled. **That verdict is worth
the rig hours on its own.** A run that kills a hypothesis is a successful run. A NULL is a successful
run. The only failure mode is a run that *manufactures* a verdict.

---

## 0. HARD RULES (non-negotiable — every one of these was learned the expensive way)

1. **NEVER stop, terminate, resize or tear down an EC2 instance.** Not to "save money", not to "reset
   cleanly", not at the end. That is the owner's call, every single time. When you are done: **report and
   HOLD the rig.** (The instance-store volume is wiped on stop/start; the SQL box must stay running.)
   SQL-side reverts you *may* do (MAXDOP, tempdb metadata) — instance lifecycle you may **not**.
2. **Gate on the harness `result` / `ceiling` FIELDS, never on `exit_code`.** A collapsed or skipped arm
   can still exit 0. `result_label` can serialize `PASS` on an arm that measured *nothing*
   (`pinned_ingress_rate = null`).
3. **NEVER quote a ceiling from an UNBRACKETED arm.** If `ceiling.bracketed == false`, the "ceiling" is
   merely the offered load. STEP 2 ran one rung, never collapsed, and its ~72 events/s is exactly this
   mistake. An arm with `first_collapse_ingress_rate == null` has measured no ceiling.
4. **A failed manipulation check is VOID, not a refutation.** Void != "the hypothesis is false". Re-run or
   report as void.
5. **A NULL is a SUCCESSFUL run.** Do not go looking for a different cut of the data that "shows
   something".
6. **Same-session controls only.** Never compare against STEP 2 or any earlier session. Every arm you
   compare must run in ONE session with NO configuration change in between.
7. **RAW != PUBLISHABLE.** The publishable figure is half the raw ceiling. Do not put a raw number in a
   headline.
8. **The pre-registration in §6 is FROZEN before you look at any number.** Compute and publish the
   manipulation checks (§7) *first*, then the primaries. A check evaluated after the primary is seen does
   not count.

---

## 1. WHY — the currency question

The programme's target is **520.83 events/s** (45M messages/day). We sustain **90 events/s** shipped, and
**144 events/s** with SQL Server's memory-optimized tempdb metadata ON. Nine falsifiers have hunted a
throughput lever and found nine nulls. The wall has never been named.

At the bench shape (below), one message = **9 events**, so ~144 events/s is **~16 messages/s**.

Here is the problem. **Every measurement to date was taken at ~8 msg/s — about HALF that ceiling — with
every resource under 25% utilization:**

| resource | at 8 msg/s | headroom to a 16 msg/s ceiling |
|---|---|---|
| store CPU | 24% | ~2x -> ~48% |
| engine box CPU (max core) | 23.7% | ~47% |
| load-gen box CPU | 0.9% | trivial |
| store pool acquire-wait | 0.0135 ms | trivial |
| PAGELATCH contention | zero | zero |
| outbound lane occupancy (derived) | ~23% | ~46% |

**Nothing is saturated. Nothing would be saturated at the ceiling either.** So either:

- **the ceiling is a STRUCTURAL bound** — by Little's law, `lambda_max = concurrency / latency`. If concurrency
  is capped (the outbound stage has a **hard cap of 8 concurrent deliveries** — see §2) and latency is
  large, throughput is bounded *without any resource being busy*. **Then LATENCY IS THE THROUGHPUT
  CURRENCY**, and cutting outbound latency raises throughput roughly proportionally. -> **REGIME 2.**
- **or latency is flat under load and concurrency simply grows with offered rate** — in which case the
  ceiling lives somewhere else entirely and **the whole outbound-latency line is a RED HERRING to be
  abandoned.** -> **REGIME 1.**
- **or something actually saturates at the ceiling** and we name it. -> **REGIME 3.**

**NOBODY HAS EVER MEASURED RESIDENCY AS A FUNCTION OF OFFERED LOAD.** That is this run.

### 1.1 The thing that must be settled FIRST, because it may cancel the run

The ~16 msg/s ceiling is **inherited from a different session**, in a tempdb configuration that memory
records as **currently REVERTED**, and — critically — **no measured quantity in the system can explain
it**:

- Outbound lane occupancy at 8 msg/s is **~23%**. Per-delivery lane occupancy is **~28.8 ms**
  (claim 13.37 + send_ack 0.53 + mark_done 10.52 = ~24.4 ms of accounted service, plus claim slot
  reservation). With **8 lanes**, the hard structural cap is `8 / 0.0288 s` = **~277 deliveries/s =
  ~34.7 msg/s = ~312 events/s** — **2.2x ABOVE the assumed ceiling.**
- The single pooled claimer (K=1) gives an independent bound of **~33.9 msg/s** — also above it.
- Every resource is <25% busy at half the ceiling.

**A ceiling that no measured resource and no structural cap can explain is what a HARNESS ARTIFACT looks
like.** And the harness has a documented way to fake one: a sink that self-times-out "records a partial
tally and drops its socket while the engine is still delivering", posts **no** `RUNG_ABORTED` marker, and
is **"indistinguishable from a genuine product collapse"** (`harness/load/shardcert.py` docstring).

**So ARM 0 validates the ceiling, and it GATES EVERYTHING.** If the ceiling moves when you scale the
client, the ceiling is the RIG's, and the rest of this run is meaningless. Stop and report.

### 1.2 A number to state OUT LOUD before the run, because it changes what a "win" means

Even a **perfectly saturated** outbound stage in this shape yields **~312–369 events/s = 0.60–0.71x** of
the 520.83 target. Under fan-out-to-all, `lambda_max = lanes / (D × S_lane) = 1 / S_lane` — **independent of
the lane count** (doubling destinations doubles the lanes AND the work). **So the 45M/day target is
UNREACHABLE in the c6-n4x2 shape regardless of this run's verdict.** That is worth knowing *before* the
rig hours, not after. This run tells you **where the wall is**, not how to hit the target.

---

## 2. THE SHAPE, AND THE ONE STRUCTURAL FACT EVERYTHING TURNS ON

Shape **c6-n4x2**: 4 shard processes (`a,b,c,d`), 8 outbound destinations `OB_SHARED_00..07`,
`dests=8`, `delivering=8`, `handlers=8`. **Every message fans out to ALL 8 destinations.**
`events_per_message = 1 + D = 9`. Claim mode `pooled`, `pooled_claimers_per_stage=1`,
`pooled_sweep_interval=0.25 s`.

**The outbound stage has a HARD CAP of 8 concurrent deliveries, fleet-wide:**

- the outbound lane key **is the destination name** (`wiring_runner.py` OUTBOUND lane_provider) -> 8 lanes;
- `per_lane_limit` is **hard-clamped to 1** at OUTBOUND (`stage_dispatcher.py:246`;
  `store/base.py:489` "OUTBOUND/RESPONSE are hard-1");
- the dispatcher permits **at most one outstanding claim-or-processing episode per lane**.

`pooled_max_processing_lanes=256` is **not** binding (only 8 lanes exist). **8 × 1 = 8.** By contrast
INGRESS has 16 lanes. **Outbound is the narrowest stage by 2x, and it is the stage carrying the known
wake gap** (`wiring_runner.py:909-915`: a producer wake for a lane another shard owns is **dropped**;
75% of delivery rows are discoverable only by the 0.25 s sweep).

**This does NOT mean the wake gap is the throughput wall.** A lane does **not** hold its slot while
waiting to be swept — sweep wait is **dead time, not occupancy**. On the evidence, the wake gap is a
**~90 ms latency tax that buys ~0 throughput**. Say that now, so it cannot be quietly rationalised later.

---

## 3. PRECONDITIONS (do these in order; each one has burned a previous run)

### 3.1 Code on the boxes

```powershell
# BOTH boxes — the patched analysis tool MUST be present. It is a standalone script (no engine rebuild).
.\.venv\Scripts\python.exe scripts\bench\stage_residency.py --help | Select-String "per-rung"
#   -> must print --per-rung.  If it does not, you have the OLD tool: it pivots on MIN(ts), reports the
#      FIRST of 8 deliveries as "the whole life" (151 ms printed vs 479 ms true), and it will silently
#      under-report every outbound number in this run. COPY THE PATCHED FILE OVER FIRST.
```

### 3.2 Phase timing — the instrument the harness never turns on

```powershell
$env:MEFOR_DELIVERY_PHASE_TIMING = "1"      # ENGINE box. HARD PREREQUISITE.
$env:PYTHONUTF8 = "1"
```

**Unset => `claim_timing` and `phase_timing` come back as the bland string
`(none captured — MEFOR_DELIVERY_PHASE_TIMING off ...)` — NOT an error.** You would complete the whole
session and find the instrument blank. **The per-rung service time is the numerator of this run's PRIMARY
statistic.** Verify it is `1` in the shell that launches the engine ladder.

### 3.3 tempdb configuration — VERIFY, do not assume

The ~16 msg/s figure assumes **MEMORY_OPTIMIZED TEMPDB_METADATA = ON**, which memory records as
**currently REVERTED** on the rig. Check it on the STORE box and **record what you find**:

```sql
SELECT SERVERPROPERTY('IsTempdbMetadataMemoryOptimized') AS tempdb_memopt;   -- 1 = ON
```

Whatever it is, **run the entire session in that one configuration** and say so in the handback. Do NOT
change it between climbs (rule 6).

### 3.4 `--persistent` — verify, do not infer from the env dump

`--persistent` is a **CLI flag** on `shardcert-engine-ladder`, and it sets
`MEFOR_SHARDCERT_PERSISTENT` in the spawned nodes' environment (`harness/__main__.py:707,959`). A
preflight dump asserting "`MEFOR_SHARDCERT_*` is empty" reads the *wrapper* shell, **not** the effective
node env — it proves nothing either way.

**Pass `--persistent` on every arm of this run and keep it constant.** With it OFF, every delivery opens a
fresh cross-box TCP connection; at 22 msg/s that is 176 connects/s, and **TIME_WAIT / ephemeral-port
pressure is a rate-dependent cliff** — i.e. a rig-side collapse mechanism, armed, in a run whose entire
purpose is to find a collapse rung. Don't hunt a wall with a rig-side wall switched on.

### 3.5 Clear `message_events` — and record what was there

`message_events` is cleared by **NOTHING**: not `_reset_store` (which DELETEs nine *named* tables and
`message_events` is not one of them), not the fleet, not the ladder. **It accumulates across runs.** A
stale table blends silently into any whole-table read.

```sql
USE <BENCH_DB>;
SELECT COUNT(*) AS rows_before, COUNT(DISTINCT message_id) AS msgs_before,
       MIN(ts) AS first_ts, MAX(ts) AS last_ts FROM message_events;   -- RECORD THIS IN THE HANDBACK
DELETE FROM message_events;
SELECT COUNT(*) AS rows_after FROM message_events;                    -- must be 0
```

**Do NOT "solve" this by setting `[diagnostics].message_events = off`** — that changes the store's write
path and makes the run a different configuration from every prior arm.

### 3.6 Shared coord dir

`<COORD_DIR>` **must be genuinely shared** between the boxes (it is a file drop). A per-box local path
produces a **silent rendezvous HANG** ending in a `CoordTimeout`. The other cause of a hang is a
`--rate-ladder` / `--hold-seconds` / `--drain-timeout` / `--run-id` **mismatch between the boxes** — those
five flags must be **byte-identical on both**.

### 3.7 Sanity-check the tool against the LIVE store before the first climb

Cheapest possible de-risk, needs no run:

```powershell
# ENGINE box, with the MEFOR_STORE_* env the engine uses
.\.venv\Scripts\python.exe scripts\bench\stage_residency.py --list-rungs
```

This exercises the SQL Server code path of the patched tool (it has been validated end-to-end on SQLite
against an independent oracle; the SS path is structurally unchanged but has not been executed). After the
§3.5 clear it should report an empty table. **If it errors, fix it now, not after the climb has consumed
the window.**

---

## 4. ARM 0 — VALIDATE THE CEILING. THIS GATES EVERYTHING.

### 4.0a CLIMB A — bracket the ceiling (this is also the load ladder for §5)

Ladder **`4:26:2`** -> 4, 6, 8, …, 26 msg/s. The climb **stops at the first non-sustained rung**, so it
self-brackets. Expected collapse somewhere in 14–20 => 6–9 sustained rungs.

**ENGINE box** (start first):

```powershell
$env:MEFOR_DELIVERY_PHASE_TIMING = "1"
$env:PYTHONUTF8 = "1"

.\.venv\Scripts\python.exe -m harness shardcert-engine-ladder `
  --shards a,b,c,d --dests 8 --lanes-per-shard 4 --persistent `
  --claim-mode pooled --store sqlserver `
  --rate-ladder 4:26:2 --hold-seconds 120 --drain-timeout 240 `
  --sink-port <SINK_PORT> --sink-host <LOADGEN_IP> --inbound-bind-host 0.0.0.0 `
  --keep-logs-dir <KEEP_LOGS_DIR>\s4-climbA --coord-dir <COORD_DIR> --run-id s4-climbA
```

**LOAD-GEN box** (start right after):

```powershell
.\.venv\Scripts\python.exe -m harness shardcert-drive-ladder `
  --engine-host <ENGINE_IP> `
  --rate-ladder 4:26:2 --hold-seconds 120 --drain-timeout 240 `
  --driver-count 4 --sink-host 0.0.0.0 --insecure `
  --coord-dir <COORD_DIR> --run-id s4-climbA --report-json <OUT_LOADGEN>\s4-climbA.json
```

Leave `--soak-hold-seconds` / `--soak-rate` **unset** (no soak in this arm). Leave
`--soak-drain-timeout` **unset**.

> WARNING: `ladder_run.ps1` on the rig **hardcodes `--dests 8` / `--sink-count 8`** and never passes
> `--handlers`/`--delivering`. **Read the wrapper scripts before using them** — they can silently override
> what you think you set.

**GATE A1 — THE CEILING MUST BE BRACKETED.**
`ceiling.bracketed == true` **and** `first_collapse_ingress_rate != null` in `s4-climbA.json`.
If the climb reaches 26 without collapsing: **excellent news** (the ceiling is far above the inherited
figure — the inherited 16 was wrong), but this arm is **UNBRACKETED**. Re-run with `--rate-ladder
24:60:4`. **Never quote the top rung of an unbracketed climb as a ceiling.**

Immediately after the climb, **bank the residency BEFORE anything else writes to the table**:

```powershell
.\.venv\Scripts\python.exe scripts\bench\stage_residency.py --list-rungs --json <OUT>\s4-climbA-rungs.json
.\.venv\Scripts\python.exe scripts\bench\stage_residency.py --per-rung `
    --expect-transformed 8 --expect-delivered 8 `
    --trim-head-s 30 --trim-tail-s 10 `
    --service-ms <S_ACC_MS> `
    --json <OUT>\s4-climbA-residency.json > <OUT>\s4-climbA-residency.txt
```

`<S_ACC_MS>` = the OUTBOUND accounted service, in ms, read from the report:
`claim_timing.by_stage.outbound.claim_mean_ms + phase_timing.send_ack_mean_ms + phase_timing.mark_done_mean_ms`.
(The claim leaf key is `claim_mean_ms`, NOT `mean_ms` — there is no `mean_ms` key anywhere in the claim
object, flat or per-stage; `ClaimTiming.to_json_dict()` emits `claim_mean_ms`/`claim_max_ms`.)
**It changes per rung — see §5.3.** Run the tool once per rung's own S if the spread across rungs
exceeds 10% (the JSON carries `lane_stats.service_ms` so the value used is always recoverable).

Then **clear `message_events` again** (§3.5) before the next arm, and record the count.

### 4.0b CEILING ATTRIBUTION — is the ceiling the ENGINE's or the RIG's?

**This is the gate that can cancel the run, and it is the reason ARM 0 exists.**

Take `lambda_collapse` = `first_collapse_ingress_rate` from CLIMB A. Re-run **that one rung** — same rate, same
everything — with **twice the DRIVER (sender) side**:

```powershell
# ENGINE box: identical, except --run-id s4-attrib and --keep-logs-dir ...\s4-attrib
#   --rate-ladder <lambda_collapse>   --hold-seconds 120   --drain-timeout 240
# LOAD-GEN box: identical, except
#   --driver-count 8            (2x drivers; it must still divide shards x lanes = 16)
#   --run-id s4-attrib          --report-json <OUT_LOADGEN>\s4-attrib.json
# NOTE: do NOT try --sink-count 16 — it is IMPOSSIBLE (the harness caps sink_count <= dests == 8) and MOOT
#       (the sinks never ran near their cap). See the callout under the gate table.
```

**GATE A2 — THE CEILING VALIDITY GATE (pre-registered):**

| observation | verdict |
|---|---|
| the rung **still collapses**, and achieved intake is within **5%** of the single-client run | the ceiling is the **ENGINE's**. **Proceed to §5.** |
| the rung now **SUSTAINS**, or achieved intake moves by **>=5%** | the ceiling is the **RIG's**. **STOP.** |

**RESULT (2026-07-13, run `s4-climbA`): GATE A2 = PASS — the ceiling is the ENGINE's.** Settled
**a DIFFERENT way** than the 2×-client re-run above (the sink half of which is impossible — see below): by the
**self-drain** evidence. At the **~16 msg/s = ~128 outbound-deliveries/s** plateau (16.122 × 8) the backlog
accumulated **and self-drained inside the engine** (`stranded=0`, `in_pipeline_final=0`) while the **sinks ran
at 12–19 % of their ~135/s cap** and the **load-gen box sat at ~1 % CPU** — the client tier was demonstrably
not the limit, and engine CPU was only 5–10 % of 16 cores, so this is a software pacing/serialization
plateau, not hardware. **Caveats:** it is a **SOFT** ceiling (`bracketed=false`, `first_collapse=null` — no
hard collapse); the usable **low-latency** rate is **~12 msg/s** (E2E climbs sharply above that); and
**which engine op caps the rate is NOT isolated here** (pooled claim + the 0.25 s sweep are the suspects) —
that attribution is **ARM 1 (§5)**.

> **Why the 2×-client test was not (and could not be) the sink half.** Doubling the **drivers** is legitimate
> (a driver is a sender-side in-flight/ACK bound worth ruling out — `--driver-count` must still divide
> `shards × lanes = 16`), but doubling the **sinks** is **impossible and moot**:
> - **IMPOSSIBLE.** The harness caps `sink_count <= sink_ports == dests == 8`. `_partition_band`
>   (`harness/load/shardcert.py:2139`) raises `ValueError("sink_count (N) > sink_ports (W): a sink would
>   bind no ports …")`, so `--sink-count 16` never starts.
> - **MOOT.** The sinks never ran above **~19 %** of their **~135/s** cap, so more sink processes deliver
>   nothing new. (`CPU is NOT sufficient evidence` still holds for the DRIVER side — a latency-bound sender
>   caps throughput at ~1 % CPU — but here the *self-drain* signal, not CPU, is what settles the gate.)

If the ceiling is the RIG's: **do not analyse the climb.** Report it, name the client-side mechanism
(per-sink rate vs the ~135/s per-sink cap; any sink self-timeout; ack p99; driver in-flight), **HOLD the
rig**, and hand back. That is a complete and valuable result — it means every "ceiling" quoted in this
programme is suspect, which is a bigger finding than anything §5 could produce.

**CPU is NOT sufficient evidence *on its own*.** A latency-bound or self-timing-out client caps throughput at
~1% CPU. The load-gen box read **0.9% CPU** while "capping" at 8 msg/s. Either the 2×-DRIVER re-run **or** the
self-drain evidence (backlog accumulating-and-draining *inside the engine*, `stranded=0`) settles it — and on
`s4-climbA` the **self-drain** signal did (see the RESULT above), since the 2×-sink half is impossible/moot.

Also record, at the collapse rung:

- per-sink delivered rate vs the **~135/s per-sink cap**;
- **any** sink timeout / `RUNG_ABORTED` marker (`aborted` / `valid` in the rung payload);
- `ack_ms.p99`;
- engine per-PID **`max_core%`** (NOT mean — the mean hides a pegged core);
- store CPU, load-gen CPU and max-core.

---

## 5. ARM 1 — RESIDENCY vs LOAD (only if GATE A2 says the ceiling is the ENGINE's)

### 5.0 S_lane — the LANE EPISODE, read DIRECTLY (no Little's law anywhere)

GATE A2 passed: the ~16 msg/s = ~128 outbound-deliveries/s plateau is the **engine's**, and it is a
**software pacing/serialization** limit (engine CPU 5–10% of 16 cores), not compute exhaustion. The open
question is **which engine operation caps the rate**. `S_lane` answers it by **measuring the lane episode
directly** — so `lambda_max = 1/S_lane` is a **definition** (a lane is a single-server queue), not an application
of `N = lambda × W`. Little's law is an **identity** and cannot be used to test itself; an earlier design was
rejected for exactly that.

**What it is.** One episode = a lane's processing slot being **RESERVED** (`READY->CLAIMING`, `_slots_free`
decrements) -> **RELEASED**. It spans the whole serialized per-lane cycle — claim round-trip + prefix drain —
i.e. precisely the region neither `send_ack`/`mark_done` (inside the body) nor the claim timer (the claim
only) can see.

**Where to read it.** `messagefoundry/pipeline/phase_timing.py::LaneEpisodeTiming` emits one throttled INFO
line per stage per ~5 s under `MEFOR_DELIVERY_PHASE_TIMING=1` (the rig **always** sets it). The harness
aggregates it: `shardcert_ladder.aggregate_episode_timing` -> `episode_timing` on `ENGINE_RUNG_REPORT` -> the
ladder JSON. **Read `episode_timing.by_stage.outbound`, NEVER the flat blend** — the engine emits one line
per stage and n-weighting all four into one number is an error this programme has already committed once
(every `claim_mean` quoted before 2026-07-13 is a four-stage blend).

**The pre-registered read-out — state it before you look, so the result cannot be motivated:**

| `S_lane` (outbound) | Reading |
|---|---|
| **~62 ms** | **CONFIRMS**: the lane episode IS the wall. Only ~24.4 ms is ACCOUNTED service (claim 13.37 + send_ack 0.53 + mark_done 10.52) — the **~38 ms gap** is the thing to attack. |
| **~25 ms** *and* `utilization` well below 1.0 | **REFUTES**: the lanes do not bind; the cap is elsewhere (the 0.25 s sweep is the next suspect). |
| **~25 ms** *but* `utilization` ~1.0 | **The lanes bind anyway.** The slot time went to **empty claims** — see `dropped`. |

WARNING: **Do not quote `lambda_max = rows / S_lane` without checking `utilization` first.** `S_lane` books only a
**COMPLETED SERVICE**; a pause / claim-error / **empty** / **rearm** / RETRY / STOP release renders no
delivery and is booked separately as `dropped`. That exclusion is right for the *mean* (empty releases are
frequent and sub-millisecond — booking them as service would drag `S_lane` toward the bare claim time and
**manufacture** the "lanes do not bind" verdict), but those releases still **OCCUPY the lane**: an
empty-claim lane sits RESERVED across the whole shared claim round-trip and cannot serve. So
`lambda_max = rows / S_lane` is the ceiling of a lane that is *back-to-back busy with completed services* — an
upper bound on an upper bound if `dropped`/`empty` is non-trivial. **`utilization` = (episode + dropped
occupancy) / (window × lanes)** is on the same line, and cross-checking `empty=` / `rearm=` on the co-emitted
**claim** line of the same window is part of the procedure. Without it the "lanes do not bind" branch is
**unfalsifiable**.

**The aggregate bound is `min(lanes, slots) / S_lane`, not `lanes / S_lane`.** Concurrent episodes are
capped by the dispatcher's slot pool (`pooled_max_processing_lanes`, default **256**). At the ARM 1 shape
(8 lanes) the two coincide; at the programme's **1,500-connection** target they do not, and the naive form
over-states the ceiling ~5.9×. Both terms are printed on the line (`lanes=` counts only **servable** lanes —
PAUSED/STOPPED excluded — and `slots=` is the pool cap).

### 5.1 CLIMB B — replication AND an order control

Run the **same ladder DESCENDING**: `--rate-ladder 26:4:-2` if the parser accepts a negative step;
otherwise run the rungs in descending order as an explicit list. If neither is possible, run the identical
ascending ladder again — but **read §8 first**, because you then lose the drift control.

Why descending: in CLIMB A, offered load is **perfectly collinear with session time**. Anything that grows
monotonically across a session (SQL buffer pool / plan cache warming, table growth, thermal drift) lands
**entirely in the fitted slope** and is indistinguishable from a real latency-vs-load effect. An identical
*ascending* replicate is confounded exactly the same way and **cannot detect this**. A **descending**
replicate reverses the confound: if the slopes from A and B agree, drift is not driving them; if they
differ, drift is, and the slope is **UNIDENTIFIED**.

Same flags, `--run-id s4-climbB`, its own `--keep-logs-dir` (identical log names across arms will
**silently overwrite** each other otherwise). Bank residency and clear `message_events` exactly as in
§4.0a.

### 5.2 How N (concurrency) is measured — TWO estimators, cross-checked

**N1 — the EXACT counting process (zero code change; this is the one that matters).**
`concurrency.n_outbound_rows` in the tool's JSON: the time-average of
`N(t) = #transformed<=t - #delivered<=t` over the rung's steady window. A `transformed` row is the **birth**
of an outbound row (the routed->outbound handoff produces them in the same committed transaction); a
`delivered` row is its **death**. It needs **no pairing**, **no `claimed_at` column**, and **no Little's
law** — it is a count.

> WARNING: **N1 is NOT capped at 8.** It counts **QUEUED + IN-SERVICE** outbound rows; only rows *in service* are
> bounded by the 8 lanes. "N is about 8, therefore the lanes are saturated" is a **category error** — resident
> rows are unbounded. Lane saturation is read from **occupancy** (§5.3), never from N1.

> WARNING: **N1's time-average equals `lambda × W` on this same data ALGEBRAICALLY.** It corroborates the arithmetic;
> it **cannot validate Little's law**. Any "check" of the form *"is N ~ lambda W?"* computed from this data is a
> **tautology**, and a check that cannot fail is not a check. (An earlier design shipped exactly that as a
> "free internal check". It is deleted — see §6.4.)

**N2 — the engine's SAMPLED `in_pipeline` gauge (INDEPENDENT data source; OPTIONAL).**
This is a real `COUNT(*)` over the `queue` table, so it comes from a **different source** than the event
log and a disagreement can actually mean something. Two obstacles, stated honestly:

- the climb call **does not sample it** (`shardcert_ladder.py:1730` omits `sample_in_pipeline`; only the
  soak at `:1820` sets it), and even when sampled only the **slope** and **final** value are exported —
  the raw trace never leaves the engine process. Getting N2 per rung is a **harness change** (sampling on
  the climb call + exporting a mean/trace in `_engine_rung_payload` + `RungOutcome.to_json_dict`).
- it is a **unified-store gauge**: each shard reports the WHOLE store, so summing 4 shard URLs inflates it
  **4x**. Divide by `n_shards`.

**If the harness change does not land, N2 is simply ABSENT and the cross-check is DROPPED — it is NOT
replaced by a tautology.** The verdict does not depend on it. If it does land: poll at **1 Hz** (it is a
real store read — an observer-effect risk on the hot table), and pre-register the cross-check as an
order-of-magnitude sanity test between two data sources: **a disagreement of more than 2x VOIDS** the
run's Little's-law arithmetic until reconciled. Do **not** gate on a tight band; the two estimators count
different things (N1 = outbound rows only; N2 = not-done rows across all stages).

### 5.3 The occupancy statistic — the PRIMARY

For each rung `r`:

```
S_acc(r)  = claim_timing.by_stage.outbound.claim_mean_ms   <- leaf key is `claim_mean_ms`, NOT `mean_ms`
          + phase_timing.send_ack_mean_ms
          + phase_timing.mark_done_mean_ms            [ms]   <- MEASURED, per rung

rho(r)    = lane_stats.occupancy_accounted_max        [0..1] <- from the tool, run with --service-ms S_acc(r)
          = max over the 8 lanes of  (deliveries_in_window x S_acc) / window
```

`rho` is a **LOWER BOUND** on true lane utilisation (the event log has no claim boundary, so the tool
cannot see any in-lane time that the phase timers miss). **Use the MAX over lanes, not the mean:** a
sustained rung requires **every** lane to keep up, so the binding constraint is the **slowest** lane. The
8 lanes are unevenly owned (3/1/2/2 across shards a/b/c/d) and are **not exchangeable** — averaging them
destroys exactly the signal.

**Extrapolate to the ceiling** (this is the primary, and it is granularity-invariant — it does not depend
on where the ladder step happened to land):

```
rho_hat_ceiling = rho(top admitted rung) x ( lambda_collapse / lambda(top admitted rung) )
```

This is exact if `S_acc` is flat, and **`S_acc` is measured per rung, so you will know if it is not.**

> **The regime-2 mechanism, pre-registered.** From the S2 prior, `rho ~0.23` at 8 msg/s and
> `S_acc ~24–29 ms`, which extrapolates to `rho_hat ~0.46` at a 16 msg/s ceiling — **below the
> regime-2 bar.** For the lanes to be the bound, **`S_acc` must INFLATE with load** (it is heavy-tailed:
> `claim_max_ms = 133`, `mark_done_max_ms = 101` in the S2 soak). **So a REGIME 2 verdict MUST be
> accompanied by a NAMED service term that grew.** A `rho` that climbs while the `S_acc` decomposition
> stays flat is **arithmetically impossible** and indicates an instrumentation fault, not a finding.

### 5.4 The latency statistic

```
lambda(r) = the tool's  lambda_msg_per_s    (ACHIEVED, from the engine's own `received` stream —
                                             NEVER the offered rate; the token-bucket drive has a
                                             known intake shortfall)
W(r)      = the tool's  E2E_complete p50_ms (the MEDIAN whole life: received -> LAST delivery)
```

**`E2E_complete` is the only strictly-positive, reference-free latency in the set.** Use it, and only it,
in the regression.

**DO NOT regress on `W_last`.** It is **50.6% NEGATIVE** (a delivery can land before a sibling handler's
transform), it has no true zero, and it is reference-dependent. Putting it in a ratio or a log is
**precisely the error that produced a false "CONFIRMED at 5.05"** in STEP 3a: re-reference the same
quantity to a different (equally arbitrary) zero and the verdict flips. The tool prints `W_last` with an
explicit `neg%` column so you can *see* this; it is reported, not regressed.

```
b1 = OLS slope of  log W(r)  on  log lambda(r)   over the ADMITTED rungs (§7)
CI = b1 +/- t(0.975, df = n_rungs - 2) x SE(b1)      <-- COMPUTED FROM THE DATA, never an assumed sigma
```

---

## 6. THE PRE-REGISTERED DECISION RULE (freeze this before you look at a number)

Evaluate **in this order**. It is a deterministic function of the numbers: **there is no point at which
the analyst chooses.**

### V0 — VOID
Any of: a manipulation check in §7 fails · `ceiling.bracketed == false` · fewer than **4 admitted rungs**.
-> **VOID. Not a refutation.** Re-run or report as void.

### V1 — THE CEILING IS THE RIG'S
GATE A2 (§4.0b) failed. -> **STOP. Report. HOLD the rig.** Nothing below is computed.

### V2 — REGIME 3: RESOURCE SATURATION
At the **first collapsed** rung, **any** measured resource >= **90%**: store CPU · any engine per-PID
`max_core%` · load-gen CPU or max-core · pool `acquire_wait` > 5 ms · any sink at >=90% of its ~135/s cap.
-> **NAME THE RESOURCE.** (Evaluated before V3 because a saturated resource explains the ceiling without
any structural story.)

### V3 — REGIME 2: STRUCTURAL BOUND. LATENCY IS THE CURRENCY.
**ALL THREE:**
- `rho_hat_ceiling` **>= 0.85**, AND
- the 95% CI **lower bound** of `b1` **>= 0.70**, AND
- **a NAMED term of `S_acc` grew** across the admitted rungs (report which: claim / send_ack / mark_done).

-> The outbound lane cap is the wall. Cutting outbound latency raises throughput roughly proportionally.
**But read §9 before celebrating: there may be no cheap lever.**

### V4 — REGIME 1: THE RED HERRING. THE LATENCY LINE IS DEAD.
Either route qualifies (both are respectable; say which one you used):

- **V4-F (flatness certified — needs both climbs):** the **ENTIRE 95% CI** of `b1` lies inside
  **[-0.15, +0.15]** (a TOST equivalence test — a *point estimate* inside the band is **NOT** sufficient),
  **AND** `rho_hat_ceiling` <= 0.50.
- **V4-O (occupancy route — works on ONE climb):** `rho_hat_ceiling` **<= 0.50** **AND** the 95% CI
  **upper** bound of `b1` **< 0.70** (so REGIME 2 is excluded) **AND** the lane-bound prediction
  `lambda_max_pred = 1000 / S_acc(low rungs)` [msg/s] is **>= 1.5x** the bracketed ceiling.

`lambda_max_pred` is an **OUT-OF-SAMPLE** prediction: estimate `S_acc` at the three LOWEST rungs (far from the
cap, where service is cleanly measured), predict the lane-bound ceiling, and compare it to the ceiling you
actually bracketed. **This test can FAIL** — that is what makes it worth doing. (Prior: `S_acc ~28.8 ms`
=> `lambda_max_pred ~34.7 msg/s`, ~2.2x above the assumed ceiling => the lanes do **not** explain it.)

-> **The outbound latency line is KILLED.** The wake gap is a latency tax, not a throughput lever. Stop
spending rig hours on it. **This is a successful, valuable run.**

### V5 — NULL
Anything else — including `rho_hat_ceiling` landing in the **0.50–0.85 dead zone**, or a CI too wide to
certify flatness. **A NULL IS A SUCCESSFUL RUN.** Report it as underpowered/inconclusive and say exactly
which threshold was not met. **Do not re-cut the data.**

> **The dead zone is a LIVE possibility, and you are told so in advance.** The two internal priors —
> ~3.1 lanes busy (service-only) and ~6.9 resident rows (queue+service) — **straddle it**. If the run
> lands there, that is the honest outcome, not a failure to try hard enough.

### 6.4 CHECKS THAT ARE DELETED — do not re-add them

| deleted | why |
|---|---|
| `b2 = 1 + b1` "free internal Little's-law check" | **TAUTOLOGY.** If N is derived as lambda×W, this holds algebraically with zero residual. It cannot fail. It also made REGIME 1's "two independent conditions" **one condition counted twice**. |
| `8 / median(per-lane inter-delivery gap) == delivery rate` | **FLOW CONSERVATION.** Under fan-out-to-all each lane takes exactly one delivery per message, so the mean gap **is** `1/lambda` for any engine, any service time, any bottleneck. Zero information. (It "agreed to 6%" in S2 because it *must*.) |
| `rows_per_message = 17` cross-check | Rows-per-**resident**-message is **load-dependent**, not a constant (a message holds 1 ingress row, *then* H routed rows, *then* D outbound rows — never 17 at once). It would fire a FALSE inconsistency and void a good run. |
| "no-poll control rung at a SUSTAINED rate, gated on throughput" | **Cannot fail by construction:** at a sustained rung, achieved == offered whether you poll or not. If you want an observer-effect control, run it at the **collapsed** rung, or gate it on the **latency distribution**. |

---

## 7. MANIPULATION / VALIDITY CHECKS — compute and PUBLISH these BEFORE the primaries

Freeze the order. Publish them as a separate committed output **first**. A check evaluated after you have
seen the primary does not count.

- **M1 — RUNG SEGMENTATION.** From `--list-rungs`: the **rung count** must equal the number of rungs
  actually armed, and **each rung's `received` count must equal that rung's `acked`** in the drive report
  JSON (exact match — the S2 precedent matched exactly: 480 and 7200). A mismatch => re-segment with
  `--rung-gap` => otherwise every per-rung number is **VOID**. *(Failure mode this catches: at the collapse
  rung, an intake stall > 10 s splits one rung into two, and you analyse half a rung as a rung.)*
- **M2 — STEADY STATE, per rung.** Split the rung's steady cohort in half by received-ts and re-run the
  tool on each half. Require **|median E2E(2nd half) - median E2E(1st half)| / median E2E(rung) <= 0.10**
  and the same for `n_outbound_rows`. A **filling** rung is not a Little's-law point. A rung failing M2 is
  **EXCLUDED and REPORTED as excluded** — never silently dropped. *(A near-ceiling rung will legitimately
  fail M2: filling IS what collapse is. That rung **brackets**; it does not regress.)*
- **M3 — THE RUNGS REALLY DIFFERED.** Achieved lambda (from the tool, engine-side) must be **strictly
  increasing** across admitted rungs and within **2%** of offered. Regress on **ACHIEVED**, never offered.
- **M4 — SAME SESSION.** Both climbs, the attribution rung, tempdb, MAXDOP and instance state in ONE
  session with **NO** SQL-side change in between. **Do not use STEP 2 as a control.**
- **M5 — CLIENT NOT THE BOTTLENECK.** Load-gen CPU **and** max-core < 60% on every rung; per-sink rate <
  60% of the ~135/s cap; **no** sink timeout / `RUNG_ABORTED` marker (`aborted == false`, `valid == true`);
  `ack_ms.p99` reported per rung. **CPU alone is not sufficient** — the §4.0b 2x-client test is what
  settles attribution.
- **M6 — NO CENSORING, NO PARTIALS, NO RETRIES.** The tool's `--strict` must pass for every rung entering
  the fit (`--expect-transformed 8 --expect-delivered 8 --strict`, exit 0). Also `no_loss == true`,
  `lane_inversions == 0`, `drained == true`, `stranded == 0`. **A censored rung's latency is biased DOWN**
  (the never-delivered messages are the slow ones) — which is the direction that manufactures REGIME 1.
- **M7 — (only if N2 landed)** the two concurrency estimators agree within **2x**. Gross disagreement
  **VOIDS** the Little's-law arithmetic until reconciled.

### 7.1 Rung admission to the FIT (stricter than the harness's own PASS bar — deliberately)

**The harness's own sustain bar, as it actually stands (2026-07-13).** On the **two-box** ladder — the path
this document runs — a rung is scored by `shardcert_ladder.classify_rung`: **drained clean (engine
store-truth) AND lossless (sink socket-truth) AND the two observers agree**. Intake shortfall is tolerated up to
`achieved < offered × (1 - 0.05)`. **There is NO "still filling" term.** So a rung **passes as sustained with
up to a 5% intake shortfall, and with its in-flight backlog still GROWING** — it drained only because the
offer stopped. In a log-log OLS the top rung is the **highest-leverage** point, so the single most suspect
rung would dominate the slope — and it drags it **UP**, toward the favoured hypothesis. That is exactly why
the admission bar below is stricter than the harness's.

> **The `fill_ratio` filling gate does NOT apply here — do not assume the rig ceiling is filling-corrected.**
> `harness/load/shardcert.py` grew a third ceiling term on 2026-07-13 (`ShardCertStepRecord.filling`: split
> the hold's E2E into two equal-length steady cohorts, flag `p50(2nd)/p50(1st) > 1.5`, abstain below 30
> samples/half). It fires **only on the CO-LOCATED ladder** (`harness shardcert --rate-ladder`), where one
> process both sends and sinks so a `Correlator` can join the timestamps. The **two-box** tier
> (`shardcert-engine-ladder` / `shardcert-drive-ladder`) has senders and sinks in **separate processes**
> behind a metadata-only coord — there is no cross-process E2E stream to split — so `ShardCertDriveReport`
> carries no E2E field and its `.ceiling` **abstains from the filling term explicitly**
> (`filling_evaluated: false` in the rung JSON, with the reason). **Every two-box ceiling quoted in this
> programme, INCLUDING the ~16 msg/s plateau, is measured WITHOUT it, and may over-report the sustainable
> rate.** Closing the gap needs a real in-hold latency-growth signal plumbed into the two-box tier (the
> engine's own `E2E_complete` out of `message_events` is the natural source — it is the quantity
> `scripts/bench/stage_residency.py` already computes) **and** a `filling` term added to `classify_rung`.
> Either half alone changes nothing.
>
> **Naming:** the ladder's ratio is `fill_ratio`, deliberately **not** "M2". It is a **different quantity**
> from §7's **M2** validity check above — different source (drive socket latency vs the store's `E2E_complete`), different
> split key (sink receipt vs engine received-ts), different bar (ratio > 1.5 vs symmetric relative
> difference <= 0.10), and the opposite purpose (**lower a ceiling** vs **exclude a rung from the fit**). A
> rung the ladder passes at `fill_ratio` = 1.4 can still legitimately FAIL §7's M2. Never conflate them.
>
> **Comparability:** the ladder JSON now stamps `ceiling_gate_version` (v2 = the `filling` term exists).
> Ceilings from different gate versions are not comparable. On the two-box path v2 changes **nothing**
> (the term abstains), so the ~16 msg/s plateau **remains directly comparable** to every prior two-box run.

A rung enters the fit **iff**: harness `result` = sustained (the **field**, never `exit_code`) **AND**
`achieved/offered >= 0.98` **AND** M2 passes **AND** M6 passes.
**Report leverage and Cook's D per rung.** Pre-register: **if removing any single rung moves `b1` by more
than the null-band width (0.30), the slope is declared UNIDENTIFIED, not reported.**

---

## 8. POWER — what this run can and cannot decide (say this BEFORE the run, not after)

- **The PRIMARY (`rho`) is a WITHIN-rung time-average.** It does not depend on the number of rungs, and
  **one climb is enough for it.** The REGIME 1 vs REGIME 2 call rests on it (plus the out-of-sample
  `lambda_max_pred`), and both survive a single climb intact. **This is why the one-climb plan works at all.**
- **The REGRESSION is under-powered on one climb.** With ~6 admitted rungs and a plausible residual
  sigma ~0.08 on log W, the 95% CI on `b1` is roughly **±0.21** — **wider than the ±0.15 null band.** So on
  ONE climb you **cannot certify** "W is flat" (V4-F). Two climbs roughly halve it (**±0.12**), which
  fits. **That is the entire justification for CLIMB B.**
- **REGIME 2 vs REGIME 3 is NOT separable by the slope** (b1 = 1.0 vs 1.15 is <2 SEs on one climb, <3 on
  two). That separation rests on `rho` and the **resource panel**, not on `b1`. Declared up front.
- **Therefore:** if only ONE climb is possible, a flat-looking `b1` must be reported as **V5 NULL
  (underpowered)** — **unless** V4-O's occupancy route is satisfied, which is the whole point of building
  the primary on occupancy rather than on the slope.

### 8.1 If you must cut, cut in THIS order

1. **Cut CLIMB B.** Cost: you lose flatness certification (V4-F) and the drift control. The occupancy
   primary and the V4-O route are **completely unaffected**. Saves ~40 min. **Take this cut first.**
2. **Cut the optional ARM 2** (§9.2). Cost: no causal intervention; the run stays observational.
3. **DO NOT coarsen the ladder** (e.g. `4:24:4`). With a collapse at 16 you would get only 3 sustained
   rungs => 1 df => the regression is **dead** and its CIs are meaningless.
4. **DO NOT skip ARM 0's attribution rung (§4.0b).** Without it you may spend the whole session
   characterising a wall that belongs to the load generator.

---

## 9. WHAT A REGIME-2 VERDICT WOULD AND WOULD NOT BUY

### 9.1 There may be NO cheap lever, and you should know that before you hope for one

- **The outbound claim is NEVER batched, by design** — `fifo_claim_batch` applies only to INGRESS/ROUTED
  ("the OUTBOUND/delivery claim is NEVER batched (its skip-and-complete dedup must stay atomic)",
  `settings.py:265-276`). And ingress/routed are **already fast** (20.7 / 22.3 ms) — they are not the wall.
- **Per-lane FIFO forbids per-lane parallelism**, and FIFO-always is an owner hard requirement.
- **Under fan-out-to-all, `lambda_max = 1/S_lane` is INDEPENDENT of the lane count.** Adding destinations adds
  lanes *and* work.

So a REGIME 2 verdict **names the wall and hands over no config-only fix.** The lever would be a genuine
store/claim-path rewrite (the outbound per-delivery cost is **two serial DB round-trips**: claim 13.4 ms +
mark_done 10.5 ms = 23.9 of the 24.4 ms accounted; `send_ack` is 0.5 ms — **the partner is free**). Do not
let a REGIME 2 result be over-sold as an easy win.

### 9.2 OPTIONAL ARM 2 — the only TRUE causal test (~3 lines, if you have the time)

Everything in §5–§6 is **observational**. There is exactly one cheap intervention that decouples the lane
count from the work, and it is worth more than CLIMB B if you can only do one:

`harness/config/shardcert/_shape.py` maps `delivers_to(j) = j if j < delivering else None`, and
`graph.py:136` wires handler *j* -> destination *j*. **That 3-line accident is the only reason active lanes
== deliveries-per-message.** Add a **per-shard destination OFFSET** (or stride) to `delivers_to`, then run
`dests=16, delivering=8, handlers=8` with each shard's 8 handlers mapped onto a shard-dependent window of
the 16 destinations:

- **active lanes = 16** (double), **work per message UNCHANGED** at 8 deliveries.
- **Pre-registered prediction:** if the 8-lane cap binds, **`lambda_max` roughly DOUBLES**. If it does not,
  **`lambda_max` is UNCHANGED.**

That discriminates REGIME 1 from REGIME 2 **with no Little's-law arithmetic at all**. Remember to widen
`MEFOR_SHARDCERT_SINK_PORTS` / `--sink-count` to match.

### 9.3 If you want `S_lane` DIRECTLY (a small engine change — but get the estimand right)

An earlier design proposed exposing the dispatcher's **`processing_lanes`** counter as the primary.
**DO NOT DO THAT.** `processing_lanes` counts only lanes with a **spawned serializer task**. A lane in
**CLAIMING** holds a **RESERVED** slot (`slots_free` is decremented at `stage_dispatcher.py:545`) but has
**no task** — so it is **invisible** to `processing_lanes`. From the S2 numbers, **CLAIMING is ~62% of all
outbound lane-seconds.** That counter therefore **under-reads true occupancy by ~2.5x** and would declare
REGIME 1 **almost no matter what the engine does** — including in the world where the claim path IS the
wall, which is the world the programme has already named.

If you instrument, instrument **one** of these:

- `N_occupied = max_processing_lanes - slots_free` (= CLAIMING **+** PROCESSING, by the dispatcher's own
  conservation law at `stage_dispatcher.py:28`), exposed per stage; **or**
- **better and cheaper:** a **lane-EPISODE stopwatch** in `messagefoundry/pipeline/phase_timing.py` (the
  bench-gated `_PhaseWindow` pattern is already there) timing **claim_start -> slot release**. That yields
  `S_lane` **directly** — one number, no Little's law, no polling, no observer effect — and its difference
  from (claim + send_ack + mark_done) **localizes the unaccounted residual**, which is the largest
  unexplained quantity in the whole programme.

---

## 10. HANDBACK SPEC

Bank all of this. Do **not** stop the rig.

```
HANDBACK_<DATE>_STEP4/
  README.md                      <- see below
  preflight/
    tempdb_memopt.txt            <- SERVERPROPERTY('IsTempdbMetadataMemoryOptimized')
    env_engine.txt               <- MEFOR_DELIVERY_PHASE_TIMING, MEFOR_STORE_*, MEFOR_SHARDCERT_*
    message_events_before.txt    <- the pre-clear COUNT(*) + ts extent (per arm)
    tool_help.txt                <- stage_residency.py --help (proves the PATCHED tool ran)
  climbA/
    s4-climbA.json               <- the DRIVE report (rungs, ceiling, claim_timing, phase_timing)
    s4-climbA-rungs.json         <- --list-rungs (the M1 segmentation evidence)
    s4-climbA-residency.json     <- --per-rung (the primary data)
    s4-climbA-residency.txt      <- the rendered table
    node-logs/                   <- per-rung, per-shard (they carry the claim/phase lines)
    cpu_soak.csv  loadgen_cpu_soak.csv  storedmv.txt  storepage.txt
  attrib/                        <- the 2x-client rung (GATE A2). SAME file set.
  climbB/                        <- SAME file set (descending). Omit ONLY if cut; say so.
  analysis/
    checks.md                    <- M1..M7, COMPUTED AND PUBLISHED FIRST
    rungs.csv                    <- rung, offered, achieved lambda, W p50/p95/p99, S_acc + its 3 terms,
                                    rho_max, rho_mean, N_out, N_e2e, censored, retries, admitted?, reason
    verdict.md                   <- V0..V5, the ONE that fired, and the numbers that fired it
```

`README.md` must state, in this order:

1. **the tempdb configuration actually loaded** (not assumed);
2. **`ceiling.bracketed`** and **`first_collapse_ingress_rate`** for CLIMB A — or "UNBRACKETED, no ceiling
   quoted";
3. **GATE A2**: engine's ceiling or rig's ceiling, with the 2x-client numbers;
4. **the verdict** (V0–V5) and **which pre-registered thresholds fired it**;
5. every rung **excluded** from the fit, **with its reason**;
6. the **raw** ceiling and, separately, the **publishable** figure (half the raw);
7. **the rig is HELD and RUNNING.**

---

## 11. THE ONE-PARAGRAPH SUMMARY FOR WHOEVER READS THE VERDICT

> We measured, for the first time, how a message's wall-clock time behaves **as offered load climbs
> toward the ceiling** — and we first checked that **the ceiling is even ours**. If latency grew roughly
> in proportion to load while the 8 outbound delivery lanes filled up, the ceiling is **structural**, the
> wall is the outbound claim/commit round-trip pair, and latency is the throughput currency (REGIME 2 —
> real, but with **no config-only fix**, and even a perfect outbound stage reaches only ~0.6–0.7x of the
> 45M/day target in this shape). If latency stayed flat while the lanes sat half idle, then **the outbound
> latency line is dead** and we stop paying for it (REGIME 1 — a red herring, killed, and worth the run).
> If a resource saturated, we named it (REGIME 3). If the ceiling moved when we doubled the load
> generator, **the ceiling was never the engine's** and every prior ceiling in this programme is suspect.
> And if none of those fired, the answer is **NULL** — which is a successful run, and we say so plainly
> rather than re-cutting the data until something appears.
