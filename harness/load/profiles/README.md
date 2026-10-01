# Load profiles

Data-driven run shapes for the headless load engine (`python -m harness --load <name>`). Each `.toml`
is parsed into a `LoadProfile` ([../profile.py](../profile.py)); a profile names the inbound MLLP
targets to drive, the message-type mix, a sequence of phases, and the SLO thresholds that decide
pass/fail. Run `python -m harness --list-profiles` to list the built-ins.

| Profile             | Purpose                                                                 | When        |
|---------------------|-------------------------------------------------------------------------|-------------|
| `smoke`             | Tiny zero-loss wiring check — proves the pipeline, not performance.      | CI gate     |
| `fanout-baseline`   | ADT-dominant mixed feed at high fan-out; characterizes a realistic mix.  | On-demand   |
| `adt-fanout-stress` | Pure-ADT feed at worst-case fan-out (~20); isolates the ADT write-amp.   | On-demand   |
| `soak`              | Long steady-state run; watches DB/WAL growth + dead-letter accumulation. | On-demand   |
| `spike-burst`       | Burst above the ceiling, then a measured recovery/drain (W2025 plan S4.3). | On-demand |
| `writeamp`          | Thin lane; serve-side fan-out is the write-amplification stress (S4.5).  | On-demand   |
| `sustained-overload`| Hold offered rate above the ceiling, then drain — backpressure (S4.7).   | On-demand   |
| `malformed-load`    | Well-formed background load; bad input GUI-injected concurrently (S4.8). | On-demand   |

## Other profile schemas in this directory
Some `.toml`s here are **not** `[load]` profiles and are driven by their own harness flags, not
`--load`:
- `connscale*` / `pooled*` / `fuse*` / `batch*` — `[connscale]` schema, the connection-scale sweep
  (`python -m harness --connscale <name>`; [../connscale/profile.py](../connscale/profile.py)).
- `estate*` — `[estate]` schema, the heterogeneous demo-shape driver
  (`python -m harness --estate <name>`; [../estate/profile.py](../estate/profile.py)): a majority of
  simple pass-through feeds + a minority of fan-out hubs, driven at a calibrated per-connection *event*
  rate so the aggregate hits a target total ev/s (`estate-demo` ≈ 520.5 ev/s; `estate-smoke` = the CI
  smoke). Run `python -m harness --list-estate-profiles` to list them. See
  [../../../docs/LOAD-TESTING.md](../../../docs/LOAD-TESTING.md) §"Estate demo shape".

## Phases and loop models
- **Phase kinds:** `warmup`, `ramp`, `sustained`, `spike`, `soak`. Only `sustained`/`soak` phases are
  *measured* — SLOs are evaluated against them; warmup/ramp/spike are transient.
- **Loop models:** `open` holds an offered rate (`rate_start`→`rate_end`, msg/s, interpolated for a
  ramp) to measure latency at a fixed load; `closed` holds a fixed `concurrency` in flight to find
  the maximum sustainable throughput (a local backlog can't inflate the achieved number).

## "Don't bake Corepoint in" + PHI
These presets model the *shape* of a large estate (one big ADT hub fanning out, plus results/orders
hubs) with **generic, synthetic** values only. They name no real partner, site code, host, IP, or
message volume; the weights are an illustrative ADT-dominant shape, not any real site's percentages.
A real-numbers profile (if you ever build one) belongs **only** in the git-ignored `migration-local/`
tree: put it at `migration-local/profiles/<name>.toml` and `--load <name>` finds it, or run any path
with `--load <path>`. That directory serves **all three** schemas — `--connscale <name>` and
`--estate <name>` resolve there too (BACKLOG #1837). It holds three schemas the way this one does,
so name a local profile the way a shipped one is named: an operator `[connscale]` profile is
`connscale-<site>.toml`, an `[estate]` one is `estate-<site>.toml`. A name outside its schema's
prefixes still runs, but `--list-connscale-profiles` / `--list-estate-profiles` will not show it.
Never commit one here, **and never drop one in this directory gitignored by
name either** — that was tried, and it shipped. The harness wheel force-includes this directory
whole; hatchling's `recurse_forced_files` walks the filesystem and consults no `.gitignore`, and
`exclude` does not reach a force-included file, so the wheel carries whatever is sitting here on the
machine that built it (BACKLOG #1835). A guard test
([../../../tests/test_packaging.py](../../../tests/test_packaging.py)) now refuses a `.gitignore`
entry that names a path inside a force-included tree. A guard test
([../../../tests/test_load_config.py](../../../tests/test_load_config.py)) asserts the shipped
profiles + load config carry none of a denylist of real tokens. Generated traffic is synthetic HL7
(the `messagefoundry` generators); run artifacts carry metrics only — never message bodies.

## The connscale herd floor is armed on ubuntu-latest only (2026-10-01, BACKLOG #1415)

The predicted empty-claims herd floor now fails a CI run on the `ubuntu-latest` py3.14 leg, and only
there. Both Windows legs failed the margin clause of the arming rule, so the floor stays recorded
and not graded on them.

Where it lives:

- The `[connscale.slo]` key `empty_claims_herd_floor_legs` names the legs it is armed on
  ([../connscale/profile.py](../connscale/profile.py)). The check is
  `_empty_claims_herd_floor_slo` in [../connscale/runner.py](../connscale/runner.py).
- A leg is `<matrix os>-py<python version>`. ci.yml's `Tests (pytest)` step exports it as
  `MEFOR_CONNSCALE_LEG`. A run without it, such as a local run, is never graded.
- It is armed in the inline N=12/24 profile in `tests/test_connscale_smoke.py`, which is what CI
  runs. It is not armed in `connscale-smoke.toml`: that file's base count is N=50, nothing runs it,
  and no harvest exists at that point.

### The harvest

The scan covered every `ci.yml` run of any event created from 2026-09-30T12:00:00Z to
2026-10-01T20:10:00Z. The first payload of the fitted population (`rate_window =
in_hold_excl_drain_reload_tail`, written since BACKLOG #2024) was uploaded at 2026-09-30T23:46:25Z,
so the window starts before any of it exists. The floor is fitted to that population only.

| What | Count |
|---|---:|
| Runs scanned | 408 |
| Runs still running at harvest time, listed and not scanned | 4 |
| `test` jobs harvested, both populations | 1,121 |
| Jobs with no readable artifact, counted unknown and adverse | 59 (56 cancelled, 3 failure, 0 success) |
| Jobs whose suite step was skipped, excluded | 45 |
| Artifacts not joined to a job | 30 |

All 30 unjoined artifacts carry a payload naming fake run 12345, which a unit test writes into the
real readings path (vault BACKLOG #2585). Each sits on a cancelled or failed job, so no passing job
lost its reading. Those 30 jobs are among the 59 counted adverse.

The wake pin reads VERIFIED for the fitted population: all 480 of its harvested jobs record
`per_lane_wake = false`. The older population records no pin, because it predates BACKLOG #2013.

The control that must be non-zero held: the same scan harvested 641 older-population jobs from the
same window. The branch fix is what made the counts reachable. Over this window the runs listing
returns 412 runs with no branch filter, the 408 scanned plus the 4 still running, and 63 with
`branch=main`, which is the filter the script used to send.

### Per cell, passing jobs only, fitted population, N=12

`F` is the predicted floor, the geometric mean of the herd-present and herd-gone levels. `idle` is
the herd-gone level. Neither was chosen against a reading.

| Leg | Lane | n | min | p1 | p5 | median | F | idle | min / F | Decision |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| ubuntu-latest | fixed_aggregate | 137 | 26.73 | 27.16 | 31.66 | 35.55 | 15.30 | 6 | 1.747 | **Armed** |
| ubuntu-latest | fixed_per_conn | 137 | 31.69 | 34.63 | 36.82 | 39.25 | 23.24 | 12 | 1.364 | **Armed** |
| windows-2022 | fixed_aggregate | 142 | 14.36 | 14.50 | 20.35 | 26.74 | 15.30 | 6 | 0.939 | Recorded only |
| windows-2022 | fixed_per_conn | 142 | 27.58 | 27.65 | 33.92 | 38.47 | 23.24 | 12 | 1.187 | Recorded only |
| windows-2025 | fixed_aggregate | 144 | 13.65 | 14.85 | 21.04 | 27.44 | 15.30 | 6 | 0.893 | Recorded only |
| windows-2025 | fixed_per_conn | 144 | 26.76 | 28.56 | 34.60 | 38.67 | 23.24 | 12 | 1.152 | Recorded only |

The median is the lower median, and every percentile is nearest-rank, so each figure is a recorded
reading.

### The four clauses, per cell

1. **(a) Margin.** `min / F` must reach 1.25. Both ubuntu cells pass. All four Windows cells fail,
   and on two of them `F` sits above a passing reading: 2 passing jobs on each Windows
   fixed_aggregate cell read below 15.30.
2. **(b) It grades more than the sign test.** `F` must sit above the herd-gone level, not merely
   above zero. Every cell passes: 15.30 is above 6, and 23.24 is above 12.
3. **(c) The known-answer case.** Run 36797223259, job 110163384729, `test (windows-2022, py3.14)`,
   lane `fixed_aggregate`, read 22.36. Against that cell's `F` of 15.30 it is not below, so (c)
   holds. The cell is still not armed, because (a) fails.
4. **(d) A true positive or a negative control.** `tests/test_connscale_herd_floor.py` feeds both
   lanes their herd-gone level on an armed leg. The floor trips, and the sign test passes the same
   readings.

**No lower floor was taken for Windows.** A smaller `F` would satisfy (a) arithmetically, for
example anything up to 11.49 on windows-2022 fixed_aggregate. Picking it after reading the numbers
is the fitted-threshold defect BACKLOG #1211 measured, and #1415's rule forbids it.

### What this does not establish

- 137 passing readings with none below `F` bound the false-alarm rate per lane per run at about
  2.2 percent, by the rule of three. The observed margin of 1.36 or more suggests far lower, but it
  is not a measurement of it.
- `ubuntu-latest` is a moving image label. A runner image change is a new leg in all but name.
- One cancelled windows-2022 job (run 36913644165) read 5.36 on fixed_per_conn, below that lane's
  herd-gone level. Nothing establishes that run as bad, so it is not used as a true positive.

### Re-checking any number here

The readings are committed under
[../../../docs/benchmarks/results/2026-10-01-connscale-herd-floor-harvest/](../../../docs/benchmarks/results/2026-10-01-connscale-herd-floor-harvest/):
`harvest.md` is the script's own report, and the three CSVs hold every reading, job and unjoined
artifact. `tests/test_connscale_herd_floor.py` recomputes clauses (a) to (c) from `readings.csv` on
every run and requires the armed legs to equal the legs that clear them.

To regenerate the scan while its artifacts last (they expire about 2026-12-30), in PowerShell 7:

```powershell
python scripts/connscale_harvest.py --since 2026-09-30T12:00:00Z --until 2026-10-01T20:10:00Z --json-out out/harvest.json
python scripts/connscale_harvest.py --from-json out/harvest.json --csv-dir out/harvest-csv > out/harvest.md
```
