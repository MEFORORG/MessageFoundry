# connscale base-reading harvest (BACKLOG #1415 instrument: a scan, it arms nothing)

repo MEFORORG/MessageFoundry, workflow ci.yml, branch any, event any
window 2026-09-30T12:00:00Z .. 2026-10-01T20:10:00Z (run creation time); with-tail ceiling none
runs scanned: 408 (max-runs none); runs not completed, not scanned: 4 [36918891337, 36918470001, 36918238724, 36916408056]
scanned runs with no test job at all: 0 []
runs from another head repository, not scanned: 0 []
carried-over job copies from re-run attempts, counted once: 14
MEFOR_PIPELINE_PER_LANE_WAKE pin: NOT VERIFIED by this scan; 480 of 1121 harvested job(s) record it. A payload records none when it predates BACKLOG #2013, came from a local run, or had a step that recorded none.
MEFOR_PIPELINE_PER_LANE_WAKE pin (post_2024 only): VERIFIED; all 480 harvested job(s) record false.
MEFOR_PIPELINE_PER_LANE_WAKE pin (post_1420 only): NOT VERIFIED by this scan; 0 of 641 harvested job(s) record it. A payload records none when it predates BACKLOG #2013, came from a local run, or had a step that recorded none.

## Jobs per leg, by what the harvest made of them

| leg | status | reason | job conclusion | jobs |
|---|---|---|---|---:|
| ubuntu-latest py3.14 | excluded | no artifact, job or Tests (pytest) step skipped | cancelled | 5 |
| ubuntu-latest py3.14 | excluded | no artifact, job or Tests (pytest) step skipped | failure | 9 |
| ubuntu-latest py3.14 | excluded | no artifact, job or Tests (pytest) step skipped | success | 9 |
| ubuntu-latest py3.14 | harvested | rate_window=in_hold_excl_drain | cancelled | 2 |
| ubuntu-latest py3.14 | harvested | rate_window=in_hold_excl_drain | failure | 37 |
| ubuntu-latest py3.14 | harvested | rate_window=in_hold_excl_drain | success | 176 |
| ubuntu-latest py3.14 | harvested | rate_window=in_hold_excl_drain_reload_tail | cancelled | 1 |
| ubuntu-latest py3.14 | harvested | rate_window=in_hold_excl_drain_reload_tail | failure | 19 |
| ubuntu-latest py3.14 | harvested | rate_window=in_hold_excl_drain_reload_tail | success | 137 |
| ubuntu-latest py3.14 | unknown_adverse | no artifact | cancelled | 12 |
| ubuntu-latest py3.14 | unknown_adverse | no artifact | failure | 1 |
| windows-2022 py3.14 | excluded | no artifact, job or Tests (pytest) step skipped | cancelled | 2 |
| windows-2022 py3.14 | excluded | no artifact, job or Tests (pytest) step skipped | success | 9 |
| windows-2022 py3.14 | harvested | rate_window=in_hold_excl_drain | cancelled | 3 |
| windows-2022 py3.14 | harvested | rate_window=in_hold_excl_drain | failure | 38 |
| windows-2022 py3.14 | harvested | rate_window=in_hold_excl_drain | success | 172 |
| windows-2022 py3.14 | harvested | rate_window=in_hold_excl_drain_reload_tail | cancelled | 4 |
| windows-2022 py3.14 | harvested | rate_window=in_hold_excl_drain_reload_tail | failure | 16 |
| windows-2022 py3.14 | harvested | rate_window=in_hold_excl_drain_reload_tail | success | 142 |
| windows-2022 py3.14 | unknown_adverse | no artifact | cancelled | 21 |
| windows-2022 py3.14 | unknown_adverse | no artifact | failure | 1 |
| windows-2025 py3.14 | excluded | no artifact, job or Tests (pytest) step skipped | cancelled | 2 |
| windows-2025 py3.14 | excluded | no artifact, job or Tests (pytest) step skipped | success | 9 |
| windows-2025 py3.14 | harvested | rate_window=in_hold_excl_drain | cancelled | 4 |
| windows-2025 py3.14 | harvested | rate_window=in_hold_excl_drain | failure | 41 |
| windows-2025 py3.14 | harvested | rate_window=in_hold_excl_drain | success | 168 |
| windows-2025 py3.14 | harvested | rate_window=in_hold_excl_drain_reload_tail | cancelled | 2 |
| windows-2025 py3.14 | harvested | rate_window=in_hold_excl_drain_reload_tail | failure | 15 |
| windows-2025 py3.14 | harvested | rate_window=in_hold_excl_drain_reload_tail | success | 144 |
| windows-2025 py3.14 | unknown_adverse | no artifact | cancelled | 23 |
| windows-2025 py3.14 | unknown_adverse | no artifact | failure | 1 |

## Population post_2024

Distribution over PASSING jobs only. `unknown adverse` is per leg and belongs to no population: an artifact-less job cannot say which one it would have been.

| leg | lane | N | n passing | min | p1 | p5 | median (low) | n non-passing | no value, passing | no value, non-passing | unknown adverse (leg) |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| ubuntu-latest py3.14 | fixed_aggregate | 12 | 137 | 26.7273 | 27.1613 | 31.6562 | 35.5455 | 20 | 0 | 0 | 13 |
| ubuntu-latest py3.14 | fixed_per_conn | 12 | 137 | 31.6875 | 34.625 | 36.8235 | 39.25 | 20 | 0 | 0 | 13 |
| windows-2022 py3.14 | fixed_aggregate | 12 | 142 | 14.3636 | 14.5 | 20.3478 | 26.7391 | 20 | 0 | 0 | 22 |
| windows-2022 py3.14 | fixed_per_conn | 12 | 142 | 27.5833 | 27.6471 | 33.9231 | 38.4667 | 20 | 0 | 0 | 22 |
| windows-2025 py3.14 | fixed_aggregate | 12 | 144 | 13.6522 | 14.8519 | 21.0385 | 27.4412 | 17 | 0 | 0 | 24 |
| windows-2025 py3.14 | fixed_per_conn | 12 | 144 | 26.7647 | 28.5625 | 34.6 | 38.6667 | 17 | 0 | 0 | 24 |

## Population post_1420

Distribution over PASSING jobs only. `unknown adverse` is per leg and belongs to no population: an artifact-less job cannot say which one it would have been.

| leg | lane | N | n passing | min | p1 | p5 | median (low) | n non-passing | no value, passing | no value, non-passing | unknown adverse (leg) |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| ubuntu-latest py3.14 | fixed_aggregate | 12 | 176 | 20.2593 | 26.0938 | 30.3125 | 35.4706 | 39 | 0 | 0 | 13 |
| ubuntu-latest py3.14 | fixed_per_conn | 12 | 176 | 35 | 35.6875 | 36.875 | 39.1875 | 39 | 0 | 0 | 13 |
| windows-2022 py3.14 | fixed_aggregate | 12 | 172 | 8.35714 | 8.42308 | 13.3333 | 22.963 | 41 | 0 | 0 | 22 |
| windows-2022 py3.14 | fixed_per_conn | 12 | 172 | 22.55 | 23.3158 | 31.6 | 38.6364 | 41 | 0 | 0 | 22 |
| windows-2025 py3.14 | fixed_aggregate | 12 | 168 | 15.5769 | 17.8 | 19.7857 | 26.7222 | 45 | 0 | 0 | 24 |
| windows-2025 py3.14 | fixed_per_conn | 12 | 168 | 15.1 | 30.9375 | 34.3529 | 38.4667 | 45 | 0 | 0 | 24 |

## Population with_tail

No readings in this population.

Unjoined artifacts: 30

- run 36899266832: connscale-readings-windows-2025-py3.14 (payload names run 12345, not this one)
- run 36899266832: connscale-readings-windows-2022-py3.14 (payload names run 12345, not this one)
- run 36888268050: connscale-readings-windows-2022-py3.14 (payload names run 12345, not this one)
- run 36888268050: connscale-readings-windows-2025-py3.14 (payload names run 12345, not this one)
- run 36888268050: connscale-readings-ubuntu-latest-py3.14 (payload names run 12345, not this one)
- run 36886576587: connscale-readings-windows-2025-py3.14 (payload names run 12345, not this one)
- run 36886576587: connscale-readings-windows-2022-py3.14 (payload names run 12345, not this one)
- run 36885156513: connscale-readings-windows-2022-py3.14 (payload names run 12345, not this one)
- run 36885156513: connscale-readings-ubuntu-latest-py3.14 (payload names run 12345, not this one)
- run 36885156513: connscale-readings-windows-2025-py3.14 (payload names run 12345, not this one)
- run 36834111947: connscale-readings-windows-2022-py3.14 (payload names run 12345, not this one)
- run 36834111947: connscale-readings-windows-2025-py3.14 (payload names run 12345, not this one)
- run 36832387947: connscale-readings-windows-2025-py3.14 (payload names run 12345, not this one)
- run 36816724625: connscale-readings-windows-2025-py3.14 (payload names run 12345, not this one)
- run 36816059581: connscale-readings-ubuntu-latest-py3.14 (payload names run 12345, not this one)
- run 36815269162: connscale-readings-ubuntu-latest-py3.14 (payload names run 12345, not this one)
- run 36815269162: connscale-readings-windows-2025-py3.14 (payload names run 12345, not this one)
- run 36792124946: connscale-readings-windows-2022-py3.14 (payload names run 12345, not this one)
- run 36792124946: connscale-readings-windows-2025-py3.14 (payload names run 12345, not this one)
- run 36788918025: connscale-readings-ubuntu-latest-py3.14 (payload names run 12345, not this one)
- run 36788918025: connscale-readings-windows-2022-py3.14 (payload names run 12345, not this one)
- run 36788918025: connscale-readings-windows-2025-py3.14 (payload names run 12345, not this one)
- run 36787986352: connscale-readings-windows-2022-py3.14 (payload names run 12345, not this one)
- run 36787986352: connscale-readings-windows-2025-py3.14 (payload names run 12345, not this one)
- run 36787986352: connscale-readings-ubuntu-latest-py3.14 (payload names run 12345, not this one)
- run 36787621386: connscale-readings-windows-2025-py3.14 (payload names run 12345, not this one)
- run 36787621386: connscale-readings-ubuntu-latest-py3.14 (payload names run 12345, not this one)
- run 36787621386: connscale-readings-windows-2022-py3.14 (payload names run 12345, not this one)
- run 36733146699: connscale-readings-windows-2025-py3.14 (payload names run 12345, not this one)
- run 36733146699: connscale-readings-windows-2022-py3.14 (payload names run 12345, not this one)

