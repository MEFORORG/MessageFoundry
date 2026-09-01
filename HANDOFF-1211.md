# HANDOFF -- BACKLOG #1211 limb two, stopped mid-build at a usage cutoff

Seat: reviewer-1873a2. Branch `fix/1211-connscale-monotonic-band`, pushed, tip `1de7af0bb`,
cut from `origin/main` at `72bfddfad`. Claim taken on #1211. **#1411 is ALLOCATED but has no
heading yet** -- if you abandon this work, release it.

The commit is deliberately marked WIP. **The suite is not green.** Read "What is broken" before
anything else.

---

## The finding, in one paragraph

The `empty_claims_monotonic` gate was not too tight or too loose. Its threshold was anchored to
the **previous reading** instead of to the rise the sweep predicts, and that single fault made it
both. It reddened a required context on 9.8 percent of runs -- twice on `main` itself -- while
passing a curve flattened to half its healthy value 143 times out of 144. Widening it was never
the fix.

## Evidence (all reproducible, scripts kept -- see "Artifacts")

Harvested 200 ci.yml runs; 153 carried a `connscale-readings` artifact; 454 payloads, 0 expired,
0 failures; **894 lane transitions**, 2026-08-29 to 2026-09-01, 92 branches.

    leg              lane                n     min      p5  median     max  breach
    ubuntu-latest    fixed_aggregate   144   0.779   1.813   1.988   4.071      0
    ubuntu-latest    fixed_per_conn    149   1.231   1.399   1.673   1.805      0
    windows-2022     fixed_aggregate   150   0.672   0.879   1.310   4.396      2
    windows-2022     fixed_per_conn    153   0.383   0.753   1.083   1.744      8
    windows-2025     fixed_aggregate   146   0.858   1.083   1.436   2.548      0
    windows-2025     fixed_per_conn    152   0.551   0.761   0.962   2.804      7

**Five defects, each verified by executing the real code, not by reasoning:**

1. Fires on the environment: 15 of 153 runs, including two `event: push` runs on `main`
   (33310605221, 33352508672).
2. Passes the regression it exists for. A flattened curve (39.89 -> 39.89, ratio 1.00) is a 50
   percent loss and `_monotonic_slo` returns ok. 143 of 144 ubuntu transitions would still pass.
3. Passes a **total** collapse when it hits both N: 0.0 -> 0.0 gives `not (0.0 < 0.0)` = True and
   reports `observed = 'monotonic'`.
4. The floor is fitted, and the corpus proves it about itself: an 88-run pass put the worst ratio
   at 0.539, this 153-run pass found **0.383**. No positive floor at or above 0.40 is clean.
5. Silently half-covers: 14 of 454 legs (3.1 percent) lost a whole lane to `None` readings and
   still reported `monotonic`. `fd_count_monotonic` has a guard for exactly this; this had none.

**The splitting variable is the hosted runner, not the OS.** A local control on this box
(Windows, 20 cores) read 1.840 / 1.615 -- ubuntu-CI-like, not Windows-CI-like. So "gate only on
Linux" gates on a proxy. Ubuntu is not clean either: its minimum, 0.779, cleared the floor by
0.029.

## The design, and the owner decision that shaped it

A 13-agent design panel converged on replacing the ratio with an **absolute floor on the base-N
reading, predicted from the sweep's own configuration**:

    W    = 3                              # router + transform + delivery worker per connection
    wake = W * (N - 1)                    # engine-wide singleton wake; N-1 book an empty claim
    idle = W * N / (0.25 * R)             # each idle worker re-SELECTs once per backstop interval
    total = wake + idle                   # healthy
    floor = sqrt(total * idle)            # log-midpoint of "herd present" and "herd gone"

All three inputs were verified in code, not taken on trust: `graph.py` registers one inbound AND
one outbound per index (so W=3); `pooled_sweep_interval` really defaults to 0.25; the smoke really
runs `per_lane`. **The model reproduces all four harvested ubuntu medians to within 5.1 percent**
having been derived, not fitted (predicted 39.0 / 81.0 / 45.0 / 81.0 against observed 39.89 /
79.29 / 47.41 / 79.17).

**Then its own pre-landing check failed, and that is why the floor is not a gate.** On run
33448760672 -- a push to `main` whose `test (windows-2022, py3.14)` job **PASSED** -- the base
reading was 13.12 against a floor of 15.30. Gating on it would have reddened a green leg, which
is the defect being fixed. The plan had pre-committed the decision rule before seeing this.

**Owner ruled (this session): record it, do not gate it yet**, and **allocate a follow-up item**.
So: the enforced check is narrow and unflakeable; the predicted floor is computed and RECORDED in
the artifact and step summary on every run, so #1411 can turn it on from a distribution.

The enforced check (`empty_claims_base_reading`) asserts only that each `per_lane` lane produced a
**strictly positive** base reading. It closes defect 3, cannot flake on level noise (a sign test,
not a threshold), and would have fired 0 times in 454 legs.

---

## What is DONE (committed at `1de7af0bb`)

- `report.py`: `CONNSCALE_WORKERS_PER_CONNECTION`, `ENGINE_IDLE_POLL_INTERVAL_S`,
  `HerdPrediction`, `predict_herd_levels`, `HerdFloorReading`, `herd_floor_readings`.
- `report.py`: `readings_payload` gains `base_count` and a `herd_floor` block, payload
  `schema_version` 1 -> 2 (NOT the module `SCHEMA_VERSION`, which governs `to_json_dict`).
  Ratio rows byte-unchanged so the 454 harvested payloads stay comparable.
- `report.py`: `render_readings_markdown` gains `base_count` + `_render_herd_floor_rows`.
- `runner.py`: `_empty_claims_base_reading_slo` replaces the `empty_claims_monotonic` branch;
  `herd_floor_readings` imported.
- `profile.py`: `empty_claims_monotonic` -> `empty_claims_base_reading` in the dataclass,
  `_SLO_KEYS` and `_slo_from`. No shim (zero deployments).
- `tests/test_connscale_smoke.py`: flag swapped, `base_count` passed to both emitters, the welded
  `test_the_fd_and_empty_claim_curves_are_monotonic_in_n` split into two named tests, run-level
  "was anything graded" bound added.

## What is BROKEN or NOT STARTED -- do these in order

1. **The suite is red.** `tests/test_connscale_empty_claims_per_msg.py` still drives
   `_monotonic_slo` with `empty_claims_per_msg` in roughly 8 places (lines ~153, 164, 173, 195,
   210, 254, 268, 311). Retarget those onto `_empty_claims_base_reading_slo` /
   `herd_floor_readings`. **Keep** the emitter tests (~245, 288-311, 480-491) -- they cover the
   ratio recording, which is unchanged and is limb one's deliverable. Its `_rec` helper hard-codes
   `offered_aggregate_rate=35.0`, which is neither shipped profile's rate and makes every
   prediction wrong; give it a parameter defaulting to 24.0.
2. `tests/test_connscale_report.py::test_monotonic_slo_tolerates_jitter_but_catches_regression`
   (~line 91) exercises `_monotonic_slo` through `empty_claims_per_s`. Point it at
   `fd_count_monotonic` / `fd_count_peak` -- the one caller that still exists. Logic unchanged,
   which is the point: it proves the FD path did not move.
3. `harness/load/profiles/connscale-smoke.toml`: swap the flag; fix the header (lines 2-3) and the
   `[connscale.slo]` comment (lines 28-30), which is wrong on per-second, on both-modes and on
   slope. Note honestly that no workflow invokes this file (PERF-36), so its N=50/100 point is
   predicted and unexercised.
4. `profile.py` `_validate`: reject `empty_claims_base_reading = true` when `PER_LANE not in
   claim_modes`. Structural positive control -- it cannot flake.
5. **Docstrings, and this is not optional tidying.** `_empty_claims_per_msg` still carries a HOLD
   saying the band must not be touched "until several deliberate samples exist". They exist. Left
   standing, the next reader re-opens what this closed. Retire it **in words**, not by deletion.
   Keep the contention-immunity correction and the #343/#355 table -- both still true, now the tail
   of a measured distribution. Also: the `_MONOTONIC_TOLERANCE` comment (~1409) claims 0.25
   "catches a genuine collapse (a halving)" -- falsified, since 0.50 sits inside windows-2022
   `fixed_per_conn`'s healthy population (p5 0.753). After this change `fd_count_monotonic` is its
   ONLY consumer and the FD ratio distribution has never been harvested, so say that and forbid
   retuning it on empty-claims evidence. Also `_monotonic_slo`'s docstring (scope it to FD) and
   `ConnScaleSlo`'s field comment.
6. **`docs/BACKLOG.md` -- required check, the PR cannot merge without it.** Amend #1211 as the
   single home for the harvest (SDS-3.5: state it once, link, do not restate the table in code).
   File #1411 with the enable criterion. Update the index row near line 336. Draft prose is in
   `evidence.md` and `docstring_draft.md` (see Artifacts).
7. Consider: pin `MEFOR_PIPELINE_PER_LANE_WAKE=false` in the engine env (runner.py ~line 602). The
   prediction assumes the singleton wake; today the harness inherits the default, so an unrelated
   flip would move the recorded floor with no connscale change. Not required while the floor is
   ungated -- but required before #1411 turns it on.
8. `ruff format`, `ruff check`, `mypy messagefoundry`, then the connscale tests. The smoke test
   spawns engines; it did NOT complete inside 7 minutes on this box (it wrote its readings, then
   pytest hung), so budget for that or rely on CI.
9. Open the PR. Cite `(BACKLOG #1211)` in the title so the required backlog check fires, and only
   after step 6 is done. Notify the Reviewer seat; the merge is the Lander's.

## Traps that already cost time

- **The primary checkout's venv is safe to use as an interpreter** (`<HOME>\Code\
  MessageFoundry\.venv\Scripts\python.exe`); this worktree has none. Verified that `harness` and
  `messagefoundry` both resolve to THIS worktree, not the primary.
- **Do not use a bash heredoc for Python that contains `\n` string literals** -- a backslash gets
  mangled and the patch silently fails to match. Use the Edit tool.
- The commit-msg claim gate fires on any code commit whose subject says `BACKLOG #N`. Claim first.
- `git rev-list --count origin/<branch>..HEAD` returning 0 is not proof of a push when the
  positive control also returns 0. Verify with `git ls-remote` plus a ref that must NOT exist.

## Artifacts (scratchpad -- NOT in the repo, copy anything you need before it is cleaned)

`<HOME>\AppData\Local\Temp\claude\C--Users-Scott-Code-MessageFoundry--claude-worktrees-reviewer-1873a2\9e6b07d2-79f6-4c30-9d68-8b6be26f790a\scratchpad\`

- `harvest.py` -- re-runs the whole harvest (~3 min, prints what it scanned)
- `readings.jsonl` -- 1789 rows, the raw evidence
- `runs.json`, `scan.json` -- provenance
- `analyze.py`, `tails.py`, `counterfactual.py` -- the three tables above
- `evidence.md` -- the BACKLOG amendment draft
- `docstring_draft.md` -- what each docstring half must say and why
- `local_run1.json` -- the local 20-core control reading

Workflow transcript (4 designs, 8 critiques, 1 synthesis, with the full implementation plan):
`<HOME>\.claude-account-2\projects\C--Users-Scott-Code-MessageFoundry--claude-worktrees-reviewer-1873a2\9e6b07d2-79f6-4c30-9d68-8b6be26f790a\subagents\workflows\wf_6071ed6d-eba\journal.jsonl`
