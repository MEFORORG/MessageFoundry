# `results_relay` — Wave-1 porting template (ORU results relay)

A fully **synthetic** worked example of the standard MessageFoundry feed shape:

```
IB_LABCO_ORU (MLLP in)  →  @router oru_router  →  @handler relay_results  →  OB_EHR_ORU   (MLLP out)
                                                                          →  FILE-OUT_LABCO_ORU (file archive)
```

Use it as the reference when porting a feed: copy the structure, swap in the real connection
names/endpoints (via `env()`), the real code sets, and the real transform.

## What it demonstrates

| Concern | How |
|---|---|
| Routing | `@router` returns handler name(s); non-`ORU` → routed nowhere (logged `UNROUTED`) |
| Filtering | handler returns `None` when every result is cancelled (logged `FILTERED`) |
| Reference data | `code_set("test_codes")` maps the local lab code → the EHR's code (`codesets/test_codes.csv`) |
| Per-environment endpoints | `env("ehr_host")`, `env("ehr_port")`, `env("archive_dir")` with local defaults |
| **Repeating fields** | `repetitions("PID-3")` + `field(..., repetition=k)` to find the MR identifier; whole-field write to collapse the list |
| **Repeating segments** | `count_segments("OBX")` + `field(..., occurrence=i)` to read each OBX; `delete_segments("OBX")` + `add_segment(...)` to rebuild the block (drop cancelled, remap codes, renumber) |
| Fan-out | handler returns a list of `Send`s (EHR + file archive) |
| Separators | read from MSH-1/MSH-2 (`_separators`), never hardcoded |

## Run / verify

```bash
# validate + dry-run the transform over the fixtures (what CI gates)
python -m messagefoundry check --config samples/results_relay --messages samples/results_relay/messages

# see the before/after (synthetic data only)
python -m messagefoundry dryrun --config samples/results_relay \
    --messages samples/results_relay/messages --show-phi

# run it for real (dev env)
python -m messagefoundry serve --config samples/results_relay --env dev --db ./mf.db
```

`messages/oru_results.hl7` → relayed: PID-3 collapsed to the MR id, the cancelled Potassium result
dropped, GLU/NA/CL remapped to GLUC/SOD/CHLOR, OBX renumbered, sent to both destinations.
`messages/oru_all_cancelled.hl7` → `FILTERED` (nothing to relay).

This sample is gated by `tests/test_checks.py` (validate + dryrun on every CI run).
