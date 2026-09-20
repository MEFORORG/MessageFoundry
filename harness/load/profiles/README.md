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
with `--load <path>`. Never commit one here, **and never drop one in this directory gitignored by
name either** — that was tried, and it shipped. The harness wheel force-includes this directory
whole; hatchling's `recurse_forced_files` walks the filesystem and consults no `.gitignore`, and
`exclude` does not reach a force-included file, so the wheel carries whatever is sitting here on the
machine that built it (BACKLOG #1835). A guard test
([../../../tests/test_packaging.py](../../../tests/test_packaging.py)) now refuses a `.gitignore`
entry that names a path inside a force-included tree. A guard test
([../../../tests/test_load_config.py](../../../tests/test_load_config.py)) asserts the shipped
profiles + load config carry none of a denylist of real tokens. Generated traffic is synthetic HL7
(the `messagefoundry` generators); run artifacts carry metrics only — never message bodies.
