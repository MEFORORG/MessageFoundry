# ADR 0072 — Traced dry-run mode: `dryrun --trace json` for the interactive live-debug loop

**Status:** Accepted (2026-07-06). Ratified by the owner — the engine lane (MULTISESSION-PLAN-7 **L5**) may build. The traced mode is **additive + opt-in**; nothing here changes the shipped `dryrun` default. The §6 test gates are the acceptance criteria (byte-identical run · live-lookup identical · coverage-intact · redacted-by-default).
**Deciders:** owner + IDE/DX working group
**Related:** BACKLOG **#92** (interactive live-debug loop — the primary consumer, v2), BACKLOG **#84** (Test Bench profiling/coverage — the second consumer), BACKLOG **#48** (Insert Element palette — sibling DX lane), ADR 0004 (payload-agnostic ingress — `RawMessage` vs `Message` in a handler), ADR 0010/0043 (`db_lookup`/`fhir_lookup` — the sanctioned non-pure reads that raise in dry-run), CLAUDE.md §9 (PHI handling — `dryrun` output can contain full bodies). Plan: [`docs/releases/MULTISESSION-PLAN-7.md`](../releases/MULTISESSION-PLAN-7.md) (L5 builds this; L6/L7 consume it).
**Code references** are `origin/main @ 0f0ba08`; line numbers are approximate — locate exactly at implementation time.

---

## 1. Context — why the existing `dryrun` output can't drive a live-debug loop

BACKLOG **#92** (P1, the highest-leverage DX item from the #87 competitive recon) wants an *interactive* loop: on save, re-run a Router/Handler against a synthetic sample and render **per-statement inline values** (`x = msg["PID-3.1"]  ▸ "12345"`) plus a per-`@handler` disposition/`Send` summary. BACKLOG **#84** wants **profiling** (per-line/per-handler timings) and **coverage** (which handler/router lines executed) in the Test Bench. Both need the same thing: **machine-readable, line-addressable execution data from a dry-run.**

Today [`messagefoundry/pipeline/dryrun.py`](../../messagefoundry/pipeline/dryrun.py) + the `dryrun` CLI ([`messagefoundry/__main__.py`](../../messagefoundry/__main__.py) `_dryrun()`, ~line 1458) produce **one JSON row per message**: a per-message `disposition`, a flat `handlers: string[]`, and a `deliveries` list (`DeliveryPreview`) that **has no `handler` field** — `run_one_handler`'s per-handler deliveries are flattened (`deliveries.extend(ds)`, `dryrun.py` ~line 312). So even per-*handler* attribution is lost for a multi-handler module, and there is **no per-statement/per-line data at all**. The IDE Test Bench renders a whole-payload before/after diff from this; it cannot show "what did line 7 compute."

**Non-goal / already-built:** step-through debugging *exists* — the Test Bench's **Debug** action launches the Router/Handler under `debugpy` (real breakpoints). That is an *interactive breakpoint* session, not a *passive per-statement value stream* rendered inline on every save. #92 is deliberately **no-breakpoints, no debug session** — a deterministic annotation pass. This ADR defines its data source.

## 2. Decision — an additive, preview-only traced dry-run

Add a **`dryrun --trace json`** mode. A `sys.settrace`-based tracer wraps **only** the Router/Handler call inside the existing dry-run path and emits, per invocation, a **line-addressable event sequence + the final disposition + the resulting `Send`s**, as the JSON schema in §3. It is:

- **Additive and opt-in** — a new `--trace` flag on the `dryrun` subparser (`__main__.py` ~line 156); `_dryrun()` branches to the trace builder. Absent the flag, `dryrun` is byte-for-byte unchanged.
- **Preview-only — no dispatch/logic change.** The tracer observes; it never alters routing, transform, disposition, or `Send`s. **A traced run's `disposition` + `Send`s MUST be byte-identical to the same non-traced run** (a hard test gate, §6).
- **Engine-owned, single-editor.** Implemented in `dryrun.py` (optionally a new SPDX-headed `pipeline/dryrun_trace.py`) + the CLI branch — the sole engine surface; the IDE consumers (L6/L7) only parse the emitted JSON contract.

This is the concrete data contract the two IDE consumers build against; freezing it here is what lets L5 (engine) and L6/L7 (IDE) proceed against a stable interface.

## 3. The trace schema (v1)

Emitted as JSON (streamed — see §5). One object per Router/Handler invocation:

```
{
  "kind": "handler" | "router",
  "name": "<registered name>",
  "module": "<config module path>",
  "def_line": <int>,                     // line of the @handler/@router def
  "events": [
    { "line": <int>, "event": "line",
      "assigned": { "<localname>": "<value|REDACTED>" } }   // locals that CHANGED entering this line
    // ... in execution order; loops repeat lines
  ],
  "disposition": "PROCESSED" | "ROUTED" | "UNROUTED" | "FILTERED" | "ERROR",
  "sends": [ { "outbound": "<name>" }, ... ],   // handler only
  "routed_to": [ "<handler name>", ... ],       // router only
  "annotations": [
    { "line": <int>, "kind": "live_lookup_skipped",
      "call": "db_lookup" | "fhir_lookup" }
  ]
}
```

- **Value-capture timing.** `sys.settrace` `"line"` events fire on line *entry*, so a value assigned on line *N* is only observable once the tracer reaches line *N+1*. The tracer therefore reports a **locals-diff per line** (`assigned` = locals that changed since the previous line event), and attributes each change to the line that produced it. This is deterministic and needs no AST rewrite; an AST-assisted refinement is a possible v2 (§7), out of scope here.
- **`msg` mutations.** Field writes (`msg[...] = …` / `msg.set(...)`) surface as a change to the `msg` object; the tracer records the **path + new value** written on that line (not the whole message), so the IDE can annotate `msg["PID-5.1"] ▸ "SMITH"`. Whole-payload before/after stays the Test Bench's job (L4), not the trace's.
- **Scope.** Events are captured **only** for frames inside the config module's Router/Handler (by `co_filename` + the def's line range); calls into engine/library code return `None` from the trace function (not traced) — the annotation surface is the author's own code, nothing else.

## 4. Live lookups (`db_lookup` / `fhir_lookup`) — annotate, do not resume

The sanctioned non-pure reads (ADR 0010/0043) are **unavailable in dry-run and raise `DbLookupError`** (`dryrun.py` `_dry_run_raw`, ~line 369), which classifies the message **`ERROR`**. Under `--trace` this behavior is **unchanged and byte-identical**: the handler still terminates at the raise, disposition stays **`ERROR`**. The tracer's *only* added behavior is to **classify that terminal exception** as a live-lookup skip and emit a `live_lookup_skipped` annotation on that line. "Graceful, not a crash" means the **IDE degrades the annotation** ("⚠ live lookup — not evaluated in preview") — it emphatically does **not** mean the tracer swallows the exception or resumes the handler. Stubbing/mocking a live lookup for a fuller preview is a possible future enhancement, explicitly **not** in this ADR.

## 5. Capture semantics + PHI (the load-bearing correctness section)

**`sys.settrace` robustness — mandatory:**
- **Restore the prior tracer.** Save `prev = sys.gettrace()` and restore it in a `finally` — **never `sys.settrace(None)`**. `coverage.py` / `pytest-cov` install a global trace function; clobbering it corrupts coverage for the process (including L5's own test run). This is a hard test gate (§6.3).
- **Frame-scoped.** The trace function returns a local trace only for the exact Router/Handler frame (matched on `co_filename` + def line range) and `None` for every other frame — no library/engine code is traced.
- **Thread-locality.** `sys.settrace` is **per-thread**, and the handler (and `db_lookup`) may run **off the event-loop thread** (they run in a worker per ADR 0001/0010). The tracer must install on the thread that actually executes the handler — either assert the handler runs on the tracer's thread in dry-run, or use `threading.settrace` so worker threads inherit it. Get this wrong and the trace is silently empty.
- **Python 3.14 `sys.monitoring` (PEP 669).** The project is 3.14+. `sys.settrace` and `sys.monitoring` coexist; the tracer must not assume it is the only instrumentation and must tolerate `sys.monitoring`-based coverage tools. State the coexistence explicitly at implementation.

**PHI — a hard requirement, not prose (CLAUDE.md §9):** trace `assigned`/`msg`-write **values are PHI** (an `assigned` `mrn` is a real MRN).
- **Redacted by default.** Values serialize as `"REDACTED"` (or a length/type shape) unless an explicit opt-in is passed. Reuse the existing `dryrun` PHI gate (`--show-phi` / the `_redact` path, `__main__.py` ~line 1452) — do **not** invent a second, looser gate.
- **Un-redaction is explicit, per-session, and non-persisted.** Real values require the operator to pass the existing show-PHI opt-in; it is **never** auto-enabled by the IDE "on" toggle (L6 keeps a *separate* "reveal values" control that is off by default and never auto-passes `--show-phi`).
- **Streamed, never a temp file.** The trace JSON is produced and consumed **in-process / over stdout**; it is **never written to a persisted or committable temp file**. There is no on-disk trace artifact to leak or accidentally commit.
- **Synthetic data only.** Live-debug (L2/L6) runs the traced dry-run **only against synthetic samples under `messageSetsDir`** (MeFor generates PHI-free corpora); the concrete guard is "the input file is a synthetic sample," not an environment sniff.

## 6. Consequences

**Enables:** #92 **v2** (per-statement inline decorations + hover, L6) and #84 **profiling/coverage** (L7) — both purely by *consuming* this CLI contract, with no further engine change. #92 **v1** (L2) and #84 **diff** (L4) ship *before* this ADR against today's `dryrun --json` and the client-side diff respectively — this ADR gates only the v2/profiling tier.

**Costs / risks:** a `sys.settrace` pass slows the traced handler (acceptable — dry-run is a dev-time preview, not the hot path). The trace function is correctness-sensitive (prior-tracer restore, thread-locality) — hence the mandatory §5 rules and the §6 test gates.

**Test gates (L5 `tests/`):**
1. **Byte-identical:** a `--trace` run's `disposition` + `sends`/`routed_to` equal the non-traced run's for the same sample.
2. **Live-lookup identical:** a handler hitting an unstubbed `db_lookup` yields identical disposition/Sends **with and without** `--trace`, plus a `live_lookup_skipped` annotation.
3. **Coverage-intact:** a traced run executed **under `pytest-cov`** leaves the outer coverage data intact (proves the prior tracer was restored).
4. **PHI-redacted-by-default:** values are `REDACTED` without the show-PHI opt-in.

**Not changed:** the staged-pipeline invariants (ADR 0001), the `dryrun` default output, dispatch/routing/transform, and the store. No runtime dependency added (`sys.settrace` is stdlib). Not store-touching → no 3-backend parity suite.

## 7. Alternatives considered

- **`debugpy` / DAP (already shipped for step-through).** Interactive breakpoints require a live debug session and user-driven stepping; it does not yield a passive, deterministic per-statement value stream on every save. Kept for its purpose (Test Bench "Debug"); not the #92 data source.
- **AST instrumentation / bytecode rewriting.** Could attribute values to sub-expressions more precisely, but it rewrites author code, is fragile across Python versions, and risks diverging behavior from the real run (violating the byte-identical guarantee). Rejected for v1; a bounded AST-assisted *value-timing* refinement is a possible v2.
- **Enrich the existing `--json` with per-handler attribution only** (add a `handler` tag to `DeliveryPreview`). Cheap, and it would let #92 **v1** show accurate multi-handler summaries — but it yields **no per-statement data**, so it cannot drive #92 v2 or #84 profiling/coverage. Noted as the **owner option** in MULTISESSION-PLAN-7 §H for v1 only; insufficient as the v2 contract.

---

*This ADR is Proposed / direction-setting. It fixes the trace contract, the capture semantics, the live-lookup rule, and the PHI posture; it is ratified (Accepted) before L5 writes code, and nothing here changes the shipped `dryrun` default.*
