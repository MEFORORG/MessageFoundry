# HANDOFF (dev → bench) — P0 Q3a: the exact `committed_txns` recorder diff

**Date:** 2026-07-12 · **From:** dev (traced against local `main` = mirror `28f860e` content) ·
**Re:** `HANDOFF_bench_to_dev_P0_recorder_followup.md`
**Answer up front, then the copy-pasteable diff. One correctness landmine flagged (§A). Anchor on the code strings, not
the line numbers — the mirror may drift a line or two.** Read-only; no secrets/IPs/PHI.

## A. The landmine your instinct already half-caught — capture it ONCE, in the coordinator

**`committed_txns` is an ENGINE-WIDE cumulative counter, summed across shards by `EnginePoller`. It is NOT
per-driver-worker.** So the recorder must **not** live in `run_shardcert_driver` (the K sender-workers) and must **not**
be summed out of `driver_dones` — K workers each polling `/stats` would each report the *same* engine-wide total, and
summing them **multiplies it by K**. Capture it **once, in the coordinator** — the same function that builds
`ShardCertDriveReport` and already opens an advisory poller against the engine `/stats`.

**Target report = `ShardCertDriveReport`** (`"kind": "shardcert_drive"`, the go/no-go verdict, constructed ~`:2748`).
You were right that it's the two-box drive record, not the single-box `ShardCertReport` — but the build site is the
**coordinator**, not the driver.

## B. Why a naive `final − baseline` on the existing poller is ~0 (and the fix)

The coordinator's poller is opened **only at drain** (`:2686`, right before `poller.await_drain`), so `poller.baseline`
= the first *drain* sample ≈ soak-END. `final.committed_txns − poller.baseline.committed_txns` would measure the drain
window (~zero), not the soak. **Fix: take one explicit `sample_once()` at soak START** (right after the coordinator
posts `DRIVE_START`), and delta it against the existing drain-time `final.committed_txns`.

## C. The denominator is `acked`, not `sink_received`

`committed_txns` is durable-write work **per ingress message** (the modelled `3+2H+2D` is per ingress message). The
coordinator's ingress-message count is **`a = Σ driver_dones["acked"]`** (`:2731`), which becomes `acked=a` in the
report. `sink_received` is `A × delivering` (delivered *copies*) — wrong denominator (they only coincide at D=1). Use
**`acked`**.

---

## D. THE DIFF (coordinator function that builds `ShardCertDriveReport`; all sites in one function)

**D1 — soak-START snapshot.** Immediately after the coordinator posts `DRIVE_START` (anchor: `coord.post(DRIVE_START,
{"t0": time.time()})`, ~`:2667`), insert:

```python
        coord.post(DRIVE_START, {"t0": time.time()})
        # --- P0 (ADR 0099) manipulation-check instrument -------------------------------------------
        # committed_txns is an ENGINE-WIDE cumulative gauge (summed across shards by the poller), so
        # snapshot it ONCE here in the coordinator — never per driver-worker (K workers would each read
        # the same total and summing multiplies by K). Bracket START (here) vs END (drain `final`).
        _txn_urls = [f"http://{engine_host}:{p}" for p in api_ports]
        _txn_poller = EnginePoller(
            _txn_urls, None, origin=time.perf_counter(), allow_insecure=allow_insecure
        )
        committed_txns_start: int | None = None
        try:
            await _txn_poller.open()
            _s0 = await _txn_poller.sample_once()
            committed_txns_start = _s0.committed_txns if _s0 is not None else None
        finally:
            with contextlib.suppress(Exception):
                await _txn_poller.close()
        # -------------------------------------------------------------------------------------------
```

**D2 — the delta at drain.** After the existing `final = poller.final` (anchor: `final = poller.final`, ~`:2689`), add:

```python
        final = poller.final
        committed_txns_run = (
            (final.committed_txns - committed_txns_start)
            if (final is not None and committed_txns_start is not None)
            else None
        )
```

**D3 — the dataclass field.** In `ShardCertDriveReport` (anchor: `notes: list[str] = field(default_factory=list)`,
~`:2352`), add a field **after** `notes` (keep it last + defaulted so an older record still deserializes):

```python
    notes: list[str] = field(default_factory=list)
    committed_txns_run: int | None = None  # P0: engine-wide committed_txns delta over the soak (None = not captured)
```

**D4 — populate at construction** (anchor: the `return ShardCertDriveReport(` at `:2748`; add beside `acked=a,`):

```python
        acked=a,
        ...
        notes=notes,
        committed_txns_run=committed_txns_run,
    )
```

**D5 — the measured-per-msg property.** Beside `txn_per_message` (anchor: `def txn_per_message`, ~`:2361`):

```python
    @property
    def committed_txns_per_msg(self) -> float | None:
        """MEASURED durable-write transactions per ingress message (P0 arming proof) — the engine-wide
        committed_txns delta over the soak divided by ``acked`` (A, ingress messages; NOT sink_received,
        which is A*delivering). Contrast with the MODELLED ``txn_per_message`` (3+2H+2D). ``None`` when
        the counter wasn't captured (older engine) or no intake."""
        if self.committed_txns_run is None or self.acked <= 0:
            return None
        return self.committed_txns_run / self.acked
```

**D6 — the JSON entry.** In `to_json_dict`, in the `"topology"` block beside `"txn_per_message"` (anchor:
`"txn_per_message": self.txn_per_message,`, ~`:2461`):

```python
                "txn_per_message": self.txn_per_message,
                "committed_txns_run": self.committed_txns_run,
                "committed_txns_per_msg": self.committed_txns_per_msg,
```

That surfaces both in every per-soak `"kind": "shardcert_drive"` record, so the `shardcert_ladder_two_box` top-level
JSON carries it per rung and the go/no-go reads `topology.committed_txns_per_msg` for arm A vs arm B at `R_sustain`.

---

## E. Sanity checks before you trust an arm
- **Imports:** `EnginePoller` and `contextlib` are already imported in this module (poller at `:543`/`:1860`/`:2686`,
  `contextlib.suppress` used in the same `finally`) — no new imports.
- **`baseline`/`final` are `@property`** on `EnginePoller` — no parens.
- **Expected read:** arm A `committed_txns_per_msg ≈ 5` (H=D=1 modelled dedicated), arm B `≈ 3` — a drop of ~2, well
  clear of the **≥ 0.9** floor. If arm B's value ≈ arm A's, `inline` didn't engage (knob unset, or a gate) → **VOID**,
  fix and re-run (not a refutation).
- **Homogeneity caveat holds:** because every cert message is identical, `committed_txns_per_msg` is the whole story —
  no fallback counter needed (Q3b).

If anything in the coordinator doesn't match these anchors on `28f860e` (e.g. `final` isn't named at the drain site),
send me the ±15 lines around `coord.post(DRIVE_START` and the `return ShardCertDriveReport(` and I'll re-cut D1/D2 to
your exact lines — but the shape (start snapshot after DRIVE_START, delta against drain `final`, one coordinator-side
capture, ÷`acked`) is the correct instrument regardless of line drift.
