# ADR 0141 — Publish copies-per-message as the #207 sizing proxy; the bytes-per-message figure stays refused

- **Status:** Accepted (2026-07-20) — MULTISESSION-PLAN-13 Wave 2 build (lane `plan13-207-bytes`);
  owner-ratified proxy decision. Pushes/PR owner-approved.
- **Built:** Yes — `EngineSummary.body_copies` + `EngineSummary.copies_per_message` in
  [`harness/load/report.py`](../../harness/load/report.py), rendered on `engine_side` (JSON) and in
  `render_console()` beside the measured `txn/msg` (#207 loose end 1). `SCHEMA_VERSION` 2 → 3.
- **Related:** [ADR 0051](0051-corepoint-throughput-parity-strategy.md) (the `3 + 2H + 2N` transaction
  cost model this sits beside), [ADR 0084](0084-accepts-router-seam.md) (`H ≠ N` at the hub shape),
  BACKLOG **#207** (this closes it). The amplification model itself is pinned by
  [`tests/test_bytes_per_message_amplification.py`](../../tests/test_bytes_per_message_amplification.py).

## Context

BACKLOG #207 asked for **two** per-run parity counters the incumbent publishes and MessageFoundry never
measured: `txn/msg` and `bytes/msg`. The first shipped as the *measured* `txn_per_message_measured` (loose
end 1, PR #1130) — a self-differenced live `committed_txns` counter beside the analytical `3 + 2H + 2N`
model. This ADR decides the second.

The engine already exports a live **`body_copies`** counter (`/stats`, summed across shards by the load
harness's poller): the number of raw/payload **body strings durably written**. Its analytical counterpart is
the `2 + H + N` amplification pinned by `test_bytes_per_message_amplification.py` — `messages.raw` + the
ingress `queue.payload` (2), one full raw copy per selected handler (`H`), one per delivery (`N`).

`body_copies` is a **copy count, not bytes**. The A2 analysis that pinned the amplification model recorded
an explicit **refusal to publish a byte figure**, and that refusal is the thing this ADR has to either keep
or reverse. Three candidates were on the table:

1. **copies/msg** — the `body_copies` delta ÷ the run message count.
2. **A "measured" bytes/msg** — the `db_size_bytes` delta ÷ acked.
3. **A per-backend byte estimate** — copies × mean body size × width/cipher multipliers.

## Decision

**Publish (1): `copies/msg`, backend-named, explicitly labelled NOT bytes. No byte figure is published.**

Concretely, in `harness/load/report.py`:

- `EngineSummary.body_copies` — the run delta, self-differenced `final − base` exactly as
  `committed_txns` / `db_size_bytes` already are.
- `EngineSummary.copies_per_message` — that delta ÷ the run message count (`Counters.acked`),
  `float | None`.
- JSON `engine_side` gains `body_copies`, `copies_per_message`, **`copies_per_message_backend`** (the
  reading is not portable between backends) and **`copies_per_message_unit`** =
  `"body copies (NOT bytes)"` (the unit travels with the number, so a downstream consumer cannot read it
  as a byte figure).
- Console renders, beside the measured `txn/msg`:
  `copies/msg (sqlserver; NOT bytes): 4.00/msg (body_copies=420)`.
- `SCHEMA_VERSION` 2 → 3.

**Not-measured is never 0.** A backend whose `body_copies` never moves (Postgres never wired the counter,
so it reads a flat `0`), or a run that acked nothing, renders `copies_per_message = None` / `"not measured"`
— **never a fabricated `0.00/msg`**. Every real run that acks a message writes at least its `messages.raw`
and ingress `queue.payload` copies, so a `0` delta over acked traffic is an *unwired counter*, not a
zero-copy run. A red-first guard test pins this (`test_unwired_body_copies_renders_not_measured_never_zero`).

**The published figure is welded to the model.**
`test_the_rendered_copies_per_message_matches_the_2_H_N_model` drives a real `RunReport` at the pinned
shapes `(H=1,N=1)`, `(8,8)`, `(20,4)` and asserts the *rendered* copies/msg equals `2 + H + N`. A wrong
counter no longer agrees with the model, and the model can no longer drift from what the harness prints.

### Caveats that ship WITH the number

1. **Backend dependence — this is why the label names the backend.** SQLite implements
   store-once-deliver-many: a byte-identical fan-out is stored once in `shared_body`, each outbound row
   carrying a `body_ref` with an empty inline payload ⇒ **1 copy**. SQL Server does not — `body_ref` stays
   NULL and it writes **N** inline copies. The same traffic therefore reads *materially lower* on SQLite.
   **The rig and production run SQL Server**, so a SQLite reading must never be carried across.
2. **It is a count, not a size.** It says nothing about how large each body is.
3. **NVARCHAR UTF-16 (×2).** `queue.payload` / `messages.raw` are `NVARCHAR(MAX)` on SQL Server with no
   UTF-8 collation — 2 bytes per ASCII character. SQLite `TEXT` is UTF-8 (1).
4. **Cipher expansion.** With `MEFOR_STORE_ENCRYPTION_KEY` set each copy becomes
   `mfenc:v1:<key_id>:<base64(nonce||ct||tag)>` — roughly `4/3 × raw + ~64` bytes.
5. **Everything the database writes that is not the body** — row and page overhead, indexes, and above all
   the **transaction log**, which durably records each of the `3 + 2H + 2N` transactions.

## Why the byte figure stays refused

A `db_size_bytes`-delta ÷ acked number is **plausible-but-wrong**, which is precisely the failure class this
programme has repeatedly been burned by (a confident number nobody can falsify at a glance). It is not a
body-bytes measurement:

- it sweeps up **index, row and page overhead**, and the **transaction log**, which are not per-message body
  bytes at all and scale with `txn/msg`, not with copies;
- it captures **autogrowth, checkpoints and log truncation** that happen to land inside the sampling
  window — a file that grew in 8 MB increments reports the increment, not the traffic;
- it is simultaneously **deflated by page reuse** and **inflated by UTF-16 width and cipher expansion**, with
  no way to separate the terms from the outside;
- it would be published against the incumbent's **10.9 KB/message** budget (500 GB/day ÷ 45M) — the number
  that sizes the drive an adopter is told to buy. A wrong figure there is not a cosmetic error.

Candidate (3), a per-backend byte *estimate*, is worse still: multiplying (2)–(4) yields a **lower bound on
body bytes**, not durable bytes, and dressing an estimate as a measurement is the same defect with an extra
layer of arithmetic.

So: **no `bytes_per_message` key exists in the report**, and a test asserts that
(`test_no_bytes_per_message_figure_is_published`). `db_growth_bytes` remains emitted as a **raw
observation** — nothing divides it by the message count.

## Consequences

- #207 closes with the honest half of its ask: one *measured* `txn/msg` and one *measured* copies/msg
  sizing proxy, each with its unit and its backend attached.
- Sizing guidance an adopter can act on still needs the per-body byte width for their own message mix and
  their own backend/encryption posture; the report gives them the multiplier (copies), not the product.
- Reversing this — publishing a byte figure — requires a **real** measurement (an isolated store, a known
  fixed body, a quiesced log, growth attributed per table) and a new ADR that supersedes this one. It is
  not a matter of dividing an existing gauge.
- `SCHEMA_VERSION` 3 is additive: consumers reading v2 keys are unaffected.
