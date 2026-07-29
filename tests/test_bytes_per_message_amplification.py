# Copyright (c) MessageFoundry contributors.
# SPDX-License-Identifier: Apache-2.0
"""A2 (part 1) — pin the BODY-COPY amplification factor per ingress message.

The incumbent's qualified spec budgets **~10.9 KB of storage per message** (500 GB/day over 45M). Nothing
in this project has ever measured what a message actually costs on disk. This module pins the part that is
*exactly derivable from the code* — how many copies of the body are written — and deliberately stops short
of publishing a bytes-vs-budget verdict, which needs a live measurement.

## What is pinned here (measured against the real store methods)

Per ingress message, with `H` handlers selected and `N` destinations delivered:

| write                              | body copies |
|------------------------------------|-------------|
| `enqueue_ingress` -> `messages.raw`| 1           |
| `enqueue_ingress` -> ingress `queue.payload` | 1 |
| `route_handoff` -> `H` routed rows | `H`         |
| `transform_handoff` -> outbound rows | `N` (SQL Server) |

Total: **`2 + H + N`**.

The 2026-07-10 audit estimated `(1 + H + N)` — it omitted the `messages.raw` copy, which is written in the
same transaction as the ingress queue row and is retained for the message's whole lifetime. The ADT hub
(`H=20, N=4`) therefore writes **26** body copies, not 25.

## The SQL Server / SQLite asymmetry, which matters because the rig and production run SQL Server

SQLite implements store-once-deliver-many: when >=2 of a handler's deliveries carry a byte-identical
transformed body, it stores the body **once** in `shared_body` and each outbound row carries a `body_ref`
with an empty inline `payload`. **SQL Server does not** — `sqlserver.py` creates the `shared_body` table
for schema parity and its own comment records that "on SQL Server `body_ref` stays NULL today". So a
fan-out of `N` identical bodies costs `1` copy on SQLite and `N` copies on SQL Server.

## What is NOT concluded here, and why

Converting copies to durable bytes requires three multipliers this module does not measure:

1. **Character width.** `queue.payload` / `messages.raw` are `NVARCHAR(MAX)` on SQL Server with no UTF-8
   collation, i.e. UTF-16: **2 bytes per ASCII character.** SQLite `TEXT` is UTF-8: 1.
2. **Cipher expansion.** With `MEFOR_STORE_ENCRYPTION_KEY` set, each copy becomes
   `mfenc:v2:<alg>:<key_id>:<base64(nonce||ct||tag)>` — the shipped at-rest format since ADR 0148
   defaulted `[store].aad_bind` on; `aad_bind=false` selects the frozen `mfenc:v1:<key_id>:<b64>`
   writer. Either way roughly `4/3 * raw + ~64` bytes. Default cipher is identity (no key set).
3. **Everything the database writes that is not the body**: row and page overhead, indexes, and above all
   the **transaction log**, which durably records each of the `3 + 2H + 2N` transactions.

Multiplying (1) and (2) by the copy count gives a *lower bound* on body bytes, not durable bytes. A
confident `bytes/msg` published from that product would be exactly the kind of plausible-but-wrong number
this programme keeps producing.

## What the harness publishes instead (ADR 0141, #207 loose end 2)

**Copies per message**, not bytes: `harness/load/report.py` self-differences the live `body_copies` store
counter over a run and divides by the message count, rendering `copies/msg (<backend>; NOT bytes)`. That is
the LIVE counterpart of the `2 + H + N` model pinned above, so the two are welded together by
`test_the_rendered_copies_per_message_matches_the_2_H_N_model` below: a wrong counter no longer agrees with
the model, and the model can no longer drift from what the harness prints.

The **byte** figure stays refused. A `db.size_bytes`-delta ÷ acked number — the "real figure" this docstring
used to point at — is not a body-bytes measurement: it also carries row/page/index overhead, the transaction
log, and any autogrowth or checkpoint that happened to land inside the window, and it is deflated or inflated
by (1) and (2) besides. Publishing it as `bytes/msg` would be the same plausible-but-wrong class this module
was written to refuse, so no `bytes_per_message` key exists in the report.
"""

from __future__ import annotations

import pytest

from harness.load.enginepoll import EnginePoller, EngineSample
from harness.load.metrics import Counters, Histogram
from harness.load.profile import load_profile_text
from harness.load.report import PhaseRecord, RunReport, build_report
from tests.adr0075_batch_harness import AsyncRecCursor, RecConn, bare_store, drive_async

pytestmark = pytest.mark.asyncio

BODY = "M" * 512


def _copies_of(cur: AsyncRecCursor, *bodies: str) -> int:
    """How many times a body string was handed to the driver as a bound parameter."""
    wanted = set(bodies)
    return sum(1 for _, params in cur.calls for p in params if isinstance(p, str) and p in wanted)


async def _drive(method: str, **kwargs: object) -> AsyncRecCursor:
    conn, cur = RecConn(), AsyncRecCursor()
    await drive_async(bare_store(), method, cursor=cur, conn=conn, **kwargs)
    return cur


async def test_enqueue_ingress_writes_TWO_copies_of_the_raw() -> None:
    """`messages.raw` (retained for the message's lifetime) AND the ingress `queue.payload`.

    The audit's `(1 + H + N)` estimate counted one. This is the missing copy.
    """
    cur = await _drive("enqueue_ingress", channel_id="IB", raw=BODY, now=100.0)
    assert _copies_of(cur, BODY) == 2


@pytest.mark.parametrize("handlers", [1, 4, 20])
async def test_route_handoff_writes_one_raw_copy_per_selected_handler(handlers: int) -> None:
    """Every routed row carries the full raw body — so `H` is a storage amplifier, not just a txn one.

    `H=20` is the reference estate's ADT hub.
    """
    import messagefoundry.store.sqlserver as ss

    cur = await _drive(
        "route_handoff",
        ingress_id="i",
        message_id="m",
        channel_id="IB",
        handlers=[(f"H{i}", BODY) for i in range(handlers)],
        disposition=ss.MessageStatus.ROUTED,
        now=100.0,
    )
    assert _copies_of(cur, BODY) == handlers


@pytest.mark.parametrize("deliveries", [1, 2, 4])
async def test_sqlserver_does_not_dedup_identical_fanout_bodies(deliveries: int) -> None:
    """The rig's and production's backend writes `N` inline copies of an identical fan-out body.

    SQLite stores it once (`shared_body` + `body_ref`). SQL Server keeps `body_ref` NULL — its own schema
    comment says so. This asymmetry means a storage figure measured on SQLite understates SQL Server.
    """
    cur = await _drive(
        "transform_handoff",
        routed_id="r",
        message_id="m",
        channel_id="IB",
        deliveries=[(f"OB{i}", BODY) for i in range(deliveries)],
        state_ops=(),
        pt_deliveries=(),
        now=100.0,
    )
    assert _copies_of(cur, BODY) == deliveries


def body_copies_per_message(handlers: int, destinations: int) -> int:
    """Body copies durably written per ingress message on SQL Server: `2 + H + N`."""
    return 2 + handlers + destinations


@pytest.mark.parametrize(
    ("handlers", "destinations", "expected"),
    [
        (1, 1, 4),  # simple feed
        (8, 8, 18),  # bench topology
        (20, 4, 26),  # the reference estate's ADT hub
    ],
)
async def test_body_copies_per_message(handlers: int, destinations: int, expected: int) -> None:
    assert body_copies_per_message(handlers, destinations) == expected


async def test_the_audit_estimate_was_short_by_exactly_one_copy() -> None:
    """Regression guard on the correction itself, so it cannot silently revert.

    `docs/benchmarks/THROUGHPUT-STATUS-2026-07-10.md` states bytes scale as `(1 + H + N)`. Measured, it is
    `(2 + H + N)`: `enqueue_ingress` writes `messages.raw` as well as the ingress queue row.
    """
    for h, n in ((1, 1), (8, 8), (20, 4)):
        assert body_copies_per_message(h, n) == (1 + h + n) + 1


async def test_a_high_fanout_hub_is_storage_bound_by_H_not_by_N() -> None:
    """Why `H` is the lever for storage as well as for transactions.

    The hub selects 20 handlers and delivers to ~4. Its routed rows — one full raw copy each — dominate.
    Declining the 16 self-filtering handlers in the router stage (an `accepts=` seam) would cut body copies
    from 26 to 10.
    """
    hub = body_copies_per_message(20, 4)
    if_filtered_in_router = body_copies_per_message(4, 4)

    assert hub == 26
    assert if_filtered_in_router == 10
    assert hub / if_filtered_in_router == pytest.approx(2.6)

    # The routed rows alone are 20 of the 26 copies: 77% of the body bytes this message writes.
    assert 20 / hub == pytest.approx(0.769, abs=0.001)


# --- the published figure, welded to the model (ADR 0141) ---------------------------------------

_LOAD_PROFILE = """
[load]
name = "amp"
[[load.target]]
name = "hub"
types = ["ADT"]
[load.mix]
"ADT^A05" = 1.0
[[load.phase]]
name = "steady"
kind = "sustained"
loop = "open"
rate_start = 50.0
duration_s = 10.0
"""


def _report(*, messages: int, body_copies: int, backend: str) -> RunReport:
    """A run report whose engine samples carry ``body_copies`` — the counter the harness publishes as
    ``copies/msg``. The baseline sample reads 0, so the run delta is exactly ``body_copies``."""
    profile = load_profile_text(_LOAD_PROFILE)
    (phase,) = profile.phases
    end = Counters(sent=messages, acked=messages)
    records = [PhaseRecord(phase, Counters(), end, Histogram(), Histogram(), 10.0)]
    poller = EnginePoller("http://x", None, origin=0.0)
    poller._samples.extend(
        [
            EngineSample(0.0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1000, "wal", None, 1.0),
            EngineSample(
                10.0,
                0,
                0,
                messages,
                0,
                messages,
                messages,
                0,
                0,
                0,
                5000,
                "wal",
                None,
                11.0,
                body_copies=body_copies,
            ),
        ]
    )
    return build_report(profile, "http://x", records, end, poller, 2.0, db_backend=backend)


@pytest.mark.parametrize(("handlers", "destinations"), [(1, 1), (8, 8), (20, 4)])
async def test_the_rendered_copies_per_message_matches_the_2_H_N_model(
    handlers: int, destinations: int
) -> None:
    """WELD the published figure to the model, so a wrong counter is caught.

    The harness (`harness/load/report.py`, ADR 0141) publishes ``copies/msg`` — the live ``body_copies``
    delta over the run's message count. At the shapes pinned above, a correct counter on SQL Server must
    reproduce ``2 + H + N`` exactly. If the counter under-counts (say it misses the ``messages.raw``
    copy) or the model drifts, this fails.
    """
    expected = body_copies_per_message(handlers, destinations)
    messages = 105
    report = _report(messages=messages, body_copies=messages * expected, backend="sqlserver")

    assert report.engine.copies_per_message == pytest.approx(float(expected))
    console = report.render_console()
    # The reading is named by BACKEND and labelled NOT bytes: SQLite would store an identical fan-out
    # once (`shared_body`), so the same traffic reads lower there — the backend is part of the number.
    assert f"copies/msg (sqlserver; NOT bytes): {expected:.2f}/msg" in console


async def test_no_bytes_per_message_figure_is_published() -> None:
    """A2's refusal STANDS (ADR 0141): the report carries a copy COUNT and no byte figure.

    ``db_growth_bytes`` is still emitted as a raw observation, but nothing divides it by the message
    count — a `db_size_bytes`-delta ÷ acked number conflates index/row overhead, the transaction log,
    NVARCHAR UTF-16 (x2) and cipher expansion, and would be exactly the plausible-but-wrong publication
    this module was written to refuse.
    """
    report = _report(messages=105, body_copies=420, backend="sqlserver")
    engine_side = report.to_json_dict()["engine_side"]
    assert isinstance(engine_side, dict)
    assert not any("bytes_per_message" in key for key in engine_side)
    assert engine_side["copies_per_message_unit"] == "body copies (NOT bytes)"
    assert "bytes/msg" not in report.render_console()
