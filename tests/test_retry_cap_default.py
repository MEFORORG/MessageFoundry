# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The shipped outbound-delivery retry cap is FINITE (BACKLOG #1051).

``RetryPolicy.max_attempts`` shipped as ``None`` = retry forever, which contradicted two things the
engine itself already said:

* ``docs/CONNECTIONS.md`` (the ASVS 13.1.3 artifact) discloses the default and, two lines later,
  mandates a finite ``retry_max_attempts`` plus a short ``timeout_seconds`` for synchronous HTTP;
* :func:`~messagefoundry.pipeline.wiring_runner.check_http_sync_reply` **refuses to start** a
  ``reply_from`` inbound whose effective ``max_attempts`` resolves to ``None`` — so the engine
  refused the very default it shipped.

A finite cap is safe because of two properties, and this module **asserts both** rather than
restating them:

1. **Attempts are counted per ROW, not per lane.** Only the claimed head accrues attempts, so a long
   outage burns the cap on roughly the lane heads and leaves the backlog at zero.
2. **A dead-lettered row stays replayable.** Exhaustion parks a row in the DLQ operators already
   see; it is not a discard.

The wall-clock the cap buys is measured here by DRIVING the real ``mark_failed`` with an injected
clock, not by re-deriving the backoff formula in the test (a re-derivation would agree with itself
if the implementation changed underneath it).
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
from pydantic import ValidationError

from messagefoundry.config.connections_file import load_connections_file
from messagefoundry.config.models import ContentType, OrderingMode, RetryPolicy
from messagefoundry.config.settings import DeliverySettings
from messagefoundry.config.wiring import (
    Http,
    Registry,
    Rest,
    WiringError,
    apply_sync_reply_capture_implication,
    build_inbound_connection,
    build_outbound_connection,
)
from messagefoundry.pipeline.wiring_runner import check_http_sync_reply
from messagefoundry.store import MessageStatus, MessageStore, OutboxStatus

#: The ruled default (BACKLOG #1051). Stated once here; every assertion below reads it.
SHIPPED_CAP = 100


@pytest.fixture
async def store(tmp_path):
    s = await MessageStore.open(tmp_path / "retrycap.db")
    yield s
    await s.close()


def test_the_shipped_retry_default_is_finite() -> None:
    # Both tiers, because either one left at None would resurrect retry-forever: the per-outbound
    # built-in (an outbound that declares `retry=RetryPolicy(backoff_seconds=1)` and nothing else)
    # and the [delivery] global an outbound with no retry= inherits.
    assert RetryPolicy().max_attempts == SHIPPED_CAP
    assert DeliverySettings().retry_max_attempts == SHIPPED_CAP
    assert DeliverySettings().retry_policy().max_attempts == SHIPPED_CAP


def test_retry_forever_is_still_expressible_as_an_explicit_choice() -> None:
    # The cap is a DEFAULT, not a removal. A partner that must never lose a message can still opt
    # into retry-forever; it is now a written decision rather than what you get by saying nothing.
    assert RetryPolicy(max_attempts=None).max_attempts is None


async def test_the_cap_bounds_the_outage_window_it_buys(store: MessageStore) -> None:
    """Drive the REAL ``mark_failed`` 100 times and measure the elapsed wall clock to dead-letter.

    Under the shipped backoff (5 s base, x2, capped at 300 s) the row re-pends at 5, 10, 20, 40, 80,
    160 then 300 s for every remaining attempt, and the 100th failure dead-letters with no further
    wait: 315 + 93 * 300 = 28,215 s = 7 h 50 m 15 s. Asserted as a NUMBER, so shortening the cap or
    changing the backoff has to restate the window rather than quietly shrink it.
    """
    retry = RetryPolicy()  # the shipped policy, verbatim — cap AND backoff
    assert retry.max_attempts == SHIPPED_CAP
    mid = await store.enqueue_message(channel_id="c1", raw="x", deliveries=[("d1", "p1")], now=0.0)

    t = 0.0
    attempts = 0
    while True:
        claimed = await store.claim_ready(now=t, destination_name="d1")
        assert claimed, f"the lane stalled at t={t} after {attempts} attempts"
        attempts += 1
        next_at = await store.mark_failed(claimed[0].id, "partner unreachable", retry, now=t)
        if next_at is None:  # dead-lettered: the cap is exhausted
            break
        t = next_at
        assert attempts < SHIPPED_CAP * 2, "the cap never fired — the loop is not converging"

    assert attempts == SHIPPED_CAP
    assert t == pytest.approx(28215.0)  # 7 h 50 m 15 s
    row = (await store.outbox_for(mid))[0]
    assert row["status"] == OutboxStatus.DEAD.value
    assert row["attempts"] == SHIPPED_CAP


async def test_a_long_outage_burns_the_cap_on_the_head_not_the_backlog(store: MessageStore) -> None:
    """PROPERTY 1: attempts are per ROW.

    Three messages queued to one FIFO lane; the partner is down throughout. The head exhausts a
    (deliberately tiny) cap and dead-letters, while the two rows behind it never left ``pending`` and
    still carry ``attempts == 0`` — so an outage costs roughly one dead row per cap-window, not the
    whole backlog. The successor then inherits a FULL budget, which is the same statement viewed from
    the other side.
    """
    retry = RetryPolicy(max_attempts=3, backoff_seconds=1, backoff_multiplier=1)
    ids = [
        await store.enqueue_message(
            channel_id="c1", raw=f"m{i}", deliveries=[("d1", f"p{i}")], now=0.0
        )
        for i in range(3)
    ]

    t = 0.0
    for _ in range(retry.max_attempts):
        head = await store.claim_next_fifo("d1", now=t)
        assert head is not None, f"the FIFO head was not claimable at t={t}"
        await store.mark_failed(head.id, "partner unreachable", retry, now=t)
        t += 10  # past the 1 s backoff

    head_row = (await store.outbox_for(ids[0]))[0]
    assert head_row["status"] == OutboxStatus.DEAD.value
    assert head_row["attempts"] == 3

    for mid in ids[1:]:
        row = (await store.outbox_for(mid))[0]
        assert row["status"] == OutboxStatus.PENDING.value, "the backlog was charged for the outage"
        assert row["attempts"] == 0, "attempts leaked from the head onto a row never claimed"

    # The successor is now the head and starts from zero, not from the exhausted head's count.
    successor = await store.claim_next_fifo("d1", now=t)
    assert successor is not None and successor.id == (await store.outbox_for(ids[1]))[0]["id"]
    assert successor.attempts == 1  # this claim's own first attempt


async def test_a_dead_lettered_row_stays_replayable(store: MessageStore) -> None:
    """PROPERTY 2: exhaustion parks a row in the DLQ; it does not discard it.

    After replay the row is ``pending`` with ``attempts`` reset (a full budget again) and the message
    is back to ``routed`` — the same operator affordance an ``AR`` fail-fast dead-letter already has.
    """
    retry = RetryPolicy(max_attempts=2, backoff_seconds=1, backoff_multiplier=1)
    mid = await store.enqueue_message(channel_id="c1", raw="x", deliveries=[("d1", "p1")], now=0.0)
    t = 0.0
    for _ in range(2):
        claimed = await store.claim_ready(now=t, destination_name="d1")
        assert claimed
        await store.mark_failed(claimed[0].id, "partner unreachable", retry, now=t)
        t += 10

    assert (await store.outbox_for(mid))[0]["status"] == OutboxStatus.DEAD.value
    assert (await store.get_message(mid))["status"] == MessageStatus.ERROR.value
    assert len(await store.list_dead(channel_id="c1")) == 1  # visible to the operator

    assert await store.replay_dead(channel_id="c1", now=t) == 1

    row = (await store.outbox_for(mid))[0]
    assert row["status"] == OutboxStatus.PENDING.value
    assert row["attempts"] == 0  # a full budget again, not a row wedged at the cap
    assert row["last_error"] is None
    assert (await store.get_message(mid))["status"] == MessageStatus.ROUTED.value
    # Claimable again — the strongest form of "replayable" is that a worker can actually take it.
    assert await store.claim_next_fifo("d1", now=t) is not None


def _sync_reply_graph() -> tuple[Registry, object]:
    """A ``reply_from`` graph that declares NO retry policy — the shape whose effective cap comes
    entirely from ``[delivery]``, which is what the startup refusal reads."""
    reg = Registry()
    ic = build_inbound_connection(
        "IB_HTTP",
        Http(port=0, reply_from="OB_PARTNER"),
        router="r",
        content_type=ContentType.JSON,
    )
    reg.add_inbound(ic)
    reg.add_outbound(
        build_outbound_connection(
            "OB_PARTNER",
            Rest(url="https://partner.example/ingest", capture_response=True),
            ordering=OrderingMode.UNORDERED,  # the OTHER refusal arm, satisfied so it cannot mask this one
        )
    )
    apply_sync_reply_capture_implication(reg)
    return reg, ic


def test_the_engine_no_longer_refuses_the_default_it_ships() -> None:
    # The contradiction #1051 names, stated as a test: a reply_from graph that declares nothing and
    # inherits the SHIPPED [delivery] defaults must now start. Before the cap landed this raised.
    reg, ic = _sync_reply_graph()
    assert reg.outbound["OB_PARTNER"].retry is None, "the test lost its own premise"
    check_http_sync_reply(ic, reg, delivery=DeliverySettings(ordering=OrderingMode.UNORDERED))


def test_the_refusal_still_fires_on_an_explicit_retry_forever() -> None:
    # ...and the refusal is not gone, only no longer self-inflicted: an operator who deliberately
    # configures retry-forever under a synchronous reply is still refused at start.
    reg, ic = _sync_reply_graph()
    with pytest.raises(WiringError, match="EFFECTIVE max_attempts"):
        check_http_sync_reply(
            ic,
            reg,
            delivery=DeliverySettings(ordering=OrderingMode.UNORDERED, retry_max_attempts=None),
        )


# --- BACKLOG #1217: the catalog row must describe the loader that ships ----------------------
#
# The floor landed in PR #383 and the docs/CONFIGURATION.md row was not moved with it, so the
# catalog asserted "`0` or a negative value is accepted and dead-letters on the first failure"
# about a loader that had started REFUSING both. A catalog row describing a configuration the
# loader refuses is worse than silence: an operator writes it, the start fails, and the document
# that sent them there still reads as authoritative.
#
# These drive the REAL settings model rather than re-reading the Field, and then check the prose
# against that behaviour, so the two cannot drift apart again silently.


@pytest.mark.parametrize("value", [0, -1, -100])
def test_the_operator_facing_retry_cap_refuses_zero_and_negatives(value: int) -> None:
    """The floor itself, driven rather than read off the Field declaration."""
    with pytest.raises(ValidationError):
        DeliverySettings(retry_max_attempts=value)


@pytest.mark.parametrize("value", [1, 100, None])
def test_the_floor_does_not_narrow_what_was_already_legal(value: int | None) -> None:
    """The other direction. A floor that also refuses `None` would delete the documented
    retry-forever posture, and a suite that only asserts refusals could not tell the two apart."""
    assert DeliverySettings(retry_max_attempts=value).retry_max_attempts == value


def test_the_internal_no_retry_idiom_is_untouched_by_the_operator_facing_floor() -> None:
    """THE ONE THAT MUST NOT BE 'TIDIED'. `RetryPolicy(max_attempts=0)` is the deliberate idiom for
    a permanent, no-retry failure and FOUR test modules depend on it -- test_batch_completion,
    test_postgres_store, test_resend, test_sqlserver_store.

    Adding `ge=1` to the RetryPolicy field looks like the symmetrical completion of the same
    tightening and would instead DELETE A USED MECHANISM. settings.py says so in its own comment;
    this makes it executable.
    """
    assert RetryPolicy(max_attempts=0).max_attempts == 0


def test_the_configuration_catalog_does_not_still_promise_the_pre_floor_behaviour() -> None:
    """BACKLOG #1217. Pins the PROSE against the behaviour asserted above.

    Deliberately negative rather than matching the new wording: an exact-sentence assertion would
    red on any rewording, which trains the next author to edit the test instead of the doc. What
    must never come back is the CLAIM that a zero loads.
    """
    doc = (Path(__file__).resolve().parents[1] / "docs" / "CONFIGURATION.md").read_text(
        encoding="utf-8"
    )
    row = next((ln for ln in doc.splitlines() if ln.startswith("| `retry_max_attempts`")), None)
    assert row is not None, "the retry_max_attempts catalog row has moved or been renamed"

    assert "is accepted and dead-letters on the first failure" not in row, (
        "the catalog again promises that a zero loads. It has not since PR #383 -- the loader "
        "refuses it, which the tests above drive directly."
    )
    assert "REFUSED at load" in row, "the row must say what the loader actually does with a zero"
    assert "RetryPolicy(max_attempts=0)" in row, (
        "the row must keep naming the internal idiom the floor deliberately does NOT touch, or a "
        "later reader completes the tightening and deletes it"
    )


# --- BACKLOG #1217 half 2: the "forever" string spelling, per-outbound side -------------------
#
# `DeliverySettings.retry_max_attempts` (tested in tests/test_settings.py) is the [delivery]
# GLOBAL default. A per-outbound `[outbound.retry]` table in connections.toml decodes through a
# SEPARATE path -- connections_file.py builds a RetryPolicy straight from the TOML table, never
# touching DeliverySettings -- so it needed its own, independent coercion. A spelling that works
# in one place and silently corrupts (or just fails to load) in the other would be worse than not
# shipping it at all.


def _outbound_retry_toml(max_attempts_literal: str) -> str:
    return textwrap.dedent(
        f"""
        [[outbound]]
        name = "OB"
        transport = "file"
          [outbound.settings]
          directory = "out"
          [outbound.retry]
          max_attempts = {max_attempts_literal}
        """
    )


def test_retry_forever_spelling_loads_from_a_per_outbound_toml_table(
    tmp_path: Path,
) -> None:  # #1217
    cfg = tmp_path / "connections.toml"
    cfg.write_text(_outbound_retry_toml('"Forever"'), encoding="utf-8")  # mixed case, on purpose
    reg = Registry()
    load_connections_file(cfg, reg)
    ob = reg.outbound["OB"]
    assert ob.retry is not None and ob.retry.max_attempts is None


def test_retry_max_attempts_per_outbound_still_refuses_a_garbage_string(
    tmp_path: Path,
) -> None:  # #1217
    cfg = tmp_path / "connections.toml"
    cfg.write_text(_outbound_retry_toml('"sometimes"'), encoding="utf-8")
    reg = Registry()
    with pytest.raises(WiringError):
        load_connections_file(cfg, reg)


def test_retry_max_attempts_per_outbound_numeric_forms_are_unaffected(
    tmp_path: Path,
) -> None:  # #1217
    """The new coercion must be a narrow addition, not a rewrite of the existing per-outbound path --
    a real integer (including the `RetryPolicy(max_attempts=0)` no-retry idiom, unfloored here on
    purpose, see test_the_internal_no_retry_idiom_is_untouched_by_the_operator_facing_floor above)
    still loads exactly as it did before this item."""
    cfg = tmp_path / "connections.toml"
    cfg.write_text(_outbound_retry_toml("0"), encoding="utf-8")
    reg = Registry()
    load_connections_file(cfg, reg)
    assert reg.outbound["OB"].retry is not None and reg.outbound["OB"].retry.max_attempts == 0


def test_the_configuration_catalog_no_longer_claims_no_toml_or_env_spelling() -> None:
    """BACKLOG #1217 half 2. Companion to test_the_configuration_catalog_does_not_still_promise_the_
    pre_floor_behaviour above: that one pins half 1's prose, this one pins half 2's. Deliberately
    negative -- what must never come back is the claim that the spelling does not exist."""
    doc = (Path(__file__).resolve().parents[1] / "docs" / "CONFIGURATION.md").read_text(
        encoding="utf-8"
    )
    row = next((ln for ln in doc.splitlines() if ln.startswith("| `retry_max_attempts`")), None)
    assert row is not None, "the retry_max_attempts catalog row has moved or been renamed"
    assert "there is no TOML or env spelling for retry-forever" not in row, (
        "the catalog again claims retry-forever has no TOML/env spelling. It has since #1217 -- "
        'the string "forever" is coerced to None, which the tests above drive directly.'
    )
    assert '"forever"' in row, "the row must name the spelling an operator would actually write"


# --- #1217 review finding 1: the docs named a file that refuses the key ----------------------
#
# The first cut of half 2 told an operator to write `retry_max_attempts = "forever"` into
# connections.toml, at BOTH levels. Neither spelling loads, so following the doc produced a startup
# error rather than a retry-forever connection. The two negative controls below are the tests that
# would have caught it: they drive the two WRONG spellings through the real loader and pin the
# refusal, so a doc edit that reintroduces either has a failing test sitting beside it.
#
# The three surfaces and their spellings, each proven by a test in this file or in
# tests/test_settings.py:
#
#   code-first Python       retry=RetryPolicy(max_attempts=None)
#   global default          messagefoundry.toml   [delivery]         retry_max_attempts = "forever"
#   per-outbound override   connections.toml      [outbound.retry]   max_attempts       = "forever"


def test_connections_toml_refuses_a_delivery_table(tmp_path: Path) -> None:  # #1217
    """`[delivery]` is a messagefoundry.toml section, NOT a connections.toml one -- the loader takes
    only `[[inbound]]`/`[[outbound]]` at top level, so a doc that sends an operator here produces a
    startup error. Pinned as refused, with the message shape a reader would actually see."""
    cfg = tmp_path / "connections.toml"
    cfg.write_text('[delivery]\nretry_max_attempts = "forever"\n', encoding="utf-8")
    with pytest.raises(WiringError, match="unknown top-level key"):
        load_connections_file(cfg, Registry())


def test_connections_toml_refuses_a_flat_retry_max_attempts_key(tmp_path: Path) -> None:  # #1217
    """The other spelling a reader could mistake for the real one. `retry_max_attempts` is the
    GLOBAL's key name; an outbound table carries `retry` (a sub-table) whose key is `max_attempts`,
    so the flat form trips `_reject_unknown`."""
    cfg = tmp_path / "connections.toml"
    cfg.write_text(
        textwrap.dedent(
            """
            [[outbound]]
            name = "OB"
            transport = "file"
            retry_max_attempts = "forever"
              [outbound.settings]
              directory = "out"
            """
        ),
        encoding="utf-8",
    )
    with pytest.raises(WiringError, match="retry_max_attempts"):
        load_connections_file(cfg, Registry())


_FOREVER_DOCS = ("CONNECTIONS.md", "CONFIGURATION.md", "USER-GUIDE.md")


def _forever_passage(doc: str) -> str:
    """The doc's retry-forever passage: everything between its first and last `"forever"`, plus a
    margin. Scoped rather than whole-file because these are long documents and `connections.toml`
    appears all over them -- a whole-file search could not tell the passage from the neighbours."""
    first = doc.index('"forever"')
    last = doc.rindex('"forever"')
    return doc[max(0, first - 600) : last + 600]


@pytest.mark.parametrize("name", _FOREVER_DOCS)
def test_a_doc_that_teaches_the_forever_spelling_names_the_file_that_accepts_it(
    name: str,
) -> None:  # #1217
    """Both anchors, because the passage teaches two different surfaces and the retired text had
    NEITHER -- it named connections.toml for the global and gave no per-outbound key at all. An
    operator who can only find one of the two is still one file away from a startup error."""
    doc = (Path(__file__).resolve().parents[1] / "docs" / name).read_text(encoding="utf-8")
    passage = _forever_passage(doc)
    assert "messagefoundry.toml" in passage, (
        f"docs/{name}'s retry-forever passage does not name messagefoundry.toml, which is the only "
        "file whose [delivery] table accepts retry_max_attempts. connections.toml refuses it -- see "
        "test_connections_toml_refuses_a_delivery_table above, which drives that refusal."
    )
    assert "[outbound.retry]" in passage, (
        f"docs/{name}'s retry-forever passage does not name the [outbound.retry] table, so a reader "
        "cannot find the per-outbound spelling. The key there is max_attempts, NOT "
        "retry_max_attempts -- see test_connections_toml_refuses_a_flat_retry_max_attempts_key."
    )
