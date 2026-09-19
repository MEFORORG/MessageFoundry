# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Per-connection egress send pacing — BACKLOG #82 (the OPEN half of the bundle).

``send_min_interval_seconds`` on an outbound holds each ``send`` until at least that many seconds have
elapsed since the lane's previous send began, so a partner that cannot absorb bursts sees a bounded send
rate. Pacing is enforced ONCE at the pipeline delivery seam (``_pace_outbound``, called before the
item/batch body in both the per_lane worker and the pooled dispatcher), keyed per-lane, and is
byte-identical when unset. These tests cover at least the seam gate, the per-lane clock, lane
independence, the already-elapsed path, the no-pacing default, and the wiring validation. The BATCH seam proof lives in ``test_outbound_batch.py``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from _pace_probe import install_pace_probe

from messagefoundry.config.models import ConnectorType, RetryPolicy
from messagefoundry.config.wiring import (
    MLLP,
    ConnectionSpec,
    Registry,
    WiringError,
    build_outbound_connection,
    env,
    validate_config,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner, _resolve_send_pace
from messagefoundry.store import MessageStore

DEST = "OB_ADT"
DEST2 = "OB_LAB"


def _msg(n: int) -> str:
    return f"MSH|^~\\&|A|B|C|D|20260101000000||ADT^A0{n}|MSG{n}|P|2.5.1\rPID|1||{n}00||DOE^P{n}\r"


class _Recorder:
    """A minimal non-capturing outbound (returns None → mark_done). Records each delivered payload."""

    def __init__(self) -> None:
        self.sent: list[str] = []

    async def send(self, payload: str) -> None:
        self.sent.append(payload)
        return None

    async def aclose(self) -> None:
        return None


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "pacing.db")
    yield s
    await s.close()


def _runner(store: MessageStore) -> RegistryRunner:
    return RegistryRunner(Registry(), store, poll_interval=0.02)


# --- _resolve_send_pace: None/absent/0 → off; positive kept; negative clamped ----------------------


def test_resolve_send_pace() -> None:
    assert _resolve_send_pace({}) == 0.0  # absent → no pacing
    assert _resolve_send_pace({"send_min_interval_seconds": None}) == 0.0
    assert _resolve_send_pace({"send_min_interval_seconds": 0}) == 0.0
    assert _resolve_send_pace({"send_min_interval_seconds": 0.25}) == 0.25
    # A negative can't reach here past wiring, but the seam must never be asked to sleep negative.
    assert _resolve_send_pace({"send_min_interval_seconds": -5}) == 0.0


# --- wiring validation: a negative interval is rejected loud at build; a positive one is carried ---


def test_negative_send_pace_rejected() -> None:
    with pytest.raises(WiringError, match="send_min_interval_seconds"):
        build_outbound_connection(
            "OB", MLLP(host="127.0.0.1", port=1234, send_min_interval_seconds=-0.5)
        )


def test_positive_send_pace_carried() -> None:
    oc = build_outbound_connection(
        "OB", MLLP(host="127.0.0.1", port=1234, send_min_interval_seconds=0.5)
    )
    assert oc.spec.settings["send_min_interval_seconds"] == 0.5
    # And a File outbound (no such setting) resolves to off — pacing is opt-in where meaningful.
    file_oc = build_outbound_connection(
        "OB_F",
        ConnectionSpec(ConnectorType.FILE, {"directory": "/tmp", "filename": "{MSH-10}.hl7"}),
    )
    assert _resolve_send_pace(file_oc.spec.settings) == 0.0


# --- BACKLOG #1653: an env() ref is refused at the shared choke point, identically on both --------
# authoring surfaces. It used to reach the `send_pace < 0` comparison and raise a raw
# `TypeError: '<' not supported between instances of 'EnvRef' and 'int'`, which escaped `validate`
# and `load` on the connections.toml surface (`_build_spec` wraps only the factory call) while the
# code-first surface got an opaque `_exec_module` wrap naming no field.

_ENV_PACE_REFUSAL = "send_min_interval_seconds may not use env"


def test_env_ref_send_pace_refused_at_build() -> None:
    """The refusal fires at ``build_outbound_connection`` and names the field and the env key.

    Refusal, not a skipped sign check: ``_resolve_send_pace`` reads ``oc.spec.settings``
    **unresolved** at both of its call sites and calls ``float(raw)``, so accepting the ref here
    would only move the ``TypeError`` into outbound start -- a dead lane after the sender's ACK.
    """
    with pytest.raises(WiringError, match=_ENV_PACE_REFUSAL) as caught:
        build_outbound_connection(
            "OB", MLLP(host="127.0.0.1", port=1234, send_min_interval_seconds=env("pace"))
        )
    assert "'pace'" in str(caught.value)  # names the key the operator has to go remove


def _code_first_dir(tmp_path: Path) -> Path:
    d = tmp_path / "codefirst"
    d.mkdir()
    (d / "feed.py").write_text(
        "from messagefoundry import MLLP, outbound\n"
        "from messagefoundry.config.wiring import env\n"
        "outbound('OB_X', MLLP(host='h', port=1, send_min_interval_seconds=env('pace')))\n",
        encoding="utf-8",
    )
    return d


def _toml_dir(tmp_path: Path) -> Path:
    d = tmp_path / "tomlsurface"
    d.mkdir()
    (d / "connections.toml").write_text(
        '[[outbound]]\nname = "OB_X"\ntransport = "mllp"\n'
        '[outbound.settings]\nhost = "h"\nport = 1\n'
        'send_min_interval_seconds = { env = "pace", cast = "float" }\n',
        encoding="utf-8",
    )
    return d


def test_env_ref_send_pace_diagnosed_identically_on_both_surfaces(tmp_path: Path) -> None:
    """``validate_config`` RETURNS the same diagnostic for both surfaces instead of raising.

    The identical string is the point: the divergence this closes was one surface raising a raw
    ``TypeError`` out of ``validate`` while the other reported a message naming no field.
    """
    code_first = [d.message for d in validate_config(_code_first_dir(tmp_path))]
    from_toml = [d.message for d in validate_config(_toml_dir(tmp_path))]
    assert len(code_first) == 1 and len(from_toml) == 1
    assert code_first == from_toml  # byte-identical, not merely both-non-empty
    assert _ENV_PACE_REFUSAL in code_first[0]
    assert "TypeError" not in code_first[0]


def test_env_ref_send_pace_refused_at_load_on_the_toml_surface(tmp_path: Path) -> None:
    """``load_config`` refuses it too -- as a ``WiringError``, not the raw ``TypeError`` it was."""
    from messagefoundry.config.wiring import load_config

    with pytest.raises(WiringError, match=_ENV_PACE_REFUSAL):
        load_config(_toml_dir(tmp_path))


def test_validate_config_reports_an_unexpected_toml_loader_failure_as_a_diagnostic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #1653 step 2: whatever the TOML loader fails to wrap becomes a diagnostic.

    ``validate_config``'s contract is to return ALL problems and raise none; the ``*.py`` arm cannot
    break it (``_exec_module`` wraps whatever a module raises) but the TOML arm could, and an escape
    took the other diagnostics with it. Monkeypatched rather than driven through a real bad file so
    the test pins the ARM, not whichever loader gap happens to be open today.
    """
    from messagefoundry.config import connections_file as cf

    def _boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("loader fell over")

    monkeypatch.setattr(cf, "load_connections_file", _boom)
    d = tmp_path / "unexpected"
    d.mkdir()
    (d / "connections.toml").write_text("", encoding="utf-8")
    # A SECOND, EARLIER problem, because "took the other diagnostics with it" is the actual harm and
    # a directory holding only a connections.toml cannot exhibit it: `diagnostics` is a local list,
    # so an escape discards everything collected before the TOML arm. This module's diagnostic is
    # appended first and must still be there.
    (d / "feed.py").write_text("raise RuntimeError('module fell over too')\n", encoding="utf-8")
    messages = [x.message for x in validate_config(d)]
    assert len(messages) == 2, f"a prior diagnostic was lost: {messages!r}"
    assert any("module fell over too" in m for m in messages), "the *.py diagnostic did not survive"
    unexpected = [m for m in messages if "unexpected RuntimeError" in m]
    assert len(unexpected) == 1 and "loader fell over" in unexpected[0]


def test_an_unexpected_loader_failure_is_scrubbed_before_it_becomes_a_diagnostic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both ``validate_config`` connections.toml arms interpolate somebody else's exception text, so
    both run through ``scrub_credentials``. The reasoning, the three measured shapes and the limits
    of the backstop are stated once at the handler in ``config/wiring.py`` (SDS-3.5); this pins only
    the LABELLED-credential shape, which is the one the scrub actually covers.
    """
    from messagefoundry.config import connections_file as cf
    from messagefoundry.secretscrub import CREDENTIAL_PLACEHOLDER

    # ASSEMBLED AT RUNTIME, never a committed literal: gitleaks scans this repository and cannot tell
    # a test needle from a live credential. `tests/test_merge_gate_controls.py::_fabricated_secrets`
    # already sets this practice, and it is what keeps .gitleaks.toml from owing another entry.
    secret = "pw" + "-Scrub" + "M3_Val" + "-77"

    def _boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError(f"connect failed password={secret}")

    monkeypatch.setattr(cf, "load_connections_file", _boom)
    d = tmp_path / "leaky"
    d.mkdir()
    (d / "connections.toml").write_text("", encoding="utf-8")
    messages = [x.message for x in validate_config(d)]
    assert len(messages) == 1
    assert secret not in messages[0], (
        f"the credential survived into the diagnostic: {messages[0]!r}"
    )
    assert CREDENTIAL_PLACEHOLDER in messages[0], f"nothing was scrubbed: {messages[0]!r}"
    # The exception TYPE still survives -- it is the actionable half, naming the loader gap to fix.
    assert "unexpected RuntimeError" in messages[0]


# --- _pace_outbound: (a) a single lane's second send is held >= the interval ----------------------


async def test_pace_second_send_delayed(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # THE ASSERTION IS THE WAIT THE PACER ASKED FOR, NOT ONE THE TEST TIMES. An elapsed-time bound
    # cannot do this job on a loaded runner: tests/_pace_probe.py has the measurement, the
    # reproduction, and why Windows timer granularity is not the mechanism.
    runner = _runner(store)
    interval = 0.05
    runner._send_pace[DEST] = interval
    work = 0.02  # the first send's body, charged to the pacer's clock
    probe = install_pace_probe(monkeypatch, runner)

    await runner._pace_outbound(DEST)  # first: no prior send → returns at once, stamps the clock
    assert probe.slept == []  # nothing owed
    first_stamp = runner._send_pace_at[DEST]

    probe.advance(work)
    await runner._pace_outbound(DEST)  # second: elapsed < interval → holds the REMAINDER
    # The wait is the REMAINDER: the pacer credits the work already done against the interval.
    assert probe.slept == [pytest.approx(interval - work, abs=1e-9)]
    # Stamped AFTER the wait, so the next interval is measured from THIS send's start (a send-to-send
    # rate). Mutation: stamp before the sleep instead, and this reads first_stamp + work.
    assert runner._send_pace_at[DEST] == pytest.approx(first_stamp + interval, abs=1e-9)


# --- _pace_outbound: (b) two DIFFERENT lanes pace INDEPENDENTLY (per-lane clock, not a global bucket) ---


async def test_lanes_pace_independently(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = _runner(store)
    interval = 0.05
    runner._send_pace[DEST] = interval
    runner._send_pace[DEST2] = interval
    probe = install_pace_probe(monkeypatch, runner)

    await runner._pace_outbound(DEST)  # stamps DEST's clock (a recent send on lane A)
    await runner._pace_outbound(DEST2)  # lane B has NO prior send → must NOT be delayed by A
    # A global (cross-lane) bucket would make B wait ~interval here; an independent per-lane clock asks
    # for no wait at all. Asserted as "the pacer requested nothing", which a slow box cannot perturb —
    # the `elapsed < interval * 0.4` bound this replaces would fail on a runner that merely stalled.
    assert probe.slept == []
    assert (
        DEST in runner._send_pace_at and DEST2 in runner._send_pace_at
    )  # each lane has its own clock


# --- _pace_outbound: (c) unset / 0 is byte-identical — no delay, clock never touched ---------------


async def test_unset_is_noop(store: MessageStore) -> None:
    runner = _runner(store)
    # DEST absent from _send_pace (the default) → off.
    await runner._pace_outbound(DEST)
    await runner._pace_outbound(DEST)
    assert DEST not in runner._send_pace_at  # never stamped → the delivery path is byte-identical

    runner._send_pace[DEST2] = 0.0  # explicit 0 is likewise off
    await runner._pace_outbound(DEST2)
    assert DEST2 not in runner._send_pace_at


# --- _pace_outbound: (d) a lane that already waited long enough is NOT delayed again --------------


async def test_pace_skips_the_wait_once_the_interval_has_passed(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The fourth path through the pacer: a prior send exists, but MORE than the interval has already
    gone by, so nothing is owed and the lane must not be held at all. It still re-stamps, or the send
    after this one would measure its interval from a stale instant and under-space.

    THIS PATH HAD NO TEST. Measured 2026-09-05: adding ``else: await asyncio.sleep(interval)`` to the
    elapsed branch -- a mutant that corrupts this path and no other -- left the whole pacing suite
    green. The assertion below kills it. Reaching the branch against a real clock would have meant
    really sleeping past the interval, which is why the wall-clock form never covered it; on a clock
    the test owns it is one call to ``advance``.
    """
    runner = _runner(store)
    interval = 0.05
    runner._send_pace[DEST] = interval
    probe = install_pace_probe(monkeypatch, runner)

    await runner._pace_outbound(DEST)  # stamps the lane clock
    probe.advance(interval * 2)  # a slow send: the interval elapsed on its own, twice over
    await runner._pace_outbound(DEST)

    assert probe.slept == []  # nothing owed, so nothing waited
    # Re-stamped even though it did not wait, so the NEXT send paces from this one rather than the first.
    assert runner._send_pace_at[DEST] == pytest.approx(probe.now, abs=1e-9)


# --- integration: the SINGLE-MESSAGE seam is paced end-to-end via _dispatch_delivery (non-batch) --


async def test_single_message_seam_is_paced(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A non-batch lane routes _dispatch_delivery → _process_delivery_item; the pacing gate sits before
    # that call, so the SECOND single-message delivery is held for the remainder of the interval. Same
    # shape as the batch proof in test_outbound_batch.py, and asserted the same way: on the pacer's
    # decision, never on elapsed time (tests/_pace_probe.py).
    for i in (1, 2):
        await store.enqueue_message(
            channel_id="c1", raw=_msg(i), deliveries=[(DEST, _msg(i))], now=100.0 + i
        )
    runner = _runner(store)
    rec = _Recorder()
    runner._destinations[DEST] = rec
    runner._retry[DEST] = RetryPolicy()
    interval = 0.05
    runner._send_pace[DEST] = interval
    work = 0.02  # the first delivery's body, charged to the pacer's clock
    probe = install_pace_probe(monkeypatch, runner)

    head1 = await store.claim_next_fifo(DEST)
    assert head1 is not None
    await runner._dispatch_delivery(DEST, head1)  # first: not paced (no prior send)
    assert len(rec.sent) == 1
    assert probe.calls == [DEST]  # the seam reached the pacer
    assert probe.slept == []  # …and nothing was owed yet

    probe.advance(work)
    head2 = await store.claim_next_fifo(DEST)
    assert head2 is not None
    await runner._dispatch_delivery(DEST, head2)  # second: held for the remainder before its send
    assert len(rec.sent) == 2  # both delivered, in order
    assert probe.calls == [DEST, DEST]  # ONE interval per send
    assert probe.slept == [pytest.approx(interval - work, abs=1e-9)]
    depth, _ = await store.pending_depth(DEST)
    assert depth == 0
