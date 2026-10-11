# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``python -m harness --fuzz``: seeded mutation of generated HL7 against a live engine.

Three claims, each with its control. A short seeded campaign against the REAL ``harness/config``
graph, served in-process, holds every invariant -- and it is not vacuous: positive ACKs were matched
to stored rows, NAKs fired, and all four layers ran. The fuzzer does say no: a client that hides one
stored message, a transport that mangles one reply, a 5xx and a store that does not grow each fail
the campaign, exit 1, and keep the exact bytes. And the same seed gives the same bytes, in this
process and in fresh ones with different hash seeds.
"""

from __future__ import annotations

import os
import re
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import pytest

import harness.fuzz.cli as fuzz_cli
from harness.__main__ import main
from harness.endpoints import Endpoints
from harness.fuzz import (
    LAYERS,
    Case,
    Exchange,
    FuzzConfig,
    SetupError,
    Transport,
    build_transport,
    invariants,
    make_case,
    replay,
    run,
)
from harness.fuzz.invariants import DISPOSITIONS, queryable
from harness.fuzz.mutate import frames
from harness.fuzz.transport import CLOSED, MALFORMED, REPLY, WireMLLPDriver, _read_replies
from harness.scenarios._core import control_id_of
from messagefoundry.api.models import Health, MessageList, MessageSummary
from messagefoundry.apiclient import ApiError, EngineClient
from messagefoundry.mllpcodec import frame
from messagefoundry.store.store import MessageStatus
from tests._harness_engine import REPO, ephemeral_overrides, free_port, serve_harness_config

SEED = 2682
ITERATIONS = 60


@pytest.fixture
def server(tmp_path: Path) -> Iterator[tuple[str, Endpoints]]:
    with serve_harness_config(tmp_path, ephemeral_overrides(tmp_path)) as served:
        yield served


def _first(seed: int, layer: str, *, wire: bool = True) -> Case:
    """The first case of ``seed`` in ``layer``."""
    for i in range(500):
        case = make_case(seed, i, wire=wire)
        if case.layer == layer:
            return case
    raise AssertionError(f"no {layer} case in the first 500 of seed {seed}")


def _fuzz_args(api_url: str, eps: Endpoints, out: Path, *extra: str) -> list[str]:
    return [
        "--fuzz",
        "--engine",
        api_url,
        "--endpoint",
        f"mllp_in={eps.port('mllp_in')}",
        "--fuzz-seed",
        str(SEED),
        "--fuzz-iterations",
        str(ITERATIONS),
        "--fuzz-out",
        str(out),
        "--timeout",
        "10",
        *extra,
    ]


# --- determinism ---------------------------------------------------------------------------------


def test_the_same_seed_gives_the_same_bytes() -> None:
    for wire in (True, False):
        first = [make_case(SEED, i, wire=wire) for i in range(200)]
        assert first == [make_case(SEED, i, wire=wire) for i in range(200)]
        # Control: the seed matters, so the equality above is not a constant generator. Same
        # transport shape on both sides, so framing alone cannot make the two differ.
        other = [make_case(SEED + 1, i, wire=wire).data for i in range(200)]
        assert sum(a.data != b for a, b in zip(first, other, strict=True)) > 190


def test_every_layer_fires_and_frame_edits_stay_off_a_payload_transport() -> None:
    wire_layers = {make_case(SEED, i).layer for i in range(200)}
    assert wire_layers == set(LAYERS)
    payload_cases = [make_case(SEED, i, wire=False) for i in range(200)]
    assert "frame" not in {c.layer for c in payload_cases}
    assert {c.layer for c in payload_cases} == set(LAYERS) - {"frame"}
    # A field edit goes through the model, which re-encodes a whole message: the header survives.
    field = [c for c in payload_cases if c.layer == "field"]
    assert field and all(c.mutation.startswith("field.") for c in field)
    assert all(c.data.startswith(b"MSH|") for c in field)


_SUBPROCESS_DUMP = (
    "from harness.fuzz import make_case\n"
    "print(','.join(make_case({seed}, i).data.hex() for i in range(40)))\n"
)


@pytest.mark.parametrize("hash_seed", ["1", "4242"])
def test_the_bytes_do_not_depend_on_the_process(hash_seed: str) -> None:
    """A replay is only as good as a fresh process reproducing the case, so the bytes must not
    lean on hash randomization or anything else that differs between interpreters."""
    env = {**os.environ, "PYTHONHASHSEED": hash_seed, "PYTHONPATH": str(REPO)}
    out = subprocess.run(
        [sys.executable, "-c", _SUBPROCESS_DUMP.format(seed=SEED)],
        capture_output=True,
        text=True,
        check=True,
        cwd=REPO,
        env=env,
        timeout=120,
    ).stdout.strip()
    assert out == ",".join(make_case(SEED, i).data.hex() for i in range(40))


# --- against the real graph ----------------------------------------------------------------------


def test_a_seeded_campaign_holds_every_invariant(
    server: tuple[str, Endpoints], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    api_url, eps = server
    transport = build_transport("mllp", eps, "mllp_in", timeout=10.0)
    config = FuzzConfig(seed=SEED, iterations=ITERATIONS, out_dir=tmp_path / "out")
    with EngineClient(api_url) as client:
        result = run(client, transport, config)
    assert result.ok, [f.reason for f in result.failures]
    assert result.cases == ITERATIONS
    # Not vacuous: stored rows were matched, both kinds of acknowledgement came back, every layer ran.
    assert result.stored_checked > 0
    assert result.replies["AA"] > 0 and result.replies["AR"] > 0
    assert set(result.layers) == set(LAYERS)
    assert not (tmp_path / "out").exists()
    out = capsys.readouterr().out
    assert f"PASS seed={SEED}" in out
    # The wire driver also honours the plain Driver contract: one clean frame, one ACK, no error.
    driver = WireMLLPDriver(eps.host, eps.port("mllp_in"), timeout=10.0)
    (injection,) = driver.inject([_first(SEED, "none").data])
    assert not injection.error and injection.reply is not None
    assert injection.reply.startswith(b"MSH|") and b"MSA|AA|" in injection.reply


def test_the_cli_exits_zero_on_a_clean_campaign(
    server: tuple[str, Endpoints], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    api_url, eps = server
    assert main(_fuzz_args(api_url, eps, tmp_path / "out", "--fuzz-iterations", "20")) == 0
    assert f"PASS seed={SEED} cases=20" in capsys.readouterr().out


class _HidingClient:
    """The real client, except one control id's stored row is hidden: an engine that ACKed a
    message it did not keep, as far as the fuzzer can tell."""

    def __init__(self, real: EngineClient, hidden: str) -> None:
        self.real = real
        self.hidden = hidden

    def __enter__(self) -> _HidingClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.real.close()

    def list_messages(self, **kw: Any) -> MessageList:
        if kw.get("control_id") == self.hidden:
            return MessageList(total=0, limit=1, offset=0, messages=[])
        return self.real.list_messages(**kw)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.real, name)


def test_a_dropped_stored_message_fails_with_the_seed_and_a_replay_file(
    server: tuple[str, Endpoints],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    api_url, eps = server
    victim = _first(SEED, "none")
    assert victim.iteration < ITERATIONS and victim.control_id is not None
    monkeypatch.setattr(
        fuzz_cli,
        "EngineClient",
        lambda url, cacert=None: _HidingClient(EngineClient(url, cacert=cacert), victim.control_id),
    )
    out_dir = tmp_path / "out"
    assert main(_fuzz_args(api_url, eps, out_dir)) == 1

    printed = capsys.readouterr().out
    fail = next(line for line in printed.splitlines() if line.startswith("FAIL seed="))
    assert f"seed={SEED} iteration={victim.iteration} " in fail
    assert "is not in the store" in fail
    replay_file = out_dir / f"fuzz-seed{SEED}-iter{victim.iteration}.mllp.bin"
    assert f"replay={replay_file}" in fail
    assert replay_file.read_bytes() == victim.data
    # The report names the case and never carries its body.
    assert "MSH|" not in printed and "PID|" not in printed

    # The kept file replays: against the engine as it really is, the same bytes hold.
    monkeypatch.undo()
    assert main(["--fuzz-replay", str(replay_file), *_fuzz_args(api_url, eps, out_dir)]) == 0


class _ManglingTransport(Transport):
    """The real transport, except the reply to one case is not an acknowledgement."""

    def __init__(self, real: Transport, target: bytes) -> None:
        self.real = real
        self.kind = real.kind
        self.wire = real.wire
        self.target = target

    def send(self, data: bytes) -> Exchange:
        exchange = self.real.send(data)
        if data == self.target:
            return Exchange(REPLY, (b"MSH|^~\\&|X|Y\rZZZ|1\r",))
        return exchange


def test_a_malformed_reply_fails_and_exits_one(
    server: tuple[str, Endpoints],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    api_url, eps = server
    victim = _first(SEED, "byte")

    def mangled(kind: str, endpoints: Endpoints, key: str, *, timeout: float) -> Transport:
        return _ManglingTransport(
            build_transport(kind, endpoints, key, timeout=timeout), victim.data
        )

    monkeypatch.setattr(fuzz_cli, "build_transport", mangled)
    assert main(_fuzz_args(api_url, eps, tmp_path / "out")) == 1
    fail = next(
        line for line in capsys.readouterr().out.splitlines() if line.startswith("FAIL seed=")
    )
    assert f"iteration={victim.iteration} " in fail
    assert "reply is not an ACK" in fail


#: Two cases the campaign found (seeds 11 and 13): a byte deletion leaves an MSH whose delimiters
#: are letters -- MSH-2 "^AB" (repetition separator "A") in one, MSH-1 "D" in the other.
_ALPHANUMERIC_DELIMITERS = ((11, 5686), (13, 1071))


@pytest.mark.xfail(
    strict=True,
    reason="engine defect: build_ack (messagefoundry/mllpcodec.py) echoes the inbound's MSH-1/MSH-2 "
    "verbatim and writes its literal fields unescaped, so an inbound whose delimiters are letters "
    "gets an AA whose MSH-9 and MSA-1 do not read back as ACK/AA under the ACK's own delimiters",
)
@pytest.mark.parametrize(("seed", "iteration"), _ALPHANUMERIC_DELIMITERS)
def test_an_inbound_with_letter_delimiters_gets_a_readable_ack(
    server: tuple[str, Endpoints], seed: int, iteration: int
) -> None:
    _api_url, eps = server
    case = make_case(seed, iteration)
    exchange = build_transport("mllp", eps, None, timeout=10.0).send(case.data)
    # The engine did answer, in one frame; it is the answer's content that is unreadable.
    assert exchange.outcome == REPLY and len(exchange.replies) == 1
    verdict = invariants.judge(exchange, expected=len(frames(case.data)))
    assert not verdict.problem, verdict.problem


# --- invariants without an engine ----------------------------------------------------------------


def _plain_ack(payload: bytes) -> bytes:
    """An AA for ``payload`` under the standard delimiters, echoing its control id when that id is
    plain text. Not build_ack: that echoes the payload's own delimiters, which is the engine defect
    the xfail above pins, and these fakes stand in for an engine without it."""
    cid = control_id_of(payload) or ""
    if not queryable(cid) or any(ch in cid for ch in "|^~\\&"):
        cid = ""
    return f"MSH|^~\\&|E|E|H|H|||ACK||P|2.5.1\rMSA|AA|{cid}\r".encode()


class _EchoTransport(Transport):
    """Answers every complete frame AA, echoing the control id it carries."""

    kind = "mllp"
    wire = True

    def __init__(self, delay: float = 0.0) -> None:
        self.delay = delay
        self.sent: list[bytes] = []

    def send(self, data: bytes) -> Exchange:
        time.sleep(self.delay)
        self.sent.append(data)
        replies = tuple(_plain_ack(payload) for payload in frames(data))
        return Exchange(REPLY if replies else CLOSED, replies)


class _FakeClient:
    """A store that keeps a row for every case the echo transport sent, with switchable faults."""

    def __init__(self, transport: _EchoTransport) -> None:
        self.transport = transport
        self.health_calls = 0
        #: Answer /health with ``health_status`` once it has been called more than this many times.
        self.health_fails_after: int | None = None
        self.health_status = 500
        self.frozen_total: int | None = None

    def health(self) -> Health:
        self.health_calls += 1
        if self.health_fails_after is not None and self.health_calls > self.health_fails_after:
            raise ApiError("server error", status=self.health_status)
        return Health()

    def list_messages(self, *, control_id: str | None = None, limit: int = 50) -> MessageList:
        ids = [control_id_of(f) for data in self.transport.sent for f in frames(data)]
        if control_id is None:
            total = len(ids) if self.frozen_total is None else self.frozen_total
            return MessageList(total=total, limit=limit, offset=0, messages=[])
        rows = [
            MessageSummary(
                id=str(i),
                channel_id="IB",
                received_at=0.0,
                source_type="mllp",
                control_id=cid,
                message_type=None,
                status="received",
                error=None,
            )
            for i, cid in enumerate(ids)
            if cid == control_id
        ]
        return MessageList(total=len(rows), limit=limit, offset=0, messages=rows[:limit])


def _offline(tmp_path: Path, **config: Any) -> tuple[_EchoTransport, _FakeClient, FuzzConfig]:
    transport = _EchoTransport(delay=config.pop("delay", 0.0))
    client = _FakeClient(transport)
    return transport, client, FuzzConfig(out_dir=tmp_path / "out", settle=0.0, **config)


def test_the_offline_fakes_pass_a_campaign(tmp_path: Path) -> None:
    """Control for the three fault tests below: with no fault switched on, the fakes pass."""
    transport, client, config = _offline(tmp_path, seed=3, iterations=30)
    result = run(cast(EngineClient, client), transport, config, emit=lambda _: None)
    assert result.ok and result.stored_checked > 0


def test_a_5xx_breaks_the_api_invariant(tmp_path: Path) -> None:
    transport, client, config = _offline(tmp_path, seed=3, iterations=30)
    client.health_fails_after = 1  # the preflight passes; the first batch check gets a 500
    result = run(cast(EngineClient, client), transport, config, emit=lambda _: None)
    assert not result.ok
    assert "GET /health returned 500 (5xx)" in result.failures[0].reason
    # A batch-level failure keeps every case of the batch, since any of them may be the cause.
    assert len(result.failures[0].replay) == config.batch


def test_a_store_that_does_not_grow_breaks_the_count_invariant(tmp_path: Path) -> None:
    transport, client, config = _offline(tmp_path, seed=3, iterations=30)
    client.frozen_total = 0
    result = run(cast(EngineClient, client), transport, config, emit=lambda _: None)
    assert not result.ok
    assert "the store grew by 0 row(s)" in result.failures[0].reason


def test_an_unreachable_api_is_a_setup_error(tmp_path: Path) -> None:
    transport, client, config = _offline(tmp_path, iterations=5)
    client.health_fails_after, client.health_status = 0, 503
    with pytest.raises(SetupError):
        run(cast(EngineClient, client), transport, config, emit=lambda _: None)


def test_the_time_budget_stops_the_campaign(tmp_path: Path) -> None:
    transport, client, config = _offline(
        tmp_path, iterations=10_000, batch=1, seconds=0.3, delay=0.05
    )
    lines: list[str] = []
    result = run(cast(EngineClient, client), transport, config, emit=lines.append)
    assert result.ok and 0 < result.cases < 100
    assert any(line.startswith("time budget of 0.3s reached") for line in lines)
    # Stopping early never changes the bytes of the cases that ran.
    assert transport.sent == [make_case(0, i).data for i in range(result.cases)]


class _SilentTransport(_EchoTransport):
    """Closes on every case without a word: an engine that answers nothing."""

    def send(self, data: bytes) -> Exchange:
        self.sent.append(data)
        return Exchange(CLOSED)


def test_silence_on_a_well_framed_message_breaks_the_reply_invariant(tmp_path: Path) -> None:
    transport = _SilentTransport()
    client = _FakeClient(transport)
    config = FuzzConfig(out_dir=tmp_path / "out", settle=0.0, seed=3, iterations=30)
    result = run(cast(EngineClient, client), transport, config, emit=lambda _: None)
    assert not result.ok
    failure = result.failures[0]
    assert failure.case is not None
    assert "complete frame(s) sent but 0 acknowledgement(s) came back" in failure.reason


def test_a_4xx_mid_campaign_is_a_setup_error_not_a_verdict(tmp_path: Path) -> None:
    transport, client, config = _offline(tmp_path, seed=3, iterations=30)
    client.health_fails_after, client.health_status = 1, 401
    with pytest.raises(SetupError, match="refused the campaign"):
        run(cast(EngineClient, client), transport, config, emit=lambda _: None)


def test_a_rate_limit_is_waited_out(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(invariants, "_RATE_LIMIT_WAITS", (0.0, 0.0))
    limited = [ApiError("slow down", status=429), ApiError("slow down", status=429)]

    def call() -> str:
        if limited:
            raise limited.pop()
        return "ok"

    assert invariants.api("GET /x", call) == "ok"

    # Control: a limit that outlasts the waits is reported, and as a 4xx, not an invariant.
    def always_limited() -> str:
        raise ApiError("slow down", status=429)

    with pytest.raises(invariants.ApiFault) as caught:
        invariants.api("GET /x", always_limited)
    assert not caught.value.invariant


@pytest.mark.parametrize(
    ("sent", "detail"),
    [
        (frame(b"MSH|^~\\&|E|F\rMSA|AA|1\r")[:-6], "inside a reply frame"),
        (b"junk" + frame(b"MSH|^~\\&|E|F\rMSA|AA|1\r"), "outside an MLLP frame"),
    ],
)
def test_a_cut_off_or_unframed_reply_is_not_a_clean_close(sent: bytes, detail: str) -> None:
    ours, theirs = socket.socketpair()
    with ours, theirs:
        theirs.sendall(sent)
        theirs.close()
        ours.settimeout(5.0)
        exchange = _read_replies(ours)
    assert exchange.outcome == MALFORMED and detail in exchange.detail
    # Control: the same reply, whole and framed, is a reply.
    ours, theirs = socket.socketpair()
    with ours, theirs:
        theirs.sendall(frame(b"MSH|^~\\&|E|F\rMSA|AA|1\r"))
        theirs.close()
        ours.settimeout(5.0)
        assert _read_replies(ours).outcome == REPLY


def test_replies_past_the_exchange_ceiling_stop_the_read(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every reply frame was capped but the list of them was not, and an engine that kept writing
    never hit the per-read timeout (BACKLOG #1127). The case's total read is capped now."""
    import harness.fuzz.transport as transport

    assert transport._MAX_EXCHANGE_BYTES == 16 * transport._MAX_REPLY_BYTES
    ack = frame(b"MSH|^~\\&|E|F\rMSA|AA|1\r")
    monkeypatch.setattr(transport, "_MAX_EXCHANGE_BYTES", 3 * len(ack))
    for count, outcome in ((3, REPLY), (4, MALFORMED)):
        ours, theirs = socket.socketpair()
        with ours, theirs:
            theirs.sendall(ack * count)
            theirs.close()
            ours.settimeout(5.0)
            exchange = _read_replies(ours)
        assert exchange.outcome == outcome, (count, exchange)
    assert "reply bytes for one case" in exchange.detail


def test_queryable_matches_the_api_control_id_filter() -> None:
    """``queryable`` copies ControlIdFilter by hand (the API module is not a harness import); this
    holds the copy to the original over the shapes the mutations produce."""
    from messagefoundry.api.validation import ControlIdFilter

    (constraints,) = ControlIdFilter.__metadata__  # type: ignore[attr-defined]
    printable, longest = re.compile(constraints.pattern), constraints.max_length
    samples = [
        "FZ1",
        "",
        "X" * longest,
        "X" * (longest + 1),
        "a\x0b",
        "a\x00b",
        "a\x7f",
        "a\x9f",
        "\xa0b",
        "a b",
    ]
    samples += [make_case(SEED, i).control_id or "" for i in range(300)]
    for sample in samples:
        expected = len(sample) <= longest and printable.match(sample) is not None
        assert queryable(sample) == expected, ascii(sample)


def test_the_disposition_list_matches_the_store() -> None:
    assert {status.value for status in MessageStatus} == DISPOSITIONS


def test_failing_cases_default_to_a_private_directory_outside_the_checkout(
    tmp_path: Path,
) -> None:
    transport, client, _config = _offline(tmp_path, seed=3, iterations=30)
    client.frozen_total = 0
    config = FuzzConfig(seed=3, iterations=30, settle=0.0)  # no out_dir
    result = run(cast(EngineClient, client), transport, config, emit=lambda _: None)
    kept = result.failures[0].replay[0]
    assert not kept.resolve().is_relative_to(REPO)
    assert kept.parent.name.startswith("messagefoundry-harness-fuzz-")
    if os.name == "posix":
        assert kept.parent.stat().st_mode & 0o077 == 0  # mkdtemp: owner-only
    for path in kept.parent.iterdir():
        path.unlink()
    kept.parent.rmdir()


def test_replay_refuses_a_file_for_another_transport(tmp_path: Path) -> None:
    transport, client, config = _offline(tmp_path)
    stray = tmp_path / "fuzz-seed0-iter0.file.bin"
    stray.write_bytes(b"MSH|")
    with pytest.raises(SetupError, match="not a mllp replay file"):
        replay(cast(EngineClient, client), transport, [stray], config, emit=lambda _: None)


def test_a_payload_driver_is_pluggable(tmp_path: Path) -> None:
    eps = Endpoints({"file_in": str(tmp_path / "in")})
    transport = build_transport("file", eps, "file_in", timeout=1.0)
    assert (transport.kind, transport.wire) == ("file", False)
    exchange = transport.send(make_case(SEED, 0, wire=False).data)
    assert exchange.outcome == CLOSED
    assert len(list((tmp_path / "in").iterdir())) == 1


# --- CLI setup errors ----------------------------------------------------------------------------


def test_fuzz_and_scenario_are_mutually_exclusive(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--fuzz", "--scenario", "processed"]) == 2
    assert "mutually exclusive" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("extra", "expected"),
    [
        (["--fuzz-driver", "carrier-pigeon", "--fuzz-endpoint", "mllp_in"], "no harness driver"),
        (["--fuzz-driver", "file"], "name the endpoint"),
        (["--fuzz-endpoint", "no_such_endpoint"], "no_such_endpoint"),
        (["--fuzz-seed", "-1"], "non-negative"),
        (["--endpoint", "garbage"], "KEY=VALUE"),
    ],
)
def test_bad_fuzz_options_are_setup_errors(
    extra: list[str], expected: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["--fuzz", "--engine", "http://127.0.0.1:9", *extra]) == 2
    assert expected in capsys.readouterr().err


def test_an_engine_that_is_not_there_is_a_setup_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = main(
        [
            "--fuzz",
            "--engine",
            f"http://127.0.0.1:{free_port()}",
            "--endpoint",
            f"mllp_in={free_port()}",
            "--fuzz-out",
            str(tmp_path / "out"),
        ]
    )
    assert rc == 2
    assert "fuzz setup:" in capsys.readouterr().err


def test_an_inbound_that_is_not_there_is_a_setup_error(
    server: tuple[str, Endpoints], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    api_url, _eps = server
    rc = main(
        [
            "--fuzz",
            "--engine",
            api_url,
            "--endpoint",
            f"mllp_in={free_port()}",
            "--fuzz-out",
            str(tmp_path / "out"),
        ]
    )
    assert rc == 2
    assert "cannot connect to MLLP" in capsys.readouterr().err
    assert not (tmp_path / "out").exists()
