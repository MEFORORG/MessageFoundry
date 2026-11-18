# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A Send whose message ``encode()`` raises, at ``[sandbox].mode = "subprocess"`` (BACKLOG #5890).

At ``mode=off`` dry-run calls ``send.message.encode()`` inside ``transform_one``, so any raise there,
``sys.exit()`` included, is that Handler's content fault and the message dead-letters. In the
worker the same call runs at describe time, in the codec's ``_enc_item``, which caught only
``AttributeError``, ``TypeError`` and ``ValueError``; any other raise escaped ``_respond`` and ended
the worker, so the parent read a crash and the next message paid a respawn. The generator Router
half of the finding was closed earlier (vault BACKLOG #3134); its RuntimeError case is pinned here
too. Synthetic HL7 only.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry import Send
from messagefoundry.config.run_context import RunContext
from messagefoundry.config.wiring import Registry, load_config
from messagefoundry.pipeline._sandbox_codec import SandboxCodecError, _Blobs, enc_result
from messagefoundry.pipeline.dryrun import route_only, transform_one
from messagefoundry.pipeline.sandbox import SandboxError, SandboxMode, SandboxPolicy, SandboxSession
from tests.test_sandbox import RAW, _deliveries, _session

_GRAPH = """
import sys

from messagefoundry import inbound, outbound, router, handler, File, Send

inbound("IB_OK", File(directory={inbox_ok!r}, poll_seconds=0.05), router="r_ok")
inbound("IB_GEN", File(directory={inbox_gen!r}, poll_seconds=0.05), router="r_gen_raise")
outbound("OB", File(directory={outbox!r}))


class _RaisingMessage:
    def encode(self):
        raise RuntimeError("encode failed")


class _ExitingMessage:
    def encode(self):
        sys.exit("PID-5 was DOE^JANE")


@router("r_ok")
def r_ok(msg):
    return "h_ok"


@router("r_gen_raise")
def r_gen_raise(msg):
    yield "h_ok"
    raise RuntimeError("router body failed")


@handler("h_ok")
def h_ok(msg):
    return Send("OB", "DELIVERED")


@handler("h_raise")
def h_raise(msg):
    return Send("OB", _RaisingMessage())


@handler("h_exit")
def h_exit(msg):
    return Send("OB", _ExitingMessage())
"""

_DIRS = ("inbox_ok", "inbox_gen", "outbox", "cfg")


@pytest.fixture
def graph(tmp_path: Path) -> tuple[Registry, dict[str, str]]:
    dirs = {key: tmp_path / key for key in _DIRS}
    for path in dirs.values():
        path.mkdir()
    shown = {key: str(path) for key, path in dirs.items()}
    (dirs["cfg"] / "graph.py").write_text(_GRAPH.format(**shown), encoding="utf-8")
    return load_config(shown["cfg"]), shown


def _worker_pid(session: SandboxSession) -> int | None:
    proc = session._proc
    return proc.pid if proc is not None and proc.poll() is None else None


class _Raises:
    def __init__(self, exc: BaseException) -> None:
        self.exc = exc

    def encode(self) -> str:
        raise self.exc


@pytest.mark.parametrize("exc", [RuntimeError("boom"), KeyError("k"), SystemExit(2)])
def test_the_codec_refuses_a_send_whose_encode_raises_anything(exc: BaseException) -> None:
    send = Send("OB", _Raises(exc))  # type: ignore[arg-type]
    with pytest.raises(SandboxCodecError, match="Send message is not encodable"):
        enc_result("transform", send, _Blobs())


def test_mode_off_reports_the_encode_raise_as_the_handlers_error(
    graph: tuple[Registry, dict[str, str]],
) -> None:
    """The control: at ``mode=off`` the raise is the Handler's, not the engine's."""
    registry, _ = graph
    with pytest.raises(RuntimeError, match="encode failed"):
        transform_one(registry, "h_raise", RAW, run_context=RunContext())


def test_an_encode_raise_in_the_worker_is_reported_and_the_worker_survives(
    graph: tuple[Registry, dict[str, str]],
) -> None:
    registry, dirs = graph
    session = _session(
        dirs["cfg"], "IB_OK", SandboxPolicy(mode=SandboxMode.SUBPROCESS, wall_seconds=30.0)
    )
    try:
        assert _deliveries(registry, "h_ok", sandbox=session, run_context=RunContext()) == [
            ("OB", "DELIVERED")
        ]
        pid = _worker_pid(session)
        assert pid is not None

        for name in ("h_raise", "h_exit"):
            with pytest.raises(SandboxError, match=f"sandbox failed transform '{name}'") as info:
                _deliveries(registry, name, sandbox=session, run_context=RunContext())
            assert "Send message is not encodable" in str(info.value)
            assert "crash" not in str(info.value)
            assert "DOE" not in str(info.value) and "PID-5" not in str(info.value)
            assert _worker_pid(session) == pid

        ic = registry.inbound["IB_GEN"]
        with pytest.raises(SandboxError, match="sandbox failed router 'r_gen_raise'") as routed:
            route_only(registry, ic, RAW, sandbox=session, run_context=RunContext())
        assert str(routed.value).endswith("RuntimeError: router body failed")
        assert _worker_pid(session) == pid

        assert _deliveries(registry, "h_ok", sandbox=session, run_context=RunContext()) == [
            ("OB", "DELIVERED")
        ]
        assert _worker_pid(session) == pid
    finally:
        session.close()
