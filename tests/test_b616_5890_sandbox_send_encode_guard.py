# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A Send whose message ``encode()`` raises, at ``[sandbox].mode = "subprocess"`` (BACKLOG #5890).

At ``mode=off`` dry-run calls ``send.message.encode()`` inside ``transform_one``, so any raise there,
``sys.exit()`` included, is that Handler's content fault and the message dead-letters. In the
worker the same call runs at describe time, in the codec's ``_enc_item``, which caught only
``AttributeError``, ``TypeError`` and ``ValueError``; any other raise escaped ``_respond`` and ended
the worker, so the parent read a crash and the next message paid a respawn. The worker now encodes
each Send inside ``_run_one``'s run context and exception arms, so the raise is reported in
``mode=off``'s words. The generator Router half of the finding was closed earlier (vault BACKLOG
#3134); its RuntimeError case is pinned here too. Synthetic HL7 only.
"""

from __future__ import annotations

import importlib
import logging
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from messagefoundry import Send
from messagefoundry.config.run_context import RunContext
from messagefoundry.config.wiring import Registry, load_config
from messagefoundry.pipeline.dryrun import route_only, transform_one
from messagefoundry.pipeline.sandbox import SandboxError, SandboxMode, SandboxPolicy, SandboxSession
from messagefoundry.pipeline.wiring_runner import UserCodeCalledSysExit
from tests._root_logging import root_logging_restored
from tests.test_sandbox import RAW, _deliveries, _session

_GRAPH = """
import sys

from messagefoundry import inbound, outbound, router, handler, File, Send, SetMeta

inbound("IB_OK", File(directory={inbox_ok!r}, poll_seconds=0.05), router="r_ok")
inbound("IB_GEN", File(directory={inbox_gen!r}, poll_seconds=0.05), router="r_gen_raise")
outbound("OB", File(directory={outbox!r}))


class _RaisingMessage:
    def encode(self):
        raise RuntimeError("encode failed")


class _ExitingMessage:
    def encode(self):
        sys.exit("PID-5 was DOE^JANE")


class _LoudText(str):
    # A str subclass whose own methods are user code: none of them may run outside the arms.
    def __len__(self):
        raise RuntimeError("len failed")

    def encode(self, *args, **kwargs):
        raise RuntimeError("str encode failed")


class _LoudTextMessage:
    def encode(self):
        return _LoudText("DELIVERED-LOUD")


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


class _LoudLen(str):
    def __len__(self):
        raise RuntimeError("len failed")


@handler("h_bad_order")
def h_bad_order(msg):
    return [Send("OB", _RaisingMessage()), 42]


@handler("h_meta_loud")
def h_meta_loud(msg):
    return [Send("OB", "DELIVERED"), SetMeta("k", _LoudLen("v"))]


@handler("h_loud_text")
def h_loud_text(msg):
    return [Send("OB", _LoudTextMessage()), Send("OB", _LoudText("DIRECT-LOUD"))]
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


class _Bytes:
    def encode(self) -> bytes:
        return b"x"


_WORKER = "messagefoundry.pipeline._sandbox_worker"


def _root_state() -> tuple[list[logging.Handler], int, list[Any]]:
    root = logging.getLogger()
    return list(root.handlers), root.level, list(root.filters)


def _import_encode_sends() -> Callable[[object], object]:
    """Import the worker's ``_encode_sends`` with the root logger put back afterwards.

    The worker's import calls ``configure_stderr_logging()``. That call replaces every root handler,
    pytest's capture handlers included, and sets the root level. It is right in the worker's child
    process and wrong here. A module-level import would leave that state from collection onward.
    """
    with root_logging_restored():
        from messagefoundry.pipeline._sandbox_worker import _encode_sends
    return _encode_sends


@pytest.fixture(scope="module")
def encode_sends() -> Callable[[object], object]:
    return _import_encode_sends()


def _forget_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    """Drop the worker module, so the next import runs its module code again."""
    import messagefoundry.pipeline as pipeline_pkg

    monkeypatch.delitem(sys.modules, _WORKER, raising=False)
    monkeypatch.delattr(pipeline_pkg, "_sandbox_worker", raising=False)


def test_import_encode_sends_restores_the_root_logger(monkeypatch: pytest.MonkeyPatch) -> None:
    """Control: the helper's fresh import leaves the root as it was, whatever test ran first.

    The positive control proves a bare fresh import does change the root. The identity check proves
    the helper's own import ran the module code again, so an unchanged root is the restore working.
    Monkeypatch undoes the module swaps. If the worker was never imported before this test, a fresh
    copy stays in ``sys.modules`` afterwards.
    """
    _forget_worker(monkeypatch)
    with root_logging_restored():
        before = _root_state()
        first = importlib.import_module(_WORKER)
        changed = _root_state() != before
    assert changed, "the bare import no longer touches the root, so this control proves nothing"
    _forget_worker(monkeypatch)
    before = _root_state()
    _import_encode_sends()
    assert sys.modules[_WORKER] is not first
    assert _root_state() == before


@pytest.mark.parametrize("exc", [RuntimeError("boom"), KeyError("k"), SystemExit(2), MemoryError()])
def test_encode_sends_lets_any_encode_raise_reach_the_callers_arms(
    encode_sends: Callable[[object], object], exc: BaseException
) -> None:
    with pytest.raises(type(exc)):
        encode_sends([Send("OB", _Raises(exc))])  # type: ignore[arg-type]


def test_encode_sends_carries_exact_text_and_keeps_the_shape(
    encode_sends: Callable[[object], object],
) -> None:
    class _Text(str):
        pass

    class _Msg:
        def encode(self) -> str:
            return _Text("BODY")

    one = encode_sends(Send("OB", _Msg()))  # type: ignore[arg-type]
    assert isinstance(one, Send) and type(one.message) is str and one.message == "BODY"
    many = encode_sends([Send("OB", _Text("A")), Send("OB", "B")])
    assert isinstance(many, list) and [type(m.message) for m in many] == [str, str]
    # An inadmissible item leaves the whole result to the codec, so no encode() runs first.
    held = [Send("OB", _Raises(RuntimeError("never called"))), "not a send"]  # type: ignore[arg-type]
    assert encode_sends(held) is held
    with pytest.raises(TypeError, match="encoded to bytes, expected a str"):
        encode_sends(Send("OB", _Bytes()))  # type: ignore[arg-type]


def test_mode_off_reports_the_encode_raise_as_the_handlers_error(
    graph: tuple[Registry, dict[str, str]],
) -> None:
    """The control: at ``mode=off`` the raise is the Handler's, not the engine's."""
    registry, _ = graph
    with pytest.raises(RuntimeError, match="encode failed"):
        transform_one(registry, "h_raise", RAW, run_context=RunContext())


def test_mode_off_reports_an_inadmissible_item_before_any_encode(
    graph: tuple[Registry, dict[str, str]],
) -> None:
    registry, _ = graph
    with pytest.raises(ValueError, match="unsupported int"):
        transform_one(registry, "h_bad_order", RAW, run_context=RunContext())


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

        exited = str(UserCodeCalledSysExit.from_exit(SystemExit("text")))
        for name, tail in (
            ("h_raise", "RuntimeError: encode failed"),
            ("h_exit", f"UserCodeCalledSysExit: {exited}"),
        ):
            with pytest.raises(SandboxError, match=f"sandbox failed transform '{name}'") as info:
                _deliveries(registry, name, sandbox=session, run_context=RunContext())
            assert str(info.value).endswith(tail)
            assert "DOE" not in str(info.value) and "PID-5" not in str(info.value)
            assert _worker_pid(session) == pid

        # An inadmissible item is refused before any encode() runs, as mode=off refuses it.
        with pytest.raises(SandboxError, match="unsupported int"):
            _deliveries(registry, "h_bad_order", sandbox=session, run_context=RunContext())
        assert _worker_pid(session) == pid

        # User code the describe step still meets (a str subclass's own __len__ in a SetMeta value)
        # is this Handler's error, and the worker survives it.
        with pytest.raises(SandboxError, match="sandbox failed transform 'h_meta_loud'") as meta:
            _deliveries(registry, "h_meta_loud", sandbox=session, run_context=RunContext())
        assert str(meta.value).endswith("RuntimeError: len failed")
        assert _worker_pid(session) == pid

        # A str subclass, returned by encode() or carried directly, crosses as its exact text.
        assert _deliveries(registry, "h_loud_text", sandbox=session, run_context=RunContext()) == [
            ("OB", "DELIVERED-LOUD"),
            ("OB", "DIRECT-LOUD"),
        ]
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
