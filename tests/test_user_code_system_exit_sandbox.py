# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``sys.exit()`` in a Router, an ``accepts=`` predicate or a Handler, at ``[sandbox].mode =
"subprocess"`` (vault BACKLOG #3134, step 3). ``tests/test_user_code_system_exit.py`` holds
``mode=off``.

The user code runs in the worker there. Before the fix the ``SystemExit`` ended the worker, so the
parent raised ``SandboxError`` naming a crash and the next message paid a fresh worker; the message
still dead-lettered. Each test below fails on that code: the worker's pid changes, and the error
names a crash rather than the ``sys.exit()``. Synthetic HL7 only.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.config.run_context import RunContext
from messagefoundry.config.settings import EgressSettings, SandboxSettings
from messagefoundry.config.wiring import Registry, load_config
from messagefoundry.pipeline.dryrun import route_only
from messagefoundry.pipeline.sandbox import (
    SandboxError,
    SandboxMode,
    SandboxPolicy,
    SandboxSession,
    policy_from_settings,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner, UserCodeCalledSysExit
from messagefoundry.store import MessageStatus, MessageStore, Stage
from tests.test_sandbox import RAW, _deliveries, _session
from tests.test_sandbox_reload_race import _settled

_GRAPH = """
import sys

from messagefoundry import inbound, outbound, router, handler, File, Send

inbound("IB_OK", File(directory={inbox_ok!r}, poll_seconds=0.05), router="r_ok")
inbound("IB_EXIT", File(directory={inbox_exit!r}, poll_seconds=0.05), router="r_to_exit")
inbound("IB_REXIT", File(directory={inbox_rexit!r}, poll_seconds=0.05), router="r_exit")
inbound("IB_PRED", File(directory={inbox_pred!r}, poll_seconds=0.05), router="r_pred")
outbound("OB", File(directory={outbox!r}))


@router("r_ok")
def r_ok(msg):
    return "h_ok"


@router("r_to_exit")
def r_to_exit(msg):
    return "h_exit"


@router("r_exit")
def r_exit(msg):
    sys.exit(0)


@router("r_pred")
def r_pred(msg):
    return "h_guarded"


def _exits(msg):
    sys.exit(5)


@handler("h_ok")
def h_ok(msg):
    return Send("OB", "DELIVERED")


@handler("h_exit")
def h_exit(msg):
    sys.exit(3)


@handler("h_exit_text")
def h_exit_text(msg):
    sys.exit("PID-5 was DOE^JANE")


@handler("h_guarded", accepts=_exits)
def h_guarded(msg):
    return Send("OB", "NEVER")
"""

_DIRS = ("inbox_ok", "inbox_exit", "inbox_rexit", "inbox_pred", "outbox", "cfg")


@pytest.fixture
def graph(tmp_path: Path) -> tuple[Registry, dict[str, str]]:
    dirs = {key: tmp_path / key for key in _DIRS}
    for path in dirs.values():
        path.mkdir()
    shown = {key: str(path) for key, path in dirs.items()}
    (dirs["cfg"] / "graph.py").write_text(_GRAPH.format(**shown), encoding="utf-8")
    return load_config(shown["cfg"]), shown


def _exited(code: object) -> str:
    """The text ``mode=off`` gives a ``sys.exit(code)``."""
    return str(UserCodeCalledSysExit.from_exit(SystemExit(code)))


def _route(registry: Registry, inbound: str, session: SandboxSession) -> object:
    ic = registry.inbound[inbound]
    return route_only(registry, ic, RAW, sandbox=session, run_context=RunContext())


def _worker_pid(session: SandboxSession) -> int | None:
    proc = session._proc
    return proc.pid if proc is not None and proc.poll() is None else None


@pytest.mark.parametrize("mode", [SandboxMode.SUBPROCESS, SandboxMode.ISOLATED])
def test_sys_exit_in_worker_user_code_is_a_handler_error_and_the_worker_survives(
    graph: tuple[Registry, dict[str, str]], mode: SandboxMode
) -> None:
    """A Handler, a Router and an ``accepts=`` predicate in one worker: each ``sys.exit()`` is
    reported in ``mode=off``'s words, and the same worker answers the next message. ``isolated``
    runs the same worker, with the lookup broker on."""
    registry, dirs = graph
    session = _session(dirs["cfg"], "IB_OK", SandboxPolicy(mode=mode, wall_seconds=30.0))
    try:
        assert _deliveries(registry, "h_ok", sandbox=session, run_context=RunContext()) == [
            ("OB", "DELIVERED")
        ]
        pid = _worker_pid(session)
        assert pid is not None

        with pytest.raises(SandboxError, match="sandbox failed transform 'h_exit'") as handler:
            _deliveries(registry, "h_exit", sandbox=session, run_context=RunContext())
        assert str(handler.value).endswith(f"UserCodeCalledSysExit: {_exited(3)}")
        assert _worker_pid(session) == pid

        # sys.exit("...") carries the author's text, which could quote a field: none of it crosses.
        with pytest.raises(SandboxError) as texted:
            _deliveries(registry, "h_exit_text", sandbox=session, run_context=RunContext())
        assert str(texted.value).endswith(_exited("text"))
        assert "DOE" not in str(texted.value) and "PID-5" not in str(texted.value)
        assert _worker_pid(session) == pid

        with pytest.raises(SandboxError, match="sandbox failed router 'r_exit'") as routed:
            _route(registry, "IB_REXIT", session)
        assert str(routed.value).endswith(_exited(0))
        assert _worker_pid(session) == pid

        with pytest.raises(SandboxError) as predicate:
            _route(registry, "IB_PRED", session)
        assert str(predicate.value).endswith(_exited(5))
        assert _worker_pid(session) == pid

        assert _deliveries(registry, "h_ok", sandbox=session, run_context=RunContext()) == [
            ("OB", "DELIVERED")
        ]
        assert _worker_pid(session) == pid
    finally:
        session.close()


async def test_the_runner_dead_letters_the_message_and_keeps_running(
    graph: tuple[Registry, dict[str, str]], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End to end through the staged pipeline: the message is ``ERROR`` with a dead-letter reason
    naming the ``sys.exit()``, and the engine goes on to process the next message."""
    registry, dirs = graph
    egress = EgressSettings(allowed_file_dirs=[dirs["outbox"]])
    store = await MessageStore.open(tmp_path / "exit.db")
    runner = RegistryRunner(
        registry,
        store,
        sandbox_policy=policy_from_settings(
            SandboxSettings.model_validate({"mode": "subprocess", "wall_seconds": 60.0}), egress
        ),
        sandbox_config_source=(dirs["cfg"], None),
        egress=egress,
    )
    reasons: list[str] = []
    dead_letter_now = store.dead_letter_now

    async def _recorded(item_id: str, reason: str) -> None:
        reasons.append(reason)
        await dead_letter_now(item_id, reason)

    monkeypatch.setattr(store, "dead_letter_now", _recorded)
    await runner.start()
    try:
        bad = await store.enqueue_ingress(
            channel_id="IB_EXIT", raw=RAW, control_id="MSG00001", message_type="ADT^A01"
        )
        runner._wake_lane(Stage.INGRESS, "IB_EXIT")
        assert await _settled(store, bad) == MessageStatus.ERROR.value

        assert len(reasons) == 1
        assert reasons[0].startswith("handler error:")
        assert reasons[0].endswith(_exited(3))
        assert "crashed" not in reasons[0]

        assert runner.running
        good = await store.enqueue_ingress(
            channel_id="IB_OK", raw=RAW, control_id="MSG00002", message_type="ADT^A01"
        )
        runner._wake_lane(Stage.INGRESS, "IB_OK")
        assert await _settled(store, good) == MessageStatus.PROCESSED.value
    finally:
        await runner.stop()
        await store.close()
    assert [p.read_text(encoding="utf-8") for p in Path(dirs["outbox"]).iterdir()] == ["DELIVERED"]
