# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``sys.exit()`` in a Router, a Handler or a config module, at ``[sandbox].mode = "off"`` (vault
BACKLOG #3134).

``SystemExit`` is a ``BaseException``, so every ``except Exception`` on the router and transform
path let it through, and asyncio re-raises it out of the event loop rather than storing it on the
task: one Handler that called ``sys.exit()`` would have stopped every connection on the engine,
not dead-lettered one message. A config module calling it at top level during a reload would have
done the same through ``Engine.reload_detail``. Each test below fails on the code before the fix
with the ``SystemExit`` itself.

The sites, at least: the router hop and the inline transform (``_process_ingress_item``), the split
transform (``_process_routed_item``), both fused bodies (``_run_fused_route``,
``_run_fused_transform``) and the config loader's ``_exec_module``, which a reload runs.
``mode=subprocess`` is not covered here: the Handler runs in a worker process there.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType
from messagefoundry.config.run_context import RunContext
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
    WiringError,
    load_config,
)
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.wiring_runner import RegistryRunner, _ItemOutcome, _UserCodeExit
from messagefoundry.store import MessageStore, OutboxItem, Stage

RAW = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"


def _exit(_msg: Any) -> Any:
    sys.exit(0)


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "exit.db")
    yield s
    await s.close()


def _runner(store: MessageStore, *, router: Any = None, handler: Any = None) -> RegistryRunner:
    """IB -> r -> h -> OB1, never started, so nothing binds."""
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "IB",
            ConnectionSpec(ConnectorType.FILE, {"directory": "/tmp/mefor-in", "pattern": "*.hl7"}),
            router="r",
        )
    )
    reg.add_outbound(
        OutboundConnection("OB1", ConnectionSpec(ConnectorType.FILE, {"directory": "/tmp/out"}))
    )
    reg.add_router("r", router or (lambda m: ["h"]))
    reg.add_handler("h", handler or (lambda m: Send("OB1", m)))
    return RegistryRunner(reg, store, egress=EgressSettings(deny_by_default=False))


def _item(stage: Stage, *, handler_name: str | None = None) -> OutboxItem:
    return OutboxItem(
        id="row-1",
        message_id="m-1",
        channel_id="IB",
        destination_name=None,
        payload=RAW,
        attempts=1,
        stage=stage.value,
        handler_name=handler_name,
    )


def _spy_dead_letter(monkeypatch: pytest.MonkeyPatch, store: MessageStore) -> list[str]:
    reasons: list[str] = []

    async def _dl(item_id: str, reason: str) -> None:
        reasons.append(reason)

    monkeypatch.setattr(store, "dead_letter_now", _dl)
    return reasons


async def test_a_router_calling_sys_exit_dead_letters_the_message(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = _runner(store, router=_exit)
    reasons = _spy_dead_letter(monkeypatch, store)

    outcome = await runner._process_ingress_item("IB", _item(Stage.INGRESS))

    assert outcome == (_ItemOutcome.PROCESSED, None)
    assert len(reasons) == 1 and reasons[0].startswith("router error:")
    assert "SystemExit" in reasons[0]


async def test_a_handler_calling_sys_exit_on_the_split_path_dead_letters_the_message(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = _runner(store, handler=_exit)
    reasons = _spy_dead_letter(monkeypatch, store)

    outcome = await runner._process_routed_item("IB", _item(Stage.ROUTED, handler_name="h"))

    assert outcome == (_ItemOutcome.PROCESSED, None)
    assert len(reasons) == 1 and reasons[0].startswith("handler error:")


async def test_a_handler_calling_sys_exit_on_the_inline_path_dead_letters_the_message(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = _runner(store, handler=_exit)
    runner._inline_ok["IB"] = True  # the router and the handler run in one hop (ADR 0057)
    reasons = _spy_dead_letter(monkeypatch, store)

    outcome = await runner._process_ingress_item("IB", _item(Stage.INGRESS))

    assert outcome == (_ItemOutcome.PROCESSED, None)
    assert len(reasons) == 1 and "SystemExit" in reasons[0]


def test_the_fused_route_body_returns_sys_exit_as_a_content_fault(store: MessageStore) -> None:
    runner = _runner(store, router=_exit)
    ic = runner.registry.inbound["IB"]

    result = runner._run_fused_route("IB", ic, _item(Stage.INGRESS), RunContext(), None)

    assert isinstance(result.route_exc, _UserCodeExit)
    assert result.handoff_exc is None and not result.handed_off


def test_the_fused_transform_body_returns_sys_exit_as_a_content_fault(
    store: MessageStore,
) -> None:
    runner = _runner(store, handler=_exit)

    result = runner._run_fused_transform(
        "IB", _item(Stage.ROUTED, handler_name="h"), RunContext(), "hl7v2", None
    )

    assert isinstance(result.xform_exc, _UserCodeExit)
    assert result.handoff_exc is None


def test_the_exit_code_is_named_only_when_it_is_an_integer() -> None:
    """``sys.exit("text")`` puts the text on the exception, and that text is the author's, so it
    could carry a field value; the stored reason names an integer code and nothing else."""
    assert "code 3" in str(_UserCodeExit.from_exit(SystemExit(3)))
    assert "PID" not in str(_UserCodeExit.from_exit(SystemExit("PID-5 was DOE^JANE")))


def _write_config(cfg: Path, *, inbox: Path, outdir: Path, top_level: str = "") -> None:
    cfg.mkdir(parents=True, exist_ok=True)
    inbox.mkdir(parents=True, exist_ok=True)
    outdir.mkdir(parents=True, exist_ok=True)
    (cfg / "cfg.py").write_text(
        "import sys\n"
        "from messagefoundry import inbound, outbound, router, handler, Send, File\n"
        f"inbound('IB_LIVE', File(directory={str(inbox)!r}, pattern='*.hl7', "
        "poll_seconds=0.02), router='r')\n"
        f"outbound('OUT_LIVE', File(directory={str(outdir)!r}))\n"
        "@router('r')\n"
        "def route(msg):\n"
        "    return ['h']\n"
        "@handler('h')\n"
        "def handle(msg):\n"
        "    return Send('OUT_LIVE', msg)\n" + top_level,
        encoding="utf-8",
    )


def test_a_config_module_calling_sys_exit_is_a_wiring_error_at_load(tmp_path: Path) -> None:
    """The refusal sits in the loader, so every load path takes it: a reload, a connection-flag
    write's validation, ``serve`` and ``check``. The module is unregistered as for any failure."""
    bad = tmp_path / "bad"
    _write_config(bad, inbox=tmp_path / "in", outdir=tmp_path / "out", top_level="sys.exit(7)\n")
    before = set(sys.modules)

    with pytest.raises(WiringError, match=r"sys\.exit\(\)") as ei:
        load_config(bad)

    assert "7" not in str(ei.value)  # the code is not quoted
    assert ei.value.__cause__ is None and ei.value.__context__ is None
    # Nothing left registered for the module itself (the loader may import engine modules lazily).
    cfg = str(bad / "cfg.py")
    added = [sys.modules[name] for name in set(sys.modules) - before]
    assert [m for m in added if getattr(m, "__file__", None) == cfg] == []


async def test_a_config_module_calling_sys_exit_refuses_the_reload_and_keeps_the_graph(
    tmp_path: Path,
) -> None:
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    live = tmp_path / "live"
    _write_config(live, inbox=inbox, outdir=outdir)
    eng = await Engine.create(
        tmp_path / "e.db", poll_interval=0.02, egress_settings=EgressSettings(deny_by_default=False)
    )
    eng.add_registry(load_config(live))
    await eng.start()
    try:
        bad = tmp_path / "bad"
        _write_config(bad, inbox=inbox, outdir=outdir, top_level="sys.exit(0)\n")

        with pytest.raises(WiringError, match=r"sys\.exit\(\)"):
            await eng.reload_detail(bad)

        assert eng.registry_runner is not None
        assert eng.registry_runner.running
        assert "IB_LIVE" in eng.registry_runner.registry.inbound
    finally:
        await eng.stop()
