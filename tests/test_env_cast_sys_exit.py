# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``sys.exit()`` inside an ``env(cast=fn)`` (vault BACKLOG #5105).

A cast is code the config author writes, and ``resolve_env_settings`` runs it at every load,
reload and ``messagefoundry check``. ``SystemExit`` is a ``BaseException``, so the handler's
``except Exception`` let it through: a reload left with it, and ``check`` ended with the cast's own
code, 0 included, which reads as a pass. It is now refused like any other cast failure: one
``WiringError``, value and exit text withheld, nothing chained. A ``KeyboardInterrupt`` still
propagates.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.checks import run_checks
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import WiringError, env, load_config, resolve_env_settings
from messagefoundry.pipeline import Engine

# The #1656 needle, reused so no new .gitleaks.toml entry is owed.
SECRET = "pw-K3yErr_Val-88"


def _exit_with(code: int | str | None) -> Any:
    def cast(raw: object) -> int:
        sys.exit(code if code != "echo" else f"bad port {raw}")

    cast.__name__ = "int"
    return cast


@pytest.mark.parametrize("code", [0, 3, None, "echo"])
def test_a_cast_that_exits_is_refused_value_and_text_withheld(code: int | str | None) -> None:
    with pytest.raises(WiringError) as ei:
        resolve_env_settings({"port": env("p", cast=_exit_with(code))}, {"p": SECRET})
    msg = str(ei.value)
    assert "setting 'port' (env 'p')" in msg and "not a valid int" in msg, msg
    assert "SystemExit" in msg and "value withheld" in msg, msg
    assert SECRET not in msg, msg
    # Raised outside the handler: the exit, and the text it carries, is on neither link.
    assert ei.value.__cause__ is None and ei.value.__context__ is None


def test_an_exiting_cast_is_batched_with_the_other_problems() -> None:
    settings = {"host": env("a_host"), "port": env("b_port", cast=_exit_with(0))}
    with pytest.raises(WiringError) as ei:
        resolve_env_settings(settings, {"b_port": "6661"})
    msg = str(ei.value)
    assert "missing: a_host" in msg and "b_port" in msg, msg


def test_a_keyboard_interrupt_in_a_cast_still_propagates() -> None:
    def interrupt(raw: object) -> int:
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        resolve_env_settings({"port": env("p", cast=interrupt)}, {"p": "6661"})


_EXITING_CONFIG = (
    "import sys\n"
    "from messagefoundry import inbound, outbound, router, handler, Send, File, MLLP, env\n"
    "def port(raw):\n"
    "    sys.exit(0)\n"
    "inbound('IB_E', File(directory={inbox!r}, pattern='*.hl7', poll_seconds=0.02), router='r')\n"
    "outbound('OUT_PEER', MLLP(host='127.0.0.1', port=env('peer_port', cast=port)))\n"
    "@router('r')\n"
    "def route(msg):\n"
    "    return ['h']\n"
    "@handler('h')\n"
    "def handle(msg):\n"
    "    return Send('OUT_PEER', msg)\n"
)

_LIVE_CONFIG = (
    "from messagefoundry import inbound, outbound, router, handler, Send, File\n"
    "inbound('IB_LIVE', File(directory={inbox!r}, pattern='*.hl7', poll_seconds=0.02), router='r')\n"
    "outbound('OUT_LIVE', File(directory={outdir!r}))\n"
    "@router('r')\n"
    "def route(msg):\n"
    "    return ['h']\n"
    "@handler('h')\n"
    "def handle(msg):\n"
    "    return Send('OUT_LIVE', msg)\n"
)


def _write(cfg: Path, text: str) -> Path:
    cfg.mkdir(parents=True, exist_ok=True)
    (cfg / "c.py").write_text(text, encoding="utf-8")
    return cfg


async def test_a_reload_whose_cast_exits_is_refused_and_leaves_the_graph(tmp_path: Path) -> None:
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    outdir.mkdir()
    live = _write(tmp_path / "live", _LIVE_CONFIG.format(inbox=str(inbox), outdir=str(outdir)))
    eng = await Engine.create(
        tmp_path / "e.db",
        poll_interval=0.02,
        env_values={"peer_port": "6661"},
        egress_settings=EgressSettings(deny_by_default=False),
    )
    eng.add_registry(load_config(live))
    await eng.start()
    try:
        bad = _write(tmp_path / "bad", _EXITING_CONFIG.format(inbox=str(inbox)))
        for dry_run in (True, False):  # the promote pre-flight, then the real reload
            with pytest.raises(WiringError, match="peer_port.*SystemExit"):
                await eng.reload(bad, dry_run=dry_run)
            assert eng.registry_runner is not None
            assert set(eng.registry_runner.registry.inbound) == {"IB_LIVE"}
            assert eng.registry_runner.running
    finally:
        await eng.stop()


_EXIT_CAST = "import sys\ndef quit(raw):\n    sys.exit(0)\n"
_PLACEMENTS = {
    # resolve_env_settings, when the outbound is built.
    "outbound_port": _EXITING_CONFIG,
    # The listener-port pre-flight (_resolve_port), which runs before any connector is built.
    "inbound_port": _EXIT_CAST
    + "from messagefoundry import inbound, router, MLLP, env\n"
    + "inbound('IB_E', MLLP(port=env('peer_port', cast=quit)), router='r')\n"
    + "@router('r')\ndef route(msg):\n    return []\n",
    # The encoding pre-flight (_resolve_one_env_value), also before the build.
    "encoding": _EXIT_CAST
    + "from messagefoundry import inbound, outbound, router, File, env\n"
    + "inbound('IB_E', File(directory={inbox!r}), router='r')\n"
    + "outbound('OUT_F', File(directory={inbox!r}, encoding=env('peer_port', cast=quit)))\n"
    + "@router('r')\ndef route(msg):\n    return []\n",
}


@pytest.mark.parametrize("placement", sorted(_PLACEMENTS))
def test_check_fails_a_cast_that_exits_zero(tmp_path: Path, placement: str) -> None:
    # The gate's build-check leg resolves env() as serve does. A cast that exits 0 there ended
    # `messagefoundry check` with exit status 0, a pass; it must be a blocking failure instead,
    # wherever the cast is first run.
    text = _PLACEMENTS[placement].format(inbox=str(tmp_path / "in"))
    cfg = _write(tmp_path / "config", text)
    (tmp_path / "environments").mkdir()
    (tmp_path / "environments" / "dev.toml").write_text('peer_port = "6661"\n', encoding="utf-8")
    report = run_checks(cfg, run_lint=False, env="dev", project_root=tmp_path)
    build = next(r for r in report.results if r.name == "build-check")
    assert not build.ok and build.required and not build.skipped, build
    assert "peer_port" in build.detail and "SystemExit" in build.detail, build.detail
    assert not report.ok
