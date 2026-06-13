"""Global-default + per-connection-override resolution for outbound delivery (RetryPolicy).

Resolution order: a connection's own ``retry=`` wins; an outbound that sets none inherits the
``[delivery]`` global default; absent any config, the built-in default applies.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from messagefoundry import BuildupThreshold, InternalErrorPolicy, RetryPolicy
from messagefoundry.config.settings import DeliverySettings, load_settings
from messagefoundry.config.wiring import load_config
from messagefoundry.pipeline import Engine


def test_delivery_settings_default_matches_retry_policy() -> None:
    # The [delivery] section mirrors RetryPolicy; guard that the two default sets never drift.
    assert DeliverySettings().retry_policy() == RetryPolicy()


def test_delivery_section_loads_and_overrides_builtin(tmp_path: Path) -> None:
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text(
        textwrap.dedent(
            """
            [delivery]
            retry_max_attempts = 99
            retry_backoff_seconds = 1.5
            """
        )
    )
    settings = load_settings(config_path=cfg)
    rp = settings.delivery.retry_policy()
    assert rp.max_attempts == 99
    assert rp.backoff_seconds == 1.5
    assert rp.max_backoff_seconds == RetryPolicy().max_backoff_seconds  # unspecified → built-in


def test_delivery_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    # MEFOR_DELIVERY_RETRY_MAX_ATTEMPTS overrides the file/built-in (same precedence as every section).
    settings = load_settings(environ={"MEFOR_DELIVERY_RETRY_MAX_ATTEMPTS": "3"})
    assert settings.delivery.retry_policy().max_attempts == 3


def test_outbound_keeps_retry_none_when_unset(tmp_path: Path) -> None:
    cfgdir = tmp_path / "cfg"
    cfgdir.mkdir()
    (cfgdir / "c.py").write_text(
        textwrap.dedent(
            f"""
            from messagefoundry import outbound, inbound, router, File, RetryPolicy
            outbound("ob_default", File(directory={str(tmp_path / "a")!r}, filename="{{MSH-10}}.hl7"))
            outbound("ob_override", File(directory={str(tmp_path / "b")!r}, filename="{{MSH-10}}.hl7"),
                     retry=RetryPolicy(max_attempts=2))
            inbound("in", File(directory={str(tmp_path / "in")!r}, pattern="*.hl7", poll_seconds=0.05),
                    router="r")

            @router("r")
            def route(msg):
                return []
            """
        )
    )
    reg = load_config(cfgdir)
    assert reg.outbound["ob_default"].retry is None  # unset → inherit the global default later
    assert reg.outbound["ob_override"].retry == RetryPolicy(max_attempts=2)


def test_buildup_threshold_default_and_toml_override(tmp_path: Path) -> None:
    # The [delivery] buildup_* keys mirror BuildupThreshold; guard the defaults never drift, and that
    # the file overrides them.
    assert DeliverySettings().buildup_threshold() == BuildupThreshold()
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text("[delivery]\nbuildup_max_depth = 500\nbuildup_max_oldest_seconds = 60\n")
    bt = load_settings(config_path=cfg).delivery.buildup_threshold()
    assert bt.max_depth == 500
    assert bt.max_oldest_seconds == 60.0


def test_internal_error_default_and_toml_override(tmp_path: Path) -> None:
    # Built-in default is continue; [delivery] internal_error overrides it (parsed to the enum).
    assert DeliverySettings().internal_error is InternalErrorPolicy.CONTINUE
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text('[delivery]\ninternal_error = "stop"\n')
    assert load_settings(config_path=cfg).delivery.internal_error is InternalErrorPolicy.STOP


async def test_runner_resolves_internal_error_override_over_global(tmp_path: Path) -> None:
    for d in ("in", "a", "b"):
        (tmp_path / d).mkdir()
    cfgdir = tmp_path / "cfg"
    cfgdir.mkdir()
    (cfgdir / "c.py").write_text(
        textwrap.dedent(
            f"""
            from messagefoundry import outbound, inbound, router, File, InternalErrorPolicy
            outbound("ob_default", File(directory={str(tmp_path / "a")!r}, filename="{{MSH-10}}.hl7"))
            outbound("ob_override", File(directory={str(tmp_path / "b")!r}, filename="{{MSH-10}}.hl7"),
                     internal_error=InternalErrorPolicy.STOP)
            inbound("in", File(directory={str(tmp_path / "in")!r}, pattern="*.hl7", poll_seconds=0.05),
                    router="r")

            @router("r")
            def route(msg):
                return []
            """
        )
    )
    reg = load_config(cfgdir)
    assert reg.outbound["ob_default"].internal_error is None  # unset → inherit global later
    assert reg.outbound["ob_override"].internal_error is InternalErrorPolicy.STOP
    engine = await Engine.create(
        tmp_path / "mf.db", internal_error_default=InternalErrorPolicy.CONTINUE
    )
    engine.add_registry(reg)
    await engine.start()
    try:
        resolved = engine._registry_runner._internal_error  # type: ignore[union-attr]
        assert (
            resolved["ob_default"] is InternalErrorPolicy.CONTINUE
        )  # inherited the global default
        assert resolved["ob_override"] is InternalErrorPolicy.STOP  # per-connection override wins
    finally:
        await engine.stop()


async def test_runner_resolves_override_over_global_default(tmp_path: Path) -> None:
    for d in ("in", "a", "b"):
        (tmp_path / d).mkdir()
    cfgdir = tmp_path / "cfg"
    cfgdir.mkdir()
    (cfgdir / "c.py").write_text(
        textwrap.dedent(
            f"""
            from messagefoundry import outbound, inbound, router, File, RetryPolicy
            outbound("ob_default", File(directory={str(tmp_path / "a")!r}, filename="{{MSH-10}}.hl7"))
            outbound("ob_override", File(directory={str(tmp_path / "b")!r}, filename="{{MSH-10}}.hl7"),
                     retry=RetryPolicy(max_attempts=2))
            inbound("in", File(directory={str(tmp_path / "in")!r}, pattern="*.hl7", poll_seconds=0.05),
                    router="r")

            @router("r")
            def route(msg):
                return []
            """
        )
    )
    engine = await Engine.create(tmp_path / "mf.db", delivery_defaults=RetryPolicy(max_attempts=42))
    engine.add_registry(load_config(cfgdir))
    await engine.start()
    try:
        retry = engine._registry_runner._retry  # type: ignore[union-attr]
        assert retry["ob_default"].max_attempts == 42  # inherited the global default
        assert retry["ob_override"].max_attempts == 2  # per-connection override wins
    finally:
        await engine.stop()
