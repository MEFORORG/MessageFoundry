# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Global-default + per-connection-override resolution for outbound delivery (RetryPolicy).

Resolution order: a connection's own ``retry=`` wins; an outbound that sets none inherits the
``[delivery]`` global default; absent any config, the built-in default applies.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from messagefoundry import (
    BuildupThreshold,
    InternalErrorPolicy,
    RetryPolicy,
    SaturationThreshold,
    StallThreshold,
)
from messagefoundry.config.settings import DeliverySettings, EgressSettings, load_settings
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


def test_stall_threshold_default_off_and_toml_override(tmp_path: Path) -> None:
    # The [delivery] stall_max_oldest_seconds key mirrors StallThreshold; the message_stall alert is
    # OFF by default (deny-by-default), and the file turns it on. (#50, Corepoint "Max Message Stall".)
    assert DeliverySettings().stall_threshold() == StallThreshold()
    assert DeliverySettings().stall_threshold().max_oldest_seconds is None  # off unless configured
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text("[delivery]\nstall_max_oldest_seconds = 120\n")
    st = load_settings(config_path=cfg).delivery.stall_threshold()
    assert st.max_oldest_seconds == 120.0


@pytest.mark.parametrize("value", [0, -1, float("nan"), True])
def test_buildup_and_stall_thresholds_refuse_non_positive_nan_or_bool(value: float) -> None:
    # BACKLOG #5778: zero or below is crossed by every lane holding a message (a page for each such
    # lane, at the re-alert interval); NaN is never crossed (the alert silently off); a boolean would read as 1. Each is
    # refused at load, on the per-connection models and on the [delivery] keys that mirror them.
    with pytest.raises(ValueError):
        BuildupThreshold(max_oldest_seconds=value)
    with pytest.raises(ValueError):
        StallThreshold(max_oldest_seconds=value)
    with pytest.raises(ValueError):
        DeliverySettings(buildup_max_oldest_seconds=value)
    with pytest.raises(ValueError):
        DeliverySettings(stall_max_oldest_seconds=value)


def test_infinite_age_threshold_loads_as_off(tmp_path: Path) -> None:
    # BACKLOG #5778: TOML has no null, so `inf` is the settings-file spelling of an off age
    # dimension. It loads as None, so the runner skips the store read an off dimension needs no read
    # for, and a JSON view carries null. Negative infinity is still refused.
    assert BuildupThreshold(max_oldest_seconds=float("inf")).max_oldest_seconds is None
    assert StallThreshold(max_oldest_seconds=float("inf")).max_oldest_seconds is None
    assert BuildupThreshold(max_oldest_seconds="inf").max_oldest_seconds is None  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        BuildupThreshold(max_oldest_seconds=float("-inf"))
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text(
        "[delivery]\nbuildup_max_oldest_seconds = inf\nstall_max_oldest_seconds = inf\n",
        encoding="utf-8",
    )
    delivery = load_settings(config_path=cfg).delivery
    assert delivery.buildup_max_oldest_seconds is None
    assert delivery.stall_max_oldest_seconds is None
    assert delivery.buildup_threshold() == BuildupThreshold(max_oldest_seconds=None)
    assert delivery.stall_threshold().max_oldest_seconds is None


@pytest.mark.parametrize("depth", [0, -5, True])
def test_buildup_depth_refuses_below_one(depth: int) -> None:
    with pytest.raises(ValueError):
        BuildupThreshold(max_depth=depth)
    with pytest.raises(ValueError):
        DeliverySettings(buildup_max_depth=depth)


def test_saturation_threshold_default_off_and_toml_override(tmp_path: Path) -> None:
    # The [delivery] saturation_sustain_samples key mirrors SaturationThreshold; the saturation
    # (rising-backlog derivative) alert is OFF by default (deny-by-default, #93, ADR 0014 amendment),
    # and the file turns it on. Floor of 2 is enforced by the model (fewer can't tell a burst from
    # sustained growth).
    assert DeliverySettings().saturation_threshold() == SaturationThreshold()
    assert (
        DeliverySettings().saturation_threshold().sustain_samples is None
    )  # off unless configured
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text("[delivery]\nsaturation_sustain_samples = 4\n")
    sat = load_settings(config_path=cfg).delivery.saturation_threshold()
    assert sat.sustain_samples == 4


def test_saturation_min_growth_default_bounds_and_toml_override(tmp_path: Path) -> None:
    # BACKLOG #5768: the growth floor has a documented default, loads from the file, and refuses a
    # value out of range or a boolean (the boolean refusal is the shared one, BACKLOG #5509).
    from pydantic import ValidationError

    from messagefoundry.config.models import (
        SATURATION_MIN_GROWTH_DEFAULT,
        SATURATION_MIN_GROWTH_MAX,
    )

    assert DeliverySettings().saturation_threshold().min_growth == SATURATION_MIN_GROWTH_DEFAULT
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text("[delivery]\nsaturation_sustain_samples = 4\nsaturation_min_growth = 20\n")
    assert load_settings(config_path=cfg).delivery.saturation_threshold().min_growth == 20
    for bad in (0, SATURATION_MIN_GROWTH_MAX + 1, True):
        with pytest.raises(ValidationError, match="saturation_min_growth"):
            DeliverySettings.model_validate({"saturation_min_growth": bad})
    # The key that turns the alert on is refused at load by its own name too.
    for bad in (1, True):
        with pytest.raises(ValidationError, match="saturation_sustain_samples"):
            DeliverySettings.model_validate({"saturation_sustain_samples": bad})


def test_outbound_stall_override_kept_when_set(tmp_path: Path) -> None:
    # A per-connection stall= is preserved on the OutboundConnection (resolution to the global default
    # happens later in the runner, like retry/buildup).
    cfgdir = tmp_path / "cfg"
    cfgdir.mkdir()
    (cfgdir / "c.py").write_text(
        textwrap.dedent(
            f"""
            from messagefoundry import outbound, inbound, router, File, StallThreshold
            outbound("ob_default", File(directory={str(tmp_path / "a")!r}, filename="{{MSH-10}}.hl7"))
            outbound("ob_override", File(directory={str(tmp_path / "b")!r}, filename="{{MSH-10}}.hl7"),
                     stall=StallThreshold(max_oldest_seconds=30))
            inbound("in", File(directory={str(tmp_path / "in")!r}, pattern="*.hl7", poll_seconds=0.05),
                    router="r")

            @router("r")
            def route(msg):
                return []
            """
        )
    )
    reg = load_config(cfgdir)
    assert reg.outbound["ob_default"].stall is None  # unset → inherit the global default later
    assert reg.outbound["ob_override"].stall == StallThreshold(max_oldest_seconds=30)


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
        tmp_path / "mf.db",
        internal_error_default=InternalErrorPolicy.CONTINUE,
        egress_settings=EgressSettings(deny_by_default=False),
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
    engine = await Engine.create(
        tmp_path / "mf.db",
        delivery_defaults=RetryPolicy(max_attempts=42),
        egress_settings=EgressSettings(deny_by_default=False),
    )
    engine.add_registry(load_config(cfgdir))
    await engine.start()
    try:
        retry = engine._registry_runner._retry  # type: ignore[union-attr]
        assert retry["ob_default"].max_attempts == 42  # inherited the global default
        assert retry["ob_override"].max_attempts == 2  # per-connection override wins
    finally:
        await engine.stop()
