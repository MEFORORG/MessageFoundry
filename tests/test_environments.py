"""Per-environment values (DEV/PROD): ``env()`` references resolve per instance and fail loud if a
referenced value is missing (Part B)."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from messagefoundry.config.environments import load_environment_values
from messagefoundry.config.wiring import (
    EnvRef,
    WiringError,
    display_settings,
    env,
    load_config,
    referenced_env_keys,
    resolve_env_settings,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner, _dest_config


def _write(directory: Path, body: str) -> Path:
    (directory / "cfg.py").write_text(textwrap.dedent(body), encoding="utf-8")
    return directory


def test_env_returns_ref() -> None:
    ref = env("epic_host")
    assert isinstance(ref, EnvRef) and ref.key == "epic_host"


def test_resolve_env_settings_resolves_casts_and_defaults() -> None:
    settings = {
        "host": env("epic_host"),
        "port": env("epic_port", cast=int),
        "timeout": env("missing_timeout", default=30.0),  # default used when key absent
        "encoding": "utf-8",  # plain value passes through untouched
    }
    out = resolve_env_settings(settings, {"epic_host": "10.0.0.9", "epic_port": "6661"})
    assert out == {"host": "10.0.0.9", "port": 6661, "timeout": 30.0, "encoding": "utf-8"}


def test_resolve_env_settings_missing_raises_listing_all() -> None:
    settings = {"host": env("a_host"), "port": env("b_port")}
    # All missing keys are reported at once, sorted — fail loud, never a silent blank.
    with pytest.raises(WiringError, match="a_host, b_port"):
        resolve_env_settings(settings, {})


def test_resolve_env_settings_cast_failure_is_wiringerror_not_raw() -> None:
    # A bad value for a cast (a typo'd port) must surface as a WiringError naming the setting/key/
    # value, not a raw ValueError that names nothing (review M-22).
    settings = {"port": env("epic_port", cast=int)}
    with pytest.raises(WiringError, match="epic_port"):
        resolve_env_settings(settings, {"epic_port": "66O1"})  # letter O, not a number


def test_resolve_env_settings_reports_missing_and_uncastable_together() -> None:
    settings = {"host": env("a_host"), "port": env("b_port", cast=int)}
    with pytest.raises(WiringError) as ei:
        resolve_env_settings(settings, {"b_port": "notnum"})  # a_host missing + b_port uncastable
    msg = str(ei.value)
    assert "missing: a_host" in msg and "b_port" in msg


def test_referenced_env_keys_and_display() -> None:
    settings = {"host": env("h"), "port": env("p", default=1), "x": "lit"}
    assert referenced_env_keys(settings) == ["h", "p"]
    assert display_settings(settings) == {
        "host": {"env": "h"},
        "port": {"env": "p", "default": 1},
        "x": "lit",
    }


def test_load_environment_values_file_and_env_overlay(tmp_path: Path) -> None:
    envdir = tmp_path / "environments"
    envdir.mkdir()
    (envdir / "dev.toml").write_text('a_host = "127.0.0.1"\na_port = 2601\n', encoding="utf-8")
    values = load_environment_values(
        base_dir=tmp_path,
        dir_name="environments",
        environment="dev",
        environ={"MEFOR_VALUE_A_HOST": "10.0.0.1", "MEFOR_VALUE_SECRET": "s3cret"},
    )
    assert values["a_host"] == "10.0.0.1"  # env overrides the file
    assert values["a_port"] == 2601  # file value (TOML int preserved)
    assert values["secret"] == "s3cret"  # env-only value (e.g. a secret)


def test_load_environment_values_lowercases_file_keys(tmp_path: Path) -> None:
    envdir = tmp_path / "environments"
    envdir.mkdir()
    (envdir / "prod.toml").write_text('EPIC_HOST = "10.0.0.9"\n', encoding="utf-8")
    # The file key folds to lower-case, so a MEFOR_VALUE_* override (also lower-cased) wins over it
    # rather than forking into two separate entries.
    values = load_environment_values(
        base_dir=tmp_path,
        dir_name="environments",
        environment="prod",
        environ={"MEFOR_VALUE_EPIC_HOST": "10.9.9.9"},
    )
    assert values == {"epic_host": "10.9.9.9"}


def test_env_ref_key_is_lowercased() -> None:
    assert env("EPIC_HOST").key == "epic_host"
    # a mixed-case reference resolves against the lower-cased values
    out = resolve_env_settings({"host": env("Epic_Host")}, {"epic_host": "10.0.0.1"})
    assert out["host"] == "10.0.0.1"


def test_load_environment_values_missing_file_is_empty(tmp_path: Path) -> None:
    assert (
        load_environment_values(
            base_dir=tmp_path, dir_name="environments", environment="prod", environ={}
        )
        == {}
    )


def test_build_resolves_env_outbound(tmp_path: Path) -> None:
    d = _write(
        tmp_path,
        """
        from messagefoundry import outbound, MLLP, env
        outbound("OB", MLLP(host=env("peer_host"), port=env("peer_port", cast=int)))
        """,
    )
    reg = load_config(d)
    dest = _dest_config(reg.outbound["OB"], {"peer_host": "10.0.0.2", "peer_port": "6000"})
    assert dest.settings["host"] == "10.0.0.2"
    assert dest.settings["port"] == 6000


def test_build_check_fails_loud_on_missing_env_value(tmp_path: Path) -> None:
    d = _write(
        tmp_path,
        """
        from messagefoundry import outbound, MLLP, env
        outbound("OB", MLLP(host=env("peer_host"), port=2601))
        """,
    )
    reg = load_config(d)
    # A missing value is refused when the connector is built (here, on this instance) — exactly the
    # promote-time guarantee: a graph whose env keys aren't defined for the target never goes live.
    runner = RegistryRunner(reg, store=None, env_values={})  # type: ignore[arg-type]
    with pytest.raises(WiringError, match="peer_host"):
        runner.build_check(reg)
