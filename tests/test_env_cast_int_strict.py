# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``env(key, cast=int)`` and ``cast = "int"`` read a whole number strictly (vault BACKLOG #1650).

The builtin ``int`` was the cast, and it runs before the connector's own ``port_setting`` sees the
value. ``environments/<env>.toml`` is TOML, so a ``true`` there reached the cast as a bool and became
port 1, and ``2575.9`` became port 2575; ``port_setting`` then saw a valid int. Measured on engine
origin/main 895925f2d3a: ``resolve_env_settings({"port": env("p", cast=int)}, {"p": True})`` gave
``{"port": 1}``. Each refusal test below is red there."""

from __future__ import annotations

import math
import textwrap
from pathlib import Path

import pytest

from messagefoundry.config.environments import load_environment_values
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    EnvRef,
    WiringError,
    env,
    load_config,
    parse_env_setting,
    resolve_env_settings,
)
from messagefoundry.pipeline.wiring_runner import _dest_config

_REFUSED = [True, False, 2575.9, 0.5, math.nan, math.inf, "2575.9", "true", [2575]]


@pytest.mark.parametrize("raw", _REFUSED)
def test_env_cast_int_refuses_a_bool_a_fraction_and_other_shapes(raw: object) -> None:
    with pytest.raises(WiringError) as ei:
        resolve_env_settings({"port": env("acme_port", cast=int)}, {"acme_port": raw})
    msg = str(ei.value)
    assert "'port'" in msg and "'acme_port'" in msg
    assert "not a valid int" in msg and "value withheld" in msg
    assert "2575" not in msg


@pytest.mark.parametrize("raw", _REFUSED)
def test_the_named_int_cast_refuses_the_same_values(raw: object) -> None:
    ref = parse_env_setting({"env": "acme_port", "cast": "int"})
    with pytest.raises(WiringError, match="not a valid int"):
        resolve_env_settings({"port": ref}, {"acme_port": raw})


@pytest.mark.parametrize(
    ("raw", "want"), [("2575", 2575), (" 2575 ", 2575), (2575, 2575), (2575.0, 2575)]
)
def test_env_cast_int_still_reads_a_whole_number(raw: object, want: int) -> None:
    out = resolve_env_settings({"port": env("p", cast=int)}, {"p": raw})
    assert out["port"] == want and type(out["port"]) is int


def test_an_env_ref_built_directly_with_the_builtin_int_is_held_to_the_same_reading() -> None:
    ref = EnvRef(key="p", cast=int)
    assert ref.cast is not int
    with pytest.raises(WiringError):
        resolve_env_settings({"port": ref}, {"p": True})


def test_a_toml_true_port_is_refused_at_the_outbound_build(tmp_path: Path) -> None:
    """End to end: the instance's ``environments/<env>.toml`` holds ``partner_port = true``, and the
    outbound build, the choke point start and ``messagefoundry check`` share, refuses it rather
    than dialling port 1."""
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "cfg.py").write_text(
        textwrap.dedent(
            """
            from messagefoundry import MLLP, env, outbound
            outbound("OB_P", MLLP(host="partner.example.org", port=env("partner_port", cast=int)))
            """
        ),
        encoding="utf-8",
    )
    envdir = tmp_path / "environments"
    envdir.mkdir()
    (envdir / "prod.toml").write_text("partner_port = true\n", encoding="utf-8")
    values = load_environment_values(
        base_dir=tmp_path, dir_name="environments", environment="prod", environ={}
    )
    reg = load_config(cfg)
    egress = EgressSettings(deny_by_default=False)
    with pytest.raises(WiringError, match="not a valid int"):
        _dest_config(reg.outbound["OB_P"], values, None, egress)
