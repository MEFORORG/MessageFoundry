# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``env(key, cast=float)`` and ``cast = "float"`` refuse a bool (vault BACKLOG #1650).

The builtin ``float`` was the cast, and ``environments/<env>.toml`` is TOML, so a ``true`` there
reached it as a bool and became 1.0. Measured on engine origin/main d15534be951:
``resolve_env_settings({"rate": env("r", cast=float)}, {"r": True})`` gave ``{"rate": 1.0}``. The
bool cases are red there; the rest are controls the builtin already met."""

from __future__ import annotations

import math
from decimal import Decimal

import pytest

from messagefoundry.config.wiring import (
    EnvRef,
    WiringError,
    env,
    parse_env_setting,
    resolve_env_settings,
)


@pytest.mark.parametrize("raw", [True, False, "abc", [1.5]])
def test_env_cast_float_refuses_a_bool_and_other_shapes(raw: object) -> None:
    with pytest.raises(WiringError) as ei:
        resolve_env_settings({"rate": env("acme_rate", cast=float)}, {"acme_rate": raw})
    msg = str(ei.value)
    assert "'rate'" in msg and "'acme_rate'" in msg
    assert "not a valid float" in msg and "value withheld" in msg
    assert "abc" not in msg


@pytest.mark.parametrize(
    "raw", ["nan", "inf", "-inf", math.nan, math.inf, "1e-400", Decimal("1e-400"), "1e400"]
)
def test_env_cast_float_refuses_a_non_finite_or_underflowing_value(raw: object) -> None:
    """The builtin read each of these as nan, an infinity or 0.0, so a float cap read through the
    cast could turn off from a value nobody wrote as zero. Red on branch head b0172e13bd8."""
    with pytest.raises(WiringError) as ei:
        resolve_env_settings({"rate": env("acme_rate", cast=float)}, {"acme_rate": raw})
    msg = str(ei.value)
    assert "not a valid float" in msg and "value withheld" in msg
    assert "400" not in msg


@pytest.mark.parametrize("raw", ["0", "0.0", "-0", 0, 0.0])
def test_env_cast_float_still_reads_an_exact_zero(raw: object) -> None:
    assert resolve_env_settings({"rate": env("r", cast=float)}, {"r": raw})["rate"] == 0.0


@pytest.mark.parametrize("raw", [True, False])
def test_the_named_float_cast_refuses_a_bool(raw: object) -> None:
    ref = parse_env_setting({"env": "acme_rate", "cast": "float"})
    with pytest.raises(WiringError, match="not a valid float"):
        resolve_env_settings({"rate": ref}, {"acme_rate": raw})


@pytest.mark.parametrize(("raw", "want"), [("2.5", 2.5), (" 3 ", 3.0), (2, 2.0), (0.25, 0.25)])
def test_env_cast_float_still_reads_a_number(raw: object, want: float) -> None:
    out = resolve_env_settings({"rate": env("r", cast=float)}, {"r": raw})
    assert out["rate"] == want and type(out["rate"]) is float


def test_an_env_ref_built_directly_with_the_builtin_float_is_held_to_the_same_reading() -> None:
    ref = EnvRef(key="r", cast=float)
    assert ref.cast is not float
    with pytest.raises(WiringError):
        resolve_env_settings({"rate": ref}, {"r": True})


def test_a_cast_of_the_authors_own_runs_as_given() -> None:
    """The documented limit: an author's cast is not swapped, so it still reads a TOML ``true``."""
    out = resolve_env_settings({"port": env("p", cast=lambda v: int(v))}, {"p": True})
    assert out["port"] == 1
