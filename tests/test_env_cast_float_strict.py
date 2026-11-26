# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``env(key, cast=float)`` and ``cast = "float"`` refuse a bool (vault BACKLOG #1650).

The builtin ``float`` was the cast, and ``environments/<env>.toml`` is TOML, so a ``true`` there
reached it as a bool and became 1.0. Measured on engine origin/main d15534be951:
``resolve_env_settings({"rate": env("r", cast=float)}, {"r": True})`` gave ``{"rate": 1.0}``. The
bool cases are red there; the rest are controls the builtin already met."""

from __future__ import annotations

import math
import operator
from decimal import Decimal
from fractions import Fraction
from typing import Any

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


_NUMERIC_BUILTIN_CASTS = [
    abs,
    round,
    Decimal,
    Fraction,
    complex,
    math.floor,
    math.ceil,
    math.trunc,
    math.fabs,
    operator.index,
]


@pytest.mark.parametrize("cast", _NUMERIC_BUILTIN_CASTS, ids=lambda c: c.__name__)
@pytest.mark.parametrize("raw", [True, False])
def test_a_numeric_builtin_cast_refuses_a_bool(cast: Any, raw: bool) -> None:
    """Each of these read a TOML ``true`` as 1 (``abs(True) == 1``, ``Decimal(True) == 1``), the
    remainder engine PR 3163 named. A bool is refused before the cast runs, value withheld."""
    with pytest.raises(WiringError) as ei:
        resolve_env_settings({"rate": env("acme_rate", cast=cast)}, {"acme_rate": raw})
    msg = str(ei.value)
    assert "'rate'" in msg and "'acme_rate'" in msg
    assert f"not a valid {cast.__name__}" in msg and "value withheld" in msg


@pytest.mark.parametrize("cast", _NUMERIC_BUILTIN_CASTS, ids=lambda c: c.__name__)
def test_a_numeric_builtin_cast_still_reads_a_number(cast: Any) -> None:
    """The control: the same casts on a number give what the builtin gives."""
    out = resolve_env_settings({"rate": env("r", cast=cast)}, {"r": 3})
    assert out["rate"] == cast(3)


def test_a_numeric_builtin_cast_keeps_two_refs_equal() -> None:
    """The guard compares equal per cast, so two references written alike still compare equal."""
    assert env("r", cast=abs) == env("r", cast=abs)
    assert EnvRef(key="r", cast=Decimal).cast == env("r", cast=Decimal).cast


_EQ_CALLS: list[object] = []


class _ComparingMeta(type):
    """A metaclass whose ``__eq__`` is author code: the numeric-cast test must never run it."""

    def __eq__(cls, other: object) -> bool:
        _EQ_CALLS.append(other)
        return False

    __hash__ = type.__hash__


class _AuthorCast(metaclass=_ComparingMeta):
    def __init__(self, raw: object) -> None:
        self.raw = raw


def test_the_numeric_cast_test_runs_no_metaclass_eq() -> None:
    """The cast is matched against ``bool``, ``int`` and ``float`` by identity, as the docstring
    says, so an author cast's metaclass ``__eq__`` never runs. A type that is not a number is left
    as given (vault BACKLOG #1650)."""
    _EQ_CALLS.clear()
    ref = env("r", cast=_AuthorCast)
    assert _EQ_CALLS == []
    assert ref.cast is _AuthorCast
