# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Connection-scale profile parsing (B11) — fail-loud on a bad profile, correct sweep math."""

from __future__ import annotations

import pytest

from harness.load.connscale.profile import (
    ConnScaleProfileError,
    get_connscale_profile,
    list_connscale_profiles,
    load_connscale_profile_text,
)

_OK = """
[connscale]
name = "t"
counts = [50, 100]
sweep_mode = "both"
aggregate_rate = 35.0
per_conn_rate = 0.35
hold_seconds = 3.0
store_backend = "sqlite"
"""


def test_parses_a_valid_profile() -> None:
    p = load_connscale_profile_text(_OK)
    assert p.name == "t"
    assert p.counts == (50, 100)
    assert p.modes() == ("fixed_aggregate", "fixed_per_conn")
    assert p.store_backend is None  # sqlite normalizes to None (the default branch)


def test_sweep_math() -> None:
    p = load_connscale_profile_text(_OK)
    # fixed_aggregate holds R constant across N; fixed_per_conn scales with N.
    assert p.aggregate_rate_for("fixed_aggregate", 50) == 35.0
    assert p.aggregate_rate_for("fixed_aggregate", 100) == 35.0
    assert p.aggregate_rate_for("fixed_per_conn", 50) == pytest.approx(0.35 * 50)
    assert p.aggregate_rate_for("fixed_per_conn", 100) == pytest.approx(0.35 * 100)


def test_both_sweep_modes_run_by_default() -> None:
    p = load_connscale_profile_text("""
[connscale]
name = "d"
counts = [10]
aggregate_rate = 5.0
""")
    assert p.sweep_mode == "both"
    assert p.modes() == ("fixed_aggregate", "fixed_per_conn")


def test_base_port_is_configurable() -> None:
    p = load_connscale_profile_text("""
[connscale]
name = "bp"
counts = [10]
aggregate_rate = 5.0
base_port = 4000
""")
    assert p.base_port == 4000


@pytest.mark.parametrize(
    "body, needle",
    [
        ("[connscale]\nname='x'\n", "counts"),  # missing counts
        ("[connscale]\nname='x'\ncounts=[10]\nsweep_mode='nope'\n", "sweep_mode"),
        ("[connscale]\nname='x'\ncounts=[10]\ntransform='loud'\n", "transform"),
        ("[connscale]\nname='x'\ncounts=[10]\nstore_backend='oracle'\n", "store_backend"),
        ("[connscale]\nname='x'\ncounts=[10]\nbogus=1\n", "unknown key"),
        ("[load]\nname='x'\n", "unknown top-level key"),
        ("connscale = 5\n", "missing [connscale]"),
        ("[connscale]\nname='x'\ncounts=[]\n", "non-empty list"),
        ("[connscale]\nname='x'\ncounts=[0]\n", ">= 1"),
        # base_port + max count past the port space.
        ("[connscale]\nname='x'\ncounts=[100]\naggregate_rate=1.0\nbase_port=65500\n", "past"),
        # both rates zero.
        (
            "[connscale]\nname='x'\ncounts=[10]\naggregate_rate=0.0\nper_conn_rate=0.0\n",
            "must be positive",
        ),
    ],
)
def test_fails_loud(body: str, needle: str) -> None:
    with pytest.raises(ConnScaleProfileError) as exc:
        load_connscale_profile_text(body)
    assert needle in str(exc.value)


def test_builtin_profiles_resolve() -> None:
    names = list_connscale_profiles()
    assert "connscale" in names and "connscale-smoke" in names
    # Both built-ins parse cleanly (no "(invalid profile)").
    assert all(desc != "(invalid profile)" for desc in names.values())
    smoke = get_connscale_profile("connscale-smoke")
    assert smoke.counts == (50, 100)
    assert smoke.store_backend is None  # the CI smoke runs on SQLite


def test_unknown_profile_name_lists_builtins() -> None:
    with pytest.raises(ConnScaleProfileError) as exc:
        get_connscale_profile("does-not-exist")
    assert "connscale" in str(exc.value)
