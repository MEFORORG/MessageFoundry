# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Connection-scale profile parsing (B11) — fail-loud on a bad profile, correct sweep math."""

from __future__ import annotations

from pathlib import Path

import pytest

from harness.load.connscale.profile import (
    ConnScaleProfileError,
    get_connscale_profile,
    list_connscale_profiles,
    load_connscale_profile,
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


def test_claim_modes_defaults_to_single_per_lane() -> None:
    # Absent claim_modes ⇒ the single-arm ("per_lane",) default, so every pre-existing profile keeps
    # its byte-identical single-arm sweep.
    p = load_connscale_profile_text(_OK)
    assert p.claim_modes == ("per_lane",)


def test_claim_modes_ab_axis_parses_and_dedups() -> None:
    p = load_connscale_profile_text("""
[connscale]
name = "ab"
counts = [10]
aggregate_rate = 5.0
claim_modes = ["per_lane", "pooled", "per_lane"]
""")
    # De-duplicated, first-seen order preserved.
    assert p.claim_modes == ("per_lane", "pooled")


def test_pooled_ab_builtin_resolves() -> None:
    p = get_connscale_profile("pooled_ab")
    assert p.claim_modes == ("per_lane", "pooled")
    assert p.sweep_mode == "fixed_aggregate"
    assert "pooled_ab" in list_connscale_profiles()


def test_file_loader_tolerates_utf8_bom(tmp_path: Path) -> None:
    # PowerShell `Set-Content -Encoding utf8` writes a UTF-8 BOM that bare tomllib rejects with an
    # opaque "Invalid statement (line 1, col 1)". The loader must strip it and parse cleanly.
    p = tmp_path / "bommed.toml"
    p.write_bytes(b"\xef\xbb\xbf" + _OK.encode("utf-8"))
    prof = load_connscale_profile(p)
    assert prof.name == "t"
    assert prof.counts == (50, 100)


def test_file_loader_still_rejects_non_utf8(tmp_path: Path) -> None:
    # utf-8-sig decode still enforces UTF-8: an invalid byte is a loud profile error, not a crash.
    p = tmp_path / "bad-bytes.toml"
    p.write_bytes(b"[connscale]\nname='x'\ncounts=[10]\naggregate_rate=1.0\n\xff\xfe")
    with pytest.raises(ConnScaleProfileError) as exc:
        load_connscale_profile(p)
    assert "UTF-8" in str(exc.value)


def test_text_loader_tolerates_leading_bom() -> None:
    prof = load_connscale_profile_text("\ufeff" + _OK)
    assert prof.name == "t"


@pytest.mark.parametrize(
    "body, needle",
    [
        # not a list
        ("[connscale]\nname='x'\ncounts=[10]\nclaim_modes='pooled'\n", "claim_modes"),
        # empty list
        ("[connscale]\nname='x'\ncounts=[10]\nclaim_modes=[]\n", "claim_modes"),
        # unknown mode
        ("[connscale]\nname='x'\ncounts=[10]\nclaim_modes=['turbo']\n", "turbo"),
        # non-string entry
        ("[connscale]\nname='x'\ncounts=[10]\nclaim_modes=[1]\n", "string"),
    ],
)
def test_claim_modes_fail_loud(body: str, needle: str) -> None:
    with pytest.raises(ConnScaleProfileError) as exc:
        load_connscale_profile_text(body)
    assert needle in str(exc.value)


# --------------------------------------------------------------------------- #
# trials — bank >= N trials/arm per invocation (ADR 0071 B5 PR5)
# --------------------------------------------------------------------------- #


def test_trials_defaults_to_one() -> None:
    # Absent trials ⇒ 1 (the pre-PR5 single-trial-per-cell sweep, byte-identical for every profile).
    p = load_connscale_profile_text(_OK)
    assert p.trials == 1


def test_trials_explicit_parses() -> None:
    p = load_connscale_profile_text("""
[connscale]
name = "t3"
counts = [256]
aggregate_rate = 400.0
trials = 3
""")
    assert p.trials == 3


@pytest.mark.parametrize(
    "value",
    [
        "0",
        "-1",
        "1.5",
        "'3'",
        "true",
    ],  # < 1 or not an int — all must fail loud, not silently coerce
)
def test_trials_fail_loud(value: str) -> None:
    body = f"[connscale]\nname='x'\ncounts=[10]\naggregate_rate=1.0\ntrials={value}\n"
    with pytest.raises(ConnScaleProfileError) as exc:
        load_connscale_profile_text(body)
    assert "trials" in str(exc.value)
