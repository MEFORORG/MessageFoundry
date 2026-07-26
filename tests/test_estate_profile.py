# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Estate profile parsing (#216) — fail-loud on a bad profile, correct event-rate identity."""

from __future__ import annotations

from pathlib import Path

import pytest

from harness.load.estate.profile import (
    EstateProfileError,
    get_estate_profile,
    list_estate_profiles,
    load_estate_profile,
    load_estate_profile_text,
)

_OK = """
[estate]
name = "t"
count = 100
simple_fraction = 0.72
hub_fanout = 3
per_conn_event_rate = 0.347
hold_seconds = 3.0
store_backend = "sqlite"
"""


def test_parses_a_valid_profile() -> None:
    p = load_estate_profile_text(_OK)
    assert p.name == "t"
    assert p.count == 100
    assert p.simple_fraction == 0.72
    assert p.hub_fanout == 3
    assert p.store_backend is None  # sqlite normalizes to None (the default branch)


def test_defaults_when_omitted() -> None:
    p = load_estate_profile_text("[estate]\nname='d'\n")
    assert p.count == 1500
    assert p.simple_fraction == 0.72
    assert p.hub_fanout == 3
    assert p.per_conn_event_rate == 0.347


def test_total_event_rate_identity() -> None:
    # The demo target IS per_conn_event_rate × count — the number the aggregate must converge on.
    p = load_estate_profile_text(_OK)
    assert p.total_event_rate == pytest.approx(0.347 * 100)
    # 1,500 conns at 0.347 ev/s/conn → the 45M/day target of ~520.5 ev/s.
    demo = load_estate_profile_text("[estate]\nname='x'\ncount=1500\nper_conn_event_rate=0.347\n")
    assert demo.total_event_rate == pytest.approx(520.5)


def test_topology_split_by_count() -> None:
    p = load_estate_profile_text("[estate]\nname='x'\ncount=1500\nsimple_fraction=0.72\n")
    assert p.simple_count() == 1080
    assert p.hub_count() == 420


def test_stated_total_event_rate_must_be_consistent() -> None:
    # An author who states BOTH must keep them consistent (520.5 == 0.347 × 1500).
    ok = load_estate_profile_text(
        "[estate]\nname='x'\ncount=1500\nper_conn_event_rate=0.347\ntotal_event_rate=520.5\n"
    )
    assert ok.total_event_rate == pytest.approx(520.5)
    # A contradictory pair is rejected (600 != 0.347 × 1500).
    with pytest.raises(EstateProfileError) as exc:
        load_estate_profile_text(
            "[estate]\nname='x'\ncount=1500\nper_conn_event_rate=0.347\ntotal_event_rate=600.0\n"
        )
    assert "inconsistent" in str(exc.value)


@pytest.mark.parametrize(
    "body, needle",
    [
        ("[estate]\nname='x'\ntransform='loud'\n", "transform"),
        ("[estate]\nname='x'\nstore_backend='oracle'\n", "store_backend"),
        ("[estate]\nname='x'\nbogus=1\n", "unknown key"),
        ("[load]\nname='x'\n", "unknown top-level key"),
        ("estate = 5\n", "missing [estate]"),
        ("[estate]\n", "name"),  # missing required name
        ("[estate]\nname='x'\nsimple_fraction=1.5\n", "simple_fraction"),
        ("[estate]\nname='x'\nsimple_fraction=-0.1\n", "simple_fraction"),
        ("[estate]\nname='x'\nhub_fanout=0\n", "hub_fanout"),
        ("[estate]\nname='x'\nper_conn_event_rate=0.0\n", "positive"),
        # base_port + count past the port space.
        ("[estate]\nname='x'\ncount=100\nbase_port=65500\n", "past port 65535"),
        # wrong types.
        ("[estate]\nname='x'\ncount='many'\n", "count"),
        ("[estate]\nname='x'\nsimple_fraction='high'\n", "simple_fraction"),
    ],
)
def test_fails_loud(body: str, needle: str) -> None:
    with pytest.raises(EstateProfileError) as exc:
        load_estate_profile_text(body)
    assert needle in str(exc.value)


def test_builtin_profiles_resolve() -> None:
    names = list_estate_profiles()
    assert "estate-demo" in names and "estate-smoke" in names
    # Both built-ins parse cleanly (no "(invalid profile)").
    assert all(desc != "(invalid profile)" for desc in names.values())
    demo = get_estate_profile("estate-demo")
    assert demo.count == 1500
    assert demo.total_event_rate == pytest.approx(520.5)
    smoke = get_estate_profile("estate-smoke")
    assert smoke.count == 50
    assert smoke.store_backend is None  # the CI smoke runs on SQLite


def test_unknown_profile_name_lists_builtins() -> None:
    with pytest.raises(EstateProfileError) as exc:
        get_estate_profile("does-not-exist")
    assert "estate" in str(exc.value)


def test_file_loader_tolerates_utf8_bom(tmp_path: Path) -> None:
    # PowerShell `Set-Content -Encoding utf8` writes a UTF-8 BOM that bare tomllib rejects.
    p = tmp_path / "bommed.toml"
    p.write_bytes(b"\xef\xbb\xbf" + _OK.encode("utf-8"))
    prof = load_estate_profile(p)
    assert prof.name == "t"
    assert prof.count == 100


def test_file_loader_still_rejects_non_utf8(tmp_path: Path) -> None:
    p = tmp_path / "bad-bytes.toml"
    p.write_bytes(b"[estate]\nname='x'\ncount=10\n\xff\xfe")
    with pytest.raises(EstateProfileError) as exc:
        load_estate_profile(p)
    assert "UTF-8" in str(exc.value)


def test_text_loader_tolerates_leading_bom() -> None:
    prof = load_estate_profile_text("﻿" + _OK)
    assert prof.name == "t"
