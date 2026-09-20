# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The one profile lookup the three ``harness/load`` schemas share (BACKLOG #1837).

BACKLOG #1835 moved operator-local ``[load]`` profiles out of the force-included package tree and
taught ``--load <name>`` to resolve them under ``migration-local/profiles/``. ``[connscale]`` and
``[estate]`` carried the identical lookup body and did not get the escape hatch, so a site-specific
profile for either had nowhere to live but a full path.

These tests are parameterized over all THREE schemas deliberately: the point of extracting the body
is that no schema can have the lookup and lack the hatch, and a test that covered one schema would
not report that regression.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

import pytest

from harness.load._lookup import (
    CONNSCALE_PATTERNS,
    ESTATE_PATTERNS,
    SIBLING_PATTERNS,
    local_profiles_dir,
)
from harness.load.connscale.profile import (
    ConnScaleProfileError,
    get_connscale_profile,
    list_connscale_profiles,
)
from harness.load.estate.profile import (
    EstateProfileError,
    get_estate_profile,
    list_estate_profiles,
)
from harness.load.profile import (
    PROFILES_DIR,
    LoadProfileError,
    get_profile,
    list_profiles,
    load_profile,
)

_LOAD_BODY = """
[load]
name = "{name}"
description = "site profile"
[[load.target]]
name = "hub"
[load.mix]
ADT = 1.0
[[load.phase]]
name = "hold"
kind = "sustained"
loop = "open"
rate_start = 1.0
duration_s = 1.0
"""

_CONNSCALE_BODY = """
[connscale]
name = "{name}"
description = "site profile"
counts = [50]
aggregate_rate = 35.0
per_conn_rate = 0.35
hold_seconds = 3.0
store_backend = "sqlite"
"""

_ESTATE_BODY = """
[estate]
name = "{name}"
description = "site profile"
count = 100
simple_fraction = 0.72
hub_fanout = 3
per_conn_event_rate = 0.347
hold_seconds = 3.0
store_backend = "sqlite"
"""


@dataclass(frozen=True)
class Schema:
    """One schema's entry points, plus a local filename its own listing glob will claim."""

    id: str
    body: str
    get: Callable[[str], Any]
    listing: Callable[[], dict[str, str]]
    error: type[Exception]
    local_stem: str  # a site-specific name, matching this schema's glob
    shadowed_builtin: str  # a shipped profile name this schema owns


_SCHEMAS = (
    Schema(
        id="load",
        body=_LOAD_BODY,
        get=get_profile,
        listing=list_profiles,
        error=LoadProfileError,
        local_stem="hospital-baseline",
        shadowed_builtin="smoke",
    ),
    Schema(
        id="connscale",
        body=_CONNSCALE_BODY,
        get=get_connscale_profile,
        listing=list_connscale_profiles,
        error=ConnScaleProfileError,
        local_stem="connscale-hospital",
        shadowed_builtin="connscale-smoke",
    ),
    Schema(
        id="estate",
        body=_ESTATE_BODY,
        get=get_estate_profile,
        listing=list_estate_profiles,
        error=EstateProfileError,
        local_stem="estate-hospital",
        shadowed_builtin="estate-smoke",
    ),
)

_IDS = [s.id for s in _SCHEMAS]


def _write_local(root: Path, schema: Schema, stem: str, name: str | None = None) -> Path:
    local = root / "migration-local" / "profiles"
    local.mkdir(parents=True, exist_ok=True)
    path = local / f"{stem}.toml"
    path.write_text(schema.body.format(name=name or stem), encoding="utf-8")
    return path


# --- the escape hatch, on every schema -----------------------------------------------------------


@pytest.mark.parametrize("schema", _SCHEMAS, ids=_IDS)
def test_an_operator_local_profile_resolves_by_bare_name(
    schema: Schema, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_local(tmp_path, schema, schema.local_stem)
    monkeypatch.chdir(tmp_path)
    assert schema.get(schema.local_stem).name == schema.local_stem


@pytest.mark.parametrize("schema", _SCHEMAS, ids=_IDS)
def test_an_operator_local_profile_is_listed_and_labelled(
    schema: Schema, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_local(tmp_path, schema, schema.local_stem)
    monkeypatch.chdir(tmp_path)
    listed = schema.listing()
    # Both sets, and the local one says which it is: a profile sized for one site is not a built-in.
    assert schema.shadowed_builtin in listed
    assert "(operator-local)" in listed[schema.local_stem]
    assert "(operator-local)" not in listed[schema.shadowed_builtin]


@pytest.mark.parametrize("schema", _SCHEMAS, ids=_IDS)
def test_a_local_profile_shadowing_a_builtin_raises_rather_than_picking_one(
    schema: Schema, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Either precedence is a silent wrong answer half the time: built-in-wins ignores the file the
    # operator just wrote, local-wins reshapes a named CI run for anyone in the wrong directory.
    _write_local(tmp_path, schema, schema.shadowed_builtin)
    monkeypatch.chdir(tmp_path)
    with pytest.raises(schema.error, match="ambiguous"):
        schema.get(schema.shadowed_builtin)


@pytest.mark.parametrize("schema", _SCHEMAS, ids=_IDS)
def test_no_local_directory_changes_nothing(
    schema: Schema, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The ordinary case, and the control for the three above: without migration-local/profiles/ the
    # built-ins still resolve, so a pass there is not the lookup silently failing open.
    monkeypatch.chdir(tmp_path)
    assert not (tmp_path / "migration-local").exists()
    assert schema.get(schema.shadowed_builtin).name == schema.shadowed_builtin
    assert "(operator-local)" not in schema.listing()[schema.shadowed_builtin]


@pytest.mark.parametrize("schema", _SCHEMAS, ids=_IDS)
def test_unknown_name_names_the_schema_that_refused(
    schema: Schema, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Three entry points sit behind three CLI flags, so a bare "unknown profile" would not say which
    # one refused. The listing is "known profiles", not "built-ins", because since #1835 it also
    # carries the operator's own.
    monkeypatch.chdir(tmp_path)
    with pytest.raises(schema.error) as exc:
        schema.get("does-not-exist")
    message = str(exc.value)
    assert "does-not-exist" in message
    assert "known profiles:" in message
    if schema.id != "load":
        assert f"unknown {schema.id} profile" in message


def test_local_profiles_dir_follows_the_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A module constant would freeze whichever directory was current at import time, and an installed
    # harness is run from the operator's directory, not from a checkout.
    monkeypatch.chdir(tmp_path)
    assert local_profiles_dir() == tmp_path / "migration-local" / "profiles"


# --- what the shared naming convention costs, stated as a test rather than left to chance ---------


@pytest.mark.parametrize(
    "schema", [s for s in _SCHEMAS if s.id != "load"], ids=["connscale", "estate"]
)
def test_a_local_name_outside_the_schema_glob_resolves_but_does_not_list(
    schema: Schema, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # One directory holds three schemas, in the wheel and in migration-local/ alike, so the FILENAME
    # is what tells a listing which files are its own. A local profile named outside its schema's
    # glob still RESOLVES (resolution matches the exact filename, not the glob) but is not listed by
    # that schema. It is not lost: it falls to the [load] listing, which owns whatever the siblings
    # do not claim, and shows there as an invalid [load] profile rather than vanishing from all three.
    _write_local(tmp_path, schema, "acme-site")
    monkeypatch.chdir(tmp_path)
    assert schema.get("acme-site").name == "acme-site"
    assert "acme-site" not in schema.listing()
    assert list_profiles()["acme-site"] == "(invalid profile) (operator-local)"


# --- the sibling-schema exclusion, which had drifted ----------------------------------------------


def test_the_load_listing_excludes_every_sibling_schema_file() -> None:
    # list_profiles() used to skip connscale* alone while the sibling schemas globbed five prefixes,
    # so estate-demo, estate-smoke, pooled_ab, fuse_ab and batch_ab sat on the --list-profiles menu
    # as phantom "(invalid profile)" entries (BACKLOG #1837).
    siblings = {
        path.stem
        for path in PROFILES_DIR.glob("*.toml")
        if any(fnmatch(path.name, pattern) for pattern in SIBLING_PATTERNS)
    }
    # Positive control: an exclusion test over an empty sibling set would pass while excluding
    # nothing, which is the shape of the bug it is guarding.
    assert len(siblings) >= 5, siblings
    listed = list_profiles()
    assert not (siblings & set(listed)), siblings & set(listed)
    assert not [name for name, desc in listed.items() if desc.startswith("(invalid profile)")]


def test_the_three_listings_partition_the_shipped_directory() -> None:
    # Disjoint AND exhaustive: every shipped .toml is claimed by exactly one listing, so no file is
    # double-counted and none silently falls out of all three. Counted rather than name-matched,
    # because a profile's `name` need not equal its filename stem.
    shipped = sorted(PROFILES_DIR.glob("*.toml"))
    assert len(shipped) >= 15, "expected the shipped profile set; did the directory move?"
    claimed = {"connscale": 0, "estate": 0, "load": 0}
    for path in shipped:
        connscale = any(fnmatch(path.name, pattern) for pattern in CONNSCALE_PATTERNS)
        estate = any(fnmatch(path.name, pattern) for pattern in ESTATE_PATTERNS)
        assert not (connscale and estate), path.name
        claimed["connscale" if connscale else "estate" if estate else "load"] += 1
    assert all(count > 0 for count in claimed.values()), claimed
    assert sum(claimed.values()) == len(shipped)
    assert len(list_connscale_profiles()) == claimed["connscale"]
    assert len(list_estate_profiles()) == claimed["estate"]
    assert len(list_profiles()) == claimed["load"]


# --- the BOM divergence, unified onto the tolerant read -------------------------------------------


def test_the_load_file_loader_tolerates_a_utf8_bom(tmp_path: Path) -> None:
    # PowerShell `Set-Content -Encoding utf8` writes a BOM that bare tomllib rejects with an opaque
    # "Invalid statement (line 1, col 1)". [connscale] and [estate] already tolerated it; [load] did
    # not, and one shared reader cannot hold both behaviours. Tolerance wins because it only ever
    # accepts input the strict form rejected — and because a hand-authored local profile on Windows
    # is now the expected case (BACKLOG #1837).
    path = tmp_path / "bommed.toml"
    path.write_bytes(b"\xef\xbb\xbf" + _LOAD_BODY.format(name="bommed").encode("utf-8"))
    assert load_profile(path).name == "bommed"


def test_a_non_utf8_profile_still_fails_loud(tmp_path: Path) -> None:
    # The control for the test above: stripping a BOM must not have turned the read into a
    # best-effort decode that accepts anything.
    path = tmp_path / "latin1.toml"
    path.write_bytes(b'[load]\nname = "caf\xe9"\n')
    with pytest.raises(LoadProfileError, match="not valid UTF-8"):
        load_profile(path)
