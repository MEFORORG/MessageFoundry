# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The load system-under-test graph (``harness/config/load``) + the "don't bake Corepoint in" guard.

Loads the graph and dry-runs generated traffic, asserting the fan-out factor and transform cost are
env-tunable and that the control id (MSH-10) survives every transform — the correlation sink matches
on it. The denylist guard asserts the shipped load graph + profiles carry none of a set of real
estate tokens, so synthetic-only stays enforced, not just intended.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from harness.load.profile import PROFILES_DIR, LoadProfileError, load_profile
from messagefoundry.config.wiring import load_config
from messagefoundry.generators import _core, all_types  # noqa: F401  (registers message types)
from messagefoundry.parsing import Peek, normalize
from messagefoundry.pipeline.dryrun import dry_run

_CONFIG = "harness/config/load"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    # Pin defaults so a developer's shell env can't perturb these assertions.
    for key in (
        "MEFOR_LOAD_FANOUT",
        "MEFOR_LOAD_RESULTS_FANOUT",
        "MEFOR_LOAD_TRANSFORM",
        "MEFOR_LOAD_TRANSFORM_MS",
        "MEFOR_LOAD_SINK_HOST",
        "MEFOR_LOAD_SINK_PORT",
        "MEFOR_LOAD_SINK_PORTS",
        "MEFOR_LOAD_SHARD_ADT",
        "MEFOR_LOAD_SHARD_RESULTS",
        "MEFOR_LOAD_SHARD_OTHER",
    ):
        monkeypatch.delenv(key, raising=False)


def _cid(raw: str) -> str:
    return Peek.parse(normalize(raw)).control_id or ""


def test_graph_loads_and_validates() -> None:
    reg = load_config(_CONFIG)
    reg.validate()
    assert set(reg.inbound) == {"IB_Load_ADT", "IB_Load_Results", "IB_Load_Other"}


def test_inbounds_carry_no_shard_by_default() -> None:
    # Unset MEFOR_LOAD_SHARD_* (the _clean_env default) = no tag = a single implicit shard =
    # byte-identical to the unsharded graph.
    reg = load_config(_CONFIG)
    assert all(reg.inbound[name].shard is None for name in reg.inbound)


def test_shard_env_tags_each_hub(monkeypatch: pytest.MonkeyPatch) -> None:
    # The box's 2-shard layout: ADT on shard "a", results+other on shard "b".
    monkeypatch.setenv("MEFOR_LOAD_SHARD_ADT", "a")
    monkeypatch.setenv("MEFOR_LOAD_SHARD_RESULTS", "b")
    monkeypatch.setenv("MEFOR_LOAD_SHARD_OTHER", "b")
    reg = load_config(_CONFIG)
    assert reg.inbound["IB_Load_ADT"].shard == "a"
    assert reg.inbound["IB_Load_Results"].shard == "b"
    assert reg.inbound["IB_Load_Other"].shard == "b"


def test_blank_shard_is_treated_as_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    # A present-but-blank knob must NOT tag (and must not trip the wiring's blank-shard guard) — it
    # collapses to None, identical to omitting it.
    monkeypatch.setenv("MEFOR_LOAD_SHARD_ADT", "   ")
    reg = load_config(_CONFIG)
    assert reg.inbound["IB_Load_ADT"].shard is None


def test_adt_fans_out_to_fanout_destinations(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEFOR_LOAD_FANOUT", "8")
    reg = load_config(_CONFIG)
    result = dry_run(reg, _core.generate_message("ADT", "A05", 1), inbound="IB_Load_ADT")
    assert len(result.deliveries) == 8
    assert sorted(d.to for d in result.deliveries) == [f"OB_Sink_ADT_{i:02d}" for i in range(8)]


def test_fanout_env_changes_destination_count(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEFOR_LOAD_FANOUT", "3")
    reg3 = load_config(_CONFIG)
    n3 = len(
        dry_run(reg3, _core.generate_message("ADT", "A05", 1), inbound="IB_Load_ADT").deliveries
    )
    monkeypatch.setenv("MEFOR_LOAD_FANOUT", "12")
    reg12 = load_config(_CONFIG)
    n12 = len(
        dry_run(reg12, _core.generate_message("ADT", "A05", 1), inbound="IB_Load_ADT").deliveries
    )
    assert (n3, n12) == (3, 12)


def test_control_id_survives_every_transform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEFOR_LOAD_TRANSFORM", "edit")
    monkeypatch.setenv("MEFOR_LOAD_FANOUT", "4")
    reg = load_config(_CONFIG)
    msg = _core.generate_message("ADT", "A01", 9)
    result = dry_run(reg, msg, inbound="IB_Load_ADT")
    assert all(_cid(d.payload) == _cid(msg) for d in result.deliveries)  # sink correlates on MSH-10


def test_cheap_transform_is_pass_through(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEFOR_LOAD_TRANSFORM", "cheap")
    monkeypatch.setenv("MEFOR_LOAD_FANOUT", "2")
    reg = load_config(_CONFIG)
    msg = normalize(_core.generate_message("ADT", "A05", 1))
    result = dry_run(reg, msg, inbound="IB_Load_ADT")
    assert all(normalize(d.payload) == msg for d in result.deliveries)  # unchanged receipt


def test_edit_transform_rewrites_fields_but_not_control_id(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEFOR_LOAD_TRANSFORM", "edit")
    monkeypatch.setenv("MEFOR_LOAD_FANOUT", "2")
    reg = load_config(_CONFIG)
    msg = _core.generate_message("ADT", "A05", 1)
    result = dry_run(reg, msg, inbound="IB_Load_ADT")
    assert all("MEFOR_LOAD" in d.payload for d in result.deliveries)  # MSH-4 rewritten
    assert all(_cid(d.payload) == _cid(msg) for d in result.deliveries)


def test_slow_transform_still_delivers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEFOR_LOAD_TRANSFORM", "slow")
    monkeypatch.setenv("MEFOR_LOAD_TRANSFORM_MS", "0")  # 0 ms spin keeps the test fast
    monkeypatch.setenv("MEFOR_LOAD_FANOUT", "2")
    reg = load_config(_CONFIG)
    result = dry_run(reg, _core.generate_message("ADT", "A05", 1), inbound="IB_Load_ADT")
    assert len(result.deliveries) == 2


def test_results_and_other_hubs_route(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEFOR_LOAD_RESULTS_FANOUT", "3")
    reg = load_config(_CONFIG)
    res = dry_run(reg, _core.generate_message("ORU", "R01", 1), inbound="IB_Load_Results")
    oth = dry_run(reg, _core.generate_message("SIU", "S12", 1), inbound="IB_Load_Other")
    assert len(res.deliveries) == 3 and all(d.to.startswith("OB_Sink_RES_") for d in res.deliveries)
    assert len(oth.deliveries) == 3 and all(d.to.startswith("OB_Sink_OTH_") for d in oth.deliveries)


def test_invalid_transform_mode_fails_loud(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEFOR_LOAD_TRANSFORM", "turbo")
    with pytest.raises(ValueError, match="MEFOR_LOAD_TRANSFORM"):
        load_config(_CONFIG)


# --- "don't bake Corepoint in" denylist guard --------------------------------


# Real estate tokens that must never appear in the shipped load graph or profiles. The site-code
# pattern catches 6-digit 54xxxx codes; the rest are partner/product/customer substrings drawn from
# the (git-ignored) real migration estate. NOTE: the generic product name "Corepoint" is deliberately
# NOT here — it's the competitor named all over the repo's own docs; the guard targets real customer/
# partner/site identifiers, not the product name.
#
# These estate tokens + the site-code pattern now live in the publish guard
# (scripts/publish/scan_forbidden.py) as the SINGLE source of truth (ADR 0030 §5), shared with the
# anonymizer's leak-check; this test imports them instead of keeping a divergent copy (the drift
# BACKLOG #36 recorded). The scanner lives under scripts/ (not an installed package), so it is loaded
# by path — mirroring tests/test_scan_forbidden.py.
def _load_scan_forbidden() -> object:
    path = Path(__file__).resolve().parents[1] / "scripts" / "publish" / "scan_forbidden.py"
    if not path.exists():
        # Private-only: scripts/publish/ is deny-listed in the OSS mirror, so the estate-token
        # assertions this module feeds don't apply there. Skip the whole module rather than error at
        # collection (the scanner is the single source of truth only where it exists).
        pytest.skip(
            "scan_forbidden.py is private-only (OSS-mirror deny-list)", allow_module_level=True
        )
    spec = importlib.util.spec_from_file_location("scan_forbidden", path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_SF = _load_scan_forbidden()
_FORBIDDEN_SUBSTRINGS = list(_SF.ESTATE_TOKENS)  # type: ignore[attr-defined]
_SITE_CODE = _SF.SITE_CODE_RE  # type: ignore[attr-defined]
_SCANNED_DIRS = ["harness/config/load", "harness/config/store_once", "harness/load/profiles"]
_SCANNED_SUFFIXES = {".py", ".toml", ".md"}


def _shipped_files() -> list[Path]:
    files: list[Path] = []
    for d in _SCANNED_DIRS:
        files.extend(p for p in Path(d).rglob("*") if p.suffix in _SCANNED_SUFFIXES)
    return files


def test_no_forbidden_tokens_in_shipped_load_artifacts() -> None:
    offenders: list[str] = []
    for path in _shipped_files():
        text = path.read_text(encoding="utf-8").lower()
        for token in _FORBIDDEN_SUBSTRINGS:
            if token in text:
                offenders.append(f"{path}: {token!r}")
        if _SITE_CODE.search(text):
            offenders.append(f"{path}: site-code pattern 54xxxx")
    assert not offenders, "real estate tokens leaked into shipped load artifacts: " + "; ".join(
        offenders
    )


def test_guard_actually_scans_files() -> None:
    # Guard against the guard silently scanning nothing (e.g. a moved directory).
    assert len(_shipped_files()) >= 5


def test_all_shipped_profiles_parse() -> None:
    # Every shipped profile must parse cleanly — guards against a typo'd/renamed key shipping a broken
    # profile (the failure mode that left matrix row H1 pointing at a nonexistent "steady" profile).
    profiles = sorted(PROFILES_DIR.glob("*.toml"))
    assert len(profiles) >= 8, "expected the shipped profile set; did the directory move?"
    for path in profiles:
        try:
            load_profile(path)
        except LoadProfileError as exc:
            pytest.fail(f"shipped profile {path.name} failed to parse: {exc}")
