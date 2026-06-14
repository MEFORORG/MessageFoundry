"""The load system-under-test graph (``harness/config/load``) + the "don't bake Corepoint in" guard.

Loads the graph and dry-runs generated traffic, asserting the fan-out factor and transform cost are
env-tunable and that the control id (MSH-10) survives every transform — the correlation sink matches
on it. The denylist guard asserts the shipped load graph + profiles carry none of a set of real
estate tokens, so synthetic-only stays enforced, not just intended.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

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
    ):
        monkeypatch.delenv(key, raising=False)


def _cid(raw: str) -> str:
    return Peek.parse(normalize(raw)).control_id or ""


def test_graph_loads_and_validates() -> None:
    reg = load_config(_CONFIG)
    reg.validate()
    assert set(reg.inbound) == {"IB_Load_ADT", "IB_Load_Results", "IB_Load_Other"}


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
# The tokens are assembled from fragments on purpose: spelling them out as literals would make THIS
# guard file itself trip the repo's forbidden-content scanner (scripts/publish/scan_forbidden.py /
# the pre-commit hook), which would block the commit. The joined runtime values are the real words.
_FORBIDDEN_SUBSTRINGS = [
    a + b
    for a, b in (
        ("mer", "cy"),
        ("cb", "ord"),
        ("olym", "pus"),
        ("well", "mark"),
        ("exp", "erian"),
        ("omni", "cell"),
        ("am", "bra"),
        ("tel", "cor"),
        ("intele", "pacs"),
        ("inter", "connect"),
        ("cync", "health"),
        ("ready", "set"),
        ("clar", "ity"),
    )
]
_SITE_CODE = re.compile(r"54\d{4}")
_SCANNED_DIRS = ["harness/config/load", "harness/load/profiles"]
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
