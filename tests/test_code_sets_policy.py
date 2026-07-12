# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Declared per-code-set unmapped-value policy + re-run-safe capture (BACKLOG #162, ADR 0033 amendment).

Covers: policy application on a miss (default/passthrough/flag/none), backward-compat (no policy ==
today's ``.get()``/``[]`` behavior), the ``<name>.policy.toml`` sidecar parse + skip + round-trip, the
model validation, and — the purity crux — that capture is deduped/idempotent under a simulated re-run
and that captured values never reach an INFO+ log.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from messagefoundry.config.code_sets import (
    CodeSet,
    CodeSetError,
    Flagged,
    UnmappedKind,
    UnmappedMiss,
    UnmappedPolicy,
    capturing,
    load_code_set,
    load_code_sets,
    load_policy,
    set_unmapped_sink,
)
from messagefoundry.config.codeset_edit import show_code_set


# --- model -------------------------------------------------------------------


def test_policy_validation_default_requires_value() -> None:
    with pytest.raises(CodeSetError, match="requires a 'default_value'"):
        UnmappedPolicy(kind=UnmappedKind.DEFAULT)
    # a non-default kind must NOT carry a default_value
    with pytest.raises(CodeSetError, match="must not carry a 'default_value'"):
        UnmappedPolicy(kind=UnmappedKind.PASSTHROUGH, default_value="x")


def test_policy_from_mapping() -> None:
    assert UnmappedPolicy.from_mapping(None) == UnmappedPolicy()
    assert UnmappedPolicy.from_mapping({}) == UnmappedPolicy()
    assert UnmappedPolicy.from_mapping({"kind": "passthrough"}).kind is UnmappedKind.PASSTHROUGH
    p = UnmappedPolicy.from_mapping({"kind": "default", "default_value": "UNKNOWN"})
    assert p.kind is UnmappedKind.DEFAULT and p.default_value == "UNKNOWN"
    with pytest.raises(CodeSetError, match="unknown kind"):
        UnmappedPolicy.from_mapping({"kind": "bogus"})
    with pytest.raises(CodeSetError, match="must be a string"):
        UnmappedPolicy.from_mapping({"kind": "default", "default_value": 5})


def test_default_policy_is_none_backward_compatible() -> None:
    cs = CodeSet("x", {"A": "Apple"})
    assert cs.policy == UnmappedPolicy()
    assert cs.policy.kind is UnmappedKind.NONE
    assert not cs.policy.declared


# --- policy application (AC-7) ------------------------------------------------


def test_translate_hit_returns_mapped_value() -> None:
    cs = CodeSet("x", {"A": "Apple"}, UnmappedPolicy(UnmappedKind.PASSTHROUGH))
    assert cs.translate("A") == "Apple"


def test_translate_default() -> None:
    cs = CodeSet("x", {"A": "Apple"}, UnmappedPolicy(UnmappedKind.DEFAULT, "UNKNOWN"))
    assert cs.translate("ZZ") == "UNKNOWN"


def test_translate_passthrough() -> None:
    cs = CodeSet("x", {"A": "Apple"}, UnmappedPolicy(UnmappedKind.PASSTHROUGH))
    assert cs.translate("ZZ") == "ZZ"


def test_translate_flag() -> None:
    cs = CodeSet("x", {"A": "Apple"}, UnmappedPolicy(UnmappedKind.FLAG))
    result = cs.translate("ZZ")
    assert isinstance(result, Flagged)
    assert result.code_set == "x" and result.key == "ZZ"
    assert str(result) == "ZZ"  # degrades gracefully


def test_translate_applies_policy() -> None:
    """AC-7 rolled up: each declared kind resolves a miss as specified."""
    assert CodeSet("x", {}, UnmappedPolicy(UnmappedKind.DEFAULT, "D")).translate("m") == "D"
    assert CodeSet("x", {}, UnmappedPolicy(UnmappedKind.PASSTHROUGH)).translate("m") == "m"
    assert isinstance(CodeSet("x", {}, UnmappedPolicy(UnmappedKind.FLAG)).translate("m"), Flagged)


# --- backward compatibility (AC-8) -------------------------------------------


def test_backward_compatible_no_policy() -> None:
    cs = CodeSet("x", {"A": "Apple"})
    # the mapping accessors are unchanged
    assert cs.get("ZZ") is None
    assert cs.get("ZZ", "d") == "d"
    with pytest.raises(KeyError):
        _ = cs["ZZ"]
    # translate() on a no-policy set fails loud, pointing to declare a policy
    with pytest.raises(CodeSetError, match="no unmapped_policy is declared"):
        cs.translate("ZZ")


# --- sidecar loading / round-trip --------------------------------------------


def _write_set(dir_: Path, name: str, policy_toml: str | None = None) -> Path:
    (dir_ / f"{name}.csv").write_text("code,value\nA,Apple\n", encoding="utf-8")
    if policy_toml is not None:
        (dir_ / f"{name}.policy.toml").write_text(policy_toml, encoding="utf-8")
    return dir_ / f"{name}.csv"


def test_sidecar_policy_attaches_to_code_set(tmp_path: Path) -> None:
    p = _write_set(tmp_path, "diet", 'kind = "default"\ndefault_value = "UNKNOWN"\n')
    cs = load_code_set(p)
    assert cs.policy.kind is UnmappedKind.DEFAULT
    assert cs.policy.default_value == "UNKNOWN"
    assert cs.translate("ZZ") == "UNKNOWN"


def test_absent_sidecar_is_none_policy(tmp_path: Path) -> None:
    p = _write_set(tmp_path, "diet")
    assert load_code_set(p).policy == UnmappedPolicy()
    assert load_policy(p) == UnmappedPolicy()


def test_invalid_sidecar_fails_loud(tmp_path: Path) -> None:
    p = _write_set(tmp_path, "diet", 'kind = "default"\n')  # missing default_value
    with pytest.raises(CodeSetError, match="policy sidecar 'diet.policy.toml'"):
        load_code_set(p)


def test_load_code_sets_skips_sidecar(tmp_path: Path) -> None:
    """A ``<name>.policy.toml`` sidecar is metadata, never a code set of its own."""
    _write_set(tmp_path, "diet", 'kind = "passthrough"\n')
    registry = load_code_sets(tmp_path)
    assert set(registry) == {"diet"}  # NOT {"diet", "diet.policy"}
    assert registry["diet"].policy.kind is UnmappedKind.PASSTHROUGH


def test_standalone_policy_named_set_still_loads(tmp_path: Path) -> None:
    """Backward-compat: a legacy ``<x>.policy.toml`` with NO companion code set is a code set named
    ``x.policy`` (not a sidecar) and must still load — never silently dropped."""
    (tmp_path / "region.policy.toml").write_text('A = "Apple"\n', encoding="utf-8")
    registry = load_code_sets(tmp_path)
    assert set(registry) == {"region.policy"}
    assert registry["region.policy"]["A"] == "Apple"


def test_true_sidecar_beside_companion_is_skipped(tmp_path: Path) -> None:
    """A ``<name>.policy.toml`` WITH a companion ``<name>.csv`` is a real sidecar — skipped as a code
    set, and its policy attaches to the companion."""
    _write_set(tmp_path, "region", 'kind = "passthrough"\n')  # region.csv + region.policy.toml
    registry = load_code_sets(tmp_path)
    assert set(registry) == {"region"}  # the sidecar is NOT a code set of its own
    assert registry["region"].policy.kind is UnmappedKind.PASSTHROUGH


def test_show_code_set_surfaces_policy_round_trip(tmp_path: Path) -> None:
    """The editor grid DETAIL carries the policy so the grid can SHOW it (model/parse round-trip)."""
    codesets = tmp_path / "codesets"
    codesets.mkdir()
    _write_set(codesets, "diet", 'kind = "default"\ndefault_value = "UNKNOWN"\n')
    detail = show_code_set(tmp_path, "diet")  # config_dir; the writer anchors codesets/ under it
    assert detail["policy"] == {"kind": "default", "default_value": "UNKNOWN"}


# --- re-run-safe capture (AC-9) ----------------------------------------------


def test_capture_dedups_within_a_run() -> None:
    cs = CodeSet("diet", {}, UnmappedPolicy(UnmappedKind.PASSTHROUGH))
    with capturing() as buf:
        cs.translate("ZZ")
        cs.translate("ZZ")  # same miss again — deduped
        cs.translate("YY")
    assert buf.misses() == [UnmappedMiss("diet", "ZZ"), UnmappedMiss("diet", "YY")]
    assert buf.counts() == {"diet": 2}


def test_capture_idempotent_under_rerun() -> None:
    """Purity crux: a crash-re-run re-derives the identical buffer; a (message_id,…)-keyed sink upserts
    the same rows — a no-op. Simulate two runs of the same message into a keyed store."""
    cs = CodeSet("diet", {}, UnmappedPolicy(UnmappedKind.PASSTHROUGH))
    store: dict[tuple[str | None, str, str], UnmappedMiss] = {}

    def keyed_sink(misses: list[UnmappedMiss], message_id: str | None) -> None:
        for m in misses:
            store[(message_id, m.code_set, m.key)] = m  # upsert — idempotent by construction

    set_unmapped_sink(keyed_sink)
    try:
        for _run in range(2):  # original run + crash-re-run of the SAME message
            with capturing(message_id="msg-1"):
                cs.translate("ZZ")
                cs.translate("ZZ")
    finally:
        set_unmapped_sink(None)

    # Two runs, one distinct miss → exactly one persisted row (no duplication / divergence).
    assert list(store) == [("msg-1", "diet", "ZZ")]


def test_translate_is_pure_without_a_capture_scope() -> None:
    """With no active capture scope, translate() records nothing and is strictly pure."""
    cs = CodeSet("diet", {}, UnmappedPolicy(UnmappedKind.PASSTHROUGH))
    calls: list[object] = []
    set_unmapped_sink(lambda misses, mid: calls.append((misses, mid)))
    try:
        assert cs.translate("ZZ") == "ZZ"  # returns, but no scope ⇒ no sink call
    finally:
        set_unmapped_sink(None)
    assert calls == []


# --- PHI: captured values never logged at INFO+ (AC-10) ----------------------


def test_captured_values_not_logged_at_info(caplog: pytest.LogCaptureFixture) -> None:
    cs = CodeSet("diet", {}, UnmappedPolicy(UnmappedKind.PASSTHROUGH))
    with caplog.at_level(logging.INFO, logger="messagefoundry.config.code_sets"):
        with capturing(message_id="msg-1"):
            cs.translate("SECRET-MRN-123")
    # the PHI-derived key must not appear in any INFO+ record
    for rec in caplog.records:
        assert rec.levelno < logging.WARNING or "SECRET-MRN-123" not in rec.getMessage()
    assert "SECRET-MRN-123" not in caplog.text


def test_capture_counts_at_debug_carry_no_values(caplog: pytest.LogCaptureFixture) -> None:
    cs = CodeSet("diet", {}, UnmappedPolicy(UnmappedKind.PASSTHROUGH))
    with caplog.at_level(logging.DEBUG, logger="messagefoundry.config.code_sets"):
        with capturing():
            cs.translate("SECRET-MRN-123")
    # the DEBUG drain logs per-set COUNTS only — never the value
    assert "SECRET-MRN-123" not in caplog.text
    assert any("unmapped code-set inputs" in r.getMessage() for r in caplog.records)
