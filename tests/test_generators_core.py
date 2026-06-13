"""The shared generator registry/core (``messagefoundry/generators/_core.py``)."""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.parsing import Peek
from messagefoundry.generators import _core, adt  # importing adt registers the ADT spec


def test_adt_is_registered() -> None:
    assert "ADT" in _core.message_codes()
    assert _core.triggers_for("ADT") == adt.ALL_TRIGGERS
    assert _core.structure_for("ADT", "A04") == "ADT_A01"


def test_core_generate_and_gate_roundtrip() -> None:
    msg = _core.generate_message("ADT", "A01", 1)
    peek = Peek.parse(msg)
    assert peek.message_code == "ADT"
    assert peek.trigger_event == "A01"
    assert peek.message_structure == "ADT_A01"
    ok, errors = _core.gate("ADT", msg, "ADT_A01")
    assert ok, errors


def test_adt_backcompat_matches_core() -> None:
    # The ADT-flavoured wrappers must delegate to the registry verbatim.
    assert adt.generate_message("A01", 1) == _core.generate_message("ADT", "A01", 1)


# --- GEN-1: destructive-write safety -----------------------------------------


def test_write_corpus_rejects_out_outside_corpus_root(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="outside"):
        _core.write_corpus(
            "ADT",
            triggers=["A01"],
            count=1,
            out=tmp_path / "elsewhere",
            corpus_root=tmp_path / "root",
        )


def test_write_corpus_only_clears_its_own_generated_files(tmp_path: Path) -> None:
    trigger_dir = tmp_path / "A01"
    trigger_dir.mkdir(parents=True)
    keep = trigger_dir / "hand-authored.hl7"  # not an NNNN.hl7 — must survive the cleanup
    keep.write_text("MSH|^~\\&|keep\r", encoding="utf-8")
    _core.write_corpus("ADT", triggers=["A01"], count=1, out=tmp_path)
    assert keep.exists()  # scoped delete left the user's file alone (GEN-1)
    assert (trigger_dir / "0001.hl7").exists()
