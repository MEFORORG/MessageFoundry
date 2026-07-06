# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the ADT message generator (``messagefoundry/generators/adt.py``).

Messages are generated **deterministically at test time** — the corpus itself is not committed
(it's regenerable via ``python -m messagefoundry.generators.adt``). The default suite checks a fast
representative slice (one message per trigger) plus the generator's units; set
``MEFOR_FULL_CORPUS=1`` to generate and re-validate all 2,850 messages.
"""

from __future__ import annotations

import os
from datetime import datetime

import pytest

from messagefoundry.parsing import Peek
from messagefoundry.generators import _core
from messagefoundry.generators import _hl7data as d
from messagefoundry.generators import adt
from messagefoundry.generators.adt import (
    ALL_TRIGGERS,
    TRIGGER_TO_STRUCTURE,
    gate,
    generate_message,
    seg,
)

PER_TRIGGER = 50  # messages per trigger the CLI emits (and the full-corpus check regenerates)


# --- coverage ----------------------------------------------------------------


def test_generator_covers_every_trigger() -> None:
    assert len(ALL_TRIGGERS) == 57
    assert set(ALL_TRIGGERS) == set(TRIGGER_TO_STRUCTURE)


def test_generator_produces_distinct_deterministic_messages() -> None:
    batch = [generate_message("A01", i) for i in range(1, PER_TRIGGER + 1)]
    assert len(set(batch)) == PER_TRIGGER  # 50 distinct messages for one trigger
    assert batch[0] == generate_message("A01", 1)  # and reproducible


# --- structural: routing fields match the trigger ----------------------------


@pytest.mark.parametrize("trigger", ALL_TRIGGERS)
def test_routing_fields_match_trigger(trigger: str) -> None:
    peek = Peek.parse(generate_message(trigger, 1))
    assert peek.message_code == "ADT"
    assert peek.trigger_event == trigger
    assert peek.message_structure == TRIGGER_TO_STRUCTURE[trigger]
    assert peek.field("EVN-1") == trigger


# --- compliance: a representative message per trigger passes the gate ---------


@pytest.mark.parametrize("trigger", ALL_TRIGGERS)
def test_representative_message_is_conformant(trigger: str) -> None:
    ok, errors = gate(generate_message(trigger, 1), TRIGGER_TO_STRUCTURE[trigger])
    assert ok, f"{trigger}: {errors}"


# --- structure-specific shape ------------------------------------------------


@pytest.mark.parametrize("trigger", ["A17", "A24", "A37"])
def test_two_block_structures_have_two_patients(trigger: str) -> None:
    assert Peek.parse(generate_message(trigger, 1)).segments().count("PID") == 2


def test_bed_status_message_has_npu_and_no_pid() -> None:
    segments = Peek.parse(generate_message("A20", 1)).segments()
    assert "NPU" in segments
    assert "PID" not in segments


def test_merge_structures_carry_an_mrg() -> None:
    for trigger in ("A40", "A45", "A30", "A50"):
        assert "MRG" in Peek.parse(generate_message(trigger, 1)).segments(), trigger


# --- on-the-wire encoding ----------------------------------------------------


def test_generated_messages_are_cr_delimited_hl7() -> None:
    raw = generate_message("A01", 1).encode("utf-8")
    assert raw.startswith(b"MSH|^~\\&|")
    assert b"\r" in raw
    assert b"\n" not in raw  # canonical HL7 segment terminator only


# --- generator units ---------------------------------------------------------


def test_generation_is_deterministic() -> None:
    assert generate_message("A01", 1) == generate_message("A01", 1)
    assert generate_message("A01", 1) != generate_message("A01", 2)


def test_datatype_encoders() -> None:
    assert d.cx("123") == "123^^^HOSP^MR"
    assert d.cx("9", authority="LAB", id_type="AN") == "9^^^LAB^AN"
    assert d.xpn("DOE", "JANE", "Q") == "DOE^JANE^Q"
    assert d.xpn("DOE", "JANE") == "DOE^JANE"
    assert d.pl("WARD", "101", "A") == "WARD^101^A^MAIN"
    assert d.cwe("I10", "Hypertension", "ICD10") == "I10^Hypertension^ICD10"
    assert d.ts(datetime(2026, 1, 2, 3, 4, 5)) == "20260102030405"
    assert d.date8(datetime(2026, 1, 2)) == "20260102"


def test_seg_places_fields_by_index() -> None:
    assert seg("PID", {1: "1", 3: "X"}) == "PID|1||X"
    assert seg("EVN", {}) == "EVN"


def test_every_structure_value_is_a_known_hl7apy_structure() -> None:
    from hl7apy import v2_5_1

    for structure in set(TRIGGER_TO_STRUCTURE.values()):
        assert structure in v2_5_1.MESSAGES


# --- opt-in: generate + validate the entire corpus ---------------------------


@pytest.mark.skipif(
    not os.environ.get("MEFOR_FULL_CORPUS"),
    reason="set MEFOR_FULL_CORPUS=1 to generate + validate all 2,850 messages (slow)",
)
def test_full_corpus_is_conformant() -> None:
    failures: list[tuple[str, list[str]]] = []
    for trigger in ALL_TRIGGERS:
        structure = TRIGGER_TO_STRUCTURE[trigger]
        for index in range(1, PER_TRIGGER + 1):
            ok, errors = gate(generate_message(trigger, index), structure)
            if not ok:
                failures.append((f"{trigger}/{index:04d}", errors))
    assert not failures, failures[:5]


# --- CLI: a validation failure must not dump the message to stderr by default ----


def test_adt_cli_hides_offending_message_by_default(tmp_path, monkeypatch, capsys) -> None:
    # Force a gate failure so main() takes the validation-failure branch (write_corpus raises).
    monkeypatch.setattr(_core, "gate", lambda code, msg, structure: (False, ["forced failure"]))
    rc = adt.main(["--triggers", "A01", "--count", "1", "--out", str(tmp_path)])
    assert rc == 1
    err = capsys.readouterr().err
    assert "VALIDATION FAILED" in err and "forced failure" in err
    assert "MSH" not in err  # the message body is withheld
    assert "--show-message" in err


def test_adt_cli_shows_offending_message_when_opted_in(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.setattr(_core, "gate", lambda code, msg, structure: (False, ["forced failure"]))
    rc = adt.main(["--triggers", "A01", "--count", "1", "--out", str(tmp_path), "--show-message"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "--- offending message ---" in err and "MSH" in err


def test_adt_cli_cleanup_is_scoped_to_generated_files(tmp_path, capsys) -> None:
    # A user's own *.hl7 in the trigger dir must survive a regen — only NNNN.hl7 is cleared (low-19).
    trigger_dir = tmp_path / "A01"
    trigger_dir.mkdir(parents=True)
    keep = trigger_dir / "my-fixture.hl7"
    keep.write_text("MSH|^~\\&|keep\r", encoding="utf-8")
    rc = adt.main(["--triggers", "A01", "--count", "1", "--out", str(tmp_path)])
    assert rc == 0
    assert keep.exists() and keep.read_text(encoding="utf-8").startswith("MSH|^~\\&|keep")
    assert (trigger_dir / "0001.hl7").exists()
