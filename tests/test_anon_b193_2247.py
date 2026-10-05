# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The anonymizer defects engine PR 1714 shipped open (vault BACKLOG #2247).

One section per defect, numbered as the row numbers them. Defect 5 is the ``second-msh`` case in
``tests/test_anon_core.py``. Synthetic text only.

Measured red, each with one fix reverted in the engine copy (the CLI for defect 3): the old no-separator rule failed
7 tests (defect 1); "live" from token_tables_live alone failed 2 (defect 2); no plain print
failed 2, one of them the real subprocess run (defect 3); no blank-line drop failed 4 and the
byte-identity test (defect 6). A test with a tee arm kept that arm green, which is the control.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from pathlib import Path
from types import ModuleType

import pytest

from messagefoundry.anon import DEFAULT_RULES, FieldRule, SurrogateKind
from messagefoundry.anon import anonymize as engine_anonymize
from messagefoundry.anon import anonymize_checked as engine_anonymize_checked
from messagefoundry.anon import leak as engine_leak
from tee.__main__ import main as tee_main
from tee.anon import anonymize as tee_anonymize
from tee.anon import anonymize_checked as tee_anonymize_checked
from tee.anon import leak as tee_leak
from tee.store import RelayStore

_SALT = "b193-salt-0123456789abcdef"
_HEADER = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1"
_PID = "PID|1||1^^^H^MR||X^Y"
_BASE = f"{_HEADER}\r{_PID}"

_SCANNER = Path(__file__).resolve().parents[1] / "scripts" / "security" / "scan_forbidden.py"
_NO_SCANNER = pytest.mark.skipif(
    not _SCANNER.exists(), reason="the engine leak-check needs scripts/security/scan_forbidden.py"
)
_LEAKS = pytest.mark.parametrize("leak", (engine_leak, tee_leak), ids=("engine", "tee"))
_CHECKED = pytest.mark.parametrize(
    "checked", (engine_anonymize_checked, tee_anonymize_checked), ids=("engine", "tee")
)


# --- defect 1: a legal empty segment is not a malformed line ----------------------------------------


@_NO_SCANNER
@_CHECKED
@pytest.mark.parametrize("tail", ["PV2", "PV2\rNK1|1|Q^Z"], ids=("last-line", "mid-message"))
def test_a_bare_segment_id_is_an_empty_segment_and_is_emitted(
    checked: Callable[..., str], tail: str
) -> None:
    """A segment with no fields is legal HL7. The old rule refused any line with no field
    separator, so one bare ``PV2`` failed a whole tee dataset."""
    reports: list[object] = []
    out = checked(f"{_BASE}\r{tail}", salt=_SALT, on_report=reports.append)
    assert "PV2" in out.split("\r")
    (report,) = reports
    assert report.hits == []  # type: ignore[attr-defined]
    assert "(malformed segment)-0" not in report.unmapped_fields  # type: ignore[attr-defined]


@_NO_SCANNER
@_LEAKS
def test_a_bare_name_shaped_like_a_segment_id_is_still_a_malformed_line(leak: ModuleType) -> None:
    """The control for the test above: only a DEFINED id may stand bare. ``LEE`` and ``ZOE`` are
    three letters no rule can address, so the leak-check still reports each."""
    for line in ("LEE", "ZOE"):
        assert leak.leak_report(f"{_BASE}\r{line}", rules=DEFAULT_RULES).hits == [
            leak.MALFORMED_LINE_HIT
        ], line
    assert leak.leak_report(f"{_BASE}\rPV2", rules=DEFAULT_RULES).hits == []


# --- defect 2: "live" needs the floor check too -----------------------------------------------------


def _report(leak: ModuleType, *, live: bool, floor: str | None) -> object:
    return leak.LeakReport(
        hits=[],
        unmapped_fields=("ZPD-1",),
        structural_hits=[],
        token_tables_live=live,
        token_floor_reason=floor,
    )


@_LEAKS
@pytest.mark.parametrize(
    ("live", "floor", "expected"),
    [
        (True, None, "yes"),
        (True, "section [names] is empty", "no"),  # the case the old line called live
        (False, "no token source is configured", "no"),
    ],
    ids=("live", "floor-failed", "not-loaded"),
)
def test_the_coverage_lines_say_live_only_when_the_floor_check_passed(
    leak: ModuleType, live: bool, floor: str | None, expected: str
) -> None:
    """Tables that loaded but lost a section set ``token_floor_reason`` and leave
    ``token_tables_live`` true. Both coverage lines printed "live: yes" for that."""
    report = _report(leak, live=live, floor=floor)
    assert f"denylist tables live: {expected})" in leak.coverage_clause(report)
    tally = leak.CoverageTally()
    tally.add(report)
    assert f"denylist tables live: {expected}." in tally.summary()


@_LEAKS
def test_one_report_with_a_failed_floor_makes_the_whole_run_not_live(leak: ModuleType) -> None:
    tally = leak.CoverageTally()
    tally.add(_report(leak, live=True, floor=None))
    tally.add(_report(leak, live=True, floor="section [names] is empty"))
    tally.add(_report(leak, live=True, floor=None))
    assert "denylist tables live: no." in tally.summary()


# --- defect 3: no log level hides the coverage line -------------------------------------------------


def _seed(db: str, raw: bytes) -> None:
    async def go() -> None:
        store = await RelayStore.open(db)
        try:
            await store.record_capture(direction="corepoint_copy", control_id="C1", raw=raw)
        finally:
            await store.close()

    asyncio.run(go())


def test_the_cli_prints_the_coverage_line_when_the_level_hides_info(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """In process, with the ``tee.anonymize`` logger above INFO: the line goes to stderr plain. The
    real ``--log-level WARNING`` run is the subprocess test in ``tests/test_anon_integration.py``."""
    db = str(tmp_path / "tee.db")
    _seed(db, (_BASE + "\rZPD|ZZTEST^SYNTH|19700101").encode("latin-1"))
    monkeypatch.setenv("MEFOR_ANON_SALT", _SALT)
    logger = logging.getLogger("tee.anonymize")
    monkeypatch.setattr(logger, "level", logging.WARNING)
    logger.manager._clear_cache()  # type: ignore[attr-defined]
    try:
        code = tee_main(["anonymize-captures", "--db", db, "--out", str(tmp_path / "ds.jsonl")])
    finally:
        monkeypatch.undo()
        logger.manager._clear_cache()  # type: ignore[attr-defined]
    err = capsys.readouterr().err
    assert code == 0
    assert err.count("coverage: 1 message(s) reached the leak-check") == 1
    assert "ZPD-1 x1" in err and "ZZTEST" not in err and "19700101" not in err


# --- defect 4: the advice names only the causes that fired ------------------------------------------

_REPAIR = "Repair the line with a malformed segment id."
_EXTEND = "Extend the rule map so the field that carries it is scrubbed."
_KEEP = "Add a rule for each field named, or a keep for one you reviewed."
_LOAD = "Load the denylist token source."


@_NO_SCANNER
@_CHECKED
def test_a_phi_shape_refusal_does_not_suggest_repairing_a_line(checked: Callable[..., str]) -> None:
    with pytest.raises(Exception, match="SSN-shaped value in ZPD-1") as exc:
        checked(f"{_BASE}\rZPD|123-45-6789", salt=_SALT)
    text = str(exc.value)
    assert type(exc.value).__name__ == "LeakError"
    assert _EXTEND in text
    assert "malformed" not in text and _KEEP not in text and _LOAD not in text


@_NO_SCANNER
@_CHECKED
def test_a_coverage_refusal_suggests_a_rule_or_a_keep_and_nothing_else(
    checked: Callable[..., str],
) -> None:
    with pytest.raises(Exception, match="no rule and no keep: ZPD-1") as exc:
        checked(f"{_BASE}\rZPD|free", salt=_SALT, require_full_coverage=True)
    text = str(exc.value)
    assert _KEEP in text
    assert "malformed" not in text and _EXTEND not in text and _LOAD not in text


@_LEAKS
def test_the_advice_is_one_sentence_per_kind_of_cause(leak: ModuleType) -> None:
    """Every combination, on a built report, so a cause that cannot be forced end to end (a token
    needs a token source; a malformed line is refused before the leak-check) is still pinned."""

    def advice(hits: list[str], structural: list[str], **flags: bool) -> str:
        report = leak.LeakReport(
            hits=hits,
            unmapped_fields=(),
            structural_hits=structural,
            token_tables_live=True,
            token_floor_reason=None,
        )
        return str(leak.refusal_advice(report, **flags))

    shape = "unmapped SSN-shaped value in ZPD-1"
    assert advice(["partner/site token"], []) == _EXTEND  # a token alone: the row's own example
    assert advice([shape], [shape]) == _EXTEND
    assert advice([leak.MALFORMED_LINE_HIT], [leak.MALFORMED_LINE_HIT]) == _REPAIR
    assert advice([], [], coverage_refused=True) == _KEEP
    assert advice([], [], denylist_refused=True) == _LOAD
    assert advice(
        ["routable IP address", shape, leak.MALFORMED_LINE_HIT],
        [shape, leak.MALFORMED_LINE_HIT],
        coverage_refused=True,
        denylist_refused=True,
    ) == " ".join((_EXTEND, _KEEP, _REPAIR, _LOAD))


# --- defect 6: a whitespace-only line, and whitespace at the message end ----------------------------

_BLANKS = pytest.mark.parametrize(
    "raw",
    [
        _BASE + "\r  ",  # a trailing whitespace-only line: the tee kept it, the engine dropped it
        _BASE + "\r\t",
        "  \r" + _BASE,  # a leading one
        _BASE + "\r  \rNK1|1|Q^Z",  # one in the middle
        _BASE + "\r\x1a",  # a trailing SUB
        _BASE + "\r\x00\x00",  # NUL padding
        _BASE + "\rNK1|1|Q^Z  ",  # whitespace after the last field of the last line
    ],
    ids=("trailing", "trailing-tab", "leading", "middle", "sub", "nul", "last-field"),
)


@_BLANKS
def test_engine_and_tee_agree_on_blank_lines_and_trailing_whitespace(raw: str) -> None:
    """Reproduced, then fixed. The engine's parser trims the message and the tee's splitter does
    not, so a trailing ``"  "`` line survived on the tee only, and trailing spaces in the last
    field gave the two a different surrogate. Both now see the same normalized text."""
    engine = engine_anonymize(raw, salt=_SALT)
    tee = tee_anonymize(raw, salt=_SALT)
    assert engine == tee
    assert all(line.strip() for line in engine.split("\r"))  # no blank line is emitted
    assert engine == engine.rstrip()


def test_a_blank_line_is_dropped_and_the_lines_around_it_are_kept() -> None:
    """The control: dropping a blank line must not take a real one with it."""
    out = engine_anonymize(_BASE + "\r  \rNK1|1|Q^Z\r\x1a", salt=_SALT)
    assert [line.split("|")[0] for line in out.split("\r")] == ["MSH", "PID", "NK1"]


def test_a_keep_rule_does_not_change_what_a_blank_line_is() -> None:
    rules = (*DEFAULT_RULES, FieldRule("ZPD-1", SurrogateKind.KEEP))
    raw = _BASE + "\rZPD|free\r  "
    assert engine_anonymize(raw, salt=_SALT, rules=rules).endswith("\rZPD|free")
