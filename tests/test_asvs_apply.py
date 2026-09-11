# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The ASVS scorecard WRITER (ADR 0156) — every refusal proved to fire.

This file had none. It lived at `docs/security/asvs-apply-cells.py` in the vault, outside the
`scripts/asvs/**` CI path filter, with a hardcoded absolute path and zero tests — while being the only
thing that writes the record of record. Its guards were sound and entirely unverified, which is the
combination that lets a guard rot silently.

**The tests that matter here are the ones asserting a REFUSAL, and each is mutation-proved: the guard
is removed and the test must go red.** A refusal nobody has watched fire is indistinguishable from a
refusal that cannot.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

# `scripts/asvs` has no `__init__.py`, so its modules import BY PATH -- the same line the sibling
# suites carry. Stated here rather than inside the one arm that needs `anchor_provenance`, so that
# arm does not silently depend on `apply` having been imported first for its side effect.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "asvs"))

from scripts.asvs.apply import (  # noqa: E402
    _BANNED,
    _SUBTABLES,
    _control_keys,
    _introduced_banned,
    main,
    render,
)

#: A two-cell record. `5.4.3` is owner-CLOSED, mirroring the real one, because the closed-cell guards
#: are the ones with the worst failure mode: an un-closing is invisible to every downstream check.
FIXTURE = """[scorecard]
asvs_version = "5.0.0"

[[cell]]
id = "1.1.1"
level = 1
verdict = "partial"
residual = "a control exists but ships off"
last_verified = "2026-08-09"
verified_at = "1111111111111111111111111111111111111111"
reviewed_by = "fixture"
  [[cell.evidence]]
  path = "messagefoundry/m.py"
  line = 10
  expect = "tls_cert_file"
  [[cell.evidence]]
  path = "messagefoundry/m.py"
  line = 20
  expect = "verify_mode"
[[cell]]
id = "5.4.3"
level = 2
verdict = "na"
residual = "enterprise-provided control, outside the declared scope"
last_verified = "2026-08-02"
verified_at = "2222222222222222222222222222222222222222"
reviewed_by = "owner"
decision_closed = true
decision_closed_by = "owner"
  [[cell.evidence]]
  path = "messagefoundry/m.py"
  line = 30
  expect = "_no_scan"
"""


def _record(tmp_path: Path) -> Path:
    p = tmp_path / "asvs-scorecard.toml"
    p.write_text(FIXTURE, encoding="utf-8")
    return p


def _payload(tmp_path: Path, cells: list[dict]) -> Path:
    p = tmp_path / "payload.json"
    p.write_text(json.dumps(cells), encoding="utf-8")
    return p


def _cell_111(**over: object) -> dict:
    base: dict = {
        "id": "1.1.1",
        "level": 1,
        "verdict": "partial",
        "residual": "a control exists but ships off",
        "last_verified": "2026-08-09",
        "verified_at": "3333333333333333333333333333333333333333",
        "reviewed_by": "test",
        "evidence": [
            {"path": "messagefoundry/m.py", "line": 11, "expect": "tls_cert_file"},
            {"path": "messagefoundry/m.py", "line": 21, "expect": "verify_mode"},
        ],
    }
    base.update(over)
    return base


# --- the happy path, so the refusals below are not passing vacuously ------------------------------


def test_a_dry_run_does_not_touch_the_file(tmp_path: Path) -> None:
    """DEFAULT IS DRY. The writer that rewrites the security record must not do so by accident."""
    rec = _record(tmp_path)
    before = rec.read_bytes()
    rc = main([str(_payload(tmp_path, [_cell_111()])), "--scorecard", str(rec)])
    assert rc == 0
    assert rec.read_bytes() == before


def test_apply_rewrites_only_the_named_cell(tmp_path: Path) -> None:
    rec = _record(tmp_path)
    rc = main(
        [
            str(_payload(tmp_path, [_cell_111(residual="rewritten")])),
            "--scorecard",
            str(rec),
            "--apply",
        ]
    )
    assert rc == 0
    got = {c["id"]: c for c in tomllib.loads(rec.read_text(encoding="utf-8"))["cell"]}
    assert got["1.1.1"]["residual"] == "rewritten"
    # The untouched cell keeps every byte of its metadata, including the closure keys.
    assert got["5.4.3"]["decision_closed"] is True
    assert got["5.4.3"]["decision_closed_by"] == "owner"


# --- REFUSALS. each of these is the guard the writer exists for ------------------------------------


def _naked_543() -> dict:
    """A payload for the owner-closed cell that OMITS every closure key.

    This is byte-for-byte the shape the pre-`7818991d` writer emitted, and the shape any caller
    produces who did not know the keys existed -- which is the realistic case, since nothing in the
    payload schema mentions them.
    """
    return {
        "id": "5.4.3",
        "level": 2,
        "verdict": "na",
        "residual": "enterprise-provided control, outside the declared scope",
        "last_verified": "2026-08-09",
        "verified_at": "4444444444444444444444444444444444444444",
        "reviewed_by": "test",
        "evidence": [{"path": "messagefoundry/m.py", "line": 30, "expect": "_no_scan"}],
    }


def test_omitted_keys_are_carried_through_rather_than_dropped(tmp_path: Path) -> None:
    """THE 7818991d INCIDENT, and the design that answers it.

    An earlier writer enumerated the keys it kept as an ALLOWLIST, so `decision_closed`,
    `decision_closed_by` and friends were silently deleted from the two owner-closed cells during an
    anchor repair -- un-closing them. Every downstream check stayed green, because an ABSENT
    `decision_closed` is a valid False, and a gate cannot distinguish PRESERVED from DROPPED.

    The fix is structural rather than a check: the writer enumerates only what it ORDERS, and every
    other key on the live cell survives by default. So the payload below omits the closure keys and
    they are still there afterwards. This asserts the PRESERVATION, which is the property that makes
    the record safe; the next test proves the backstop that fires if this ever breaks.
    """
    rec = _record(tmp_path)
    rc = main([str(_payload(tmp_path, [_naked_543()])), "--scorecard", str(rec), "--apply"])
    assert rc == 0
    got = {c["id"]: c for c in tomllib.loads(rec.read_text(encoding="utf-8"))["cell"]}["5.4.3"]
    assert got["decision_closed"] is True
    assert got["decision_closed_by"] == "owner"


def test_a_payload_only_unknown_key_survives_too() -> None:  # #1242
    """The INVERSE of the 7818991d incident, and the direction the carry-through never covered.

    The preservation loop's SOURCE was the LIVE cell, so a key the writer has never heard of survived
    only if it was ALREADY in the vault. A key arriving on the PAYLOAD and absent from live was never
    iterated at all -- the `key in cell` skip the design relies on never even evaluated for it, because
    the key was not in the source being walked.

    That is the same silent-drop shape as the incident, one direction over: a NEW schema field applied
    to a cell that predates it would vanish on write, and an absent field reads as a valid default, so
    no gate downstream can tell PRESERVED from DROPPED.

    The module comment already states the governing rule -- the writer enumerates only what it ORDERS,
    and everything else survives by default. This asserts that rule holds for BOTH sources.
    """
    cell = {
        "id": "1.2.3",
        "level": 1,
        "verdict": "Pass",
        "last_verified": "2026-08-13",
        "verified_at": "0" * 40,
        "a_future_scalar": "must survive",
        "a_future_flag": True,
        "a_future_count": 7,
    }
    # live has NONE of the future keys -- so a live-sourced loop can never reach them.
    out = render(cell, {"id": "1.2.3", "level": 1, "verdict": "Pass"})
    assert 'a_future_scalar = "must survive"' in out
    assert "a_future_flag = true" in out
    assert "a_future_count = 7" in out


def test_live_only_keys_still_survive_after_the_payload_fix() -> None:  # #1242
    """Negative control for the test above: widening the source must not LOSE the direction that
    already worked. A key present only on the live cell is still carried."""
    out = render(
        {"id": "1.2.3", "level": 1, "verdict": "Pass", "last_verified": "x", "verified_at": "y"},
        {"id": "1.2.3", "decision_closed": True, "decision_closed_by": "owner"},
    )
    assert "decision_closed = true" in out
    assert 'decision_closed_by = "owner"' in out


def test_the_preservation_backstop_fires_when_carry_through_is_broken(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """MUTATION PROOF of the `set(was) - set(now)` invariant.

    The test above proves the carry-through works TODAY. This proves the record is still defended if
    someone breaks it -- by breaking it. `render` is replaced with one that drops exactly the keys
    `7818991d` dropped, reproducing the historical defect in the one function that could reintroduce
    it, and the write must be REFUSED.

    Without this, the preservation invariant is a line of code nobody has watched work, guarding
    against a defect that has already happened once.
    """
    import scripts.asvs.apply as mod

    real_render = mod.render

    def dropping_render(cell: dict, live: dict | None = None) -> str:
        stripped = {k: v for k, v in (live or {}).items() if not k.startswith("decision_")}
        return real_render(cell, stripped)

    monkeypatch.setattr(mod, "render", dropping_render)
    rec = _record(tmp_path)
    before = rec.read_bytes()
    rc = main([str(_payload(tmp_path, [_naked_543()])), "--scorecard", str(rec), "--apply"])
    assert rc == 1, "the writer dropped decision_* and the preservation invariant did not fire"
    assert rec.read_bytes() == before, "refused, but wrote anyway"
    # It must refuse for THIS reason. A non-zero exit is not evidence on its own -- several other
    # guards in this writer also return 1, and a mutation proof that passes because it tripped an
    # unrelated check proves nothing about the invariant it claims to be testing.
    out = capsys.readouterr().out
    assert "would LOSE field(s)" in out
    assert "decision_closed" in out and "decision_closed_by" in out


def test_it_refuses_to_shrink_the_evidence_list(tmp_path: Path) -> None:
    """Fewer anchors that all resolve is a PASSING state for the verifier.

    So anchor-count loss is invisible downstream exactly like field loss, and for the same reason: the
    reader of a green gate cannot tell a repair from a deletion.
    """
    rec = _record(tmp_path)
    one_anchor = _cell_111(
        evidence=[{"path": "messagefoundry/m.py", "line": 11, "expect": "tls_cert_file"}]
    )
    rc = main([str(_payload(tmp_path, [one_anchor])), "--scorecard", str(rec), "--apply"])
    assert rc == 1


def test_anchor_repair_refuses_a_residual_edit(tmp_path: Path) -> None:
    """`anchor_repair` relaxes the glyph and reviewed_by guards, so it must buy that with byte-identity.

    Otherwise the exemption is a bypass with a narrow mouth: declare a repair, edit the prose, and the
    checks that exist to police prose have been told not to look.
    """
    rec = _record(tmp_path)
    sneaky = _cell_111(anchor_repair=True, residual="quietly different")
    rc = main([str(_payload(tmp_path, [sneaky])), "--scorecard", str(rec), "--apply"])
    assert rc == 1


def test_anchor_repair_refuses_a_verdict_move(tmp_path: Path) -> None:
    rec = _record(tmp_path)
    rc = main(
        [
            str(_payload(tmp_path, [_cell_111(anchor_repair=True, verdict="pass")])),
            "--scorecard",
            str(rec),
            "--apply",
        ]
    )
    assert rc == 1


def test_it_refuses_to_rescore_an_owner_closed_cell(tmp_path: Path) -> None:
    """The method permits exactly ONE change to a closed cell without the owner: an anchor repair."""
    rec = _record(tmp_path)
    reopened = {
        "id": "5.4.3",
        "level": 2,
        "verdict": "fail",  # the move the closure exists to prevent
        "residual": "enterprise-provided control, outside the declared scope",
        "last_verified": "2026-08-09",
        "verified_at": "5555555555555555555555555555555555555555",
        "reviewed_by": "test",
        "decision_closed": True,
        "decision_closed_by": "owner",
        "evidence": [{"path": "messagefoundry/m.py", "line": 30, "expect": "_no_scan"}],
    }
    rc = main([str(_payload(tmp_path, [reopened])), "--scorecard", str(rec), "--apply"])
    assert rc == 1
    got = {c["id"]: c for c in tomllib.loads(rec.read_text(encoding="utf-8"))["cell"]}
    assert got["5.4.3"]["verdict"] == "na"


def test_it_refuses_a_glyph_in_a_residual(tmp_path: Path) -> None:
    """CLAUDE.md section 11, enforced against the record itself.

    This fired for real on 13.3.4, whose carried residual was full of banner glyphs: the cell could
    not be rewritten until they were converted to words. The check reports the CODEPOINT rather than
    echoing the character, because echoing it to a cp1252 console raises UnicodeEncodeError and the
    refusal turns into a traceback that hides its own reason.
    """
    rec = _record(tmp_path)
    rc = main(
        [
            str(_payload(tmp_path, [_cell_111(residual="WARNING ⛔ do not")])),
            "--scorecard",
            str(rec),
            "--apply",
        ]
    )
    assert rc == 1


def test_the_banned_class_is_one_contiguous_emoji_range() -> None:
    """The emoji planes are ONE range, not the adjacent pair `1f000-1f2ff` + `1f300-1faff`.

    That pair was contiguous, so collapsing it is a pure refactor — CodeQL read the split as an
    overlapping range because it analyses the class in UTF-16, where both halves share a high
    surrogate. The rewrite is only safe while the seam stays covered, so the seam is what this
    asserts: a later edit that re-splits the range and mistypes a bound, or truncates it, leaves a
    hole exactly here. A hole in a FAIL-CLOSED guard is invisible — nothing goes red, a glyph simply
    starts getting written into the security record, which is the failure this guard exists to stop.

    The outside-bounds assertions matter too: a range widened to `\\U0001f000-\\U0001ffff` would pass
    every inside check while quietly banning codepoints nobody reviewed.
    """
    for cp in (0x1F000, 0x1F2FF, 0x1F300, 0x1FAFF):  # both ends, and both sides of the old seam
        assert _BANNED.search(chr(cp)), f"U+{cp:04X} escaped the banned class"
    for cp in (0x1EFFF, 0x1FB00):  # immediately outside, both ends
        assert not _BANNED.search(chr(cp)), f"U+{cp:04X} was banned but is outside the range"


def test_it_refuses_a_cell_that_is_not_in_the_record(tmp_path: Path) -> None:
    rec = _record(tmp_path)
    rc = main(
        [str(_payload(tmp_path, [_cell_111(id="9.9.9")])), "--scorecard", str(rec), "--apply"]
    )
    assert rc == 1


def test_a_verdict_move_is_refused_by_default(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The one refusal here against a WELL-FORMED payload.

    Every other guard rejects malformed input. This one rejects input that is valid and means more
    than its author intended -- a verdict moving during a pass whose stated purpose was mechanical.
    That is this writer's whole failure mode, so the safe thing is the default.
    """
    rec = _record(tmp_path)
    before = rec.read_bytes()
    rc = main(
        [str(_payload(tmp_path, [_cell_111(verdict="pass")])), "--scorecard", str(rec), "--apply"]
    )
    assert rc == 1
    assert rec.read_bytes() == before
    out = capsys.readouterr().out
    # It must answer the operator's actual next question -- WHICH cell, and TO WHAT. A refusal that
    # says only "verdict changed" gets re-run with the override reflexively, which turns the guard
    # into a speed bump.
    assert "1.1.1" in out
    assert "'partial' -> 'pass'" in out


def test_the_verdict_flag_actually_unlocks_the_move(tmp_path: Path) -> None:
    """Guard-the-guard: a refusal that cannot be lifted is a bug, not a control.

    Without this, `--allow-verdict-change` could be misspelled, unwired, or shadowed and the test
    above would still pass -- it only asserts the refusal. This asserts the other half.
    """
    rec = _record(tmp_path)
    rc = main(
        [
            str(_payload(tmp_path, [_cell_111(verdict="pass")])),
            "--scorecard",
            str(rec),
            "--apply",
            "--allow-verdict-change",
        ]
    )
    assert rc == 0
    got = {c["id"]: c for c in tomllib.loads(rec.read_text(encoding="utf-8"))["cell"]}
    assert got["1.1.1"]["verdict"] == "pass"


# --- the CLI contract ------------------------------------------------------------------------------


def test_scorecard_path_is_required_and_has_no_default(tmp_path: Path) -> None:
    """It used to be a hardcoded absolute path into the SHARED vault checkout.

    Several sessions edit that tree at once, so running the writer from a worktree rewrote a record the
    operator was not looking at. A default would restore that with a nicer spelling.
    """
    with pytest.raises(SystemExit) as e:
        main([str(_payload(tmp_path, [_cell_111()]))])
    assert e.value.code == 2  # argparse usage error, not a silent fallback


def test_an_unknown_key_INSIDE_a_subtable_entry_survives() -> None:  # #1242 limb 4
    """The carry-through was delivered for TOP-LEVEL scalars and silently not for sub-table entries.

    Evidence and absence entries were re-emitted as exactly path/line/expect and
    pattern/positive_control/mutation, so any other field in an entry vanished on every rewrite --
    the same silent loss as the allowlist incident, one level down, and equally invisible because an
    absent field reads as a valid default.

    The key used here is deliberately one the writer has never heard of. A test naming a field that
    exists today would pass against a fix that simply lengthened the list, which is the defect again.
    """
    cell = {
        "id": "1.2.3",
        "level": 1,
        "verdict": "Pass",
        "last_verified": "2026-08-14",
        "verified_at": "0" * 40,
        "evidence": [
            {"path": "a.py", "line": 3, "expect": "x", "a_future_note": "must survive"},
        ],
        "absence": [
            {"pattern": "p", "positive_control": "c", "mutation": "m", "a_future_flag": True},
        ],
    }
    out = render(cell)
    assert 'a_future_note = "must survive"' in out
    assert "a_future_flag = true" in out
    # The ordered keys must be untouched, TYPES included -- `line` stays a bare int. Carrying unknown
    # fields through is worthless if it re-types the known ones on the way past.
    assert "  line = 3" in out
    assert '  path = "a.py"' in out
    assert '  pattern = "p"' in out


def test_the_preservation_backstop_fires_when_a_SUBTABLE_field_is_dropped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """MUTATION PROOF for the sub-table half of the invariant.

    The test above proves the carry-through works today; this proves the record is still DEFENDED if
    someone breaks it. Counting entries cannot see a field vanish from inside one, so before this the
    writer and the guard were blind in the same place -- a rewrite could drop a field from every
    evidence entry, keep the count, and report green.
    """
    import scripts.asvs.apply as mod

    real_render = mod.render

    def dropping_render(cell: dict, live: dict | None = None) -> str:
        text = real_render(cell, live)
        kept = [ln for ln in text.splitlines() if not ln.strip().startswith("expect = ")]
        return "\n".join(kept) + "\n"

    monkeypatch.setattr(mod, "render", dropping_render)
    rec = _record(tmp_path)
    before = rec.read_bytes()
    rc = main([str(_payload(tmp_path, [_cell_111()])), "--scorecard", str(rec), "--apply"])
    assert rc == 1, "a field was dropped from every evidence entry and the invariant did not fire"
    assert rec.read_bytes() == before, "refused, but wrote anyway"
    # It must refuse for THIS reason. Several other guards in this writer also return 1, and a
    # mutation proof that passes by tripping an unrelated check proves nothing about its invariant.
    out = capsys.readouterr().out
    assert "evidence[0] would LOSE" in out and "expect" in out, out


# --- #1242: the value half. Carrying a KEY while corrupting its VALUE is not carrying it. ---------


def test_a_table_or_array_value_ROUND_TRIPS_rather_than_becoming_a_repr(tmp_path: Path) -> None:
    """The writer used to emit any non-bool, non-int value as ``toml_str(str(value))``, so a table
    became a quoted PYTHON REPR: ``sym_table = "{'a': 1}"``. That parses, so nothing went red, and
    re-reading returned the STRING -- the value was unrecoverable from the file.

    THE ASSERTION IS THE ROUND TRIP, NOT THE RENDERING. Checking the emitted text looks right passes
    against a serializer that emits JSON (``{"a": 1}``), which is not TOML and will not parse. Only
    reading it back with the same parser the record is read with proves the value survived.
    """
    rec = _record(tmp_path)
    payload = _cell_111(
        sym_table={"a": 1, "b": "two"},
        sym_list=[1, "x", True],
        deep={"outer": {"inner": "v"}},
        rows=[{"a": 1}, {"b": 2}],
        ratio=1.5,
        flag=True,
    )
    rc = main([str(_payload(tmp_path, [payload])), "--scorecard", str(rec), "--apply"])
    assert rc == 0

    cell = next(
        c for c in tomllib.loads(rec.read_text(encoding="utf-8"))["cell"] if c["id"] == "1.1.1"
    )
    for key in ("sym_table", "sym_list", "deep", "rows", "ratio", "flag"):
        assert cell[key] == payload[key], f"{key} did not survive the write: {cell[key]!r}"


def test_a_DOTTED_key_is_QUOTED_rather_than_silently_re_nested(tmp_path: Path) -> None:
    """THE ONLY BAD KEY THAT FAILS QUIETLY, and the reason the quoting rule is unconditional.

    A dotted key is not a syntax error in TOML -- it is a NESTING OPERATOR. Emitted bare,
    ``{1.2.2 = "x"}`` is VALID and reads back as ``{'1': {'2': {'2': 'x'}}}``: the file loads, the
    gate stays green, the structure differs. Spaces and quotes fail LOUDLY and are therefore safe.

    It is not hypothetical here -- ASVS requirement ids ARE that shape. A test using only plain keys
    passes either way, which is why this one uses a dotted key specifically, with a plain key beside
    it as the negative control.
    """
    rec = _record(tmp_path)
    payload = _cell_111(dotted={"1.2.2": "pass", "12.1.1": "fail"}, plain={"ok": 1})
    rc = main([str(_payload(tmp_path, [payload])), "--scorecard", str(rec), "--apply"])
    assert rc == 0

    cell = next(
        c for c in tomllib.loads(rec.read_text(encoding="utf-8"))["cell"] if c["id"] == "1.1.1"
    )
    assert cell["dotted"] == {"1.2.2": "pass", "12.1.1": "fail"}, cell["dotted"]
    assert cell["plain"] == {"ok": 1}  # the control: plain keys were never the problem


def test_the_TYPE_guard_refuses_a_value_the_writer_would_have_mangled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """MUTATION PROOF for the value half, and the reason the key-set check is not enough.

    ``lost = set(was) - set(now)`` is a pure KEY-SET difference: a type-mangled field KEEPS ITS KEY,
    so it passes. That is not a flaw in that check -- it was written to catch DROPPED keys and it
    does -- but it means a rewrite could corrupt every value while preserving every key and report
    green. Without the type comparison this mutation is invisible.
    """
    import scripts.asvs.apply as mod

    rec = _record(tmp_path)
    # First write the table for real, so the LIVE record holds a table to be corrupted.
    assert (
        main(
            [
                str(_payload(tmp_path, [_cell_111(sym_table={"a": 1})])),
                "--scorecard",
                str(rec),
                "--apply",
            ]
        )
        == 0
    )

    real_render = mod.render

    def mangling_render(cell: dict, live: dict | None = None) -> str:
        text = real_render(cell, live)
        return text.replace("sym_table = { a = 1 }", "sym_table = \"{'a': 1}\"")

    monkeypatch.setattr(mod, "render", mangling_render)
    before = rec.read_bytes()
    # The payload deliberately does NOT mention sym_table: this is the WRITER changing a type nobody
    # asked it to change, which is exactly the case the guard is scoped to.
    rc = main([str(_payload(tmp_path, [_cell_111()])), "--scorecard", str(rec), "--apply"])

    assert rc == 1
    assert rec.read_bytes() == before, "refused, but wrote anyway"
    # It must refuse for THIS reason -- several other guards here also return 1, and a mutation proof
    # that passes by tripping an unrelated check proves nothing about the invariant it claims.
    out = capsys.readouterr().out
    assert "would CHANGE the TYPE" in out and "sym_table" in out, out


def test_the_TYPE_guard_does_NOT_refuse_a_payload_that_intentionally_retypes(
    tmp_path: Path,
) -> None:
    """THE SCOPING, and without it the guard gets disabled the first time it cries wolf.

    The check compares the VAULT against the REWRITTEN FILE, so an unscoped version would also refuse
    a payload that legitimately changes a field's type -- schema evolution, a scalar becoming a
    table. That is an EDIT, not damage. The corruption case is the WRITER retyping a key the payload
    never mentioned, so the check skips keys the payload carries.
    """
    rec = _record(tmp_path)
    assert (
        main(
            [
                str(_payload(tmp_path, [_cell_111(note="a plain string")])),
                "--scorecard",
                str(rec),
                "--apply",
            ]
        )
        == 0
    )
    # Same key, deliberately a different type, stated by the payload.
    rc = main(
        [
            str(_payload(tmp_path, [_cell_111(note={"now": "a table"})])),
            "--scorecard",
            str(rec),
            "--apply",
        ]
    )
    assert rc == 0, "an intentional retype by the payload must be allowed"

    cell = next(
        c for c in tomllib.loads(rec.read_text(encoding="utf-8"))["cell"] if c["id"] == "1.1.1"
    )
    assert cell["note"] == {"now": "a table"}


def test_the_TYPE_guard_sees_a_corruption_the_payload_ALSO_MENTIONS(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """THE SCOPING HOLE, found by the ASVS Tracker against a scoping this author wrote and could not
    check (BACKLOG #1242).

    ``k not in c`` skipped every key the payload carries, so the guard covered the WRITER-only case
    and stopped looking at the exact moment a cell is being rewritten. **That is the case that
    matters rather than a corner:** measured on the real record, exactly ONE cell of 345 holds a
    top-level non-scalar, and the natural payload for rewriting that cell ECHOES the key. So the
    guard covered every cell that cannot be hurt and skipped the one that can.

    THE THREE ARMS, and the third is what makes the second attributable:

    ==========  =====================================  ==================================
    arm         setup                                  required
    ==========  =====================================  ==================================
    control     payload OMITS the key, writer broken   refuse (the sibling test above)
    subject     payload CARRIES the key, writer broken refuse -- THIS test
    sanity      payload CARRIES the key, writer sound  allow (the retype test above)
    ==========  =====================================  ==================================

    Carrying the key is not what corrupts the value; the writer regression is. Without the sanity
    arm a refusal here would be equally consistent with "the guard now refuses any carried key",
    which is the unscoped version this scoping exists to avoid.

    THE FIX COMPARES AGAINST WHAT THE PAYLOAD STATED rather than declining to look. The payload IS
    the record of the type the author asked for, so an intentional retype still agrees with its own
    payload and passes, while a writer corruption disagrees in BOTH zones.
    """
    import scripts.asvs.apply as mod

    rec = _record(tmp_path)
    assert (
        main(
            [
                str(_payload(tmp_path, [_cell_111(sym_table={"a": 1})])),
                "--scorecard",
                str(rec),
                "--apply",
            ]
        )
        == 0
    )

    real_render = mod.render

    def mangling_render(cell: dict, live: dict | None = None) -> str:
        text = real_render(cell, live)
        return text.replace("sym_table = { a = 1 }", "sym_table = \"{'a': 1}\"")

    monkeypatch.setattr(mod, "render", mangling_render)
    before = rec.read_bytes()
    # The payload DOES carry sym_table, and carries it as the same dict it already is. Under the
    # old scoping this is the silent-corruption path: the key is skipped, the guard never looks,
    # and the file comes back holding a Python repr inside a TOML string.
    rc = main(
        [
            str(_payload(tmp_path, [_cell_111(sym_table={"a": 1})])),
            "--scorecard",
            str(rec),
            "--apply",
        ]
    )

    assert rc == 1, "a writer corruption is invisible whenever the payload happens to carry the key"
    assert rec.read_bytes() == before, "refused, but wrote anyway"
    out = capsys.readouterr().out
    assert "would CHANGE the TYPE" in out and "sym_table" in out, out


def test_the_TYPE_guard_does_NOT_refuse_a_field_the_writer_COERCES_BY_DESIGN(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """THE FALSE-REFUSAL ARM for the corrected scoping (BACKLOG #1242).

    Comparing the payload's stated type against the output would be wrong for the keys ``render()``
    deliberately NORMALISES: ``level`` goes through ``int()``, and verdict / last_verified /
    verified_at are emitted quoted. A payload stating ``level`` as the string ``"1"`` therefore
    produces an int in the file **by design**, and refusing that is precisely the cry-wolf failure
    the scoping exists to avoid -- a guard that refuses legitimate writes is a guard someone
    disables.

    WITHOUT THIS TEST THE ``_ORDERED`` EXCLUSION IS UNPINNED. Measured while writing it: dropping
    that clause left all 23 other tests green, so the suite was silent about exactly the region the
    clause occupies -- which is this item's own defect one level up (COMMON 4.5.1).

    Its sibling ``_SUBTABLES`` clause is deliberately NOT pinned here and is belt-and-braces rather
    than load-bearing: ``evidence`` and ``absence`` render as arrays of tables on both sides, so the
    comparison cannot fire for them today. It is kept because that is a property of the current
    writer rather than an invariant, and the sub-table entries have their own key check below.
    """
    rec = _record(tmp_path)
    rc = main(
        [
            str(_payload(tmp_path, [_cell_111(level="1")])),
            "--scorecard",
            str(rec),
            "--apply",
        ]
    )

    out = capsys.readouterr().out
    assert rc == 0, f"a by-design coercion must not read as corruption: {out}"
    assert "would CHANGE the TYPE" not in out, out
    cell = next(
        c for c in tomllib.loads(rec.read_text(encoding="utf-8"))["cell"] if c["id"] == "1.1.1"
    )
    assert cell["level"] == 1, "the writer's own int() normalisation still happened"


# --- BACKLOG #1307: a retirement is a SANCTIONED outcome the writer could not express -------------
#
# The shrink guard refuses any payload where an evidence or absence list gets shorter, and it took no
# flag. But the tracking loop names four causes for an anchor that no longer resolves, and one of them
# is "the gap it certified was CLOSED, so retire it" -- the case where the engine got BETTER and the
# fix deleted the line the anchor quoted. That left a maintainer with a legitimate retirement choosing
# between a stale anchor and the unsafe writer.
#
# THE GUARD IS CORRECT AND IS NOT WIDENED. It exists because a truncating repair once cut one cell
# 15 -> 10 and another 17 -> 1 with the verifier green throughout. So the four arms below pin that the
# only way through is a DECLARED retirement whose arithmetic agrees -- the flag alone opens nothing.


def _shrunk_111(**over: object) -> dict:
    """The 1.1.1 payload with one of its two evidence anchors removed."""
    cell = _cell_111()
    cell["evidence"] = cell["evidence"][:1]
    cell.update(over)
    return cell


def test_a_shrink_is_still_refused_without_the_flag(tmp_path: Path) -> None:
    """MUST REFUSE. The default is unchanged: a silent cardinality drop is the thing the guard is
    for, and #1307 must not have relaxed it."""
    rec = _record(tmp_path)
    rc = main([str(_payload(tmp_path, [_shrunk_111()])), "--scorecard", str(rec), "--apply"])
    assert rc == 1
    assert rec.read_text(encoding="utf-8") == FIXTURE, "a refused run must not touch the file"


def test_the_flag_alone_does_not_unlock_a_shrink(tmp_path: Path) -> None:
    """MUST REFUSE, AND THIS IS THE ARM THAT MAKES THE FEATURE SAFE RATHER THAN A BYPASS.

    A bare `--allow-retirement` behaving like `--allow-verdict-change` would convert the guard into a
    speed bump: the flag would be reached for reflexively on any refusal. The payload has to say WHAT
    is being retired."""
    rec = _record(tmp_path)
    rc = main(
        [
            str(_payload(tmp_path, [_shrunk_111()])),
            "--scorecard",
            str(rec),
            "--apply",
            "--allow-retirement",
        ]
    )
    assert rc == 1
    assert rec.read_text(encoding="utf-8") == FIXTURE


def test_a_declaration_whose_arithmetic_disagrees_is_refused(tmp_path: Path) -> None:
    """MUST REFUSE. Declaring ONE retirement while the count drops by TWO is the shape that would
    let a truncation ride in behind a legitimate-looking declaration -- which is precisely the
    incident the guard was built for, wearing a permit."""
    rec = _record(tmp_path)
    # DROPS ONE (2 -> 1) but DECLARES TWO. Deliberately this direction rather than dropping both:
    # an empty evidence list trips a DIFFERENT guard ("partial needs at least one anchor"), and the
    # first version of this test did exactly that -- it passed while never reaching the arithmetic
    # check at all. Caught by mutating the check away and seeing NOTHING go red.
    cell = _cell_111()
    cell["evidence"] = cell["evidence"][:1]
    cell["retired_evidence"] = ["messagefoundry/m.py:10", "messagefoundry/m.py:20"]
    rc = main(
        [str(_payload(tmp_path, [cell])), "--scorecard", str(rec), "--apply", "--allow-retirement"]
    )
    assert rc == 1
    assert rec.read_text(encoding="utf-8") == FIXTURE


def test_a_declared_retirement_whose_arithmetic_agrees_is_applied(tmp_path: Path) -> None:
    """MUST APPLY -- the arm without which the other three are satisfied by a writer that refuses
    everything, and the outcome the item exists to make reachable."""
    rec = _record(tmp_path)
    rc = main(
        [
            str(_payload(tmp_path, [_shrunk_111(retired_evidence=["messagefoundry/m.py:20"])])),
            "--scorecard",
            str(rec),
            "--apply",
            "--allow-retirement",
        ]
    )
    assert rc == 0, "a declared, arithmetic-consistent retirement must go through"
    after = rec.read_text(encoding="utf-8")
    assert "verify_mode" not in after, "the retired anchor should be gone"
    assert "tls_cert_file" in after, "the surviving anchor must remain"
    assert "5.4.3" in after, "the untouched cell must survive byte-for-byte"


# --- BACKLOG #1363 / #1484: the retirement flag was PREEMPTED by the key-set guard ----------------
#
# #1307 shipped `--allow-retirement` and it genuinely worked -- for a PARTIAL retirement. `render()`
# emits no block for an empty list, so retiring the LAST entry of `evidence` or `absence` makes the
# KEY vanish on the round-trip, and `lost = set(was) - set(now)` refused sixty lines before
# `allow_retirement` was ever consulted. Both authorised retirements were that shape.
#
# TWO ROWS, ONE DEFECT, and the duplication is the instructive part. #1363 (2026-08-26) and #1484
# (2026-09-07) were filed twelve days apart by different sessions against the same lines; #1484 found
# it on a cell whose single absence claim had genuinely closed. The refusal names a KEY LOSS, so
# neither reader searching the ledger for "retirement" found the other's row.
#
# THE GUARD IS NOT WIDENED, WHICH IS THE WHOLE CONSTRAINT BOTH ROWS STATE. It exists because a
# truncating repair once cut one cell 15 -> 10 and another 17 -> 1 with the verifier green
# throughout. So the arms below hold the asymmetry: DECLARED under the flag reaches the retirement
# logic, UNDECLARED still refuses at the key-set guard, and a declaration whose arithmetic disagrees
# is refused by the branch it now reaches rather than waved through.

#: One absence claim, spliced into `1.1.1`. Written as a replace against a unique anchor rather than a
#: second whole fixture, so the two records cannot drift apart in a way no test would notice.
_ABSENCE_BLOCK = (
    "  [[cell.absence]]\n"
    '  pattern = "a gap this cell asserts is open"\n'
    '  positive_control = "plant the pattern and the scan finds it"\n'
    '  mutation = "remove the guard and the scan reds"\n'
)
FIXTURE_WITH_ABSENCE = FIXTURE.replace(
    '[[cell]]\nid = "5.4.3"', _ABSENCE_BLOCK + '[[cell]]\nid = "5.4.3"'
)


def _record_with_absence(tmp_path: Path) -> Path:
    """The fixture record with ONE absence claim on `1.1.1` -- the 1 -> 0 shape, which is the shape.

    ASSERTED, NOT ASSUMED. `str.replace` that matches nothing returns the original string happily, so
    a broken anchor would leave every arm below driving the plain two-evidence cell and passing for
    the wrong reason -- an absence that reads exactly like a presence, which is the failure this whole
    file is written against.
    """
    assert FIXTURE_WITH_ABSENCE != FIXTURE, "the absence block was not spliced in"
    p = tmp_path / "asvs-scorecard.toml"
    p.write_text(FIXTURE_WITH_ABSENCE, encoding="utf-8")
    live = {c["id"]: c for c in tomllib.loads(FIXTURE_WITH_ABSENCE)["cell"]}
    assert len(live["1.1.1"]["absence"]) == 1, live["1.1.1"]
    assert "absence" not in live["5.4.3"], "the splice landed in the wrong cell"
    return p


def _emptied_absence(**over: object) -> dict:
    """`1.1.1` with its evidence intact and its absence list EMPTIED.

    The evidence stays on purpose. Emptying both lists trips a different guard entirely -- "partial
    needs at least one anchor or absence claim" -- and an arm that trips that one proves nothing about
    this one. #1307's arithmetic arm records walking into exactly that trap and only catching it by
    mutating the check away and seeing nothing go red.
    """
    cell = _cell_111()
    cell["absence"] = []
    cell.update(over)
    return cell


def test_a_DECLARED_full_list_retirement_reaches_the_retirement_logic(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """MUST APPLY. The outcome both rows exist to make reachable, and the arm without which the
    three refusals below are satisfied by a writer that refuses everything."""
    rec = _record_with_absence(tmp_path)
    rc = main(
        [
            str(_payload(tmp_path, [_emptied_absence(retired_absence=["the gap closed"])])),
            "--scorecard",
            str(rec),
            "--apply",
            "--allow-retirement",
        ]
    )
    out = capsys.readouterr().out
    assert rc == 0, out
    # The writer's own evidence that the retirement BRANCH ran, rather than that the run merely
    # exited 0. #1484 measured the defect precisely by this line's absence.
    assert "RETIRING: cell 1.1.1 absence 1 -> 0" in out, out
    after = rec.read_text(encoding="utf-8")
    assert "[[cell.absence]]" not in after, "the retired claim should be gone"
    assert "tls_cert_file" in after and "verify_mode" in after, "the evidence anchors must remain"
    assert "5.4.3" in after, "the untouched cell must survive"


def test_an_UNDECLARED_full_list_loss_still_refuses_at_the_key_set_guard(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """MUST REFUSE, AND THIS IS THE ARM THAT MAKES THE FIX A FIX RATHER THAN A RELAXATION.

    Same flag, same cell, same emptied list -- the payload simply does not say what it retired. A
    reorder of the two checks that dropped this asymmetry would turn a loud false refusal into a
    quiet always-pass, which #1363 names as strictly worse than the defect.
    """
    rec = _record_with_absence(tmp_path)
    before = rec.read_bytes()
    rc = main(
        [
            str(_payload(tmp_path, [_emptied_absence()])),
            "--scorecard",
            str(rec),
            "--apply",
            "--allow-retirement",
        ]
    )
    assert rc == 1
    assert rec.read_bytes() == before, "refused, but wrote anyway"
    out = capsys.readouterr().out
    # It must refuse for THIS reason: several guards in this writer return 1.
    assert "would LOSE field(s) ['absence']" in out, out


def test_a_DECLARED_full_list_retirement_without_the_flag_still_refuses(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """MUST REFUSE. The declaration alone unlocks nothing -- the excuse is gated on the flag too, so
    the two authorisations stay independent -- and the refusal now NAMES the route out."""
    rec = _record_with_absence(tmp_path)
    before = rec.read_bytes()
    rc = main(
        [
            str(_payload(tmp_path, [_emptied_absence(retired_absence=["the gap closed"])])),
            "--scorecard",
            str(rec),
            "--apply",
        ]
    )
    assert rc == 1
    assert rec.read_bytes() == before
    out = capsys.readouterr().out
    assert "would LOSE field(s) ['absence']" in out, out
    assert "'retired_absence'" in out and "--allow-retirement" in out, (
        "an unanswerable refusal gets re-run with the override reflexively; it must name the route"
    )


def test_a_full_list_retirement_whose_ARITHMETIC_DISAGREES_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """MUST REFUSE, and it must refuse in the RETIREMENT branch rather than at the key-set guard.

    This is the arm proving the excuse did not become a bypass. The payload declares TWO retirements
    while the count drops by ONE, so it is excused past the key-set difference and then caught by the
    arithmetic -- the check #1363 says already computes the right distinction and simply never ran.
    """
    rec = _record_with_absence(tmp_path)
    before = rec.read_bytes()
    rc = main(
        [
            str(
                _payload(
                    tmp_path,
                    [_emptied_absence(retired_absence=["the gap closed", "and another"])],
                )
            ),
            "--scorecard",
            str(rec),
            "--apply",
            "--allow-retirement",
        ]
    )
    assert rc == 1
    assert rec.read_bytes() == before
    out = capsys.readouterr().out
    assert "declares 2 retirement(s) but the count drops by 1" in out, out
    assert "would LOSE field(s)" not in out, "it refused at the key-set guard, not the arithmetic"


def test_the_excuse_is_PER_SUBTABLE_and_does_not_disarm_the_guard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """MUTATION PROOF that the excuse is narrow. A declared absence retirement must not buy silence
    about an unrelated key the writer drops in the same run.

    Without this, `excused` could have been written as "skip the key-set check when a retirement is
    declared" -- which passes every arm above and re-opens the 7818991d silent-drop incident behind a
    one-line declaration.
    """
    import scripts.asvs.apply as mod

    real_render = mod.render

    def dropping_render(cell: dict, live: dict | None = None) -> str:
        stripped = {k: v for k, v in (live or {}).items() if k != "reviewed_by"}
        text = real_render(cell, stripped)
        return (
            "\n".join(ln for ln in text.splitlines() if not ln.startswith("reviewed_by = ")) + "\n"
        )

    monkeypatch.setattr(mod, "render", dropping_render)
    rec = _record_with_absence(tmp_path)
    before = rec.read_bytes()
    rc = main(
        [
            str(_payload(tmp_path, [_emptied_absence(retired_absence=["the gap closed"])])),
            "--scorecard",
            str(rec),
            "--apply",
            "--allow-retirement",
        ]
    )
    assert rc == 1, "a key was dropped beside a legitimate retirement and the guard stayed quiet"
    assert rec.read_bytes() == before
    out = capsys.readouterr().out
    assert "would LOSE field(s) ['reviewed_by']" in out, out


# ------------------------------------------- carrying vs introducing a banned glyph (BACKLOG #1308)
#
# THE DEFECT IS UNWRITABILITY, NOT UNTIDINESS. Scanning the whole residual meant a cell whose own
# prose already held a banned character could never be written by this tool again: every payload has
# to carry the residual forward, so every payload re-presented the character and was refused. The
# record went read-only through its own guard, and the only route to touching it was editing prose
# the pass was not about.
#
# Every test below drives the REAL main() against a record whose LIVE residual carries U+26D4, so
# the reassuring arm and the alarming arm differ only in what the PAYLOAD does with it.

_GLYPH = "\u26d4"  # no-entry, one of the explicitly banned singles
_OTHER_GLYPH = "\u2705"  # check mark, a DIFFERENT banned single

_FIXTURE_WITH_GLYPH = FIXTURE.replace(
    'residual = "a control exists but ships off"',
    f'residual = "a control exists but ships off {_GLYPH} see note"',
)


def _record_with_glyph(tmp_path: Path) -> Path:
    p = tmp_path / "asvs-scorecard.toml"
    p.write_text(_FIXTURE_WITH_GLYPH, encoding="utf-8")
    return p


def _live_residual() -> str:
    return f"a control exists but ships off {_GLYPH} see note"


def test_a_residual_byte_identical_to_the_live_one_still_applies(tmp_path: Path) -> None:
    """THE ARM THE OLD CHECK MADE IMPOSSIBLE. Carrying a glyph forward is not introducing one.

    Before BACKLOG #1308 this returned 1: the payload must repeat the residual, the scan saw the
    character, and the cell could not be rewritten at all.
    """
    rec = _record_with_glyph(tmp_path)
    rc = main(
        [
            str(_payload(tmp_path, [_cell_111(residual=_live_residual())])),
            "--scorecard",
            str(rec),
            "--apply",
        ]
    )
    assert rc == 0, "a byte-identical residual must remain writable"


def test_introducing_a_DIFFERENT_glyph_is_still_refused(tmp_path: Path) -> None:
    """The alarming arm, over the same record. Relaxing the scan must not disarm it."""
    rec = _record_with_glyph(tmp_path)
    rc = main(
        [
            str(
                _payload(tmp_path, [_cell_111(residual=_live_residual() + f" and {_OTHER_GLYPH}")])
            ),
            "--scorecard",
            str(rec),
            "--apply",
        ]
    )
    assert rc == 1, "a glyph the record does not carry is INTRODUCED and must refuse"


def test_adding_MORE_of_a_glyph_the_record_already_carries_is_refused(tmp_path: Path) -> None:
    """The arm a presence test cannot see, which is why the predicate COUNTS.

    A payload that adds a SECOND copy of a character the cell already had is introducing new
    vocabulary just as surely as a new character. `is it present` answers yes either way and would
    let this through.
    """
    rec = _record_with_glyph(tmp_path)
    rc = main(
        [
            str(_payload(tmp_path, [_cell_111(residual=_live_residual() + f" {_GLYPH}")])),
            "--scorecard",
            str(rec),
            "--apply",
        ]
    )
    assert rc == 1, "a second copy is new vocabulary; counting is what catches it"


def test_moving_a_glyph_within_the_residual_still_applies(tmp_path: Path) -> None:
    """The count is per codepoint, not per offset, so a rewording that keeps it is writable.

    This is the case that makes the item worth building: an ordinary mechanical edit to a cell whose
    prose carries a glyph. The old scan refused it and there was no way round short of editing the
    glyph out, which is a different act needing a different decision.
    """
    rec = _record_with_glyph(tmp_path)
    rc = main(
        [
            str(_payload(tmp_path, [_cell_111(residual=f"{_GLYPH} moved to the front, reworded")])),
            "--scorecard",
            str(rec),
            "--apply",
        ]
    )
    assert rc == 0


def test_a_glyph_in_a_cell_with_no_live_record_is_refused(tmp_path: Path) -> None:
    """FAIL-CLOSED where there is nothing to compare against.

    A cell with no live counterpart has a live count of zero for every character, so anything banned
    in it is introduced. That is the direction to be wrong in: the comparison relaxes the scan only
    where a record exists to relax it against.
    """
    assert _introduced_banned(f"brand new {_GLYPH} text", "") is not None
    assert _introduced_banned("brand new text", "") is None


# --- BACKLOG #1369: the writer persisted its own control declarations into the record --------------
#
# `--allow-retirement` requires the payload to DECLARE what it retires, and apply.py reads that
# declaration off the cell dict. The carry-through then wrote it straight back out, because ONE DICT
# CARRIED BOTH CHANNELS and a control is indistinguishable from a data field once it does. A run that
# retired two anchors left `retired_absence = [...]` in the record, where `scorecard.py` has no reader
# for it and never will -- the instruction outliving the operation it instructed.
#
# The fix must NOT be a name list. `_carried`'s docstring rejects one in terms -- "a name-keyed fix
# satisfies the symptom and drops the next field anyone adds, which is the defect itself with a longer
# list" -- and that objection is about DATA LOSS, which is the more expensive direction. So the control
# names are DERIVED from `_SUBTABLES`.


def test_a_control_declaration_is_consumed_but_never_stored() -> None:
    """The defect, at its narrowest: the writer must read the instruction and not keep it."""
    rendered = render(
        {
            "id": "1.2.3",
            "level": 1,
            "verdict": "met",
            "last_verified": "2026-08-27",
            "verified_at": "0" * 40,
            "retired_absence": ["a pattern retired by this very run"],
        }
    )
    assert "retired_absence" not in rendered, rendered


def test_AND_AN_UNKNOWN_DATA_KEY_STILL_SURVIVES_beside_it() -> None:
    """THE HALF THAT MAKES THE OTHER HALF SAFE, and the direction #1242 was filed for.

    Dropping controls is only correct while unknown DATA is still carried. A fix that suppressed both
    would satisfy the test above and silently re-introduce the 7818991d incident -- and an absent field
    reads as a valid default, so nothing downstream could tell PRESERVED from DROPPED.
    """
    rendered = render(
        {
            "id": "1.2.3",
            "level": 1,
            "verdict": "met",
            "last_verified": "2026-08-27",
            "verified_at": "0" * 40,
            "retired_absence": ["retired by this run"],
            "a_field_this_writer_has_never_heard_of": "must survive",
        }
    )
    assert "retired_absence" not in rendered, "the control leaked"
    assert "a_field_this_writer_has_never_heard_of" in rendered, "unknown DATA was dropped"


def test_a_NEW_subtable_brings_its_control_automatically(monkeypatch: pytest.MonkeyPatch) -> None:
    """THE PROPERTY, AND MY FIRST VERSION OF THIS TEST COULD NOT SEE IT.

    It asserted `_CONTROL_KEYS == tuple(f"retired_{n}" for n in _SUBTABLES)` -- VALUE EQUALITY. A
    hand-written literal matching today's value satisfies that, and a mutation run proved it: the
    literal passed all 38 tests. There was no behaviour to differ on, because the constant was computed
    once at import, so a snapshot and a derivation are indistinguishable until someone edits
    `_SUBTABLES` -- which is the exact moment the rot arrives and the exact moment no test is watching.

    The derivation is now computed per call, so it can be OBSERVED following a change rather than
    asserted to match. This adds a sub-table and checks the control follows IN BEHAVIOUR, not just in
    the tuple: render must drop the new control too.
    """
    import scripts.asvs.apply as apply_mod

    monkeypatch.setattr(apply_mod, "_SUBTABLES", (*_SUBTABLES, "mitigation"))
    assert "retired_mitigation" in _control_keys(), "the derivation did not follow _SUBTABLES"

    rendered = render(
        {
            "id": "1.2.3",
            "level": 1,
            "verdict": "met",
            "last_verified": "2026-08-27",
            "verified_at": "0" * 40,
            "retired_mitigation": ["x"],
        }
    )
    assert "retired_mitigation" not in rendered, (
        "a control for a NEWLY ADDED sub-table was persisted -- the derivation is not live: "
        + rendered
    )


def test_every_subtable_has_its_control_covered() -> None:
    """Both arms, so a fix that covered only the one in the incident would red here."""
    for name in _SUBTABLES:
        rendered = render(
            {
                "id": "1.2.3",
                "level": 1,
                "verdict": "met",
                "last_verified": "2026-08-27",
                "verified_at": "0" * 40,
                f"retired_{name}": ["x"],
            }
        )
        assert f"retired_{name}" not in rendered, f"{name}'s control leaked: {rendered}"


def test_END_TO_END_a_successful_retirement_leaves_no_declaration_behind(tmp_path: Path) -> None:
    """The whole chain, on the arm that ACTUALLY WRITES -- which is where the leak happened.

    This mirrors `test_a_declared_retirement_whose_arithmetic_agrees_is_applied` deliberately: that
    test drives the same successful retirement and asserts what the record SHOULD contain, but never
    asked what it should NOT. The declaration was sitting in its output the whole time.

    It also proves the control is still READ. If the fix had hidden the key from the reader as well as
    the writer, the retirement would refuse and `rc` would be 1.
    """
    rec = _record(tmp_path)
    rc = main(
        [
            str(_payload(tmp_path, [_shrunk_111(retired_evidence=["messagefoundry/m.py:20"])])),
            "--scorecard",
            str(rec),
            "--apply",
            "--allow-retirement",
        ]
    )
    assert rc == 0, (
        "the control must still be READ -- a refusal here means the fix broke the feature"
    )
    after = rec.read_text(encoding="utf-8")
    assert "retired_evidence" not in after, (
        f"the declaration was persisted into the record:\n{after}"
    )
    # ...and the retirement itself still happened, so this is not passing by doing nothing.
    assert "verify_mode" not in after, "the retired anchor should be gone"
    assert "tls_cert_file" in after, "the surviving anchor must remain"


# --- BACKLOG #1369, second limb: `anchor_repair` is the control the derivation could not reach -----
#
# `_control_keys()` derives from `_SUBTABLES`, so it covers `retired_evidence` and `retired_absence`
# and misses `anchor_repair` -- the OTHER declaration the same function consumes as an instruction,
# and one that nothing in `scorecard.py` reads back. Persisted, it FREEZES the cell: a later ordinary
# residual correction, authored from the live cell and therefore carrying the flag forward, is
# refused with "declared anchor_repair but 'residual' differs from the record". That is the #1333
# freeze shape, reintroduced through a persisted control.
#
# THE NAME LIST IS CORRECT HERE and is not a relapse into the one `_carried`'s docstring rejects.
# That objection is about DATA, where a missed name is a field lost silently and forever behind a
# valid-looking default. A missed name HERE keeps one key too many -- visible in the record, readable
# by anyone who opens it, recoverable on the next write. Cheap and loud against expensive and silent.
#
# AND THE SIGNAL IS REPLACED RATHER THAN DESTROYED. `anchor_provenance._repairs_declared` counts
# cells declaring a repair and its docstring says nothing else in the record marks one, so consuming
# the control without recording anything would delete a measurement. The writer records
# `anchor_repaired_at` instead: the same fact, carrying the date, instruction to nobody.


def _cell_with_repair(**over: object) -> dict:
    """An anchor-repair payload for `1.1.1` -- prose byte-identical to the fixture, anchors moved."""
    cell = _cell_111(anchor_repair=True, reviewed_by="fixture")
    cell.update(over)
    return cell


def test_anchor_repair_is_CONSUMED_and_never_stored() -> None:
    """The narrow defect: the writer must read the instruction and not keep it."""
    parsed = tomllib.loads(
        render(
            {
                "id": "1.2.3",
                "level": 1,
                "verdict": "pass",
                "last_verified": "2026-08-27",
                "verified_at": "0" * 40,
                "anchor_repair": True,
            }
        )
    )["cell"][0]
    # Asserted on the PARSED key, never as a substring: the witness field's own name contains
    # "anchor_repair", so a substring check cannot tell the control from its replacement and would
    # red on a correct fix. Exactly the presence-equals-meaning trap the glyph rule names.
    assert "anchor_repair" not in parsed, parsed
    assert parsed["anchor_repaired_at"] == "2026-08-27", parsed


def test_a_cell_that_was_NOT_repaired_gets_no_witness() -> None:
    """The witness must record a fact, not appear on every rewrite. Without this arm the field is
    decoration and the count it feeds means nothing."""
    parsed = tomllib.loads(render(_cell_111()))["cell"][0]
    assert "anchor_repaired_at" not in parsed, parsed


def test_the_named_control_rides_BESIDE_the_derivation_rather_than_replacing_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both sources, at once. A fix that swapped the derivation for a list would satisfy the arm
    above and silently un-fix the row this file's earlier section is about, so the derived half is
    re-driven here through a NEW sub-table rather than assumed still present."""
    import scripts.asvs.apply as apply_mod

    assert "anchor_repair" in _control_keys()
    monkeypatch.setattr(apply_mod, "_SUBTABLES", (*_SUBTABLES, "mitigation"))
    keys = _control_keys()
    assert "retired_mitigation" in keys, "the derived half stopped following _SUBTABLES"
    assert "anchor_repair" in keys, "the named half was lost when the derived half moved"


def test_a_cell_ALREADY_CARRYING_the_persisted_control_is_still_WRITABLE(tmp_path: Path) -> None:
    """MUST APPLY, and without the key-set exclusion this refuses.

    `render` strips the control, so the round-trip LOSES a key the live cell had, and the
    field-preservation invariant is a pure key-set difference. Fixing #1369 without excusing it
    would make every cell carrying the persisted flag permanently unwritable by this tool -- the
    same unwritability #1308 had to undo once already, arriving from a new direction.
    """
    rec = tmp_path / "asvs-scorecard.toml"
    rec.write_text(
        FIXTURE.replace(
            'reviewed_by = "fixture"\n', 'reviewed_by = "fixture"\nanchor_repair = true\n', 1
        ),
        encoding="utf-8",
    )
    live = {c["id"]: c for c in tomllib.loads(rec.read_text(encoding="utf-8"))["cell"]}
    assert live["1.1.1"]["anchor_repair"] is True, "the fixture splice did not land"

    rc = main([str(_payload(tmp_path, [_cell_with_repair()])), "--scorecard", str(rec), "--apply"])
    assert rc == 0, "the persisted control made the cell unwritable"
    after = {c["id"]: c for c in tomllib.loads(rec.read_text(encoding="utf-8"))["cell"]}
    assert "anchor_repair" not in after["1.1.1"], "the control was persisted again"
    assert after["1.1.1"]["anchor_repaired_at"] == "2026-08-09", after["1.1.1"]
    # ...and the repair itself happened, so this is not passing by writing nothing.
    assert after["1.1.1"]["evidence"][0]["line"] == 11


def test_the_FREEZE_LIFTS_once_the_control_has_been_stripped(tmp_path: Path) -> None:
    """THE WHOLE POINT OF THE ROW, driven end to end on the arm that actually writes.

    Before: a repair persisted the flag, so the NEXT ordinary residual correction -- authored the
    only way anyone authors one, by echoing the live cell -- carried it forward and was refused as
    "declared anchor_repair but 'residual' differs from the record". After: the repair strips the
    flag, so the echo carries no control and the correction goes through.
    """
    rec = tmp_path / "asvs-scorecard.toml"
    rec.write_text(FIXTURE, encoding="utf-8")
    assert (
        main([str(_payload(tmp_path, [_cell_with_repair()])), "--scorecard", str(rec), "--apply"])
        == 0
    )

    # Author the next payload the realistic way: echo the live cell, change the prose.
    live = {c["id"]: c for c in tomllib.loads(rec.read_text(encoding="utf-8"))["cell"]}["1.1.1"]
    follow_up = dict(live)
    follow_up["residual"] = "a later, ordinary correction"
    follow_up["reviewed_by"] = "a later pass"
    rc = main([str(_payload(tmp_path, [follow_up])), "--scorecard", str(rec), "--apply"])
    assert rc == 0, "the cell is still frozen -- the control survived the repair"
    assert "a later, ordinary correction" in rec.read_text(encoding="utf-8")


def test_the_repair_WITNESS_is_what_the_provenance_counter_reads(tmp_path: Path) -> None:
    """The replacement signal, checked against its actual reader rather than asserted in isolation.

    Consuming the control destroys the only thing in the record saying a repair happened. This drives
    `anchor_provenance._repairs_declared` over a record the writer produced, so the decision to
    replace the signal is verified where it is consumed -- not where it was written.
    """
    import anchor_provenance

    rec = tmp_path / "asvs-scorecard.toml"
    rec.write_text(FIXTURE, encoding="utf-8")
    text = rec.read_text(encoding="utf-8")
    assert anchor_provenance._repairs_declared(text) == 0, "the control must fire, not the fixture"

    assert (
        main([str(_payload(tmp_path, [_cell_with_repair()])), "--scorecard", str(rec), "--apply"])
        == 0
    )
    after = rec.read_text(encoding="utf-8")
    assert "anchor_repair = true" not in after, "the control was persisted"
    assert anchor_provenance._repairs_declared(after) == 1, "the repair signal was destroyed"


# --- BACKLOG #1476: a whole-file re-render from a stale clone reverts cells it never named ---------
#
# A vault commit whose subject named ONE cell re-rendered the record and reverted an owner-approved
# repair on an unrelated one. The reverted bytes were IDENTICAL to the pre-repair state, which is the
# discriminating fact: a deliberate re-edit lands on some third value and a merge conflicts, so
# reproducing the old bytes exactly means the writer rendered from a base that predated the repair.
# It stood three days. No guard in this file could see it -- nothing was wrong with the payload.
#
# TWO GUARDS, EACH WITH A MUST-FIRE AND A MUST-NOT-FIRE ARM.
#
# (a) WHERE THE RECORD IS. `repo_stamp` reads the clone holding `--scorecard`, and BEHIND or DIVERGED
#     refuses. Driven against a REAL clone of a REAL origin that is genuinely behind, because the row
#     says the check "must run against a clone that is genuinely behind, not a fresh one, or it
#     passes on the only state that was never the problem". A monkeypatched stamp would assert the
#     branch and prove nothing about reading a work tree, which is the half that stops measuring.
#
# (b) STATED SCOPE AGAINST CELLS WRITTEN. Inside this writer "named versus changed" is vacuous -- it
#     only ever edits the spans it was handed. The gap that is not vacuous is between the OPERATOR's
#     intent and the payload they were handed, so `--scope` is an independent channel for the intent.


def _git(*args: str, cwd: Path) -> str:
    return subprocess.run(
        ["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True
    ).stdout.strip()


def _clone_holding_the_record(tmp_path: Path, *, behind: bool) -> Path:
    """A real clone of a real origin, holding the fixture record. Returns the record's path.

    When `behind`, origin gains a commit AFTER the clone is taken and the clone fetches it, so its
    remote-tracking ref is ahead of its own HEAD -- the exact state the defect rides in on, and a
    purely local one, since `repo_stamp` never touches the network.
    """
    origin = tmp_path / "origin"
    origin.mkdir()
    _git("init", "-b", "main", ".", cwd=origin)
    _git("config", "user.email", "t@example.com", cwd=origin)
    _git("config", "user.name", "t", cwd=origin)
    (origin / "asvs-scorecard.toml").write_text(FIXTURE, encoding="utf-8")
    _git("add", "-A", cwd=origin)
    _git("commit", "-m", "the record", cwd=origin)

    clone = tmp_path / "clone"
    _git("clone", str(origin), str(clone), cwd=tmp_path)
    if behind:
        (origin / "landed-after-the-clone-was-taken").write_text("x", encoding="utf-8")
        _git("add", "-A", cwd=origin)
        _git("commit", "-m", "another session landed a cell", cwd=origin)
        _git("fetch", "origin", cwd=clone)
    return clone / "asvs-scorecard.toml"


def test_a_write_from_a_clone_BEHIND_its_remote_is_REFUSED(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """MUST FIRE, and the refusal must carry the MEASURED gap rather than an adjective."""
    rec = _clone_holding_the_record(tmp_path, behind=True)
    before = rec.read_bytes()
    rc = main([str(_payload(tmp_path, [_cell_111()])), "--scorecard", str(rec), "--apply"])
    assert rc == 1
    assert rec.read_bytes() == before, "refused, but wrote anyway"
    out = capsys.readouterr().out
    assert "BEHIND 1" in out, out
    assert "upstream=origin/main" in out, "the gap is not a claim until you know behind WHAT"
    assert "remote-knowledge=" in out, "BEHIND 0 from a stale fetch is a different claim"


def test_a_write_from_a_CURRENT_clone_is_NOT_refused(tmp_path: Path) -> None:
    """MUST NOT FIRE. Without this arm the guard above is satisfied by a writer that refuses every
    clone, which is the shape that gets a guard disabled inside a day."""
    rec = _clone_holding_the_record(tmp_path, behind=False)
    rc = main([str(_payload(tmp_path, [_cell_111()])), "--scorecard", str(rec), "--apply"])
    assert rc == 0
    assert "1111111111" not in rec.read_text(encoding="utf-8"), "the write did not happen"


def test_a_DRY_RUN_from_a_stale_clone_is_refused_TOO(tmp_path: Path) -> None:
    """A dry run from a stale clone reports a clean, plausible, WRONG plan: the cells it would
    revert are not in the payload, so they are not in the report either. That report is what an
    operator reads before reaching for --apply."""
    rec = _clone_holding_the_record(tmp_path, behind=True)
    rc = main([str(_payload(tmp_path, [_cell_111()])), "--scorecard", str(rec)])
    assert rc == 1


def test_the_stale_clone_override_actually_unlocks_the_write(tmp_path: Path) -> None:
    """The escape hatch exists and works -- and it is a FLAG, so it appears in the shell history of
    whoever used it, which a silently-relaxed guard does not."""
    rec = _clone_holding_the_record(tmp_path, behind=True)
    rc = main(
        [
            str(_payload(tmp_path, [_cell_111()])),
            "--scorecard",
            str(rec),
            "--apply",
            "--allow-stale-clone",
        ]
    )
    assert rc == 0


def test_a_payload_writing_a_cell_the_SCOPE_DOES_NOT_NAME_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """MUST FIRE, with the out-of-scope ids LISTED -- which is what the row asks for, because a
    refusal that will not say which cell leaves the operator with nowhere to look."""
    rec = _record(tmp_path)
    before = rec.read_bytes()
    rc = main(
        [
            str(_payload(tmp_path, [_cell_111(), _naked_543()])),
            "--scorecard",
            str(rec),
            "--apply",
            "--scope",
            "1.1.1",
        ]
    )
    assert rc == 1
    assert rec.read_bytes() == before
    out = capsys.readouterr().out
    assert "written but NOT in --scope: ['5.4.3']" in out, out


def test_a_payload_MATCHING_its_declared_scope_applies(tmp_path: Path) -> None:
    """MUST NOT FIRE. The same two-cell payload, declared honestly, goes through."""
    rec = _record(tmp_path)
    rc = main(
        [
            str(_payload(tmp_path, [_cell_111(residual="rewritten"), _naked_543()])),
            "--scorecard",
            str(rec),
            "--apply",
            "--scope",
            "1.1.1,5.4.3",
        ]
    )
    assert rc == 0
    got = {c["id"]: c for c in tomllib.loads(rec.read_text(encoding="utf-8"))["cell"]}
    assert got["1.1.1"]["residual"] == "rewritten"


def test_a_SCOPE_NAMING_A_CELL_THE_PAYLOAD_DOES_NOT_CARRY_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The other direction, and it is not symmetry for its own sake: a scope naming a cell the
    payload does not carry means the payload is not what its author believes, which is the same
    mistake one step earlier in the same pipeline."""
    rec = _record(tmp_path)
    rc = main(
        [
            str(_payload(tmp_path, [_cell_111()])),
            "--scorecard",
            str(rec),
            "--apply",
            "--scope",
            "1.1.1,5.4.3",
        ]
    )
    assert rc == 1
    assert "in --scope but NOT written: ['5.4.3']" in capsys.readouterr().out


# --- the #1476 replay, SYNTHESIZED ----------------------------------------------------------------
#
# The row's proof-of-fix item 3 replays vault commits `c117e0a2` over `0d4df75c`. Those live in the
# vault clone, which CI never checks out, so the LITERAL replay stays a local manual check and this
# is the arm that rides in the engine suite. It reproduces the SHAPE rather than the bytes: a payload
# whose stated act is one cell, carrying a whole-record re-render in which an unrelated cell's
# absence claim is its PRE-REPAIR text.

#: The owner-approved repair, and the text it replaced. Distinct strings, so an assertion about one
#: cannot pass on the other -- the incident's whole signature is that the reverted bytes were
#: byte-identical to a state that had existed before.
_REPAIRED = "the repaired pattern, owner-approved 2026-08-28"
_PRE_REPAIR = "the pattern as it stood before that repair"

#: More cells than `_SCOPE_CEILING`, so an undeclared whole-file payload is over it. The repaired
#: cell sits in the middle rather than first or last: a guard that happened to look only at the
#: payload's head or tail would pass an arm that planted it at either end.
_MANY = 14
_REPAIRED_CELL = "9.7.1"


def _record_of_many(tmp_path: Path, *, pattern: str = _REPAIRED) -> Path:
    """A `_MANY`-cell record in which `_REPAIRED_CELL` carries an absence claim."""
    out = ['[scorecard]\nasvs_version = "5.0.0"\n']
    for i in range(_MANY):
        out.append(
            f'\n[[cell]]\nid = "9.{i}.1"\nlevel = 1\nverdict = "partial"\n'
            f'residual = "cell 9.{i}.1"\nlast_verified = "2026-08-09"\n'
            f'verified_at = "{i:040d}"\nreviewed_by = "fixture"\n'
            f'  [[cell.evidence]]\n  path = "messagefoundry/m.py"\n  line = {10 + i}\n'
            f'  expect = "token_{i}"\n'
        )
        if f"9.{i}.1" == _REPAIRED_CELL:
            out.append(
                f'  [[cell.absence]]\n  pattern = "{pattern}"\n'
                '  positive_control = "a planted match is found"\n'
                '  mutation = "remove the guard and the scan reds"\n'
            )
    p = tmp_path / "asvs-scorecard.toml"
    p.write_text("".join(out), encoding="utf-8")
    live = {c["id"]: c for c in tomllib.loads(p.read_text(encoding="utf-8"))["cell"]}
    assert len(live) == _MANY, live.keys()
    assert live[_REPAIRED_CELL]["absence"][0]["pattern"] == pattern
    return p


def _whole_file_payload_carrying_the_revert(rec: Path) -> list[dict]:
    """Every cell of the record, echoed -- with the repaired claim rolled back to its old text.

    Echoing the live cell is how a real re-render payload is built, which is the point: nothing in
    this payload is malformed, and every guard that reads a cell in isolation passes it.
    """
    cells = [dict(c) for c in tomllib.loads(rec.read_text(encoding="utf-8"))["cell"]]
    for c in cells:
        if c["id"] == _REPAIRED_CELL:
            c["absence"] = [{**c["absence"][0], "pattern": _PRE_REPAIR}]
    return cells


def test_the_1476_SHAPE_is_refused_when_it_states_NO_scope(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """MUST FIRE. A whole-record re-render that never says it is one does not get to be silent."""
    rec = _record_of_many(tmp_path)
    before = rec.read_bytes()
    rc = main(
        [
            str(_payload(tmp_path, _whole_file_payload_carrying_the_revert(rec))),
            "--scorecard",
            str(rec),
            "--apply",
        ]
    )
    assert rc == 1
    assert rec.read_bytes() == before
    assert _REPAIRED in rec.read_text(encoding="utf-8"), "the owner-approved repair was reverted"
    out = capsys.readouterr().out
    assert f"writes {_MANY} cells and states no scope" in out, out


def test_the_1476_SHAPE_is_refused_when_its_SCOPE_NAMES_ONLY_THE_CELL_ITS_SUBJECT_DID(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """MUST FIRE, and this is the arm closest to the incident. The commit's subject named one cell;
    stating that as the scope now makes the disagreement with the payload loud, and the cell holding
    the reverted repair is named in the refusal."""
    rec = _record_of_many(tmp_path)
    rc = main(
        [
            str(_payload(tmp_path, _whole_file_payload_carrying_the_revert(rec))),
            "--scorecard",
            str(rec),
            "--apply",
            "--scope",
            "9.0.1",
        ]
    )
    assert rc == 1
    assert _REPAIRED in rec.read_text(encoding="utf-8"), "the owner-approved repair was reverted"
    out = capsys.readouterr().out
    assert "written but NOT in --scope" in out, out
    assert f"'{_REPAIRED_CELL}'" in out, out


def test_the_TARGETED_edit_its_subject_CLAIMED_still_applies_and_the_REPAIR_SURVIVES(
    tmp_path: Path,
) -> None:
    """MUST NOT FIRE, and it is the arm without which the two above are satisfied by a tool that
    refuses everything. The act the commit announced -- one cell -- goes through, and the unrelated
    owner-approved repair is untouched, which is the outcome #1476 exists to secure."""
    rec = _record_of_many(tmp_path)
    one = next(
        dict(c)
        for c in tomllib.loads(rec.read_text(encoding="utf-8"))["cell"]
        if c["id"] == "9.0.1"
    )
    one["residual"] = "the one cell this run announced"
    rc = main(
        [
            str(_payload(tmp_path, [one])),
            "--scorecard",
            str(rec),
            "--apply",
            "--scope",
            "9.0.1",
        ]
    )
    assert rc == 0
    after = rec.read_text(encoding="utf-8")
    assert "the one cell this run announced" in after
    assert _REPAIRED in after, "the unrelated repair did not survive the targeted edit"
    assert _PRE_REPAIR not in after


def test_a_STATED_whole_file_re_render_is_ALLOWED(tmp_path: Path) -> None:
    """MUST NOT FIRE. The row is explicit that a legitimate whole-file re-verify needs an explicit
    way to say so, "or the guard gets disabled the first time it is inconvenient". So the ceiling
    makes a large write STATED, never impossible -- and a stated revert is a reviewable one."""
    rec = _record_of_many(tmp_path)
    cells = _whole_file_payload_carrying_the_revert(rec)
    rc = main(
        [
            str(_payload(tmp_path, cells)),
            "--scorecard",
            str(rec),
            "--apply",
            "--scope",
            ",".join(str(c["id"]) for c in cells),
        ]
    )
    assert rc == 0
    assert _PRE_REPAIR in rec.read_text(encoding="utf-8"), "the stated write did not happen"
