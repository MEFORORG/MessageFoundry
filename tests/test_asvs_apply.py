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
import tomllib
from pathlib import Path

import pytest

from scripts.asvs.apply import (
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


# --------------------------------------------- BACKLOG #1363: a FULL-LIST retirement, 1 -> 0 or n -> 0


def _closed_543(**over: object) -> dict:
    """Cell 5.4.3 from the fixture: verdict ``na``, one anchor.

    ``na`` is the verdict that makes a full-list retirement expressible at all -- ``pass``/``partial``/
    ``fail`` each need at least one anchor or absence claim, so emptying their evidence trips a
    DIFFERENT guard and a test built on one of them would never reach the guard under test. The
    sibling test at ``test_a_declaration_whose_arithmetic_disagrees_is_refused`` records that trap.
    """
    base: dict = {
        "id": "5.4.3",
        "level": 2,
        "verdict": "na",
        "residual": "enterprise-provided control, outside the declared scope",
        "last_verified": "2026-08-02",
        "verified_at": "2222222222222222222222222222222222222222",
        "reviewed_by": "owner",
        "decision_closed": True,
        "decision_closed_by": "owner",
        "evidence": [],
    }
    base.update(over)
    return base


def test_a_FULL_LIST_retirement_is_expressible(tmp_path: Path) -> None:
    """BACKLOG #1363. THE ITEM. A declared, arithmetic-consistent retirement of EVERY anchor.

    ``--allow-retirement`` shipped under #1307 and genuinely works for a PARTIAL retirement, but the
    field-preservation guard runs FIRST and is a pure key-set difference. ``render()`` emits
    ``[[cell.evidence]]`` only from inside ``for a in cell.get("evidence") or []``, so emptying the
    list emits no block at all and the KEY VANISHES -- and ``set(was) - set(now)`` then refuses with
    "would LOSE field(s)" before the retirement logic is ever reached.

    That is the shape both authorised retirements take, so the sanctioned outcome #1307 exists to make
    expressible was still unreachable for the case that prompted it.
    """
    rec = _record(tmp_path)
    rc = main(
        [
            str(_payload(tmp_path, [_closed_543(retired_evidence=["messagefoundry/m.py:30"])])),
            "--scorecard",
            str(rec),
            "--apply",
            "--allow-retirement",
        ]
    )
    assert rc == 0, "a declared, arithmetic-consistent FULL-LIST retirement must go through"
    after = rec.read_text(encoding="utf-8")
    assert "_no_scan" not in after, "the retired anchor is still in the record"
    assert "retired_evidence" not in after, "the declaration leaked into the record"
    assert 'id = "1.1.1"' in after, "the untouched sibling cell was damaged"


def test_a_full_list_drop_WITHOUT_the_flag_is_still_refused(tmp_path: Path) -> None:
    """The arm without which the fix is indistinguishable from deleting the guard.

    It must still refuse, AND it must refuse as a RETIREMENT question rather than as a lost field --
    the message is what tells the operator which flag makes it expressible, and an unanswerable
    refusal is the one that gets re-run with an override reflexively.
    """
    rec = _record(tmp_path)
    before = rec.read_bytes()
    rc = main(
        [
            str(_payload(tmp_path, [_closed_543(retired_evidence=["messagefoundry/m.py:30"])])),
            "--scorecard",
            str(rec),
            "--apply",
        ]
    )
    assert rc == 1
    assert rec.read_bytes() == before


def test_a_full_list_drop_WITH_the_flag_but_NO_declaration_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The flag permits a DECLARED retirement, never any drop. A bare flag is a blanket bypass, and
    this guard exists because a truncating repair once cut one cell 15 -> 10 and another 17 -> 1 with
    the verifier green throughout.

    ASSERTS WHICH REFUSAL FIRED, NOT MERELY THAT ONE DID, and that is not fussiness -- a mutation run
    caught the first version of this row passing vacuously. With the declaration check removed the
    ARITHMETIC check refuses the same payload (declaring nothing while the count drops by one), so
    ``rc == 1`` held and the mutant survived the whole file. Two guards, one exit code.
    """
    rec = _record(tmp_path)
    before = rec.read_bytes()
    rc = main(
        [
            str(_payload(tmp_path, [_closed_543()])),
            "--scorecard",
            str(rec),
            "--apply",
            "--allow-retirement",
        ]
    )
    assert rc == 1
    assert "declares no 'retired_evidence'" in capsys.readouterr().out
    assert rec.read_bytes() == before


def test_a_full_list_drop_whose_arithmetic_disagrees_is_refused(tmp_path: Path) -> None:
    """Declaring TWO retirements while the count drops by ONE. The arithmetic check must survive the
    key-set exemption -- this is the truncation-behind-a-permit shape, at the full-list boundary."""
    rec = _record(tmp_path)
    before = rec.read_bytes()
    rc = main(
        [
            str(
                _payload(
                    tmp_path,
                    [
                        _closed_543(
                            retired_evidence=[
                                "messagefoundry/m.py:30",
                                "messagefoundry/m.py:31",
                            ]
                        )
                    ],
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
