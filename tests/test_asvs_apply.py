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

from scripts.asvs.apply import main

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


def test_it_refuses_a_cell_that_is_not_in_the_record(tmp_path: Path) -> None:
    rec = _record(tmp_path)
    rc = main(
        [str(_payload(tmp_path, [_cell_111(id="9.9.9")])), "--scorecard", str(rec), "--apply"]
    )
    assert rc == 1


# --- the CLI contract ------------------------------------------------------------------------------


def test_scorecard_path_is_required_and_has_no_default(tmp_path: Path) -> None:
    """It used to be a hardcoded absolute path into the SHARED vault checkout.

    Several sessions edit that tree at once, so running the writer from a worktree rewrote a record the
    operator was not looking at. A default would restore that with a nicer spelling.
    """
    with pytest.raises(SystemExit) as e:
        main([str(_payload(tmp_path, [_cell_111()]))])
    assert e.value.code == 2  # argparse usage error, not a silent fallback
