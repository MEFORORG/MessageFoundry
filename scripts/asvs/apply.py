# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Apply re-verified ASVS cells into the scorecard TOML, replacing whole [[cell]] blocks.

Rewrites only the named cells and leaves every other byte of the file alone, because the vault
working tree is shared and a whole-file re-emit would silently reformat another session's work.

Input JSON: [ {id, level, verdict, residual, evidence:[{path,line,expect,...}],
               absence:[{pattern,positive_control,mutation,...}]}, ... ]

Those sub-table keys are the ones this writer ORDERS, not the ones it accepts. Every other key on
an entry -- at least ``sym`` and ``ctx`` today, plus whatever is added next -- is emitted verbatim
by :func:`_carried`. **Enumerate what you ORDER, never what you KEEP**, which is the rule that
function states and this line used to break: read as exhaustive, it says the writer drops
``sym``/``ctx``, and the careful response to that is a hand edit "to preserve them" which loses the
very fields the tool would have kept. No count is given here on purpose -- a tally in a docstring
goes stale silently, and the field list is the thing that must not be re-enumerated.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from collections import Counter
from pathlib import Path
from typing import Any

# The sibling verifier, imported by PATH rather than as a package: `scripts/asvs` has no
# `__init__.py`, and the vault runs these tools as bare scripts from its own working directory.
# Inserting this file's own directory is what makes `import scorecard` resolve there as well as
# here -- the same line, for the same reason, as `anchor_provenance.py` and `anchor_report.py`.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from scorecard import repo_stamp  # noqa: E402

VERDICTS = {"pass", "partial", "fail", "na", "needs-review", "unverified"}

#: How many cells one payload may write WITHOUT naming them in `--scope` (BACKLOG #1476).
#:
#: A POLICY NUMBER RATHER THAN A MEASUREMENT, and saying so beats inventing a derivation for it.
#: What it is for is the gap between what a write SAYS and what it DOES: the incident behind #1476
#: announced one cell in its subject and changed most of the record. The exact rung matters far less
#: than the property -- a write big enough to hide a revert cannot happen until somebody types the
#: ids. A legitimate whole-file re-verify is still available; it just has to say so.
_SCOPE_CEILING = 10

#: The banner alphabet and the general emoji planes. CLAUDE.md section 11 bans these in prose; the
#: only sanctioned holdout is docs/BACKLOG.md, which this file is not. Fail closed rather than
#: writing one into a security record where a later reader would copy the vocabulary forward.
_BANNED = re.compile(
    "["
    "\u26a0\u26d4\u2705\u2b50\u274c\u2714\u2716\u2717\u2718"  # warning, no-entry, check, star, crosses
    # ONE range, not the adjacent pair 1f000-1f2ff + 1f300-1faff it replaces. Those are contiguous,
    # so the union is identical (asserted at the seam by
    # test_the_banned_class_is_one_contiguous_emoji_range); splitting them read as an overlapping
    # range to CodeQL, which analyses the class in UTF-16 where both halves share a high surrogate.
    "\U0001f000-\U0001faff"  # emoji planes
    "\u2190-\u21ff"  # arrows
    "\u2022"  # bullet
    "\ufe0f\ufe0e"  # variation selectors
    "]"
)


def _introduced_banned(payload: str, live: str) -> tuple[str, int] | None:
    """The first banned codepoint the payload carries MORE of than the record already does.

    Returns ``(character, how_many_more)`` or ``None``. BACKLOG #1308.

    Scanning the payload alone made a record UNWRITABLE once its own prose held a banned
    character: every payload must carry the residual forward, so every payload re-presented it and
    was refused. The comparison is what separates *carrying* from *introducing*.

    COUNTS, NOT PRESENCE. Presence alone would let a payload add a SECOND warning sign to a cell
    that already had one -- new vocabulary, which is exactly what the ban is for. Counting refuses
    that while allowing the character to be kept or moved.

    Iterating the PAYLOAD rather than the counter keys is deliberate: it makes the reported
    codepoint the first offender as written, so the refusal points at a place the author can find,
    and it is stable rather than dependent on dict ordering.
    """
    if not payload:
        return None
    live_counts = Counter(ch for ch in live if _BANNED.search(ch))
    payload_counts = Counter(ch for ch in payload if _BANNED.search(ch))
    for ch in payload:
        if ch in payload_counts and payload_counts[ch] > live_counts[ch]:
            return ch, payload_counts[ch] - live_counts[ch]
    return None


def toml_str(s: str) -> str:
    """A TOML basic string. JSON escaping is a strict subset of TOML's, so json.dumps is safe."""
    return json.dumps(s, ensure_ascii=False)


#: Scalar keys this writer knows how to emit. ANY OTHER scalar key found on the live cell is carried
#: through verbatim rather than dropped.
#:
#: This list was an ALLOWLIST once, and it silently deleted `decision_closed`, `decision_closed_verdict`,
#: `decision_closed_on` and `decision_closed_by` from the two owner-closed cells during an anchor
#: repair -- un-closing them. The gate passed, because an absent `decision_closed` is a valid False.
#: A green gate cannot distinguish PRESERVED from DROPPED, so the writer must never enumerate what it
#: keeps; it enumerates only what it ORDERS, and everything else survives by default.
_ORDERED = ("id", "level", "verdict", "residual", "last_verified", "verified_at", "reviewed_by")

#: Every field that can carry free text. anchor_repair must hold ALL of these byte-identical, not just
#: the one the glyph check reads -- otherwise the exemption is a bypass with a narrow mouth.
_PROSE_FIELDS = (
    "residual",
    "reviewed_by",
    "decision_closed_by",
    "decision_reopen_requires",
    "decision_permits_without_owner",
)
_SUBTABLES = ("evidence", "absence")


#: Keys the WRITER CONSUMES AS INSTRUCTIONS rather than storing as record fields (BACKLOG #1369).
#:
#: `--allow-retirement` requires the payload to DECLARE what it is retiring, and `:468` reads that
#: declaration off the cell dict. The carry loop below then wrote it straight back out, because a
#: control and a data field are indistinguishable once they share one dict -- so a run that retired
#: two anchors left `retired_absence = [...]` sitting in the record, where `scorecard.py` has no
#: reader for it and never will. The instruction outlived the operation it instructed.
#:
#: DERIVED FROM _SUBTABLES, NOT ENUMERATED. `_carried`'s docstring rejects a name-keyed fix -- "a
#: name-keyed fix satisfies the symptom and drops the next field anyone adds" -- and that objection
#: is right and applies here too. Deriving means a new sub-table brings its own control with it and
#: this line never changes, while a hand list would rot exactly as the docstring predicts.
#:
#: The derivation above covers the `retired_{sub}` FAMILY and nothing else, which is the whole of
#: what a derivation can reach. The constant below is the second source, for a control that belongs
#: to no family.


#: A control the `_SUBTABLES` derivation cannot reach, because it is not one of a family.
#:
#: NAMING IT IS CORRECT HERE AND IS NOT A RELAPSE INTO THE LIST `_carried` REJECTS, because the two
#: lists fail in opposite directions. A name list governing DATA loses the next field anyone adds,
#: silently and forever, and an absent field reads as a valid default -- that is the 7818991d
#: incident. A name list governing CONTROLS fails by keeping one key too many: the control is simply
#: persisted, which is visible in the record, readable by anyone who opens it, and recoverable on
#: the next write. Cheap and loud against expensive and silent.
#:
#: `anchor_repair` was the one it missed. The same function consumes it as an instruction -- it
#: relaxes the glyph and `reviewed_by` guards for exactly one run -- and nothing reads it back, so it
#: sat in the record FREEZING the cell: a later ordinary residual correction, authored from the live
#: cell and therefore carrying the flag forward, is refused with "declared anchor_repair but
#: 'residual' differs from the record". That is the #1333 freeze shape, reintroduced through a
#: persisted control.
_NAMED_CONTROLS = ("anchor_repair",)

#: The field the writer records INSTEAD, so consuming the instruction does not destroy the evidence.
#: `anchor_provenance._repairs_declared` counts cells that declare a repair and its docstring says
#: nothing else in the record marks one. That reader is why this exists: plain data, carrying the
#: date of the pass, read as an instruction by nothing.
_REPAIR_WITNESS = "anchor_repaired_at"


def _control_keys() -> tuple[str, ...]:
    """Computed on EVERY call, deliberately, so the derivation is a live property rather than a
    snapshot. A module-level constant holding the same tuple is byte-identical in behaviour today and
    silently stops tracking `_SUBTABLES` the moment anyone edits it -- which is precisely the rot
    `_carried`'s docstring warns a name list invites. A mutation run proved that: a hand-written
    literal matching today's value passed every test, because there was no behaviour to differ on."""
    return tuple(f"retired_{name}" for name in _SUBTABLES) + _NAMED_CONTROLS


#: The keys each sub-table entry is ORDERED by. Exactly the same distinction as `_ORDERED` one level
#: down: these fix the emission order, they do NOT define the set that survives. #1242 limb 4 -- the
#: entries were re-emitted as precisely these keys and nothing else, so a field inside an evidence or
#: absence entry was dropped on every rewrite. The promotion of this writer was specified to carry the
#: union through so the schema could grow without hand-editing the record; that was delivered for
#: top-level scalars and silently not for sub-table entries.
_EVIDENCE_ORDERED = ("path", "line", "expect")
_ABSENCE_ORDERED = ("pattern", "positive_control", "mutation")


#: A TOML bare key. Anything else must be QUOTED, and the reason is not cosmetic: a DOTTED key is not
#: a syntax error in TOML, it is a NESTING OPERATOR. `{1.2.2 = "x"}` is VALID and parses to
#: `{'1': {'2': {'2': 'x'}}}` -- the file loads, the gate stays green, the structure silently differs.
#: Every other bad key (spaces, quotes, empty) fails LOUDLY and is therefore safe. The dot is the only
#: one that corrupts quietly, and dotted identifiers are this record's native shape: requirement ids
#: like 1.2.2, version strings, file paths. So the rule is unconditional -- quote unless it matches
#: this exactly. "Quote the odd-looking ones" fails here, because 1.2.2 does not look odd.
_BARE_KEY = re.compile(r"^[A-Za-z0-9_-]+$")


def _toml_value(value: object) -> str:
    """Render any value as TOML. Recurses, so the quoting rule above applies at EVERY depth and
    inside arrays of tables -- measured, not assumed: a dot at depth 3 re-nests exactly as one at
    depth 1, and so does one inside a list.

    NOT ``json.dumps``. `{"a": 1}` is JSON, not TOML; an inline table is `{a = 1}`, key EQUALS value.
    Arrays happen to coincide between the two and tables do not, so a serializer that looks right on
    arrays emits a file that will not parse the moment a table appears.
    """
    if isinstance(value, bool):  # before int -- bool IS an int in Python
        return str(value).lower()
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, dict):
        inner = ", ".join(
            f"{k if _BARE_KEY.match(str(k)) else toml_str(str(k))} = {_toml_value(v)}"
            for k, v in value.items()
        )
        return "{ " + inner + " }" if inner else "{}"
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_toml_value(v) for v in value) + "]"
    return toml_str(str(value))


def _scalar(key: str, value: object) -> str:
    """#1242: the name is now a misnomer kept for its call sites -- it renders ANY value, not just a
    scalar. It used to fall through to ``toml_str(str(value))`` for anything that was not a bool or
    an int, so a TABLE or ARRAY became a quoted PYTHON REPR: `sym_table = "{'a': 1}"`. That parses,
    so nothing went red, and re-reading returned the STRING -- the value was not recoverable from the
    file. Every carry path routes through here (the top-level union walk, the rewrite, and
    ``_carried``), which is why one branch closes all three.
    """
    return f"{key} = {_toml_value(value)}"


def _carried(entry: dict[str, Any], ordered: tuple[str, ...]) -> list[str]:
    """Every key of a sub-table entry the writer does not ORDER, emitted verbatim after the ordered
    ones. The same rule the top-level loop follows -- enumerate what you ORDER, never what you KEEP.

    Deliberately NOT keyed on the field names that happen to exist today: a name-keyed fix satisfies
    the symptom and drops the next field anyone adds, which is the defect itself with a longer list.
    """
    return [f"  {_scalar(key, value)}" for key, value in entry.items() if key not in ordered]


def render(cell: dict[str, Any], live: dict[str, Any] | None = None) -> str:
    out = ["[[cell]]", f'id = "{cell["id"]}"', f"level = {int(cell['level'])}"]
    out.append(f'verdict = "{cell["verdict"]}"')
    if cell.get("residual"):
        out.append(f"residual = {toml_str(cell['residual'])}")
    out.append(f'last_verified = "{cell["last_verified"]}"')
    out.append(f'verified_at = "{cell["verified_at"]}"')
    if cell.get("reviewed_by"):
        out.append(f"reviewed_by = {toml_str(cell['reviewed_by'])}")
    # Carry through every other scalar from BOTH SOURCES -- decision_closed and friends off the live
    # cell, and anything a future schema adds that this writer has never heard of, from either side.
    #
    # The source is the UNION deliberately. Walking `live` alone meant a key arriving on the PAYLOAD
    # and absent from the vault was never iterated, so the `key in cell` skip never even evaluated for
    # it and the value was dropped -- the same silent loss as the allowlist incident above, one
    # direction over, and equally invisible downstream because an absent field reads as a valid
    # default. `cell` wins on a collision: the payload is the update.
    #
    # Skipping _ORDERED, _SUBTABLES and _CONTROL_KEYS keeps the rule the header states -- enumerate
    # what you ORDER, never what you KEEP. The old `key in cell` clause was an enumeration of the
    # second kind wearing a de-duplication's clothes: every key it legitimately suppressed is already
    # in _ORDERED.
    #
    # _CONTROL_KEYS is not a fourth enumeration of things to KEEP OUT: those keys are not record data
    # at all, they are instructions to this writer, and they are DERIVED from _SUBTABLES rather than
    # listed (BACKLOG #1369). Without it a retirement declaration is consumed at :468 and then written
    # back into the record, where nothing reads it -- the instruction outliving the operation.
    _controls = _control_keys()
    merged = {**(live or {}), **cell}
    # THE INSTRUCTION IS CONSUMED; THE FACT IT RECORDED IS KEPT (BACKLOG #1369). Dropping
    # `anchor_repair` un-freezes the cell, and it would also destroy the only thing in the record
    # saying a repair ever happened -- `anchor_provenance._repairs_declared` counts exactly that, and
    # its docstring says nothing else marks one. So the control leaves as DATA: same evidence,
    # carrying the date of the pass, read as an instruction by nothing. A re-render of a cell that
    # was never repaired adds nothing, so this cannot manufacture a witness.
    if cell.get("anchor_repair"):
        merged[_REPAIR_WITNESS] = str(cell.get("last_verified", ""))
    for key, value in merged.items():
        if key in _ORDERED or key in _SUBTABLES or key in _controls:
            continue
        out.append(_scalar(key, value))
    # The three explicit emissions in each loop below are an ORDERING, not a membership test, and the
    # `_carried` tail is what makes that true (#1242 limb 4). They are left spelled out rather than
    # generated so the ordered keys keep their exact typing -- `line` stays an int through int(), the
    # rest stay TOML basic strings -- which keeps every byte of today's output identical.
    for a in cell.get("evidence") or []:
        out.append("  [[cell.evidence]]")
        out.append(f"  path = {toml_str(a['path'])}")
        out.append(f"  line = {int(a['line'])}")
        out.append(f"  expect = {toml_str(a['expect'])}")
        out.extend(_carried(a, _EVIDENCE_ORDERED))
    for a in cell.get("absence") or []:
        out.append("  [[cell.absence]]")
        out.append(f"  pattern = {toml_str(a['pattern'])}")
        out.append(f"  positive_control = {toml_str(a['positive_control'])}")
        out.append(f"  mutation = {toml_str(a['mutation'])}")
        out.extend(_carried(a, _ABSENCE_ORDERED))
    return "\n".join(out) + "\n"


def block_spans(text: str) -> dict[str, tuple[int, int]]:
    """Map cell id -> (start, end) character offsets of its whole top-level [[cell]] block."""
    starts = [m.start() for m in re.finditer(r"^\[\[cell\]\]$", text, re.M)]
    spans: dict[str, tuple[int, int]] = {}
    for i, s in enumerate(starts):
        e = starts[i + 1] if i + 1 < len(starts) else len(text)
        m = re.search(r'^id = "([^"]+)"$', text[s:e], re.M)
        if not m:
            raise SystemExit(f"a [[cell]] block at offset {s} has no id")
        spans[m.group(1)] = (s, e)
    return spans


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Apply re-verified ASVS cells into the scorecard TOML (ADR 0156).",
    )
    ap.add_argument("payload", type=Path, help="JSON array of cells to write")
    # REQUIRED, and deliberately not defaulted. This was a hardcoded absolute path into the SHARED
    # vault checkout -- a tree several sessions edit at once -- so running the writer from a worktree
    # silently rewrote a record the operator was not looking at. A default here would restore that
    # failure with a nicer spelling: the one thing a writer must never guess is WHICH record it is
    # rewriting.
    ap.add_argument("--scorecard", type=Path, required=True, help="path to asvs-scorecard.toml")
    ap.add_argument(
        "--apply",
        action="store_true",
        help="write. Omitted, the run is a dry run and the file is not touched.",
    )
    ap.add_argument(
        "--allow-retirement",
        action="store_true",
        help=(
            "permit an evidence/absence list to SHRINK, but ONLY where the payload DECLARES the "
            "retirement. Refused by default: a silent cardinality drop is what this guard exists "
            "to stop, and the flag alone is not enough -- see retired_evidence / retired_absence."
        ),
    )
    ap.add_argument(
        "--allow-verdict-change",
        action="store_true",
        help=(
            "permit a payload to move a cell's verdict. Refused by default: a verdict move is an "
            "assessor decision, and this writer's failure mode is making one during a pass whose "
            "stated purpose was mechanical."
        ),
    )
    ap.add_argument(
        "--allow-stale-clone",
        action="store_true",
        help=(
            "write even though the clone holding --scorecard reads BEHIND or DIVERGED. Refused by "
            "default: a write from a stale base re-renders every cell landed since that base back "
            "to its old value, and the payload cannot show you that."
        ),
    )
    ap.add_argument(
        "--scope",
        default=None,
        help=(
            "comma-separated cell ids this run is allowed to write. The payload's ids must match "
            "EXACTLY: an id the payload writes and the scope does not name is refused, and so is "
            f"one the scope names and the payload does not carry. Required above {_SCOPE_CEILING} "
            "cells, which is how a whole-file re-render says it is one."
        ),
    )
    args = ap.parse_args(argv)
    allow_verdict_change = args.allow_verdict_change
    allow_retirement = args.allow_retirement
    SCORECARD = args.scorecard
    payload = json.loads(args.payload.read_text(encoding="utf-8"))
    dry = not args.apply

    # WHERE THE RECORD IS, NOT ONLY WHAT THE PAYLOAD SAYS (BACKLOG #1476). A targeted edit written
    # from a clone whose base predates other sessions' landed cells re-renders those cells back to
    # their old values. It has fired: a vault commit whose subject named one cell reverted an
    # owner-approved repair on an unrelated one, byte-identically to the pre-repair state, and stood
    # three days. No guard in this file could see it, because nothing was wrong with the payload --
    # the writer faithfully rendered a value it should never have been holding. So ask the clone.
    #
    # MEASURED, AND NEVER SILENT WHEN IT CANNOT MEASURE. `repo_stamp` is a pure local read -- no
    # fetch, no network -- so a clone that has not fetched in a week can read CURRENT and still be
    # stale. That is exactly why `remote-knowledge` is printed beside the verdict instead of being
    # left out: BEHIND 0 from a six-hour-old fetch and from a one-minute-old fetch are different
    # claims. The two states refused are the two that carry the defect; every other state --
    # NO-GIT, NO-UPSTREAM, UNRESOLVED -- is REPORTED and allowed, because a guard that refuses on
    # states that were never the problem is a guard someone disables, and this file already says so
    # about the verdict-move refusal.
    stamp = repo_stamp(SCORECARD)
    where = (
        f"{SCORECARD} is at {stamp.ref()}: freshness={stamp.freshness} "
        f"upstream={stamp.upstream} remote-knowledge={stamp.remote_knowledge}"
    )
    if (
        stamp.freshness.startswith("BEHIND ") or stamp.freshness == "DIVERGED"
    ) and not args.allow_stale_clone:
        # REFUSED ON A DRY RUN TOO. A dry run from a stale clone reports a clean, plausible,
        # wrong plan -- the cells it would revert are not in the payload and so are not in the
        # report -- and that report is what an operator reads before reaching for --apply.
        print(f"REFUSING: {where}")
        print(
            "  A write from this base would re-render every cell landed since it back to its old "
            "value. Pull the clone, rebuild the payload from the current record, and re-run. "
            "--allow-stale-clone overrides."
        )
        return 1
    print(f"  note: {where}")

    # STATED SCOPE AGAINST CELLS WRITTEN (BACKLOG #1476). This writer only ever edits the spans of
    # the cells the payload names, so comparing "named" against "changed" INSIDE it is vacuous --
    # they are the same set by construction. The gap that is not vacuous is between the operator's
    # intent and the payload they were handed: a generator that emits 298 cells under a one-cell
    # heading produces a payload this tool has no reason to doubt. `--scope` is the independent
    # channel that states the intent, so the two can disagree out loud.
    payload_ids = [str(c.get("id")) for c in payload]
    if args.scope is not None:
        declared = {s.strip() for s in args.scope.split(",") if s.strip()}
        written = set(payload_ids)
        unscoped, unwritten = sorted(written - declared), sorted(declared - written)
        if unscoped or unwritten:
            print("REFUSING: the payload's cells do not match the declared scope.")
            # BOTH DIRECTIONS, NAMED SEPARATELY. Writing a cell nobody declared is the #1476 shape;
            # declaring one the payload does not carry means the payload is not what its author
            # thinks it is, which is the same mistake one step earlier.
            if unscoped:
                print(f"  written but NOT in --scope: {unscoped}")
            if unwritten:
                print(f"  in --scope but NOT written: {unwritten}")
            return 1
    elif len(payload_ids) > _SCOPE_CEILING:
        print(
            f"REFUSING: this payload writes {len(payload_ids)} cells and states no scope "
            f"(the unstated ceiling is {_SCOPE_CEILING}). A write this size must name its cells: "
            "re-run with --scope <id>,<id>,... A whole-file re-verify is allowed and this is how "
            "it says so."
        )
        return 1

    live_text = SCORECARD.read_text(encoding="utf-8")
    live_cells = {x["id"]: x for x in tomllib.loads(live_text)["cell"]}

    problems: list[str] = []
    for c in payload:
        live = live_cells.get(c.get("id"), {})
        # An ANCHOR REPAIR re-points citations after the code moved; it must not touch anything else.
        # Declaring it lets two guards relax in a way that is strictly more conservative than the
        # alternative: the residual passes through BYTE-IDENTICAL, so no retired glyph can enter the
        # record that was not already in it, and an existing empty `reviewed_by` is preserved rather
        # than invented. Any difference in verdict or residual takes it out of this mode immediately.
        anchor_repair = bool(c.get("anchor_repair"))
        if anchor_repair and live.get("anchor_repair"):
            # A cell whose RECORD already carries the control is frozen, and the freeze is invisible
            # from the payload's side: a payload authored by echoing the live cell carries the flag
            # forward without anyone choosing it, and then every prose field must stay byte-identical
            # or the run refuses. This write strips the key, so the freeze lifts here -- but say so,
            # because a refusal the operator cannot explain gets re-run with an override.
            print(
                f"  note: {c.get('id')} carries a PERSISTED anchor_repair in the record "
                "(BACKLOG #1369) and this write strips it. If the payload echoed it from the live "
                "cell rather than meaning a fresh repair, drop it and re-run."
            )
        if anchor_repair:
            # Assert byte-identity on EVERY prose-bearing field, not just the two the glyph check
            # reads. Holding only verdict+residual was sound by argument -- the writer never rewrites
            # the others -- but an argument is worth less than a check, and it left the next reader to
            # reconstruct why two were sufficient.
            for f in _PROSE_FIELDS:
                if c.get(f, live.get(f, "")) != live.get(f, ""):
                    problems.append(
                        f"{c.get('id')}: declared anchor_repair but {f!r} differs from the record; "
                        "that is a rescore, not a repair"
                    )
            if c.get("verdict") != live.get("verdict"):
                problems.append(
                    f"{c.get('id')}: declared anchor_repair but the verdict differs from the "
                    "record; that is a rescore, not a repair"
                )
        required: tuple[str, ...] = ("id", "level", "verdict", "last_verified", "verified_at")
        if not anchor_repair:
            required = required + ("reviewed_by",)
        for field in required:
            if not c.get(field) and c.get(field) != 0:
                problems.append(f"{c.get('id')}: missing {field}")
        if c.get("verdict") not in VERDICTS:
            problems.append(f"{c.get('id')}: bad verdict {c.get('verdict')!r}")
        # A VERDICT MOVE IS AN ASSESSOR ACT AND MUST BE DECLARED. This writer's whole failure mode is
        # silent verdict movement during a pass whose stated purpose was mechanical: an anchor repair,
        # a re-render, a bulk transform. Everything else here is a refusal against malformed input;
        # this is the one refusal against a WELL-FORMED payload that means more than its author
        # intended. So the safe thing is the default and the dangerous thing is explicit.
        #
        # The message names the cell and BOTH verdicts on purpose. A refusal that says only "verdict
        # changed" leaves the operator's actual next question -- which cell, and to what -- unanswered,
        # and an unanswerable refusal gets re-run with the override flag reflexively, which converts
        # the guard into a speed bump.
        if live and c.get("verdict") != live.get("verdict") and not allow_verdict_change:
            problems.append(
                f"{c['id']}: verdict would change {live.get('verdict')!r} -> {c.get('verdict')!r}. "
                "That is an assessor decision, not a mechanical edit. Re-run with "
                "--allow-verdict-change if you mean it"
            )
        if c.get("verdict") == "na" and not (c.get("residual") or "").strip():
            problems.append(f"{c['id']}: verdict 'na' requires a written rationale in residual")
        if c.get("verdict") in {"pass", "partial", "fail"} and not (
            c.get("evidence") or c.get("absence")
        ):
            problems.append(f"{c['id']}: {c['verdict']} needs at least one anchor or absence claim")
        # SCAN WHAT THE PAYLOAD INTRODUCES, NOT WHAT THE RECORD ALREADY CARRIES (BACKLOG #1308).
        #
        # THE DEFECT THIS FIXES IS UNWRITABILITY, NOT UNTIDINESS -- read the other way round it
        # reads as a cosmetic item and gets deferred forever. Scanning the whole residual meant a
        # cell whose EXISTING prose held a banned character could never be written again by this
        # tool, however mechanical the edit: every payload has to carry the residual forward, so
        # every payload re-presented the same character and was refused. The record became
        # read-only through its own guard, and the only way to touch it was to edit prose the pass
        # was not about.
        #
        # COUNTED PER CODEPOINT, not merely "is it present". Presence alone would let a payload
        # ADD a second warning sign to a cell that already had one -- new vocabulary, which is the
        # thing the ban exists to stop. Counting refuses that while allowing the character to be
        # kept or MOVED, since neither introduces anything a later reader could copy forward.
        #
        # FAIL-CLOSED WHERE THERE IS NO RECORD: a cell with no live counterpart has a live count of
        # zero for everything, so any banned character in a NEW cell is introduced and refused.
        payload_residual = "" if anchor_repair else str(c.get("residual", "") or "")
        introduced = _introduced_banned(
            payload_residual, str((live or {}).get("residual", "") or "")
        )
        if introduced:
            # Report the codepoint, never the character: echoing it to a cp1252 console raises
            # UnicodeEncodeError and the refusal turns into a traceback that hides its own reason.
            ch, extra = introduced
            problems.append(
                f"{c['id']}: residual INTRODUCES a banned glyph U+{ord(ch):04X} "
                f"({extra} more than the record already carries)"
            )
    if problems:
        print("REFUSING TO APPLY:")
        for p in problems:
            print("  " + p)
        return 1

    text = SCORECARD.read_text(encoding="utf-8")
    spans = block_spans(text)

    edits = []
    for c in payload:
        if c["id"] not in spans:
            print(f"REFUSING: cell {c['id']} not present in the scorecard")
            return 1
        s, e = spans[c["id"]]
        old = text[s:e]
        if "decision_closed = true" in old:
            # The method permits exactly ONE change to a closed cell without the owner: repairing a
            # broken evidence anchor, re-anchored by content. So allow it only when the verdict and
            # the residual are byte-identical to what is already recorded -- i.e. anchors only.
            import tomllib as _t

            live = {x["id"]: x for x in _t.loads(text)["cell"]}[c["id"]]
            if c["verdict"] != live["verdict"] or c.get("residual", "") != live.get("residual", ""):
                print(
                    f"REFUSING: cell {c['id']} is decision_closed and this edit changes its "
                    "verdict or residual; only an anchor repair is permitted without the owner"
                )
                return 1
            print(
                f"  note: {c['id']} is decision_closed - anchor-only repair, verdict and residual unchanged"
            )
        edits.append((s, e, render(c, live_cells.get(c["id"], {})), old))

    new_text = text
    for s, e, rendered, _old in sorted(edits, key=lambda t: -t[0]):
        new_text = new_text[:s] + rendered + new_text[e:]

    # Parse before writing: a scorecard that does not load is worse than one not updated.
    parsed = tomllib.loads(new_text)
    by_id = {c["id"]: c for c in parsed["cell"]}
    for c in payload:
        got = by_id[c["id"]]["verdict"]
        if got != c["verdict"]:
            print(f"REFUSING: round-trip mismatch on {c['id']}: {got!r} != {c['verdict']!r}")
            return 1
    if len(parsed["cell"]) != len(spans):
        print(f"REFUSING: cell count changed {len(spans)} -> {len(parsed['cell'])}")
        return 1

    # FIELD-PRESERVATION INVARIANT. A rewrite must never silently DROP a key, and the anchor gate
    # cannot see that: an absent `decision_closed` is a valid False, so un-closing an owner-closed
    # cell reads as green. Assert cardinality too - a repair that deletes working anchors also passes
    # a resolution check, because fewer anchors that all resolve is a passing state.
    for c in payload:
        was, now = live_cells[c["id"]], by_id[c["id"]]
        # A SUB-TABLE KEY THAT VANISHED BECAUSE ITS LIST WAS EMPTIED IS NOT A DROPPED KEY, and telling
        # those two apart is the whole of BACKLOG #1363 (re-filed independently as #1484). `render()`
        # emits no block for an empty list, so a FULL-LIST retirement loses the key on the round-trip
        # and this pure key-set difference refused it -- sixty lines before the code that AUTHORISES a
        # retirement is ever read. Measured both ways before the fix, with the flag, the declaration
        # and the arithmetic all held constant: evidence 2 -> 1 exited 0 and wrote the file, absence
        # 1 -> 0 exited 1 on "would LOSE field(s) ['absence']" and never printed RETIRING.
        #
        # THIS EXCUSES; IT DOES NOT AUTHORISE. The declaration and the arithmetic stay exactly where
        # they are, in the retirement branch below, which is the only place that knows `before` and
        # `after` and can refuse a declaration that fails to account for every removed entry. All this
        # set does is stop the key-set guard answering FIRST, and only on the state that branch is
        # about to examine: the flag is set AND the payload declares a retirement for THAT sub-table.
        # Undeclared, or without the flag, the key stays in `lost` and refuses here exactly as before.
        # That asymmetry is what #1363 says any fix must preserve -- a bare reordering of the two
        # checks converts a loud false refusal into a quiet always-pass, which is worse than the bug.
        #
        # A CONTROL KEY ALREADY IN THE RECORD IS LIKEWISE NOT A DROPPED FIELD (#1369). `render`
        # consumes controls and declines to store them, so rewriting a cell that already carries one
        # strips it BY DESIGN -- and without this exclusion the fix for #1369 would make every such
        # cell PERMANENTLY UNWRITABLE by this tool, which is the same unwritability #1308 had to
        # undo once already. The strip is the point: it is what lifts the freeze.
        excused = {sub for sub in _SUBTABLES if allow_retirement and c.get(f"retired_{sub}")}
        lost = set(was) - set(now) - excused - set(_control_keys())
        if lost:
            # Name the retirement route when the lost key is a sub-table. This refusal is otherwise
            # unanswerable for the one legitimate way to reach it -- the operator is told a key
            # vanished, not that the tool has a flag for exactly this -- and an unanswerable refusal
            # is what turns a guard into a speed bump, which is the reasoning the verdict-move
            # refusal above already states in full.
            emptied = sorted(lost & set(_SUBTABLES))
            route = ""
            if emptied:
                names = " and ".join(f"'retired_{s}'" for s in emptied)
                route = (
                    f" If that is a RETIREMENT, declare it in the payload as {names} and "
                    "re-run with --allow-retirement"
                )
            print(f"REFUSING: cell {c['id']} would LOSE field(s) {sorted(lost)}{route}")
            return 1
        # ...and the same question about the VALUE rather than the key (#1242). The check above is a
        # pure KEY-SET difference, so a field whose value was type-mangled -- a table rewritten as a
        # quoted Python repr -- KEEPS ITS KEY and passes it. That is not an oversight in the check
        # above; it was written to catch DROPPED KEYS and it does. It is simply blind to this, and a
        # rewrite that corrupts every value while preserving every key would report green.
        #
        # COMPARE AGAINST THE TYPE THE PAYLOAD STATED, rather than declining to look at keys it
        # carries. The intent behind the original scoping is right and is preserved: a payload that
        # INTENTIONALLY retypes a field -- schema evolution, a scalar becoming a table -- is an EDIT,
        # not damage, and a guard that refuses legitimate edits is a guard someone disables.
        #
        # RETRACTED AND WHY (#1242): the first version expressed that as `k not in c`, which skipped
        # every key the payload carries. Measured by the ASVS Tracker against this author's own
        # scoping -- with the writer's dict branch disabled, a payload OMITTING the key was refused
        # while a payload CARRYING it exited 0 and wrote a Python repr into a TOML string. So the
        # guard stopped looking at the exact moment a cell is rewritten. That is not a corner: of
        # the whole record exactly ONE cell holds a top-level non-scalar, and the natural payload
        # for rewriting that cell ECHOES the key -- the guard covered every cell that cannot be hurt.
        # (The record's cell TOTAL is deliberately not stated here. It is vault-derived, this file
        # ships to PyPI, and a coverage count over a closed public requirement set discloses the
        # uncovered set by subtraction. `main` already words it this way; the figure is the only
        # thing that differs, and it must not come back through a merge.)
        #
        # The payload IS the record of the type the author asked for, so it can be compared against.
        # An intentional retype agrees with its own payload and still passes; a writer corruption
        # disagrees whether or not the payload happened to mention the key.
        #
        # _ORDERED is excluded because render() deliberately COERCES those -- `int(cell['level'])`
        # and the quoted emissions -- so a payload stating another type there is NORMALISED BY
        # DESIGN, and refusing it would be the false-refusal this scoping exists to prevent.
        # _SUBTABLES are excluded because they have their own key comparison below.
        retyped = sorted(
            k
            for k in was
            if k in now
            and k not in _ORDERED
            and k not in _SUBTABLES
            and type(c[k] if k in c else was[k]) is not type(now[k])  # noqa: E721
        )
        if retyped:
            print(
                f"REFUSING: cell {c['id']} would CHANGE the TYPE of field(s) {retyped} "
                f"(key kept, value corrupted -- the key-set check above cannot see this)"
            )
            return 1
        for sub in ("evidence", "absence"):
            before, after = len(was.get(sub, [])), len(now.get(sub, []))
            if after < before:
                # RETIREMENT IS A SANCTIONED OUTCOME THIS WRITER COULD NOT EXPRESS (BACKLOG #1307).
                # One of the tracking loop's four causes for an anchor that no longer resolves is
                # "the gap it certified was CLOSED, so retire it" -- the case where the engine got
                # BETTER and the fix deleted the line the anchor quoted. Before this the only ways
                # out were leaving a stale anchor in place or reaching for the unsafe writer.
                #
                # THE FLAG ALONE DELIBERATELY DOES NOT UNLOCK IT. A bare --allow-retirement would
                # be a blanket bypass, and this guard exists because a truncating repair once cut
                # one cell 15 -> 10 and another 17 -> 1 WITH THE VERIFIER GREEN THROUGHOUT. So the
                # payload must DECLARE the retirement AND the arithmetic must agree: declare one
                # and drop two and this still refuses. The declaration is what keeps the refusal
                # answerable instead of turning the guard into a speed bump.
                declared = c.get(f"retired_{sub}") or []
                if not allow_retirement:
                    print(
                        f"REFUSING: cell {c['id']} {sub} count would DROP {before} -> {after}. "
                        f"If this is a RETIREMENT, declare it in the payload as "
                        f"'retired_{sub}' and re-run with --allow-retirement"
                    )
                    return 1
                if not declared:
                    print(
                        f"REFUSING: cell {c['id']} {sub} would DROP {before} -> {after} and "
                        f"--allow-retirement was given, but the payload declares no "
                        f"'retired_{sub}'. The flag permits a DECLARED retirement, not any drop"
                    )
                    return 1
                if before - after != len(declared):
                    print(
                        f"REFUSING: cell {c['id']} {sub} declares {len(declared)} retirement(s) "
                        f"but the count drops by {before - after} ({before} -> {after}). The "
                        f"declaration must account for every removed entry"
                    )
                    return 1
                print(
                    f"RETIRING: cell {c['id']} {sub} {before} -> {after}, declared: "
                    f"{', '.join(str(d) for d in declared)}"
                )
            # ...and the same question one level down (#1242 limb 4). Counting ENTRIES cannot see a
            # FIELD vanish from inside one, so a sub-table entry could be rewritten with fewer keys
            # while the count matched and this invariant reported green -- exactly the state the
            # top-level `set(was) - set(now)` above exists to prevent.
            for i, (wsub, nsub) in enumerate(zip(was.get(sub, []), now.get(sub, []), strict=False)):
                lost_sub = set(wsub) - set(nsub)
                if lost_sub:
                    print(
                        f"REFUSING: cell {c['id']} {sub}[{i}] would LOSE field(s) {sorted(lost_sub)}"
                    )
                    return 1

    print(f"{len(edits)} cell blocks re-rendered; file parses; {len(parsed['cell'])} cells intact")
    for c in payload:
        print(
            f"  {c['id']:<8} -> {c['verdict']:<12} "
            f"({len(c.get('evidence') or [])} anchors, {len(c.get('absence') or [])} absence)"
        )
    if dry:
        print("\nDRY RUN. Re-run with --apply to write.")
        return 0
    SCORECARD.write_text(new_text, encoding="utf-8", newline="")
    print(f"\nWROTE {SCORECARD}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
