# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Apply re-verified ASVS cells into the scorecard TOML, replacing whole [[cell]] blocks.

Rewrites only the named cells and leaves every other byte of the file alone, because the vault
working tree is shared and a whole-file re-emit would silently reformat another session's work.

Input JSON: [ {id, level, verdict, residual, evidence:[{path,line,expect}],
               absence:[{pattern,positive_control,mutation}]}, ... ]
"""

from __future__ import annotations

import argparse
import json
import re
import tomllib
from collections import Counter
from pathlib import Path
from typing import Any

VERDICTS = {"pass", "partial", "fail", "na", "needs-review", "unverified"}

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
def _control_keys() -> tuple[str, ...]:
    """Computed on EVERY call, deliberately, so the derivation is a live property rather than a
    snapshot. A module-level constant holding the same tuple is byte-identical in behaviour today and
    silently stops tracking `_SUBTABLES` the moment anyone edits it -- which is precisely the rot
    `_carried`'s docstring warns a name list invites. A mutation run proved that: a hand-written
    literal matching today's value passed every test, because there was no behaviour to differ on."""
    return tuple(f"retired_{name}" for name in _SUBTABLES)


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
    for key, value in {**(live or {}), **cell}.items():
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
    args = ap.parse_args(argv)
    allow_verdict_change = args.allow_verdict_change
    allow_retirement = args.allow_retirement
    SCORECARD = args.scorecard
    payload = json.loads(args.payload.read_text(encoding="utf-8"))
    dry = not args.apply

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
        # _SUBTABLES ARE EXEMPT HERE BECAUSE THE CARDINALITY CHECK BELOW OWNS THEM (BACKLOG #1363).
        # This is a pure KEY-SET difference, and `render()` emits `[[cell.evidence]]` only from
        # inside `for a in cell.get("evidence") or []` -- so retiring the LAST anchor emits no block
        # and the KEY VANISHES. That made a FULL-LIST retirement refuse here, before the retirement
        # logic below was ever reached: `--allow-retirement` shipped under #1307 and worked for a
        # PARTIAL retirement, while the shape both authorised retirements actually take stayed
        # unreachable. The sanctioned outcome #1307 exists to express could not be expressed for the
        # case that prompted it.
        #
        # EXEMPTING THEM WEAKENS NOTHING, AND THAT IS THE LOAD-BEARING CLAIM. Every case this check
        # would have caught for those two keys is caught below with a BETTER message, because
        # `len(now.get(sub, []))` reads an absent key as zero: a drop with no flag is refused and
        # told which flag to use, a flag with no declaration is refused, and a declaration whose
        # arithmetic disagrees is refused. The exemption is scoped to `_SUBTABLES` for the same
        # reason the retype check below excludes them -- they have their own comparison. Every OTHER
        # key must keep failing here, because nothing else re-checks it.
        lost = set(was) - set(now) - set(_SUBTABLES)
        if lost:
            print(f"REFUSING: cell {c['id']} would LOSE field(s) {sorted(lost)}")
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
