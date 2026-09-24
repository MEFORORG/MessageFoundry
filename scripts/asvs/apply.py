# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

# `_git` is private to `scorecard`, and taken deliberately rather than re-implemented here: it is one
# read-only probe with a timeout and a standing prohibition on any command that writes, and a second
# copy of that plumbing in this file is a second place for the no-network rule to rot. The two modules
# already share a process and a directory. `scorecard.py` is mirrored into the vault byte-for-byte
# (tests/test_asvs_verifier_vault_contract.py), so this name does not drift out from under us silently.
from scorecard import _git, repo_stamp  # noqa: E402

VERDICTS = {"pass", "partial", "fail", "na", "needs-review", "unverified"}

#: The branch that IS the record, and the ref BACKLOG #1476's question is actually about.
#:
#: NOT the same question as `repo_stamp().freshness`, which measures HEAD against the branch's OWN
#: `@{upstream}` when it has one. On a pushed feature branch -- how the record is normally edited --
#: a clone can be perfectly current with `origin/<branch>` while missing every cell landed here since
#: the branch was cut. Such a clone re-renders those cells back to their old values, and the branch
#: reading prints CURRENT while it happens. `_freshness` is not wrong: it returns the upstream it
#: used precisely BECAUSE the two are different questions. Choosing which one to refuse on is the
#: caller's job, and this file is the caller.
_RECORD_LINE = "origin/main"

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


def _record_line_gap(record: Path) -> tuple[int | None, str]:
    """``(commits on the record line this clone lacks, a printable reading)``.

    The count is the number of commits reachable from ``origin/main`` and not from ``HEAD``. That is
    the whole question BACKLOG #1476 asks, and it answers the same on every branch: a feature branch
    cut from a current record line reads zero however far ahead of its own upstream it has run, and
    one cut from a stale base reads the gap even when it is perfectly in step with the ref it tracks.

    ``None`` when the question cannot be ASKED here -- no work tree, or no ``origin/main`` in this
    clone -- and NEVER when it can be asked and the answer is zero. An unaskable question and a
    measured zero are different claims and must not print the same string; that is the never-silent
    rule :class:`RepoStamp` states, from the caller's side.

    No network, for the reason ``scorecard._git`` gives: a query that fetches gets bypassed, and a
    bypassed guard is worse than none because its absence reads as nobody needing it.
    """
    repo = record if record.is_dir() else record.parent
    if _git(repo, "rev-parse", "--verify", f"{_RECORD_LINE}^{{commit}}") is None:
        return None, f"UNASKABLE ({_RECORD_LINE} is not in this clone)"
    behind = _git(repo, "rev-list", "--count", f"HEAD..{_RECORD_LINE}")
    if behind is None or not behind.isdigit():
        return None, f"UNRESOLVED against {_RECORD_LINE}"
    n = int(behind)
    return n, (f"BEHIND {n} of {_RECORD_LINE}" if n else f"CURRENT with {_RECORD_LINE}")


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


def toml_str(s: object) -> str:
    """A TOML basic string, ALWAYS a string, whatever type it was handed.

    The ``str()`` is load-bearing. The type guard in ``main`` excludes ``_ORDERED`` because this
    writer COERCES those fields, and ``json.dumps`` alone does not: handed an int, a bool, a list or a
    dict it emits a TOML int, bool or array, or a JSON object that does not parse at all (BACKLOG
    #1883, #1884 limb 4). Coercing here makes that exclusion's premise true for every caller at once.

    JSON escapes every control character TOML forbids except one: DEL (U+007F), which ``json.dumps``
    leaves raw and ``tomllib`` rejects. So it is escaped by hand.
    """
    return json.dumps(str(s), ensure_ascii=False).replace("\x7f", "\\u007f")


#: Scalar keys this writer knows how to emit. ANY OTHER scalar key found on the live cell is carried
#: through verbatim rather than dropped.
#:
#: This list was an ALLOWLIST once, and it silently deleted `decision_closed`, `decision_closed_verdict`,
#: `decision_closed_on` and `decision_closed_by` from the two owner-closed cells during an anchor
#: repair -- un-closing them. The gate passed, because an absent `decision_closed` is a valid False.
#: A green gate cannot distinguish PRESERVED from DROPPED, so the writer must never enumerate what it
#: keeps; it enumerates only what it ORDERS, and everything else survives by default.
_ORDERED = ("id", "level", "verdict", "residual", "last_verified", "verified_at", "reviewed_by")
#: The ordered fields `render` omits when empty. Every other ordered field is always written, which
#: is why `main` requires them; `reviewed_by` is required too unless the run is an anchor repair.
_OPTIONAL_ORDERED = ("residual", "reviewed_by")

#: AT LEAST these top-level keys carry free text. **NOT every field that can** -- `posture`,
#: `decision_closed_on`, anything a payload invents, and all sub-table text (`evidence[].expect`,
#: `absence[].pattern`, and their siblings) are free text this tuple does not name and neither guard
#: below covers. An enumeration that calls itself complete is the liability SDS-3.6 names, and this
#: one said "every field" while covering none of that. Widening the guards to the whole emitted
#: surface is a real defect and not this tuple's job to hide.
#:
#: TWO guards read the tuple -- the `anchor_repair` byte-identity check and the banned-glyph
#: introduction scan -- and BOTH must read all of it. Narrow either and the exemption becomes a
#: bypass with a narrow mouth. That is not hypothetical: the scan read `residual` alone while this
#: tuple named five, so a glyph could enter the other four unremarked (BACKLOG #1333). The two are
#: coupled tighter still, because the scan skips itself under `anchor_repair` on the strength of the
#: byte-identity loop, so narrowing THAT one silently opens the scan as well.
#:
#: Tests pin all three edges -- each guard's loop, and the membership of this tuple itself. The
#: tuple needs its own arm because the tests parametrize OVER it: shrink it and the parametrized
#: arms shrink with it, reporting fewer passes rather than a failure.
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

#: The ordered keys per sub-table, so the preservation guard can exclude them one level down exactly
#: as it excludes `_ORDERED` one level up: `render()` COERCES these by design -- `line` through
#: `int()`, the rest through `toml_str` -- so a payload stating another type there is NORMALISED, and
#: refusing it would be the false refusal that gets a guard disabled.
_SUBTABLE_ORDERED: dict[str, tuple[str, ...]] = {
    "evidence": _EVIDENCE_ORDERED,
    "absence": _ABSENCE_ORDERED,
}

#: An ordered key that cannot IDENTIFY an entry, because re-pointing it is the whole purpose of an
#: anchor repair. Identifying by `line` would leave every repaired entry matching nothing.
_NOT_IDENTIFYING = ("line",)

#: How an entry is IDENTIFIED when the guard compares the record against the rewritten file --
#: `(path, expect)` for evidence, DERIVED from the ordered tuple rather than listed, so a new
#: sub-table brings its own identity and this line never changes.
#:
#: #1242: the comparison used to pair entry `i` against entry `i`. A DECLARED retirement of the first
#: anchor then lined the record's anchor 0 up against the file's anchor 1 -- two different anchors --
#: so the entry that SURVIVED was never compared against itself, and a field dropped from it read as
#: green. `strict=False` meant the length change did not even raise.
_IDENTITY: dict[str, tuple[str, ...]] = {
    sub: tuple(k for k in ordered if k not in _NOT_IDENTIFYING)
    for sub, ordered in _SUBTABLE_ORDERED.items()
}


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
    return toml_str(value)


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
    # ONE EMISSION FOR EVERY ORDERED STRING, SO NO FIELD CAN CHOOSE ITS OWN QUOTING (BACKLOG #1883).
    # Four of these were raw f-strings carrying their own quote marks, and two of them --
    # `last_verified` (a date) and `verified_at` (a commit SHA) -- are constrained upstream only to
    # be non-empty. A quote and a newline in either closed the string early and wrote the rest into
    # the record as TOML: a payload could add any NEW key to the cell, `decision_closed` and its pins
    # included, past every key-set and type guard below. A format check would not replace this; the
    # next field added to `_ORDERED` has no format rule yet.
    #
    # `id` and `verdict` share the line, but `main`'s checks on them are STILL NEEDED: an id that
    # `toml_str` had to escape would not be found again by `block_spans`'s plain regex, so the record
    # could not be rewritten on the next run. Quoting keeps a bad id out of the TOML structure; it
    # does not make one usable.
    out = ["[[cell]]"]
    for key in _ORDERED:
        if key == "level":
            out.append(f"level = {int(cell[key])}")
        elif cell.get(key) or key not in _OPTIONAL_ORDERED:
            out.append(f"{key} = {toml_str(cell[key])}")
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
    # carrying a date, read as an instruction by nothing.
    #
    # BOTH PATHS, AND THE SECOND ONE IS THE MIGRATION. The first version of this wrote the witness
    # only when the PAYLOAD declared a repair, which is the rarer path and not the one the record
    # travels. A cell already carrying a PERSISTED `anchor_repair` is normally rewritten by an
    # ordinary payload that declares nothing -- precisely the "comes clean as it is written" route
    # the strip depends on -- and the control was stripped there with no witness written at all.
    # Measured before the fix, one variable between two arms: an undeclaring payload took
    # `_repairs_declared` from 1 to 0, exit 0, nothing printed; a declaring one kept it. So the fix
    # for #1369 quietly decayed the single counter it was chosen to preserve, on the exact path the
    # banner advertises as the migration. Silent, green, and in the direction that looks like success.
    #
    # PRECEDENCE, because the two paths carry different dates and clobbering is not symmetric:
    #   1. the PAYLOAD declares a repair -- a fresh, dated event, so it WINS and overwrites;
    #   2. otherwise the LIVE cell carries the legacy control -- a migration, so the witness takes
    #      the date the record ALREADY held for that cell, and FILLS ONLY. An existing
    #      `anchor_repaired_at` on either side is newer evidence than a legacy flag with no date of
    #      its own, so it is never overwritten by this branch.
    # A cell that was never repaired matches neither, so this cannot manufacture a witness.
    if cell.get("anchor_repair"):
        merged[_REPAIR_WITNESS] = str(cell.get("last_verified", ""))
    elif (live or {}).get("anchor_repair") and not merged.get(_REPAIR_WITNESS):
        merged[_REPAIR_WITNESS] = str((live or {}).get("last_verified", ""))
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


def _entry_pairs(sub: str, was: list[Any], now: list[Any]) -> list[tuple[int, Any, int]]:
    """Pair the record's sub-table entries against the rewritten file's BY IDENTITY (#1242).

    Yields ``(record index, record entry, file index)`` ordered by the record index, which is what a
    refusal names -- an operator reads the record, so "evidence[1]" has to mean the entry they can
    find there.

    IDENTITY FIRST, POSITION AS A FALLBACK, and the fallback is load-bearing rather than tidiness. An
    anchor repair moves ``path`` by design, so a repaired entry matches nothing by identity --
    identity matching ALONE would then silently stop comparing it, trading a loud comparison for a
    quiet always-pass. Unmatched record entries are therefore paired, in order, against whatever the
    file has left over: exactly what the index pairing did, kept for precisely the entries identity
    cannot place.

    Duplicate identities degrade to the same thing among themselves, first-come, which is the most a
    comparison can do when two entries claim to be the same anchor.
    """
    keys = _IDENTITY.get(sub, ())

    def ident(entry: Any) -> tuple[Any, ...] | None:
        if not isinstance(entry, dict) or not keys or any(k not in entry for k in keys):
            return None
        return tuple(entry[k] for k in keys)

    index: dict[tuple[Any, ...], list[int]] = {}
    for j, entry in enumerate(now):
        key = ident(entry)
        if key is not None:
            index.setdefault(key, []).append(j)

    pairs: list[tuple[int, Any, int]] = []
    unmatched: list[tuple[int, Any]] = []
    taken: set[int] = set()
    for i, entry in enumerate(was):
        key = ident(entry)
        candidates = index.get(key) if key is not None else None
        if candidates:
            j = candidates.pop(0)
            taken.add(j)
            pairs.append((i, entry, j))
        else:
            unmatched.append((i, entry))
    leftover = [j for j in range(len(now)) if j not in taken]
    for (i, entry), j in zip(unmatched, leftover, strict=False):
        pairs.append((i, entry, j))
    return sorted(pairs, key=lambda pair: pair[0])


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
            "write even though the clone holding --scorecard is missing commits from "
            f"{_RECORD_LINE}, or reads BEHIND or DIVERGED against its own upstream. Refused by "
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
    # BEHIND THE RECORD LINE, NOT BEHIND WHATEVER REF THIS BRANCH TRACKS. The first version of this
    # guard refused on `stamp.freshness` alone, which is measured against the branch's own
    # `@{upstream}` when it has one. A clone on a pushed feature branch -- the ordinary way to edit
    # the record -- then reads CURRENT however far its base has fallen behind `origin/main`, and the
    # guard printed that CURRENT while waving the write through. `_record_line_gap` asks the other
    # question. It separates the two workflows cleanly: a branch cut from a current record line reads
    # a gap of zero no matter how far ahead of its own upstream it has run.
    #
    # MEASURED, AND NEVER SILENT WHEN IT CANNOT MEASURE. Both readings are pure local reads -- no
    # fetch, no network -- so a clone that has not fetched in a week can read a gap of zero and still
    # be stale. That is exactly why `remote-knowledge` is printed beside the verdicts instead of
    # being left out: BEHIND 0 from a six-hour-old fetch and from a one-minute-old fetch are
    # different claims. Every state that is not a measured gap -- NO-GIT, UNASKABLE, UNRESOLVED -- is
    # REPORTED and falls back to the branch reading, because a guard that refuses on states that were
    # never the problem is a guard someone disables, and this file already says so about the
    # verdict-move refusal.
    stamp = repo_stamp(SCORECARD)
    gap, record_line = _record_line_gap(SCORECARD)
    where = (
        f"{SCORECARD} is at {stamp.ref()}: record-line={record_line} "
        f"branch={stamp.freshness} upstream={stamp.upstream} "
        f"remote-knowledge={stamp.remote_knowledge}"
    )
    behind_record_line = gap is not None and gap > 0
    # KEPT AS A SECOND REFUSAL RATHER THAN REPLACED. Where the record line is unaskable this is the
    # only reading left, and where both are available a branch behind its own upstream is missing
    # cells a peer pushed to the shared branch -- a smaller hole than #1476's, and a real one.
    behind_own_upstream = stamp.freshness.startswith("BEHIND ") or stamp.freshness == "DIVERGED"
    if (behind_record_line or behind_own_upstream) and not args.allow_stale_clone:
        # REFUSED ON A DRY RUN TOO. A dry run from a stale clone reports a clean, plausible,
        # wrong plan -- the cells it would revert are not in the payload and so are not in the
        # report -- and that report is what an operator reads before reaching for --apply.
        print(f"REFUSING: {where}")
        if behind_record_line:
            print(
                f"  This clone is missing {gap} commit(s) from {_RECORD_LINE}. A write from this "
                "base would re-render every cell landed there since it back to its old value."
            )
        if behind_own_upstream:
            print(
                f"  This branch reads {stamp.freshness} against its own upstream {stamp.upstream}, "
                "so it is missing commits from there too."
            )
        print(
            "  Pull the clone, rebuild the payload from the current record, and re-run. "
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
        if live.get("anchor_repair"):
            # GATED ON THE RECORD, NOT ON THE PAYLOAD, and that is the whole correction. Gating on
            # both meant the note fired only where the flag was ALSO declared -- the rare path -- and
            # stayed silent on the ordinary rewrite, which is the one that actually migrates the
            # cell. A conversion the operator never sees is a conversion nobody can check.
            print(
                f"  note: {c.get('id')} carries a PERSISTED anchor_repair in the record "
                f"(BACKLOG #1369). This write strips the control and records {_REPAIR_WITNESS} in "
                "its place, so the repair stays countable."
            )
            if anchor_repair:
                # The extra half, only where it applies: the cell is FROZEN while the flag is set,
                # and the freeze is invisible from the payload's side, because a payload authored by
                # echoing the live cell carries the flag forward without anyone choosing it.
                print(
                    "        The payload ALSO declares it. If that was an echo of the live cell "
                    "rather than a fresh repair, drop it and re-run -- while it is set, every "
                    "prose field must stay byte-identical or this run refuses."
                )
        if anchor_repair:
            # Assert byte-identity on EVERY prose-bearing field. Holding only verdict+residual was
            # sound by argument -- the writer never rewrites the others -- but an argument is worth
            # less than a check, and it left the next reader to reconstruct why two were sufficient.
            #
            # THIS is the guard on prose under `anchor_repair`; the glyph scan below skips itself
            # and stays inert here. `_PROSE_FIELDS` carries the coupling.
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
        # Every field `render` always writes, derived so the two cannot drift apart.
        required = tuple(k for k in _ORDERED if k not in _OPTIONAL_ORDERED)
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
        # EVERY `_PROSE_FIELDS` ENTRY, NOT `residual` ALONE (BACKLOG #1333). That tuple's comment
        # carries the coupling and what these five names still leave uncovered.
        #
        # PER FIELD ON BOTH SIDES: payload field against the live field of the SAME NAME. Comparing
        # against the cell's prose as a whole would let one field that already carries a glyph
        # launder new vocabulary into all the others. The cost is that a glyph MOVED between two
        # prose fields now reads as an introduction, where `_introduced_banned`'s docstring promises
        # a move is writable -- that promise holds within a field, not across them.
        #
        # THE `anchor_repair` SKIP IS BELT-AND-BRACES AND INERT TODAY, kept deliberately and marked
        # so nobody reads it as load-bearing. The byte-identity loop above already forces all five
        # fields to equal the record, so `_introduced_banned(x, x)` finds nothing whether this runs
        # or not: replacing the condition with `if True` leaves the suite green. It stays because it
        # says the exemption out loud where the old spelling said it by feeding the scan a blanked
        # payload, which reads like sanitisation rather than the decision it is.
        #
        # IT IS NOT A CLAIM ABOUT THE CELL. A repair rewrites `evidence` entries by definition, and
        # no guard here scans sub-table text, under `anchor_repair` or without it.
        if not anchor_repair:
            for prose_field in _PROSE_FIELDS:
                introduced = _introduced_banned(
                    str(c.get(prose_field, "") or ""), str(live.get(prose_field, "") or "")
                )
                if introduced:
                    # Report the codepoint, never the character: echoing it to a cp1252 console
                    # raises UnicodeEncodeError and the refusal turns into a traceback that hides
                    # its own reason. NAME THE FIELD too -- this said "residual" whatever carried
                    # the glyph, which sends the author to edit prose that is fine.
                    #
                    # `c.get('id')`, not `c['id']`: a missing id is APPENDED to problems above
                    # rather than returned on, so a payload with no id reaches here and the
                    # subscript would raise KeyError -- a traceback in place of the refusal list
                    # that names the real problem. The widening made four more fields reach it.
                    ch, extra = introduced
                    problems.append(
                        f"{c.get('id')}: {prose_field} INTRODUCES a banned glyph "
                        f"U+{ord(ch):04X} ({extra} more than that field already carries)"
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
        # _SUBTABLES are excluded because they have their own key AND type comparison below, one
        # level further in, where the entries are matched by identity. That comparison used to be
        # key-only, which is what made this exclusion a hole rather than a delegation (#1242).
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
            #
            # MATCHED BY IDENTITY, NOT BY INDEX (#1242, see `_entry_pairs`). Pairing entry `i` against
            # entry `i` compared two DIFFERENT anchors the moment a declared retirement removed one
            # from the middle, so the entry that survived was never compared against itself.
            #
            # The payload entries line up 1:1 with the file's by construction -- `render` emits one
            # block per payload entry, in order -- so `j` indexes both.
            pay_entries = c.get(sub) or []
            now_entries = now.get(sub, [])
            ordered = _SUBTABLE_ORDERED.get(sub, ())
            for i, wsub, j in _entry_pairs(sub, was.get(sub, []), now_entries):
                nsub = now_entries[j]
                lost_sub = set(wsub) - set(nsub)
                if lost_sub:
                    print(
                        f"REFUSING: cell {c['id']} {sub}[{i}] would LOSE field(s) {sorted(lost_sub)}"
                    )
                    return 1
                # ...and the VALUE question one level down, which the top-level type check excludes
                # `_SUBTABLES` from BY NAME, deferring to "their own key comparison below" -- a key
                # comparison, which a type-mangled field passes because it KEEPS ITS KEY. So the
                # writer and the guard were blind in the same place one level down, and this item is
                # explicit that leaving it there reproduces its founding defect: green while lossy.
                #
                # AGAINST THE TYPE THE PAYLOAD STATED, for the reason the top-level check gives: an
                # intentional retype inside an entry is an EDIT, and a guard that refuses legitimate
                # writes is a guard someone disables. The retracted scoping the comment above
                # describes -- skip every key the payload carries -- has no variant here, and it
                # would be worse than it was at the top level: `_carried` reads the PAYLOAD
                # entry alone, with no union against the live entry, so a payload that OMITS a field
                # loses the KEY (caught above) and a type mangle is reachable ONLY while the payload
                # CARRIES the field. Skipping carried keys would leave this check dead on every input.
                psub = pay_entries[j] if j < len(pay_entries) else None
                retyped_sub = []
                for k in wsub:
                    if k in nsub and k not in ordered:
                        want = psub[k] if isinstance(psub, dict) and k in psub else wsub[k]
                        if type(want) is not type(nsub[k]):  # noqa: E721
                            retyped_sub.append(k)
                retyped_sub.sort()
                if retyped_sub:
                    print(
                        f"REFUSING: cell {c['id']} {sub}[{i}] would CHANGE the TYPE of field(s) "
                        f"{retyped_sub} (key kept, value corrupted -- the key comparison this "
                        "check sits beside cannot see it)"
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
