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
from pathlib import Path
from typing import Any

VERDICTS = {"pass", "partial", "fail", "na", "needs-review", "unverified"}

#: The banner alphabet and the general emoji planes. CLAUDE.md section 11 bans these in prose; the
#: only sanctioned holdout is docs/BACKLOG.md, which this file is not. Fail closed rather than
#: writing one into a security record where a later reader would copy the vocabulary forward.
_BANNED = re.compile(
    "["
    "\u26a0\u26d4\u2705\u2b50\u274c\u2714\u2716\u2717\u2718"  # warning, no-entry, check, star, crosses
    "\U0001f300-\U0001faff"  # emoji planes
    "\U0001f000-\U0001f2ff"
    "\u2190-\u21ff"  # arrows
    "\u2022"  # bullet
    "\ufe0f\ufe0e"  # variation selectors
    "]"
)


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


def _scalar(key: str, value: object) -> str:
    if isinstance(value, bool):
        return f"{key} = {str(value).lower()}"
    if isinstance(value, int):
        return f"{key} = {value}"
    return f"{key} = {toml_str(str(value))}"


def render(cell: dict[str, Any], live: dict[str, Any] | None = None) -> str:
    out = ["[[cell]]", f'id = "{cell["id"]}"', f"level = {int(cell['level'])}"]
    out.append(f'verdict = "{cell["verdict"]}"')
    if cell.get("residual"):
        out.append(f"residual = {toml_str(cell['residual'])}")
    out.append(f'last_verified = "{cell["last_verified"]}"')
    out.append(f'verified_at = "{cell["verified_at"]}"')
    if cell.get("reviewed_by"):
        out.append(f"reviewed_by = {toml_str(cell['reviewed_by'])}")
    # Carry through every other scalar the live cell had -- decision_closed and friends, and anything
    # a future schema adds that this writer has never heard of.
    for key, value in (live or {}).items():
        if key in _ORDERED or key in _SUBTABLES or key in cell:
            continue
        out.append(_scalar(key, value))
    for a in cell.get("evidence") or []:
        out.append("  [[cell.evidence]]")
        out.append(f"  path = {toml_str(a['path'])}")
        out.append(f"  line = {int(a['line'])}")
        out.append(f"  expect = {toml_str(a['expect'])}")
    for a in cell.get("absence") or []:
        out.append("  [[cell.absence]]")
        out.append(f"  pattern = {toml_str(a['pattern'])}")
        out.append(f"  positive_control = {toml_str(a['positive_control'])}")
        out.append(f"  mutation = {toml_str(a['mutation'])}")
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
    args = ap.parse_args(argv)
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
        if c.get("verdict") == "na" and not (c.get("residual") or "").strip():
            problems.append(f"{c['id']}: verdict 'na' requires a written rationale in residual")
        if c.get("verdict") in {"pass", "partial", "fail"} and not (
            c.get("evidence") or c.get("absence")
        ):
            problems.append(f"{c['id']}: {c['verdict']} needs at least one anchor or absence claim")
        blob = "" if anchor_repair else " ".join(str(v) for v in (c.get("residual", ""),))
        hit = _BANNED.search(blob)
        if hit:
            # Report the codepoint, never the character: echoing it to a cp1252 console raises
            # UnicodeEncodeError and the refusal turns into a traceback that hides its own reason.
            problems.append(
                f"{c['id']}: residual contains a banned glyph U+{ord(hit.group()):04X} "
                f"at offset {hit.start()}"
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
        lost = set(was) - set(now)
        if lost:
            print(f"REFUSING: cell {c['id']} would LOSE field(s) {sorted(lost)}")
            return 1
        for sub in ("evidence", "absence"):
            if len(now.get(sub, [])) < len(was.get(sub, [])):
                print(
                    f"REFUSING: cell {c['id']} {sub} count would DROP "
                    f"{len(was.get(sub, []))} -> {len(now.get(sub, []))}"
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
