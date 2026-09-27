# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every zizmor suppression must name a workflow that still exists, and a line anchor its construct.

``.github/zizmor.yml`` was asserted by nothing, so its ``release-sync-check.yml`` entry survived that
workflow's deletion (59fbc938, 2026-07-26) and sat there reading as coverage. zizmor's ignore entries
are BASE filenames (``filename.yml[:line[:column]]``) resolved against the scan target, and
zizmor.yml's job runs ``zizmor .github/workflows`` — so the ignore namespace is exactly that
directory's contents, and an entry naming anything else can never match.

A dead entry is worse than noise: this file's header calls every entry "a REVIEWED, justified
non-finding", so a name that cannot match reads as a reviewed risk that is actually unexamined.

LINE ANCHORS (BACKLOG #1493). A line-anchored entry (``cla.yml:178``) keys on the line NUMBER, so a
pull request that inserts lines ABOVE the flagged construct strands the anchor without touching the
construct or the config. zizmor then fires on the moved line, but zizmor is not a required context,
so that pull request merges through its own red and ``main`` carries it until someone re-anchors.
PR 994 did exactly that to the ``cla.yml`` ``uses:`` line, moving it from 102 to 122. PR 1001
re-anchored it. The BACKLOG #1533 change then moved the same line to 178, and re-anchored it in its
own branch. "My diff does not touch that line" is the sentence that hides this class, so comparing
the anchored line against itself cannot find it.

This guard compares the anchor against a PIN instead: a ``# anchor-pin: <text>`` comment on the line
directly above each line-anchored entry. The anchored line, stripped of indentation, must START with
the pin text, followed by the end of the line or whitespace, so ``cla-assistant-lite-fork`` does not
satisfy a pin of ``cla-assistant-lite``. Exactly one line of the workflow may match, and it must be
the anchored one. A shift therefore fails with the construct's new line number, which is the number to
re-anchor to, derived from the file rather than copied from a zizmor report. An in-place rewrite of
the construct fails too. Column anchors are refused rather than half-checked. So is a pin left
above a file-level entry: broadening an anchor to the file is the repair both config comments
forbid, and without this check it would turn the guard green.

WHAT THIS GUARD DOES NOT COVER, stated so nobody reads it as covered:

* A zizmor upgrade that changes WHICH line an audit reports on, with the workflow unchanged. The pin
  still matches, so this guard stays green. The upgrade edits ci/locks/ci-scanners.lock, which the
  ``.github/workflows/zizmor.yml`` paths filter includes, so zizmor runs on that pull request. Its red
  is advisory, though, so nothing blocks the merge.
* Two pull requests that each move the line by one and each re-anchor to the same number. Git merges
  identical edits cleanly, and this test is in the ``tooling`` tier, which the merge queue does not
  run. The combined tree lands stale, and the post-merge push run on ``main`` is the first to see it.

WHY NOT zizmor's INLINE ``# zizmor: ignore[audit]`` COMMENT, which moves with its line and so cannot
drift. https://docs.zizmor.sh/usage/ (read 2026-09-26) says it must sit in the finding's span as a
YAML comment, and not inside a string or block literal. The ``bot-conditions`` finding sits inside a
folded ``>-`` scalar, so that form cannot reach it. The ``cla.yml`` one would move a justification
out of the one reviewed file into a ``pull_request_target`` workflow.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, NamedTuple

import pytest

from tests._workflow_contexts import ROOT, WORKFLOWS

_CONFIG = ROOT / ".github" / "zizmor.yml"

# `name.yml:LINE` or `name.yml:LINE:COL`, as zizmor's config documents the ignore syntax.
_LINE_ANCHOR = re.compile(r"^(?P<file>[^:]+):(?P<line>\d+)(?::(?P<col>\d+))?$")
_PIN = re.compile(r"^\s*#\s*anchor-pin:(?P<text>.*)$")


class _Anchor(NamedTuple):
    entry: str
    file: str
    line: int
    column: int | None
    pin: str | None  # None: no pin comment. "": a pin comment with no text.
    located: bool  # False: the entry is not written as its own `- entry` line in the config


def _entry_line(entry: str) -> re.Pattern[str]:
    """An ignore entry as block-style YAML writes it, with an optional trailing comment."""
    return re.compile(rf"\s*-\s+{re.escape(entry)}(?:\s+#.*)?\s*")


def _ignore_entries(config_text: str) -> list[tuple[str, str]]:
    """Return ``(audit, entry)`` for every ``rules.<audit>.ignore`` entry, as YAML parses them."""
    import yaml

    config: dict[str, Any] = yaml.safe_load(config_text) or {}
    return [
        (audit, str(entry))
        for audit, body in (config.get("rules") or {}).items()
        for entry in (body or {}).get("ignore") or []
    ]


def _anchors(config_text: str) -> list[_Anchor]:
    """Every line-anchored entry, from the YAML parse, with the pin comment found above it."""
    lines = config_text.split("\n")
    anchored = [e for _audit, e in _ignore_entries(config_text) if _LINE_ANCHOR.match(e)]
    found: list[_Anchor] = []
    seen: dict[str, int] = {}
    for entry in anchored:
        m = _LINE_ANCHOR.match(entry)
        assert m is not None
        # The parse says which entries exist; the raw text is only where the pin comment lives. One
        # anchor may be listed under two audits, so pair the k-th parsed copy with the k-th raw line.
        k = seen[entry] = seen.get(entry, -1) + 1
        at = [i for i, raw in enumerate(lines) if _entry_line(entry).fullmatch(raw)]
        located = len(at) == anchored.count(entry)
        pin_match = _PIN.match(lines[at[k] - 1]) if located and at[k] else None
        found.append(
            _Anchor(
                entry=entry,
                file=m["file"],
                line=int(m["line"]),
                column=int(m["col"]) if m["col"] else None,
                pin=pin_match["text"].strip() if pin_match else None,
                located=located,
            )
        )
    return found


def _starts_with_pin(text: str, pin: str) -> bool:
    code = text.strip()
    return code == pin or (code.startswith(pin) and code[len(pin)].isspace())


def _anchor_drift(config_text: str, workflows: Path) -> tuple[list[str], list[str]]:
    """Check every line-anchored entry against its pin. Returns ``(checked, problems)``."""
    checked: list[str] = []
    problems: list[str] = []
    lines = config_text.split("\n")
    anchors = _anchors(config_text)
    for i, raw in enumerate(lines):
        below = lines[i + 1] if i + 1 < len(lines) else ""
        if _PIN.match(raw) and not any(_entry_line(a.entry).fullmatch(below) for a in anchors):
            problems.append(
                f"zizmor.yml line {i + 1}: an anchor pin with no line-anchored entry directly below "
                "it. If the entry was broadened to the whole file, restore the line anchor instead."
            )
    for a in anchors:
        checked.append(a.entry)
        if not a.located:
            problems.append(
                f"{a.entry}: not found as its own unquoted `- {a.entry}` line in zizmor.yml, "
                "so its pin comment cannot be read. Write it in block style, one entry per line."
            )
        elif a.column is not None:
            problems.append(
                f"{a.entry}: a COLUMN anchor. The pin checks the line only, so a re-indent would "
                "strand this entry with the guard green. Anchor to the line, or extend this guard."
            )
        elif a.pin is None:
            problems.append(
                f"{a.entry}: no `# anchor-pin: <text>` comment on the line directly above it. A line "
                "anchor with no pin goes stale silently when lines are inserted above it."
            )
        elif not a.pin:
            problems.append(f"{a.entry}: its `# anchor-pin:` comment names no text.")
        elif not (workflows / a.file).is_file():
            problems.append(f"{a.entry}: {a.file} is not in .github/workflows/")
        else:
            # read_text translates \r\n and \r to \n, and YAML breaks lines on exactly those, so the
            # line numbers here are zizmor's. str.splitlines() would also break on U+2028 and others.
            text = (workflows / a.file).read_text(encoding="utf-8")
            hits = [
                n for n, ln in enumerate(text.split("\n"), start=1) if _starts_with_pin(ln, a.pin)
            ]
            if not hits:
                problems.append(
                    f"{a.entry}: no line of {a.file} starts with the pin {a.pin!r}. The construct "
                    "was rewritten or removed: re-verify the finding, then re-justify or delete it."
                )
            elif len(hits) > 1:
                problems.append(
                    f"{a.entry}: lines {hits} of {a.file} all start with the pin {a.pin!r}. A pin "
                    "must name exactly one line, so lengthen it until it does. If the lines are "
                    "identical, no pin can tell them apart; decide which one this entry is for."
                )
            elif hits[0] != a.line:
                problems.append(
                    f"{a.entry}: the pinned construct {a.pin!r} is now at {a.file}:{hits[0]}, not "
                    f"line {a.line}. Lines were inserted or removed above it. Re-anchor to "
                    f"{a.file}:{hits[0]}; do not broaden it to the file."
                )
    return checked, problems


def test_every_zizmor_ignore_names_a_live_workflow() -> None:
    assert _CONFIG.is_file(), f"{_CONFIG} is missing — this guard cannot pass vacuously"
    scanned: list[str] = []
    for audit, entry in _ignore_entries(_CONFIG.read_text(encoding="utf-8")):
        basename = entry.split(":", 1)[0]
        scanned.append(f"{audit} -> {entry}")
        assert (WORKFLOWS / basename).is_file(), (
            f"{audit}.ignore names {basename}, which is not in .github/workflows/ — the "
            "workflow was deleted or renamed and its suppression must go with it"
        )
    # Print what was covered: a gate that silently scanned nothing looks identical to a passing one.
    print(f"scanned {len(scanned)} zizmor ignore entries: {scanned}")
    assert scanned, (
        "parsed zero ignore entries — the config shape changed and this guard went blind"
    )


def test_every_line_anchor_still_points_at_its_pinned_construct() -> None:
    checked, problems = _anchor_drift(_CONFIG.read_text(encoding="utf-8"), WORKFLOWS)
    print(f"checked {len(checked)} line-anchored zizmor entries: {checked}")
    assert not problems, "\n".join(problems)
    # A zero here means the guard went blind, not that it passed.
    assert checked, "found no line-anchored entries; if every anchor was removed, retire this test"


def _planted_tree(tmp_path: Path, edit: str) -> tuple[str, Path]:
    """Copy the real config and anchored workflows, then plant one kind of damage."""
    config_text = _CONFIG.read_text(encoding="utf-8")
    anchors = _anchors(config_text)
    assert anchors, "no line-anchored entries to plant damage into"
    # The damage is planted relative to the real anchors, so they must be sound first. If this
    # fires, fix what test_every_line_anchor_still_points_at_its_pinned_construct reports.
    assert not _anchor_drift(config_text, WORKFLOWS)[1], (
        "the real anchors are stale; fix them first"
    )
    # Group by workflow so two anchors in one file are both damaged, not the last one only.
    for name in {a.file for a in anchors}:
        lines = (WORKFLOWS / name).read_text(encoding="utf-8").split("\n")
        if edit == "insert-above":
            # The PR 994 shape: one line inserted above the constructs, the constructs untouched.
            lines.insert(0, "# planted: one line inserted above every anchored construct")
        elif edit == "duplicate-line":
            # A second copy of each construct, appended at the end so no line number moves.
            lines.extend(lines[a.line - 1] for a in anchors if a.file == name)
        elif edit == "rewrite-in-place":
            # The line count holds, so each anchor still names the same number, but the construct
            # it was written for now has a longer name, which a bare substring check would accept.
            for a in anchors:
                if a.file == name:
                    assert a.pin is not None
                    lines[a.line - 1] = lines[a.line - 1].replace(a.pin, a.pin + "-planted", 1)
        (tmp_path / name).write_text("\n".join(lines), encoding="utf-8")
    if edit == "drop-pin":
        config_text = "\n".join(ln for ln in config_text.split("\n") if not _PIN.match(ln))
    return config_text, tmp_path


@pytest.mark.parametrize(
    ("edit", "expect"),
    [
        ("insert-above", "is now at"),
        ("rewrite-in-place", "starts with the pin"),
        ("drop-pin", "no `# anchor-pin"),
        ("duplicate-line", "all start with the pin"),
    ],
)
def test_the_guard_fails_on_planted_damage(tmp_path: Path, edit: str, expect: str) -> None:
    config_text, workflows = _planted_tree(tmp_path, edit)
    checked, problems = _anchor_drift(config_text, workflows)
    assert checked
    # Every anchor must be caught, not just one of them.
    assert len(problems) == len(checked), problems
    assert all(expect in p for p in problems), problems
    if edit == "insert-above":
        for a, problem in zip(_anchors(config_text), problems, strict=True):
            assert f"Re-anchor to {a.file}:{a.line + 1};" in problem, problem


@pytest.mark.parametrize(
    ("entry_line", "pin_line", "checked", "expect"),
    [
        ("- cla.yml:178:9", "# anchor-pin: uses: x", ["cla.yml:178:9"], ["a COLUMN anchor"]),
        ("- cla.yml:178", "# anchor-pin:", ["cla.yml:178"], ["names no text"]),
        # tmp_path holds no workflows, so a well-formed entry reaches the missing-workflow branch,
        # which also proves a trailing comment on the entry line does not hide the entry.
        ("- cla.yml:178  # a note", "# anchor-pin: uses: x", ["cla.yml:178"], ["is not in"]),
        ("- cla.yml", "# anchor-pin: uses: x", [], ["no line-anchored entry directly below"]),
        (
            '- "cla.yml:178"',
            "# anchor-pin: uses: x",
            ["cla.yml:178"],
            ["no line-anchored entry directly below", "not found as its own unquoted"],
        ),
    ],
)
def test_the_guard_refuses_entries_it_cannot_check(
    tmp_path: Path, entry_line: str, pin_line: str, checked: list[str], expect: list[str]
) -> None:
    config_text = f"rules:\n  self-repository:\n    ignore:\n      {pin_line}\n      {entry_line}\n"
    got, problems = _anchor_drift(config_text, tmp_path)
    assert got == checked
    assert len(problems) == len(expect), problems
    assert all(e in p for e, p in zip(expect, problems, strict=True)), problems


def test_one_anchor_under_two_audits_pairs_each_copy_with_its_own_pin(tmp_path: Path) -> None:
    (tmp_path / "cla.yml").write_text("a: 1\nuses: x # note\n", encoding="utf-8")
    block = "    ignore:\n      # anchor-pin: uses: x\n      - cla.yml:2\n"
    config_text = f"rules:\n  one:\n{block}  two:\n{block}"
    assert _anchor_drift(config_text, tmp_path) == (["cla.yml:2", "cla.yml:2"], [])
