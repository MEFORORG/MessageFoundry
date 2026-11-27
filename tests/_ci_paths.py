# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The one Python reader of ``.github/ci-paths/<arm>.txt``, the ``changes`` job's path lists.

``ci.yml``'s ``changes`` job decides each path-gated output (``serverdb``, ``docker``,
``packaging``, ``ide``, ``tooling``) with ``paths_match <arm>``, which runs
``grep -qEf .github/ci-paths/<arm>.txt`` over the changed paths. The lists used to be written inline
as one ``grep -qE '^(...)'`` each; they moved out because ci.yml sits at GitHub's workflow file
size limit (BACKLOG #5472).

Stdlib only, so a test with "no gate of its own" (tests/test_serverdb_ci_coverage.py) can read the
lists without the PyYAML dependency tests/_workflow_contexts.py carries.
"""

from __future__ import annotations

import functools
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CI_PATHS = ROOT / ".github" / "ci-paths"

#: Any name bash would pass as the argument, so a hyphen or digit cannot cut it short and send the
#: reader to another list than the step reads.
PATHS_MATCH = re.compile(r"\bpaths_match ([A-Za-z0-9_.-]+)(?![^\s;)|&])")


def ci_path_list(name: str, root: Path | None = None) -> list[str]:
    """The patterns in ``<root>/<name>.txt``, one per line, as ``grep -Ef`` reads them.

    Refuses what the ``changes`` step refuses -- a missing or empty list, a CR, a line that matches
    the empty line (a blank line, ``^x|``, ``^.*``), which ``grep -f`` reads as match-everything --
    so a test cannot pass against a list the step would fail the job on. Each line is also compiled
    on its own, since grep compiles each line on its own: ``^a(`` then ``^b)`` is two errors to grep
    and one valid regex joined. Read as bytes, so a CR is seen whatever a checkout did to it.
    """
    path = (root if root is not None else CI_PATHS) / f"{name}.txt"
    assert path.is_file(), f"{path} is missing; ci.yml's `paths_match {name}` fails the job"
    raw = path.read_bytes()
    assert b"\r" not in raw, f"{path} holds a CR; the changes step fails the job on it"
    lines = raw.decode("utf-8").split("\n")
    if lines[-1] == "":
        lines.pop()
    assert lines, f"{path} is empty; the changes step fails the job on it"
    for line in lines:
        try:
            compiled = re.compile(line)
        except re.error as exc:
            raise AssertionError(f"{path} line {line!r} does not compile: {exc}") from exc
        assert not compiled.search(""), (
            f"{path} line {line!r} matches the empty line, so it matches every path; the changes "
            "step fails the job on it"
        )
    return lines


def arm_list_name(ci_text: str, output: str) -> str:
    """The list ``ci.yml`` matches to decide ``output`` on a pull request.

    Anchored on the LAST ``<output>=true`` emission, because the dispatch and push arms emit one
    first with no matcher in front of them; the last ``paths_match <arm>`` before it is the path
    arm. Memoised on the text, so ci.yml is scanned once per content.
    """
    return _arm_list_name(ci_text, output)


@functools.cache
def _arm_list_name(ci_text: str, output: str) -> str:
    emit = ci_text.rfind(f'echo "{output}=true" >> "$GITHUB_OUTPUT"')
    assert emit > 0, (
        f"the {output} arm's GITHUB_OUTPUT emission is gone; this gate was restructured"
    )
    matches = list(PATHS_MATCH.finditer(ci_text, 0, emit))
    assert matches, f"no `paths_match` found before the {output} emission"
    return matches[-1].group(1)


def joined(lines: list[str] | tuple[str, ...]) -> str:
    """A list as one regex. ``grep -Ef`` selects a line ANY pattern matches, which is alternation.
    Each line is grouped, so one line's ``|`` or unbalanced bracket cannot reach into the next."""
    return "|".join(f"(?:{line})" for line in lines)


def plant_lists(cwd: Path) -> None:
    """Copy the real lists into ``cwd/.github/ci-paths/``, where the ``changes`` step reads them.

    For a test that runs the step's own script in a scratch directory: the step fails the job on a
    missing list, so a scratch run without them would exercise that refusal, not the arms.
    """
    dest = cwd / ".github" / "ci-paths"
    dest.mkdir(parents=True, exist_ok=True)
    for src in sorted(CI_PATHS.glob("*.txt")):
        (dest / src.name).write_bytes(src.read_bytes())
