#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
r"""Check changelog fragments, and fold them into ``CHANGELOG.md`` when a release is cut.

WHY THIS EXISTS (BACKLOG #2080). Every engine pull request used to add its bullet to the one
``## [Unreleased]`` section of ``CHANGELOG.md``. Two open pull requests that both did so conflicted,
so nearly every pull request conflicted with nearly every other, and each conflict was resolved by
hand. A hand resolution can drop an entry and still pass every check (``docs/WORKTREES.md``,
"Resolving a conflict").

A pull request now adds ONE NEW FILE under ``changelog.d/`` instead. Two pull requests adding
DIFFERENT files do not conflict; two that pick the same name still do, which is why a taken name
takes a suffix. The release pull request runs ``assemble`` BEFORE it renames ``[Unreleased]`` to the
version: ``assemble`` appends every fragment under ``[Unreleased]`` and deletes the fragments.

WHY IN-REPO AND NOT towncrier. The job is a couple of hundred lines of stdlib. A new dependency
costs a vet note, a lock entry and a supply-chain review (CLAUDE.md section 7); this costs none.

SCOPE. The ENGINE changelog only. The web console is separately versioned and keeps its own
``packaging/messagefoundry-webconsole/CHANGELOG.md``, edited directly as before.

FRAGMENT RULES. The name is ``<name>.<category>.md``:

* ``<name>`` is lower-case letters, digits and hyphens, starting with a letter or digit. Use the
  backlog item number (``2080``). A second fragment for the same item and category takes a suffix
  (``2080-docs``). A change with no item takes a short slug (``fix-install-typo``).
* ``<category>`` is one of the Keep a Changelog headings, in lower case: see ``CATEGORIES``.

The body is one or more Markdown bullets. Every non-blank line starts with ``- `` or with
whitespace (a continuation), and no line may start with ``#``: a heading inside a fragment would
split the section it lands in. A relative link must start with ``../`` so it resolves from
``changelog.d/``; ``assemble`` drops that ``../`` so it resolves from the repository root, where
``CHANGELOG.md`` lives. Text is otherwise copied byte for byte, trailing spaces included.

``changelog.d/README.md`` is the one other file allowed in the directory, and dot-files (editor swap
files, ``.DS_Store``) are ignored. Any other name is an ERROR, never skipped: a misnamed fragment
that ``assemble`` quietly ignored would drop its entry from the release notes.

Usage::

    python scripts/release/changelog_fragments.py check               # the tests; any time
    python scripts/release/changelog_fragments.py pr-check --base-changelog FILE  # ci.yml
    python scripts/release/changelog_fragments.py check --no-pending  # release.yml, on a tag
    python scripts/release/changelog_fragments.py assemble            # the release PR

``pr-check`` compares a pull request's ``CHANGELOG.md`` with its base's. It REFUSES a pull request
that adds a version heading while fragments remain, or while ``[Unreleased]`` still holds entries
(the fragments were assembled after the rename, so the release notes would miss them). It WARNS,
never fails, on a pull request that edits ``CHANGELOG.md`` without adding a version heading: pull
requests opened before this change still edit it, and turning them red would buy nothing.
"""

from __future__ import annotations

import argparse
import re
import subprocess  # nosec B404 - fixed argv, no shell
import sys
from pathlib import Path
from typing import NamedTuple

REPO_ROOT = Path(__file__).resolve().parents[2]
FRAGMENT_DIR = "changelog.d"
CHANGELOG = "CHANGELOG.md"
README = "README.md"

#: Keep a Changelog 1.1.0's six headings, in its order. A NEW heading is placed before the first
#: existing heading of a later category; an existing heading is never moved.
CATEGORIES: dict[str, str] = {
    "added": "Added",
    "changed": "Changed",
    "deprecated": "Deprecated",
    "removed": "Removed",
    "fixed": "Fixed",
    "security": "Security",
}

_NAME = re.compile(r"^(?P<name>[0-9a-z][0-9a-z-]*)\.(?P<category>[a-z]+)\.md$")
_UNRELEASED = "## [Unreleased]"
_VERSION_HEADING = re.compile(r"^## \[(?!Unreleased\])([^\]]+)\]", re.MULTILINE)
#: A Markdown link reference definition at column 0, e.g. ``[0.4.0]: https://...``. The compare
#: links at the foot of the file are not part of any section, so a section never runs into them.
_LINK_DEF = re.compile(r"^\[[^\]]+\]:\s")
#: An inline link target, and the targets that are NOT relative paths: a scheme, an anchor, or rooted.
_LINK_TARGET = re.compile(r"\]\(([^)\s]+)")
_NOT_RELATIVE = re.compile(r"^(?:[a-zA-Z][a-zA-Z0-9+.-]*:|#|/)")


class Fragment(NamedTuple):
    path: Path
    name: str
    category: str
    body: str


class FragmentError(ValueError):
    """A fragment directory or a changelog this script refuses to act on."""


def _sort_key(fragment: Fragment) -> tuple[int, int, str]:
    """Numeric names first, in numeric order (999 before 1000), then slugs alphabetically."""
    head = re.match(r"\d+", fragment.name)
    if head:
        return (0, int(head.group()), fragment.name)
    return (1, 0, fragment.name)


def _link_problems(number: int, line: str) -> list[str]:
    problems: list[str] = []
    for target in _LINK_TARGET.findall(line):
        if _NOT_RELATIVE.match(target):
            continue
        if not target.startswith("../") or target.startswith("../../"):
            problems.append(
                f"line {number}: relative link {target!r} must start with exactly one '../' "
                f"(written from {FRAGMENT_DIR}/; assemble drops it for {CHANGELOG})"
            )
    return problems


def _body_problems(body: str) -> list[str]:
    """One message per faulty line. The first non-blank line must be a bullet; later ones may also
    be indented continuations."""
    problems: list[str] = []
    seen_content = False
    for number, line in enumerate(body.splitlines(), start=1):
        if not line.strip():
            continue
        if line.startswith("#"):
            problems.append(f"line {number} starts with '#'; a heading would split the section")
        elif not seen_content and not line.startswith("- "):
            problems.append(f"line {number}: a fragment must start with a bullet ('- ')")
        elif not (line.startswith("- ") or line[0].isspace()):
            problems.append(
                f"line {number} is neither a bullet ('- ') nor an indented continuation"
            )
        problems.extend(_link_problems(number, line))
        seen_content = True
    return problems if seen_content else ["is empty"]


def load(fragment_dir: Path) -> list[Fragment]:
    """Every fragment in ``fragment_dir``, sorted. Raises :class:`FragmentError` listing every problem.

    A missing directory is an empty one: there is nothing pending.
    """
    if not fragment_dir.is_dir():
        return []
    fragments: list[Fragment] = []
    problems: list[str] = []
    for path in sorted(fragment_dir.iterdir()):
        if path.name == README or path.name.startswith("."):
            continue
        where = f"{FRAGMENT_DIR}/{path.name}"
        match = _NAME.match(path.name)
        if not path.is_file() or match is None:
            problems.append(f"{where}: not a fragment name; expected <name>.<category>.md")
            continue
        category = match.group("category")
        if category not in CATEGORIES:
            problems.append(
                f"{where}: unknown category {category!r}; expected one of {', '.join(CATEGORIES)}"
            )
            continue
        try:
            body = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            problems.append(f"{where}: not UTF-8")
            continue
        found = _body_problems(body)
        problems.extend(f"{where}: {problem}" for problem in found)
        if not found:
            fragments.append(Fragment(path, match.group("name"), category, body))
    if problems:
        raise FragmentError("\n".join(problems))
    return sorted(fragments, key=_sort_key)


def rendered(fragment: Fragment) -> list[str]:
    """The fragment's lines as they land in ``CHANGELOG.md``: verbatim, less one ``../`` per link."""
    body = _LINK_TARGET.sub(
        lambda m: "](" + (m.group(1)[3:] if m.group(1).startswith("../") else m.group(1)),
        fragment.body.strip("\n"),
    )
    return body.splitlines()


def _section_end(lines: list[str], start: int) -> int:
    for index in range(start + 1, len(lines)):
        if lines[index].startswith("## ") or _LINK_DEF.match(lines[index]):
            return index
    return len(lines)


def _last_content(lines: list[str], start: int, end: int) -> int:
    """Index just past the last non-blank line in ``lines[start:end]``."""
    while end > start and not lines[end - 1].strip():
        end -= 1
    return end


def _unreleased(lines: list[str]) -> int:
    heads = [i for i, line in enumerate(lines) if line.rstrip() == _UNRELEASED]
    if len(heads) != 1:
        raise FragmentError(
            f"{CHANGELOG} must hold exactly one '{_UNRELEASED}' line; found {len(heads)}"
        )
    return heads[0]


def assemble_text(changelog: str, fragments: list[Fragment]) -> str:
    """``changelog`` with every fragment appended under ``## [Unreleased]``.

    Each category's lines go at the END of that category's FIRST ``###`` subsection, after its
    existing bullets, so nothing already there moves. A category with no subsection gets a new one,
    placed before the first heading of a later category (Keep a Changelog order), else at the end.
    Raises :class:`FragmentError` if ``[Unreleased]`` is not there exactly once, or if a fragment's
    text is already in the changelog -- a second run after a partial delete would duplicate it.
    """
    if not fragments:
        return changelog
    lines = changelog.split("\n")
    head = _unreleased(lines)
    padded = "\n" + changelog.replace("\r\n", "\n") + "\n"
    already = [f for f in fragments if "\n" + "\n".join(rendered(f)) + "\n" in padded]
    if already:
        raise FragmentError(
            f"already in {CHANGELOG}, so assembling again would duplicate them; delete these:\n  "
            + _listing(already)
        )
    order = list(CATEGORIES)
    for category, title in CATEGORIES.items():
        chosen = [f for f in fragments if f.category == category]
        if not chosen:
            continue
        block_lines = [line for f in chosen for line in rendered(f)]
        end = _section_end(lines, head)
        titles = {
            i: lines[i].rstrip()[4:] for i in range(head + 1, end) if lines[i].startswith("### ")
        }
        heading = next((i for i, t in titles.items() if t == title), None)
        if heading is not None:
            sub_end = next((i for i in titles if i > heading), end)
            at = _last_content(lines, heading + 1, sub_end)
            lines[at:at] = block_lines
            continue
        later = {CATEGORIES[c] for c in order[order.index(category) + 1 :]}
        target = next((i for i, t in titles.items() if t in later), end)
        at = _last_content(lines, head + 1, target)
        block = ["", f"### {title}", *block_lines]
        # With no blank line left before the next heading, add one so the two stay apart.
        if at == target < len(lines):
            block.append("")
        lines[at:at] = block
    return "\n".join(lines)


def new_versions(base: str, head: str) -> list[str]:
    """Version headings (``## [x.y.z]``) in ``head`` that ``base`` does not have, in file order."""
    known = set(_VERSION_HEADING.findall(base))
    return [version for version in _VERSION_HEADING.findall(head) if version not in known]


def _unreleased_entries(changelog: str) -> int:
    """How many non-blank, non-heading lines ``[Unreleased]`` holds; 0 without the heading."""
    lines = changelog.split("\n")
    heads = [i for i, line in enumerate(lines) if line.rstrip() == _UNRELEASED]
    if len(heads) != 1:
        return 0
    body = lines[heads[0] + 1 : _section_end(lines, heads[0])]
    return sum(1 for line in body if line.strip() and not line.startswith("#"))


def _listing(fragments: list[Fragment]) -> str:
    return "\n  ".join(f"{FRAGMENT_DIR}/{f.path.name}" for f in fragments)


_ORDER_HINT = (
    "Undo the rename, run `python scripts/release/changelog_fragments.py assemble`, THEN rename "
    f"'{_UNRELEASED}' to the version and add a fresh empty one above it."
)


def pr_check(root: Path, base_changelog: str) -> int:
    """The pull-request check. Returns the exit status; see the module docstring.

    ``base_changelog`` is text read in universal-newline mode, like the head copy read here.
    """
    fragments = load(root / FRAGMENT_DIR)
    head = (root / CHANGELOG).read_text(encoding="utf-8")
    added = new_versions(base_changelog, head)
    if added and fragments:
        print(
            f"this pull request adds version heading(s) {', '.join(added)} to {CHANGELOG} while "
            f"{len(fragments)} fragment(s) remain, so that release would miss them. "
            f"{_ORDER_HINT}\n  {_listing(fragments)}",
            file=sys.stderr,
        )
        return 1
    stranded = _unreleased_entries(head)
    if added and stranded:
        print(
            f"this pull request adds version heading(s) {', '.join(added)}, but '{_UNRELEASED}' "
            f"still holds {stranded} line(s), so that release's notes would miss them. They were "
            f"probably assembled after the rename. Move them under the new version. {_ORDER_HINT}",
            file=sys.stderr,
        )
        return 1
    if not added and head != base_changelog:
        print(
            f"::warning file={CHANGELOG}::This pull request edits {CHANGELOG}. Add a fragment under "
            f"{FRAGMENT_DIR}/ instead (see {FRAGMENT_DIR}/README.md); only the release pull request "
            f"edits {CHANGELOG}. This is a warning, not a failure."
        )
    print(f"changelog fragments: {len(fragments)} well-formed; new version heading(s): {added}")
    return 0


def _untracked(root: Path) -> set[str]:
    """Fragment paths git does not track. Empty when ``root`` is not a git checkout."""
    try:
        out = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
            ["git", "ls-files", "--others", "--exclude-standard", "-z", "--", FRAGMENT_DIR],
            cwd=root,
            capture_output=True,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return set()
    return {name for name in out.decode("utf-8", "replace").split("\0") if name}


def assemble(root: Path, *, dry_run: bool = False) -> list[Fragment]:
    """Fold ``root/changelog.d`` into ``root/CHANGELOG.md``, then delete the fragments.

    Refuses an UNTRACKED fragment: a leftover draft from another branch would otherwise be
    announced and then deleted. The changelog is written BEFORE any fragment is deleted, so a
    failed write loses nothing.
    """
    fragments = load(root / FRAGMENT_DIR)
    if not fragments:
        return []
    loose = _untracked(root)
    untracked = [f for f in fragments if f"{FRAGMENT_DIR}/{f.path.name}" in loose]
    if untracked:
        raise FragmentError(
            "not tracked by git, so no merged pull request added them; commit or remove:\n  "
            + _listing(untracked)
        )
    changelog_path = root / CHANGELOG
    with changelog_path.open(encoding="utf-8", newline="") as handle:
        text = handle.read()
    updated = assemble_text(text, fragments)
    if dry_run:
        # Bytes, not text: the changelog is full of non-ASCII, and a stock cp1252 Windows console
        # raises UnicodeEncodeError on it.
        sys.stdout.flush()
        sys.stdout.buffer.write(updated.encode("utf-8"))
        sys.stdout.buffer.flush()
        return fragments
    with changelog_path.open("w", encoding="utf-8", newline="") as handle:
        handle.write(updated)
    for fragment in fragments:
        fragment.path.unlink()
    return fragments


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0] if __doc__ else None)
    parser.add_argument("--root", type=Path, default=REPO_ROOT, help="repository root")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check", help="refuse a malformed fragment")
    check.add_argument(
        "--no-pending",
        action="store_true",
        help="also refuse ANY fragment; the release job runs this so a tag cannot ship without them",
    )
    against = sub.add_parser(
        "pr-check", help="compare CHANGELOG.md with the base branch's copy (pull requests)"
    )
    against.add_argument(
        "--base-changelog", type=Path, required=True, help="the base branch's CHANGELOG.md"
    )
    build = sub.add_parser("assemble", help="fold fragments into CHANGELOG.md and delete them")
    build.add_argument(
        "--dry-run", action="store_true", help="print the new CHANGELOG.md; change nothing"
    )
    args = parser.parse_args(argv)
    root: Path = args.root
    try:
        if args.command == "check":
            fragments = load(root / FRAGMENT_DIR)
            if args.no_pending and fragments:
                print(
                    f"{len(fragments)} changelog fragment(s) were never assembled, so the release "
                    f"notes would miss them. Cut a release pull request that runs `python "
                    f"scripts/release/changelog_fragments.py assemble` before renaming "
                    f"'{_UNRELEASED}', then tag again:\n  {_listing(fragments)}",
                    file=sys.stderr,
                )
                return 1
            print(f"changelog fragments: {len(fragments)} well-formed, 0 malformed")
            return 0
        if args.command == "pr-check":
            base_path: Path = args.base_changelog
            return pr_check(root, base_path.read_text(encoding="utf-8"))
        done = assemble(root, dry_run=args.dry_run)
    except FragmentError as error:
        print(f"changelog fragments refused:\n{error}", file=sys.stderr)
        return 1
    if not args.dry_run:
        verb = "assembled and deleted" if done else "nothing to assemble:"
        print(f"changelog fragments: {verb} {len(done)} fragment(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
