# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Run the bounded mutation list over the named invariant tests (BACKLOG #1746, limbs 4 and 5).

Each row of ``scripts/ci/invariant_mutations.toml`` is one deliberate break and the tests that must
turn red under it. For each row this script follows docs/Code_Quality_Standards.md section 4.0
rule 7's two-directional control:

1. runs the row's tests UNMUTATED and requires them to pass with none skipped (a test already red,
   or one that never ran, proves nothing);
2. applies the break, runs the same tests, and restores the file in a ``finally``;
3. checks the file's bytes are back, then runs the tests again and requires them green.

HOW A RUN IS SCORED IS THE POINT, AND IT FOLLOWS RULE 6 OF THE SAME SECTION (limb 4). A break is
KILLED only when pytest exits 1 AND prints at least one ``FAILED`` or ``ERROR`` line naming a test
the row listed. Pytest's other exit codes are not a kill: 2 (interrupted, often a collection error),
4 (usage) and 5 (no tests collected) all mean the tests never judged the break, and a runner that
counted them red would report a control where none ran. The summary line is never parsed; a review
instrument that matched a regex against it once reported every control green while matching nothing
(Fable packet 5). A test killed by pytest-timeout's thread method exits with no summary at all, so
it scores ERROR rather than KILLED; that is the conservative reading.

Every pytest child runs with ``PYTHONSAFEPATH=1``, so the working directory cannot shadow the
installed package, with colour off and ``PYTEST_ADDOPTS`` removed, so nothing in the caller's
environment changes the lines this reads. The run prints which ``messagefoundry`` answered (#1677)
and refuses any tree but this checkout's own ``messagefoundry/``, because the breaks would then land
in files the tests never import.

IT EDITS THE LIVE CHECKOUT. While a row runs, its engine file is broken on disk, so do not run this
in a worktree anything else is using. Before writing, it saves the original next to the file as
``<file>.invariant-mutation-backup`` (ignored by git); the ``finally`` removes it. A hard kill skips
the ``finally``, so the next run looks for a backup first. It restores one only when the file still
holds exactly a break this list makes; if the file changed since, it refuses and changes nothing.

Exit codes: 0 every row killed; 1 at least one row SURVIVED, whatever else happened (a survivor is
the finding, and an error elsewhere must not hide it); 2 the run could not judge. Causes of 2 are at
least: a row not green before or after its break, an unkillable exit code, a stale ``find``, a
restore mismatch, a leftover backup it will not restore, the wrong ``messagefoundry`` tree, an
unknown ``--only`` id, any unexpected exception, and ZERO rows selected -- zero is not a pass.

Usage::

    python scripts/ci/invariant_mutations.py            # every row
    python scripts/ci/invariant_mutations.py --only ID  # one row, repeatable
    python scripts/ci/invariant_mutations.py --list
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
LIST_PATH = REPO / "scripts" / "ci" / "invariant_mutations.toml"
BACKUP_SUFFIX = ".invariant-mutation-backup"

KILLED = "KILLED"
SURVIVED = "SURVIVED"
ERROR = "ERROR"

_TIMEOUT_SECONDS = 900
_FIELDS = ("id", "item", "file", "find", "replace", "tests")


@dataclass(frozen=True)
class Mutation:
    id: str
    item: int
    file: str
    find: str
    replace: str
    tests: tuple[str, ...]


class LeftoverBackup(RuntimeError):
    """A backup from an interrupted run sits beside a file that no longer holds its break."""


def load(path: Path | None = None) -> list[Mutation]:
    """Parse the list, refusing a row with a missing field, an empty ``find`` or no tests.

    An empty ``replace`` is allowed: deleting a guard outright is the most natural break.
    """
    rows = tomllib.loads((path or LIST_PATH).read_text(encoding="utf-8")).get("mutation", [])
    out: list[Mutation] = []
    for row in rows:
        missing = [k for k in _FIELDS if k not in row]
        if missing or not row["find"] or not row["tests"]:
            raise ValueError(f"mutation {row.get('id', '?')!r} is missing or empty: {missing}")
        out.append(
            Mutation(
                id=str(row["id"]),
                item=int(row["item"]),
                file=str(row["file"]),
                find=str(row["find"]),
                replace=str(row["replace"]),
                tests=tuple(str(t) for t in row["tests"]),
            )
        )
    ids = [m.id for m in out]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        raise ValueError(f"duplicate mutation ids: {dupes}")
    return out


def _encoded(text: str, data: bytes) -> bytes:
    """``text`` as bytes in the target file's own line-ending convention."""
    raw = text.encode("utf-8")
    return raw.replace(b"\n", b"\r\n") if b"\r\n" in data else raw


def _line_anchored_count(data: bytes, needle: bytes) -> int:
    """Occurrences of ``needle`` that start a line, so an anchor cannot match mid-line."""
    return data.count(b"\n" + needle) + (1 if data.startswith(needle) else 0)


def anchor_count(m: Mutation, root: Path | None = None) -> int:
    """How many lines the row's ``find`` text starts on in its file (it must be exactly 1)."""
    data = ((root or REPO) / m.file).read_bytes()
    return _line_anchored_count(data, _encoded(m.find, data))


def break_bytes(m: Mutation, data: bytes) -> bytes:
    """``data`` with the row's break applied at its line-anchored occurrence."""
    find, replace = _encoded(m.find, data), _encoded(m.replace, data)
    if data.startswith(find):
        return replace + data[len(find) :]
    return data.replace(b"\n" + find, b"\n" + replace, 1)


def mutated_bytes(m: Mutation, root: Path | None = None) -> bytes:
    """The row's file with its break applied."""
    return break_bytes(m, ((root or REPO) / m.file).read_bytes())


def child_env() -> dict[str, str]:
    env = dict(os.environ)
    for key in ("PYTEST_ADDOPTS", "PY_COLORS", "FORCE_COLOR"):
        env.pop(key, None)
    env["PYTHONSAFEPATH"] = "1"
    env["NO_COLOR"] = "1"
    env.setdefault("QT_QPA_PLATFORM", "offscreen")
    return env


def answering_tree() -> Path:
    """The directory the child interpreter imports ``messagefoundry`` from."""
    out = subprocess.run(  # nosec B603 - fixed argv, no shell
        [sys.executable, "-c", "import messagefoundry; print(messagefoundry.__file__)"],
        cwd=REPO,
        env=child_env(),
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
    )
    return Path(out.stdout.strip()).resolve().parent


def _summary_nodes(output: str, marker: str) -> list[str]:
    nodes: list[str] = []
    for line in output.splitlines():
        if line.startswith(marker):
            nodes.append(line[len(marker) :].split(" - ", 1)[0].strip())
    return nodes


def failed_nodes(output: str) -> list[str]:
    """The node ids pytest's short summary marks ``FAILED`` or ``ERROR`` (``-rfEs``)."""
    return _summary_nodes(output, "FAILED ") + _summary_nodes(output, "ERROR ")


def skipped_lines(output: str) -> list[str]:
    """Pytest's short-summary ``SKIPPED`` lines (``-rfEs``)."""
    return [line for line in output.splitlines() if line.startswith("SKIPPED ")]


def _names_a_listed_test(node: str, tests: tuple[str, ...]) -> bool:
    # A parametrised test reports as `path::name[param]`; the row lists `path::name`.
    return any(node == t or node.startswith(t + "[") for t in tests)


def score(returncode: int, output: str, tests: tuple[str, ...]) -> str:
    """Score one mutated run by exit code and FAILED/ERROR lines only, never by summary text."""
    if returncode == 0:
        return SURVIVED
    if returncode == 1 and any(_names_a_listed_test(n, tests) for n in failed_nodes(output)):
        return KILLED
    return ERROR


def _pytest(tests: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
    argv = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--color=no"]
    return subprocess.run(  # nosec B603 - fixed argv, no shell; node ids come from the list
        [*argv, *tests, "-rfEs"],
        cwd=REPO,
        env=child_env(),
        capture_output=True,
        text=True,
        timeout=_TIMEOUT_SECONDS,
    )


def _backup(target: Path) -> Path:
    return target.with_name(target.name + BACKUP_SUFFIX)


def restore_leftovers(rows: list[Mutation]) -> list[str]:
    """Restore any file an interrupted run left broken; return the paths restored.

    A backup is trusted only while the file beside it holds exactly one of this list's breaks
    applied to it. Anything else means the file moved on (a restore, a pull, new edits), and
    writing the old bytes back would destroy that work, so this raises instead.
    """
    restored: list[str] = []
    for file in sorted({m.file for m in rows}):
        target = REPO / file
        backup = _backup(target)
        if not backup.is_file():
            continue
        saved, current = backup.read_bytes(), target.read_bytes()
        if current != saved and current not in {
            break_bytes(m, saved) for m in rows if m.file == file
        }:
            raise LeftoverBackup(
                f"{backup} is left from an interrupted run, and {file} no longer holds its "
                f"break; compare the two by hand, then delete the backup"
            )
        target.write_bytes(saved)
        backup.unlink()
        restored.append(file)
    return restored


def run_one(m: Mutation) -> tuple[str, str]:
    """Return ``(verdict, reason)`` for one row."""
    target = REPO / m.file
    found = anchor_count(m)
    if found != 1:
        return ERROR, f"`find` starts {found} line(s) in {m.file}, expected exactly 1 (stale row)"
    before = _pytest(m.tests)
    if before.returncode != 0:
        return ERROR, f"not green before the break (pytest exit {before.returncode})"
    if skipped_lines(before.stdout):
        return (
            ERROR,
            f"a listed test was skipped, so it cannot judge: {skipped_lines(before.stdout)}",
        )
    original = target.read_bytes()
    broken = break_bytes(m, original)
    backup = _backup(target)
    backup.write_bytes(original)
    try:
        target.write_bytes(broken)
        after = _pytest(m.tests)
    finally:
        target.write_bytes(original)
        backup.unlink()
    if target.read_bytes() != original:
        return ERROR, f"{m.file} was not restored byte for byte"
    reverted = _pytest(m.tests)
    if reverted.returncode != 0:
        return ERROR, f"not green again after the revert (pytest exit {reverted.returncode})"
    verdict = score(after.returncode, after.stdout + after.stderr, m.tests)
    nodes = failed_nodes(after.stdout)
    first = f", first {nodes[0]}" if nodes else ""
    return verdict, f"pytest exit {after.returncode}, {len(nodes)} FAILED/ERROR line(s){first}"


def judge(rows: list[Mutation]) -> dict[str, int]:
    """Run every row, turning a row's own exception into ERROR so later rows still run."""
    verdicts: dict[str, int] = {KILLED: 0, SURVIVED: 0, ERROR: 0}
    for m in rows:
        try:
            verdict, reason = run_one(m)
        except Exception as exc:  # noqa: BLE001 -- one row's crash must not hide another's survivor
            verdict, reason = ERROR, f"{type(exc).__name__}: {exc}"
        verdicts[verdict] += 1
        print(f"{verdict:8s} {m.id} (#{m.item}): {reason}", flush=True)
    return verdicts


def exit_code(verdicts: dict[str, int]) -> int:
    """1 when anything survived, whatever else happened; else 2 on any error; else 0."""
    if verdicts[SURVIVED]:
        return 1
    return 2 if verdicts[ERROR] else 0


def _run(args: argparse.Namespace) -> int:
    rows = load()
    if args.only:
        unknown = sorted(set(args.only) - {m.id for m in rows})
        if unknown:
            print(f"error: unknown mutation id(s): {unknown}", file=sys.stderr)
            return 2
        rows = [m for m in rows if m.id in args.only]
    if args.list:
        for m in rows:
            print(f"{m.id}  #{m.item}  {m.file}  {len(m.tests)} test(s)")
        return 0 if rows else 2
    if not rows:
        print("error: 0 mutations selected; a run over nothing is not a pass", file=sys.stderr)
        return 2
    for file in restore_leftovers(load()):
        print(f"warning: restored {file} from a backup an interrupted run left behind")

    tree = answering_tree()
    print(f"# invariant-mutations tree={tree} list={LIST_PATH.relative_to(REPO).as_posix()}")
    if tree != (REPO / "messagefoundry").resolve():
        print(f"error: messagefoundry imports from {tree}, not {REPO}", file=sys.stderr)
        return 2

    verdicts = judge(rows)
    print(
        f"# ran {len(rows)} mutation(s): {verdicts[KILLED]} killed, "
        f"{verdicts[SURVIVED]} survived, {verdicts[ERROR]} error"
    )
    return exit_code(verdicts)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--only", action="append", default=[], help="run only this id")
    parser.add_argument("--list", action="store_true", help="print the rows and exit")
    args = parser.parse_args(argv)
    try:
        return _run(args)
    except Exception as exc:  # noqa: BLE001 -- any crash is "could not judge", never "survived"
        print(f"error: the run could not judge: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
