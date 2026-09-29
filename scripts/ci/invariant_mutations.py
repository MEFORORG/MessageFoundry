# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Run the bounded mutation list over the named invariant tests (BACKLOG #1746, limbs 4 and 5).

Each row of ``scripts/ci/invariant_mutations.toml`` is one deliberate break and the tests that must
turn red under it. For each row this script:

1. runs the row's tests UNMUTATED and requires them green (a test already red proves nothing);
2. applies the break, runs the same tests, and restores the file in a ``finally``;
3. checks the file's bytes are back to what they were.

HOW A RUN IS SCORED IS THE POINT, AND IT FOLLOWS docs/Code_Quality_Standards.md SECTION 4.0 RULE 6
(limb 4). A break is KILLED only when pytest exits 1 AND prints at least one ``FAILED`` line naming a
test the row listed. Pytest's other exit codes are not a kill: 2 (interrupted, often a collection
error), 4 (usage) and 5 (no tests collected) all mean the tests never judged the break, and a runner
that counted them red would report a control where none ran. The summary line is never parsed; a
review instrument that matched a regex against it once reported every control green while matching
nothing (Fable packet 5).

Every pytest child runs with ``PYTHONSAFEPATH=1``, so the working directory cannot shadow the
installed package, and the run prints which ``messagefoundry`` answered (#1677). A tree outside this
repository is refused, because the breaks would then land in files the tests never import.

Exit codes: 0 every row killed; 1 at least one row SURVIVED; 2 the run could not judge (a row not
green before its break, an unkillable exit code, a stale ``find``, a restore mismatch, or ZERO rows
selected -- zero is not a pass).

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

KILLED = "KILLED"
SURVIVED = "SURVIVED"
ERROR = "ERROR"

_TIMEOUT_SECONDS = 900


@dataclass(frozen=True)
class Mutation:
    id: str
    item: int
    file: str
    find: str
    replace: str
    tests: tuple[str, ...]


def load(path: Path = LIST_PATH) -> list[Mutation]:
    """Parse the list, refusing a row with a missing or empty field."""
    rows = tomllib.loads(path.read_text(encoding="utf-8")).get("mutation", [])
    out: list[Mutation] = []
    for row in rows:
        missing = [k for k in ("id", "item", "file", "find", "replace", "tests") if not row.get(k)]
        if missing:
            raise ValueError(f"mutation {row.get('id', '?')!r} is missing {missing}")
        out.append(
            Mutation(
                id=row["id"],
                item=int(row["item"]),
                file=row["file"],
                find=row["find"],
                replace=row["replace"],
                tests=tuple(row["tests"]),
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


def anchor_count(m: Mutation, root: Path = REPO) -> int:
    """How many times the row's ``find`` text occurs in its file (it must be exactly 1)."""
    data = (root / m.file).read_bytes()
    return data.count(_encoded(m.find, data))


def child_env() -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONSAFEPATH"] = "1"
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


def failed_nodes(output: str) -> list[str]:
    """The node ids pytest's short summary marks ``FAILED`` (``-rf``)."""
    nodes: list[str] = []
    for line in output.splitlines():
        if line.startswith("FAILED "):
            nodes.append(line[len("FAILED ") :].split(" - ", 1)[0].strip())
    return nodes


def _names_a_listed_test(node: str, tests: tuple[str, ...]) -> bool:
    # A parametrised test reports as `path::name[param]`; the row lists `path::name`.
    return any(node == t or node.startswith(t + "[") for t in tests)


def score(returncode: int, output: str, tests: tuple[str, ...]) -> str:
    """Score one mutated run by exit code and FAILED lines only, never by summary text."""
    if returncode == 0:
        return SURVIVED
    if returncode == 1 and any(_names_a_listed_test(n, tests) for n in failed_nodes(output)):
        return KILLED
    return ERROR


def _pytest(tests: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # nosec B603 - fixed argv, no shell; node ids come from the list
        [sys.executable, "-m", "pytest", "-q", "-rf", "-p", "no:cacheprovider", *tests],
        cwd=REPO,
        env=child_env(),
        capture_output=True,
        text=True,
        timeout=_TIMEOUT_SECONDS,
    )


def run_one(m: Mutation) -> tuple[str, str]:
    """Return ``(verdict, reason)`` for one row."""
    target = REPO / m.file
    original = target.read_bytes()
    found = original.count(_encoded(m.find, original))
    if found != 1:
        return ERROR, f"`find` occurs {found} time(s) in {m.file}, expected exactly 1 (stale row)"
    before = _pytest(m.tests)
    if before.returncode != 0:
        return ERROR, f"not green before the break (pytest exit {before.returncode})"
    try:
        target.write_bytes(
            original.replace(_encoded(m.find, original), _encoded(m.replace, original), 1)
        )
        after = _pytest(m.tests)
    finally:
        target.write_bytes(original)
    if target.read_bytes() != original:
        return ERROR, f"{m.file} was not restored byte for byte"
    verdict = score(after.returncode, after.stdout + after.stderr, m.tests)
    nodes = failed_nodes(after.stdout)
    first = f", first {nodes[0]}" if nodes else ""
    reason = f"pytest exit {after.returncode}, {len(nodes)} FAILED line(s){first}"
    return verdict, reason


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--only", action="append", default=[], help="run only this id")
    parser.add_argument("--list", action="store_true", help="print the rows and exit")
    args = parser.parse_args(argv)

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

    tree = answering_tree()
    print(f"# invariant-mutations tree={tree} list={LIST_PATH.relative_to(REPO).as_posix()}")
    if not tree.is_relative_to(REPO):
        print(f"error: messagefoundry imports from {tree}, outside {REPO}", file=sys.stderr)
        return 2

    verdicts: dict[str, int] = {KILLED: 0, SURVIVED: 0, ERROR: 0}
    for m in rows:
        verdict, reason = run_one(m)
        verdicts[verdict] += 1
        print(f"{verdict:8s} {m.id} (#{m.item}): {reason}", flush=True)
    print(
        f"# ran {len(rows)} mutation(s): {verdicts[KILLED]} killed, "
        f"{verdicts[SURVIVED]} survived, {verdicts[ERROR]} error"
    )
    if verdicts[ERROR]:
        return 2
    return 1 if verdicts[SURVIVED] else 0


if __name__ == "__main__":
    sys.exit(main())
