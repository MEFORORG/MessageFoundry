#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Rebuild and verify the offline password-screening corpus (BACKLOG #1433, from #1134).

``messagefoundry/auth/data/common_passwords.txt`` was assembled by hand and no script was committed
with it, so every number in its ``.NOTICE`` was a hand-copied measurement. Nothing recomputed them,
so a corpus edit could leave the notice describing a file that no longer existed -- and the only
remedy on offer was to re-derive each count by hand, which is how a stale number becomes permanent.

This is the generator half of the tree's generator-plus-golden pattern (see
``scripts/webconsole_seam_snapshot.py``, ``scripts/quality/username_access_key_screen.py``). The
golden here is a **delimited generated block inside the notice itself**, between :data:`BLOCK_BEGIN`
and :data:`BLOCK_END`, because the notice ships in the wheel and is what a deploying reader opens: a
golden under ``tests/`` would leave that reader either numberless or holding a second copy. The prose
around the block is hand-written and this script never touches it.

Usage::

    python scripts/security/build_password_corpus.py --check              verify the block
    python scripts/security/build_password_corpus.py --write              regenerate the block
    python scripts/security/build_password_corpus.py --check --seclists DIR   also verify the corpus
    python scripts/security/build_password_corpus.py --write --seclists DIR   also rebuild the corpus

WHAT ``--check`` VERIFIES WITHOUT ``--seclists``, WHICH IS THE MODE CI AND PYTEST RUN. Every number
in the block is recomputed from the shipped corpus and diffed against the block. That covers the
digest, the line and distinct counts, the two-run split, and the whole by-floor table. It does
**not** verify that the corpus reproduces from upstream -- SecLists is an 8 MB third-party checkout
this repository deliberately does not vendor, so a run without ``--seclists`` says so in its own
output rather than reporting a green that means less than it looks like.

THE TWO-RUN STRUCTURE IS THE PART A DIGEST ALONE WOULD MISS. The file is two rank-ordered runs
concatenated, not one sorted list: lines 1-10,000 are ``Pwdb_top-10000.txt`` entire, and the rest are
the ``Pwdb_top-1000000.txt`` entries that clear the shipped policy and were not already covered. A
digest changes when anything changes; the block additionally records what each run contributes, so a
rebuild that silently reordered or truncated a run is legible in the diff instead of showing up as
one opaque hex string that moved.

THE DIGEST IS TAKEN OVER LF-NORMALIZED BYTES, DELIBERATELY. The corpus is a text file with a ``-text``
attribute (see ``.gitattributes``), so a checkout should hold the committed LF bytes on every
platform. Normalizing anyway means the recorded digest still answers "is this the same corpus" on a
checkout made before that attribute landed, which would otherwise hold CRLF and fail with a hex
mismatch that names nothing. The loader (``messagefoundry.auth.policy._common_passwords``) splits on
line boundaries and strips, so line endings cannot change what the engine screens against.

THE FILTER IS THE SHIPPED POLICY OBJECT, NOT A LENGTH TEST. ASVS 6.2.4 asks for the top passwords
*which match the application's password policy*, so :func:`selection_policy` calls
``PasswordPolicy.from_settings`` -- the same constructor ``AuthService`` uses -- which applies the
length clause **and** the context deny-list. Two flags are then turned off, for the reasons the
notice records: ``check_breached`` would have every candidate reject itself against the corpus it is
being added to, and ``check_username`` has no user context to check against.

THE BY-FLOOR TABLE ASKS THE POLICY AT EVERY FLOOR RATHER THAN DERIVING THE ROWS. Bucketing entries by
length and cumulative-summing is about seven times faster, and it is right only while ``min_length``
stays confined to one clause of ``violations()``. That is a re-derivation, and the claim this whole
file rests on is that its numbers come from the shipped policy object. Asking honestly costs about
0.1 seconds per run, which is not a price worth paying a correctness assumption for.

RE-SCORE TRIGGER. The selection depends on ``password_min_length`` **and** ``password_check_context``.
Moving either shipped default changes the corpus this script produces and the counts it records, so
both are printed in the block and both belong in the ASVS 6.2.4 re-score trigger.

THE BLOCK REPORTS THE BAR AND THE MEASUREMENT, AND STATES NO VERDICT. Whether ASVS 6.2.4 passes is a
graded cell in the vaulted scorecard (CLAUDE.md section 12), so a shipped file asserting MET would be
a second, unreviewed verdict register the vault does not know about -- and a narrower one, since
corpus depth is an input to 6.2.4 rather than the whole of it.
"""

from __future__ import annotations

import argparse
import dataclasses
import difflib
import functools
import hashlib
import importlib.util
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

_REPO_ROOT = Path(__file__).resolve().parents[2]

if str(_REPO_ROOT) not in sys.path:  # runnable as a bare script, like its siblings
    sys.path.insert(0, str(_REPO_ROOT))

from messagefoundry.auth.policy import PasswordPolicy  # noqa: E402
from messagefoundry.config.settings import AuthSettings  # noqa: E402

CORPUS_PATH = _REPO_ROOT / "messagefoundry" / "auth" / "data" / "common_passwords.txt"
NOTICE_PATH = _REPO_ROOT / "messagefoundry" / "auth" / "data" / "common_passwords.NOTICE"

#: The upstream members, in the order they are concatenated. Run 1 is taken entire; run 2 is filtered.
#: Paths are relative to a SecLists checkout root.
RUN1_MEMBER = "Passwords/Common-Credentials/Pwdb_top-10000.txt"
RUN2_MEMBER = "Passwords/Common-Credentials/Pwdb_top-1000000.txt"

#: SHA-256 of each upstream member over LF-normalized bytes, or ``None`` while nobody has recorded it.
#:
#: RECORDED AS CONSTANTS RATHER THAN CARRIED IN THE NOTICE, and that difference is not cosmetic. The
#: first draft parsed them back out of the block it had rendered, so writer and reader each owned
#: half of one format and could desync -- which they immediately did: the reader's prefix test also
#: matched the CORPUS digest line, so it found three values where it wanted two, gave up, and a
#: source-less ``--write`` erased the provenance it existed to preserve. These are the only facts
#: here not derivable from the tree, which is the same status :data:`RUN1_LINES` has.
#:
#: To record them: ``--check --seclists <checkout>`` prints the values, and they are pasted in here.
RUN1_MEMBER_SHA256: str | None = None
RUN2_MEMBER_SHA256: str | None = None

#: Where run 1 ends and run 2 begins. Recorded rather than inferred: a rebuild must reproduce the
#: same boundary, and inferring it from the file would make the check agree with any file at all.
RUN1_LINES = 10_000

#: EXTRA minimum lengths the by-floor table reports. The SHIPPED floor is added by :func:`_floors`
#: and is deliberately absent here -- listing it too would make that union a no-op, so the one branch
#: guaranteeing the table carries the row that decides the ASVS reading would never fire, and a later
#: "simplification" back to a bare loop would pass every test until someone moved the default.
REPORT_FLOORS = (8, 10, 12, 16, 17, 20)

#: ASVS 6.2.4 asks for a check against at least this many policy-matching passwords. Stated once
#: here; ``tests/test_auth_core.py`` imports it rather than writing the number a second time.
ASVS_6_2_4_BAR = 3000

BLOCK_BEGIN = "BEGIN GENERATED BLOCK -- scripts/security/build_password_corpus.py"
BLOCK_END = "END GENERATED BLOCK"

_NOT_RECORDED = "not recorded"


@functools.lru_cache(maxsize=4)
def _load_script(relative: str, name: str) -> ModuleType:
    """Import a sibling gate script by path. ``scripts/`` is not an importable package.

    Cached: the hygiene filter consults both gates once per candidate, and re-executing a module
    several thousand times turns a rebuild from seconds into minutes.
    """
    spec = importlib.util.spec_from_file_location(name, _REPO_ROOT / relative)
    if spec is None or spec.loader is None:  # pragma: no cover - a missing sibling is a broken tree
        raise SystemExit(f"cannot load {relative}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def selection_policy() -> PasswordPolicy:
    """The filter run 2 was selected with: the SHIPPED policy, minus two inapplicable clauses.

    ``PasswordPolicy.from_settings`` is the constructor ``AuthService`` uses, so a screening field
    added later is picked up here without anyone remembering to. Building the mapping by hand instead
    would filter and count the corpus under a policy that is not the shipped one, and ``--check``
    could not see it: it would apply the same wrong policy on both sides of its own comparison.

    The two overrides, for the reasons the notice records:

    * ``check_breached`` -- every candidate would reject itself against the corpus it is being added
      to, so the filter would select nothing and the run would silently come out empty.
    * ``check_username`` -- a corpus entry has no user to be compared against.
    """
    return dataclasses.replace(
        PasswordPolicy.from_settings(AuthSettings()),
        check_breached=False,
        check_username=False,
    )


def _hygienic(entry: str) -> bool:
    """Whether *entry* survives the hygiene filter -- the two junk classes the commit gates found.

    A third-party corpus carries shapes a hand-written file never would. Both rules are CALLED on the
    gates that own them rather than restated here, because a second copy of a rule is a second rule:
    it agrees today and diverges the day either gate is tightened, with nothing reporting it.

    The IP arm reads only the ``routable IP address`` reason out of ``scan_text``. The rest of that
    function's reasons come from a site-local, git-ignored token file, so consuming them would make
    the corpus a function of who ran the rebuild.
    """
    control = _load_script("scripts/quality/control_char_check.py", "_ppc_control_char_check")
    forbidden = _load_script("scripts/security/scan_forbidden.py", "_ppc_scan_forbidden")
    if any(control.is_disallowed(byte) for byte in entry.encode("utf-8")):
        return False
    reasons: list[str] = forbidden.scan_text(entry)
    return "routable IP address" not in reasons


def _lf_bytes(path: Path) -> bytes:
    """*path*'s bytes with CRLF normalized to LF. The one reader everything else is derived from."""
    return path.read_bytes().replace(b"\r\n", b"\n")


def _lf_digest(path: Path) -> str:
    """SHA-256 over *path*'s LF-normalized bytes. One definition, so the corpus digest and the
    upstream-member digests printed beside it can never come to be computed differently."""
    return hashlib.sha256(_lf_bytes(path)).hexdigest()


def _entries(raw: bytes) -> list[str]:
    """Stripped, non-empty lines of *raw*, in file order -- the way the engine's loader reads them.

    One reader for the shipped corpus AND for an upstream member, deliberately. Two readers that
    drift make ``--check --seclists`` compare two files parsed under different rules, and report a
    difference that is an artifact of the reader rather than real drift.
    """
    return [line.strip() for line in raw.decode("utf-8", "ignore").splitlines() if line.strip()]


def _read_member(root: Path, member: str) -> list[str]:
    path = root / member
    if not path.is_file():
        raise SystemExit(f"missing upstream member: {path}")
    return _entries(_lf_bytes(path))


def rebuild_corpus(seclists_root: Path) -> list[str]:
    """The corpus as it is derived from the two upstream members, in file order.

    Run 1 is taken ENTIRE, including the entries the shipped floor already rejects. That is the
    notice's load-bearing choice, not an oversight: ``password_min_length`` is an operator setting,
    and a site that lowers it makes every short entry operative again. Dropping them would delete
    protection from exactly the configuration that needs it most.
    """
    run1 = _read_member(seclists_root, RUN1_MEMBER)
    seen = {entry.lower() for entry in run1}
    policy = selection_policy()
    run2: list[str] = []
    for entry in _read_member(seclists_root, RUN2_MEMBER):
        key = entry.lower()
        if key in seen or policy.violations(key) or not _hygienic(entry):
            continue
        seen.add(key)
        run2.append(entry)
    return run1 + run2


@dataclass(frozen=True, slots=True)
class Measurement:
    """What the generated block reports, derived from the shipped corpus in one pass.

    Only independent facts are stored; everything a stored field already fixes is a property. The
    gate compares the block against a fresh measurement and never the block's numbers against each
    other, so a derived number stored as a field could become internally inconsistent, render,
    verify, and go unreported.
    """

    sha256: str
    byte_count: int
    line_count: int
    run1_distinct: int
    run2_distinct: int
    overlap: int
    min_length: int
    check_context: bool
    floors: tuple[tuple[int, int, int, int], ...]  # (floor, total, from run 1, from run 2)

    @property
    def run1_lines(self) -> int:
        return min(self.line_count, RUN1_LINES)

    @property
    def run2_lines(self) -> int:
        return self.line_count - self.run1_lines

    @property
    def distinct(self) -> int:
        """Inclusion-exclusion over the two runs -- exact for two sets."""
        return self.run1_distinct + self.run2_distinct - self.overlap

    @property
    def clearing_at_shipped_floor(self) -> int:
        return next(total for floor, total, _, _ in self.floors if floor == self.min_length)


def _floors() -> tuple[int, ...]:
    """The reported floors, always including the shipped one -- see :data:`REPORT_FLOORS`."""
    return tuple(sorted({*REPORT_FLOORS, AuthSettings().password_min_length}))


def measure() -> Measurement:
    """Recompute every recorded number from the shipped corpus."""
    raw = _lf_bytes(CORPUS_PATH)
    lines = _entries(raw)
    run1 = {entry.lower() for entry in lines[:RUN1_LINES]}
    run2 = {entry.lower() for entry in lines[RUN1_LINES:]}
    shipped = AuthSettings()

    base = selection_policy()
    rows: list[tuple[int, int, int, int]] = []
    for floor in _floors():
        policy = dataclasses.replace(base, min_length=floor)
        one = sum(1 for entry in run1 if not policy.violations(entry))
        two = sum(1 for entry in run2 if not policy.violations(entry))
        rows.append((floor, one + two, one, two))

    return Measurement(
        sha256=hashlib.sha256(raw).hexdigest(),
        byte_count=len(raw),
        line_count=len(lines),
        run1_distinct=len(run1),
        run2_distinct=len(run2),
        overlap=len(run1 & run2),
        min_length=shipped.password_min_length,
        check_context=shipped.password_check_context,
        floors=tuple(rows),
    )


def _n(value: int) -> str:
    return f"{value:,}"


def _rel(path: Path) -> str:
    """*path* named relative to the repo root, or absolute when it sits outside it.

    Falls back rather than raising: a test that redirects CORPUS_PATH/NOTICE_PATH at a temp file
    would otherwise die inside a progress message, which is a confusing way to lose a real result.
    """
    try:
        return path.relative_to(_REPO_ROOT).as_posix()
    except ValueError:
        return str(path)


def render_block(m: Measurement) -> str:
    """The generated block, as it appears between the markers in the notice."""
    lines = [
        BLOCK_BEGIN,
        "",
        "Do not hand-edit anything between these markers. Regenerate it:",
        "    python scripts/security/build_password_corpus.py --write",
        "",
        "Corpus file",
        "-----------",
        f"  sha256    {m.sha256}",
        "            over the file's bytes with CRLF normalized to LF, so the value does not",
        "            depend on the platform the checkout was made on",
        f"  bytes     {_n(m.byte_count)} (normalized)",
        f"  lines     {_n(m.line_count)}",
        f"  distinct  {_n(m.distinct)} entries, compared case-insensitively as the loader compares them",
        "",
        "Composition -- two rank-ordered runs, concatenated, NOT one sorted list",
        "----------------------------------------------------------------------",
        f"  run 1  lines 1-{_n(m.run1_lines)}",
        f"         {RUN1_MEMBER}",
        f"         taken entire: {_n(m.run1_lines)} lines, {_n(m.run1_distinct)} distinct",
        f"         upstream sha256 {RUN1_MEMBER_SHA256 or _NOT_RECORDED}",
        f"  run 2  lines {_n(m.run1_lines + 1)}-{_n(m.line_count)}",
        f"         {RUN2_MEMBER}",
        f"         filtered: {_n(m.run2_lines)} lines, {_n(m.run2_distinct)} distinct",
        f"         upstream sha256 {RUN2_MEMBER_SHA256 or _NOT_RECORDED}",
        f"  the runs share {_n(m.overlap)} entries case-insensitively",
        "",
        "How run 2 was selected",
        "----------------------",
        "  PasswordPolicy.from_settings(AuthSettings()) -- the constructor AuthService uses -- then",
        "  check_breached=False and check_username=False. The two shipped values the selection",
        "  depends on, so both belong in any ASVS 6.2.4 re-score trigger:",
        f"    password_min_length    = {m.min_length}",
        f"    password_check_context = {m.check_context}",
        "  Candidates were also dropped for a C0 control byte or a routable-IPv4 shape, using the",
        "  commit gates' own definitions (scripts/quality/control_char_check.py,",
        "  scripts/security/scan_forbidden.py).",
        "",
        "Policy-clearing coverage, by minimum length",
        "-------------------------------------------",
        "  An entry shorter than the floor can only reject what the length clause rejects first, so",
        "  the operative number is the count at the floor -- never the total entry count.",
        "",
        "    floor    clearing     from run 1     from run 2",
    ]
    for floor, total, one, two in m.floors:
        marker = " *" if floor == m.min_length else "  "
        lines.append(f"    {floor:>4}{marker} {_n(total):>9}  {_n(one):>12}   {_n(two):>12}")
    lines += [
        f"    * the shipped password_min_length ({m.min_length})",
        "",
        f"  ASVS 6.2.4 asks for a check against at least {_n(ASVS_6_2_4_BAR)} passwords matching the",
        f"  policy. At the shipped floor this corpus supplies {_n(m.clearing_at_shipped_floor)}.",
        "  The graded verdict for that requirement is a scorecard cell, not a line in this file.",
        "",
        BLOCK_END,
    ]
    return "\n".join(lines) + "\n"


def _block_bounds(notice: str) -> tuple[int, int] | None:
    """``(start, end of the END marker)`` of the generated block in *notice*, or ``None`` if absent.

    The single place either marker is located, so the two callers cannot come to disagree about
    whether the end marker's own newline belongs to the block.

    Refuses a notice with repeated markers rather than picking one: a file with two blocks has one
    the tool updates and one nobody reads, and guessing which is which is how the stale one survives.
    """
    if notice.count(BLOCK_BEGIN) > 1 or notice.count(BLOCK_END) > 1:
        raise SystemExit(f"{NOTICE_PATH.name}: repeated generated-block markers; fix by hand")
    if BLOCK_BEGIN not in notice or BLOCK_END not in notice:
        return None
    return notice.index(BLOCK_BEGIN), notice.index(BLOCK_END) + len(BLOCK_END)


def extract_block(notice: str) -> str | None:
    """The generated block currently in *notice*, or ``None`` if it has no markers."""
    bounds = _block_bounds(notice)
    return None if bounds is None else notice[bounds[0] : bounds[1]] + "\n"


def splice_block(notice: str, block: str) -> str:
    """*notice* with its generated block replaced by *block*, or the block appended if absent."""
    bounds = _block_bounds(notice)
    if bounds is None:
        return notice.rstrip("\n") + "\n\n" + block
    start, end = bounds
    return notice[:start] + block + notice[end + 1 :]  # +1 consumes the end marker's own newline


def upstream_digests(seclists_root: Path) -> tuple[str, str]:
    """The two upstream members' digests, computed from a SecLists checkout."""
    return _lf_digest(seclists_root / RUN1_MEMBER), _lf_digest(seclists_root / RUN2_MEMBER)


def check_upstream_digests(seclists_root: Path) -> tuple[list[str], list[str]]:
    """Compare the recorded member digests against a checkout. Returns ``(problems, notes)``.

    An UNRECORDED digest is a note, not a problem: nobody has run this with a checkout yet, which is
    a known-open piece of #1134's path rather than a defect in the tree. A RECORDED digest that does
    not match IS a problem -- that is a different upstream file than the corpus was built from.
    """
    problems: list[str] = []
    unrecorded: list[str] = []
    for member, recorded, actual, constant in zip(
        (RUN1_MEMBER, RUN2_MEMBER),
        (RUN1_MEMBER_SHA256, RUN2_MEMBER_SHA256),
        upstream_digests(seclists_root),
        ("RUN1_MEMBER_SHA256", "RUN2_MEMBER_SHA256"),
        strict=True,
    ):
        if recorded is None:
            unrecorded.append(f'  {constant}: str | None = "{actual}"  # {member}')
        elif recorded != actual:
            problems.append(
                f"{member} does not match the recorded digest.\n"
                f"  recorded ({constant}): {recorded}\n"
                f"  this checkout:         {actual}\n"
                "This is a DIFFERENT upstream file than the shipped corpus was built from."
            )
    notes = (
        [
            f"  no upstream digest is recorded yet. To record, edit {_rel(Path(__file__))}:",
            *unrecorded,
        ]
        if unrecorded
        else []
    )
    return problems, notes


def _corpus_text(entries: list[str]) -> str:
    return "\n".join(entries) + "\n"


def _diff(left: str, right: str, *, from_label: str, to_label: str) -> str:
    return "".join(
        difflib.unified_diff(
            left.splitlines(keepends=True),
            right.splitlines(keepends=True),
            fromfile=from_label,
            tofile=to_label,
        )
    )


_REMEDY = (
    "Regenerate it in the same commit as the corpus change:\n"
    "    python scripts/security/build_password_corpus.py --write\n"
    "Never hand-edit the block to silence this -- the block IS the record of what the corpus is."
)


def check(seclists_root: Path | None) -> int:
    notice = NOTICE_PATH.read_text(encoding="utf-8")
    problems: list[str] = []
    notes: list[str] = []

    if seclists_root is not None:
        rebuilt = _corpus_text(rebuild_corpus(seclists_root))
        shipped = _lf_bytes(CORPUS_PATH).decode("utf-8")
        if rebuilt != shipped:
            problems.append(
                "the shipped corpus does not reproduce from the recorded upstream members.\n"
                + _diff(shipped, rebuilt, from_label="shipped corpus", to_label="rebuilt corpus")
            )
        digest_problems, notes = check_upstream_digests(seclists_root)
        problems += digest_problems

    expected = render_block(measure())
    current = extract_block(notice)
    if current is None:
        problems.append(f"{NOTICE_PATH.name} carries no generated block.\n{_REMEDY}")
    elif current != expected:
        problems.append(
            f"{NOTICE_PATH.name}'s generated block no longer describes the shipped corpus.\n"
            + _REMEDY
            + "\n\n"
            + _diff(current, expected, from_label="notice (recorded)", to_label="corpus (measured)")
        )

    if problems:
        for problem in problems:
            sys.stderr.write(problem.rstrip("\n") + "\n\n")
        return 1

    print(f"corpus and notice agree ({_rel(NOTICE_PATH)})")
    if seclists_root is None:
        print(
            "  NOT verified: that the corpus reproduces from upstream. SecLists is not vendored\n"
            "  here, so pass --seclists <checkout> to check that arm."
        )
    for note in notes:
        print(note)
    return 0


def write(seclists_root: Path | None) -> int:
    if seclists_root is not None:
        entries = rebuild_corpus(seclists_root)
        # newline="\n" explicitly: the digest recorded in the block is over LF bytes, and on Windows
        # the default translation would write CRLF and record a value for a file not on disk.
        CORPUS_PATH.write_text(_corpus_text(entries), encoding="utf-8", newline="\n")
        print(f"  rewrote {_rel(CORPUS_PATH)} ({len(entries):,} lines)")

    notice = NOTICE_PATH.read_text(encoding="utf-8")
    NOTICE_PATH.write_text(
        splice_block(notice, render_block(measure())), encoding="utf-8", newline="\n"
    )
    print(f"  rewrote {_rel(NOTICE_PATH)} (generated block)")

    if seclists_root is not None:
        for note in check_upstream_digests(seclists_root)[1]:
            print(note)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="build_password_corpus.py",
        description=(
            "Rebuild or verify messagefoundry/auth/data/common_passwords.txt and the generated "
            "block in its .NOTICE."
        ),
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="verify the block (the default)")
    mode.add_argument("--write", action="store_true", help="regenerate the block")
    parser.add_argument(
        "--seclists",
        metavar="DIR",
        type=Path,
        help=(
            "a SecLists checkout root. With --write, rebuilds the corpus from the two upstream "
            "members; with --check, additionally verifies it reproduces from them."
        ),
    )
    args = parser.parse_args(argv)
    return write(args.seclists) if args.write else check(args.seclists)


if __name__ == "__main__":
    raise SystemExit(main())
