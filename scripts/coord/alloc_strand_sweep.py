#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Census of ledger allocations by WHERE the ledger gate would still let them be committed.

WHAT THIS ANSWERS. `scripts/hooks/ledger_check.py` refuses a commit that introduces an ADR or BACKLOG
number the committing worktree does not own, and `Ledger.owns` has exactly two keys: the recorded
worktree PATH, and (since BACKLOG #1282) the recorded BRANCH. Both keys can come to rest somewhere the
work is not. BACKLOG #1414 filed the shape and said the missing piece was evidence -- nobody had counted
how many allocations are in it. This counts them, read-only, and prints the worktree each one can still
be committed from.

THE SEVEN VERDICTS ARE EXHAUSTIVE AND DISJOINT, and every one of them is a statement about the KEYS,
never about whether anyone still wants the number:

    landed                the number is already on origin/main. check_backlog examines `head - base`
                          only, so the gate never asks about ownership again. Inert by construction.
    aligned               the recorded worktree is live AND still on the recorded branch. Both keys
                          point at one tree; there is nothing to recover.
    drifted-branch-held   the recorded worktree is live but has moved to another branch, and the
                          recorded branch is checked out in a DIFFERENT live worktree. THIS IS THE
                          #1414 SHAPE: git refuses to check one branch out in two worktrees, so the
                          two keys cannot be brought back together.
    drifted-branch-free   the recorded worktree is live and off the recorded branch, and that branch is
                          checked out nowhere (or no longer exists). One `git checkout` re-aligns it.
    orphan-branch-held    the recorded worktree is GONE, but the recorded branch is checked out in a
                          live worktree, so #1282's branch fallback commits it there.
    orphan-branch-free    the recorded worktree is gone and the recorded branch still EXISTS as a local
                          head, unheld. Check it out anywhere and the fallback applies.
    orphan-branch-absent  the recorded worktree is gone AND the recorded branch is not a local head.
                          Neither key can match from anywhere. This is the residual PR 703 states as
                          its own limit, and the only verdict here that means "nobody can commit it".

BRANCH EXISTENCE IS CHECKED, NOT INFERRED FROM WHETHER IT IS CHECKED OUT. The first cut of this file
conflated the last two verdicts -- an unheld branch and a deleted one both look like "no worktree is on
it" -- and reported 49 claims as recoverable without ever asking whether the branch was still there.
That is the one-sided instrument this repository keeps re-learning: the reading that would have proved
it wrong was never taken.

A THIRD LIMB THE #1414 ITEM DOES NOT NAME, AND NO REGISTRY SWEEP CAN SEE DIRECTLY. A claim can be
recorded to a tree that was never going to be the committing one -- allocated by one seat on behalf of
another, or (before alloc.ps1 anchored on its own path) from whatever directory the shell happened to be
standing in. The claim then looks PERFECTLY HEALTHY here: the recorded worktree is live, it is on the
recorded branch, and this tool calls it `aligned`. It is the committer who is somewhere else, and the
registry does not record who that was going to be. What IS measurable is the after-effect: the work gets
re-filed at a fresh number, so the registry ends up holding two claims with the SAME TITLE. `--titles`
reports those pairs. It is a lower bound on the limb, and lower bounds are named as such below.

A LIVE RECORDED WORKTREE IS ALWAYS A ROUTE, WHICH IS WHY `drifted-branch-held` IS AWKWARD RATHER THAN
IMPOSSIBLE -- and saying so is the point, because the first account of #1414 concluded the number was
undeliverable. The path key does not care which branch the entitled tree is standing on, so the entitled
tree can reach a held branch's commits under another name (`git checkout -b <alias> <held branch>`) and
commit the row from a path `owns` accepts. docs/LEDGER-GATE.md carries the worked steps and the push.

WHAT THIS CANNOT SEE, STATED RATHER THAN LEFT TO BE DISCOVERED:

  * UNCOMMITTED work. #1414's instance A was a patch that had never been committed, because the gate is
    what stopped it being committed. Nothing in git's object store records it, so no sweep can. The
    `written` column below reports whether the number's HEADING was ever committed to a local head, and
    a False there means "not committed anywhere", NOT "abandoned" -- the two are indistinguishable from
    the registry, and this tool does not guess between them.
  * ANOTHER CLONE. The registry lives under this clone's git common dir, so a claim made in a different
    clone of the same repository is invisible here, and correctly so: it is a different registry.
  * REMOTE-ONLY BRANCHES. `owns` compares against `git rev-parse --abbrev-ref HEAD`, which names a local
    branch. `origin/foo` can never satisfy it, so only refs/heads is swept for the branch key.

Stdlib only and no `messagefoundry` import, matching ledger_check.py: most worktrees have no .venv, and
this must run wherever the gate runs. It WRITES NOTHING. The registry is shared live state for every
session on this clone; reading it is safe, editing it is not this tool's business.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

BACKLOG_PATH = "docs/BACKLOG.md"
BACKLOG_ARCHIVE_DIR = "docs/archive/backlog"
BACKLOG_HEADING = re.compile(r"^#{2,3} (\d+)\.", re.M)
ADR_FILE = re.compile(r"^docs/adr/(\d{4})-[^/]+\.md$")

# Ordered worst-last so the summary reads as a severity ladder rather than an alphabet.
VERDICTS = (
    "landed",
    "aligned",
    "drifted-branch-free",
    "drifted-branch-held",
    "orphan-branch-held",
    "orphan-branch-free",
    "orphan-branch-absent",
)


def git(*args: str, repo: Path | None = None) -> str:
    """Run git, raising on a non-zero exit.

    `encoding=` is REQUIRED and not cosmetic, for the reason ledger_check.py records at its own
    wrapper: `text=True` alone decodes with the locale default, which is cp1252 on a stock Windows box,
    and docs/BACKLOG.md is UTF-8. A swallowed failure would read as "no numbers anywhere", which is the
    false-clean shape this file must never emit.
    """
    cmd = ["git"]
    if repo is not None:
        cmd += ["-C", str(repo)]
    proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell, no caller-supplied executable
        [*cmd, *args], capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    if proc.returncode != 0:
        raise OSError(
            f"git {' '.join(args)} failed ({proc.returncode}): {(proc.stderr or '').strip()}"
        )
    return proc.stdout or ""


def norm_path(value: object) -> str:
    """Fold a path the way `Ledger.owns` folds it, so this tool cannot disagree with the gate.

    The gate compares `str(repo).replace("\\\\", "/").casefold()` against the recorded value folded the
    same way and right-stripped of separators. Reimplementing that comparison with a `Path` or with
    `os.path.normcase` would be a SECOND definition of ownership that drifts from the first one
    silently -- the failure this repository names once already for `parse_items`.
    """
    return str(value or "").replace("\\", "/").casefold().rstrip("/")


@dataclass(frozen=True)
class Worktree:
    path: str  # normalised
    branch: (
        str | None
    )  # short name; None on a detached HEAD, which can never match a recorded branch


@dataclass(frozen=True)
class Claim:
    kind: str
    number: str
    title: str
    branch: str
    worktree: str  # normalised
    claimed: str


@dataclass(frozen=True)
class Finding:
    claim: Claim
    verdict: str
    written: bool
    commit_from: tuple[str, ...]  # worktrees `owns` accepts for this number, right now
    branch_held_by: str | None


def live_worktrees(repo: Path) -> list[Worktree]:
    """Every worktree registered on this clone, with the branch each currently holds.

    Read from `git worktree list --porcelain` rather than by walking directories: a stale
    administrative entry whose directory is gone is exactly the #1282 state, and porcelain reports it
    with a `prunable` line, which is how absence gets measured instead of assumed.
    """
    out: list[Worktree] = []
    path: str | None = None
    branch: str | None = None
    prunable = False
    for line in git("worktree", "list", "--porcelain", repo=repo).splitlines() + [""]:
        if line.startswith("worktree "):
            path, branch, prunable = line[len("worktree ") :].strip(), None, False
        elif line.startswith("branch "):
            branch = line[len("branch ") :].strip().removeprefix("refs/heads/")
        elif line.startswith("prunable"):
            prunable = True
        elif not line.strip():
            if path is not None and not prunable:
                out.append(Worktree(path=norm_path(path), branch=branch))
            path, branch, prunable = None, None, False
    return out


def read_claims(alloc_root: Path, kinds: tuple[str, ...]) -> list[Claim]:
    """Every claim on disk. A record that will not parse is REPORTED, never silently skipped."""
    claims: list[Claim] = []
    for kind in kinds:
        directory = alloc_root / kind
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("*.json")):
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                print(f"  UNREADABLE CLAIM {path.name} ({type(exc).__name__})", file=sys.stderr)
                continue
            claims.append(
                Claim(
                    kind=kind,
                    number=str(raw.get("number") or path.stem),
                    title=str(raw.get("title") or ""),
                    branch=str(raw.get("branch") or "").strip(),
                    worktree=norm_path(raw.get("worktree")),
                    claimed=str(raw.get("claimed") or ""),
                )
            )
    return claims


def owns_from(claim: Claim, worktree: Worktree) -> bool:
    """Would `Ledger.owns` return True for this claim if the commit were made from this worktree?

    Mirrors ledger_check.py: the path key first, then the branch key, and a legacy record with no
    recorded branch falls back to the path alone. A detached HEAD names no branch and so can never
    satisfy the second key -- the gate spells that out and this must agree.
    """
    if worktree.path == claim.worktree:
        return True
    if not claim.branch or worktree.branch is None:
        return False
    return worktree.branch.casefold() == claim.branch.casefold()


def classify(
    claim: Claim, worktrees: list[Worktree], branches: set[str], landed: bool
) -> tuple[str, str | None]:
    """The verdict for one claim, plus the worktree holding its recorded branch (if any).

    ``branches`` is every local head, casefolded. It is a REQUIRED input rather than an inferred one:
    "no worktree is standing on this branch" and "this branch does not exist" are different states with
    different remedies, and only the second is unrecoverable.

    Pure: no git, no filesystem. Every arm of the ladder is exercised from fabricated inputs in
    tests/test_coord_alloc_strand_sweep.py, including a deliberately constructed #1414 shape -- a
    classifier that has never been made to return its worst verdict is an assertion, not a measurement.
    """
    if landed:
        return "landed", None
    entitled = next((w for w in worktrees if w.path == claim.worktree), None)
    holder = next(
        (
            w
            for w in worktrees
            if claim.branch and w.branch and w.branch.casefold() == claim.branch.casefold()
        ),
        None,
    )
    held_by = holder.path if holder else None
    if entitled is not None:
        if holder is not None and holder.path == entitled.path:
            return "aligned", held_by
        return ("drifted-branch-held" if holder is not None else "drifted-branch-free"), held_by
    if holder is not None:
        return "orphan-branch-held", held_by
    if claim.branch and claim.branch.casefold() in branches:
        return "orphan-branch-free", None
    return "orphan-branch-absent", None


def _norm_title(value: str) -> str:
    return " ".join(value.split()).casefold()


def respent_titles(claims: list[Claim]) -> list[tuple[str, list[Claim]]]:
    """Titles holding more than one claim -- numbers spent twice on the same work.

    THIS IS THE ONLY DIRECT EVIDENCE OF THE THIRD LIMB THAT SURVIVES IN THE REGISTRY. When a claim is
    born in a tree that will not commit it, the gate refuses, no verb moves the number, and the work is
    re-filed at a fresh one. The abandoned claim stays on disk forever ("holes are free, collisions are
    not"), so the pair persists even though nothing records WHY the first number was dropped.

    IT IS A LOWER BOUND IN BOTH DIRECTIONS, and both are worth stating. It misses a re-file whose title
    was reworded on the way, which is common. It also over-reports: two claims can share a title because
    the allocator was run twice by accident, with no strand involved at all -- the erratum records
    exactly that for #240-#247. So this counts DISPUTED NUMBERS, not confirmed strands, and every pair
    needs its own reading before it is called one.
    """
    groups: dict[str, list[Claim]] = {}
    for claim in claims:
        if claim.title:
            groups.setdefault(f"{claim.kind}\0{_norm_title(claim.title)}", []).append(claim)
    return [
        (members[0].title, sorted(members, key=lambda c: c.claimed))
        for _, members in sorted(groups.items())
        if len(members) > 1
    ]


def _batch_blob_ids(repo: Path, specs: list[str]) -> dict[str, str]:
    """Resolve many `<ref>:<path>` specs to object ids in ONE git process.

    1,275 local heads is 1,275 subprocess launches the naive way, which on Windows is slower than the
    measurement is worth. `cat-file --batch-check` answers them all from one stdin stream, and a spec
    that does not resolve comes back on its own line as `<spec> missing` rather than as an error.
    """
    if not specs:
        return {}
    proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
        ["git", "-C", str(repo), "cat-file", "--batch-check=%(objectname) %(objecttype)"],
        input="\n".join(specs) + "\n",
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    out: dict[str, str] = {}
    for spec, line in zip(specs, (proc.stdout or "").splitlines(), strict=False):
        parts = line.split()
        if len(parts) == 2 and parts[1] in ("blob", "tree"):
            out[spec] = parts[0]
    return out


def _batch_read_blobs(repo: Path, oids: list[str]) -> dict[str, bytes]:
    """Read many blobs in ONE git process, parsed as BYTES.

    `cat-file --batch` frames each object as `<oid> blob <size>\\n<payload>\\n`, and the size is in
    BYTES. Decoding the stream first and then slicing by that number silently mis-slices the moment a
    file contains a non-ASCII character, which docs/BACKLOG.md does on nearly every line -- so the
    framing is parsed on bytes and only the payload is decoded.
    """
    if not oids:
        return {}
    proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
        ["git", "-C", str(repo), "cat-file", "--batch"],
        input=("\n".join(oids) + "\n").encode("ascii"),
        capture_output=True,
    )
    data, out, pos = proc.stdout, {}, 0
    while pos < len(data):
        end = data.find(b"\n", pos)
        if end < 0:
            break
        header = data[pos:end].split()
        if len(header) != 3:
            break
        size = int(header[2])
        out[header[0].decode("ascii")] = data[end + 1 : end + 1 + size]
        pos = end + 1 + size + 1  # payload, then git's trailing newline
    return out


def numbers_on_refs(repo: Path, kind: str, refs: list[str]) -> set[str]:
    """Every ADR/BACKLOG number committed on any of ``refs``.

    Object ids are deduplicated before anything is read, which is what makes a 1,275-ref sweep cheap:
    branches that never touched the ledger share one blob, so the read count collapses to the number of
    DISTINCT ledger versions rather than the number of branches.
    """
    if kind == "adr":
        trees = _batch_blob_ids(repo, [f"{r}:docs/adr" for r in refs])
        found: set[str] = set()
        for tree in sorted(set(trees.values())):
            for name in git("ls-tree", "--name-only", tree, repo=repo).split():
                match = ADR_FILE.match(f"docs/adr/{name}")
                if match:
                    found.add(match.group(1))
        return found
    specs = [f"{r}:{BACKLOG_PATH}" for r in refs]
    blobs = _batch_blob_ids(repo, specs)
    found = set()
    for payload in _batch_read_blobs(repo, sorted(set(blobs.values()))).values():
        found |= set(BACKLOG_HEADING.findall(payload.decode("utf-8", "replace")))
    return found


def numbers_on_base(repo: Path, kind: str, base: str) -> set[str]:
    """Numbers already on ``base`` -- the set the gate grandfathers via `head - base`.

    The archive is read as well as docs/BACKLOG.md, because a closed item is MOVED there verbatim and
    the gate reads the union of both. Reading only the published file would report every archived
    number as unlanded and manufacture a population out of nothing.
    """
    if kind == "adr":
        return numbers_on_refs(repo, "adr", [base])
    found = set(BACKLOG_HEADING.findall(git("show", f"{base}:{BACKLOG_PATH}", repo=repo)))
    listing = git("ls-tree", "-r", "--name-only", base, f"{BACKLOG_ARCHIVE_DIR}/", repo=repo)
    for path in listing.split():
        if path.endswith(".md"):
            found |= set(BACKLOG_HEADING.findall(git("show", f"{base}:{path}", repo=repo)))
    return found


def sweep(
    repo: Path, alloc_root: Path, kinds: tuple[str, ...], base: str, scan_refs: bool = True
) -> list[Finding]:
    trees = live_worktrees(repo)
    heads = git("for-each-ref", "--format=%(refname)", "refs/heads", repo=repo).split()
    branches = {h.removeprefix("refs/heads/").casefold() for h in heads}
    findings: list[Finding] = []
    for kind in kinds:
        claims = read_claims(alloc_root, (kind,))
        if not claims:
            continue
        landed = numbers_on_base(repo, kind, base)
        # Only the unlanded claims need the expensive ref sweep, and it is exactly the set whose
        # `written` answer is decision-relevant: a landed number is on a ref by definition.
        unlanded = {c.number for c in claims} - landed
        written = (
            numbers_on_refs(repo, kind, heads) & unlanded if (unlanded and scan_refs) else set()
        )
        for claim in claims:
            verdict, held_by = classify(claim, trees, branches, claim.number in landed)
            findings.append(
                Finding(
                    claim=claim,
                    verdict=verdict,
                    written=claim.number in written,
                    commit_from=tuple(sorted(w.path for w in trees if owns_from(claim, w))),
                    branch_held_by=held_by,
                )
            )
    return findings


def report(findings: list[Finding], detail: bool, titles: bool, scanned_refs: bool) -> None:
    counts = dict.fromkeys(VERDICTS, 0)
    for f in findings:
        counts[f.verdict] = counts.get(f.verdict, 0) + 1
    width = max(len(v) for v in VERDICTS)
    print(f"\n{len(findings)} allocation(s) on this clone\n")
    for verdict in VERDICTS:
        print(f"  {verdict.ljust(width)}  {counts[verdict]:>5}")
    unlanded = [f for f in findings if f.verdict != "landed"]
    print(f"\n  {'unlanded (total)'.ljust(width)}  {len(unlanded):>5}")
    written = sum(1 for f in unlanded if f.written)
    print(f"  {'  of those, written'.ljust(width)}  {written if scanned_refs else '     n/a':>5}")
    stuck = [f for f in unlanded if not f.commit_from]
    print(f"  {'  of those, no route now'.ljust(width)}  {len(stuck):>5}")
    if titles:
        pairs = respent_titles([f.claim for f in findings])
        print(f"\n{len(pairs)} title(s) hold more than one number\n")
        for title, members in pairs:
            print(f"  {' / '.join(f'{m.kind} {m.number}' for m in members)}")
            print(f"      {title[:96]}")
    if not detail:
        print("\n  --detail lists every unlanded claim and where it can be committed from.")
        return
    print("\nUnlanded claims\n")
    for f in sorted(unlanded, key=lambda x: (x.claim.kind, int(x.claim.number))):
        where = f.commit_from[0] if f.commit_from else "NOWHERE"
        print(f"  {f.claim.kind} {f.claim.number}  {f.verdict}")
        print(f"      written={f.written}  commit from: {where}")
        if f.branch_held_by and f.verdict == "drifted-branch-held":
            print(f"      recorded branch '{f.claim.branch}' is held by {f.branch_held_by}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only census of ledger allocations by which ownership key still reaches them."
    )
    parser.add_argument("--kind", choices=("adr", "backlog"), help="limit to one number space")
    parser.add_argument("--base", default="origin/main", help="ref the gate diffs against")
    parser.add_argument(
        "--repo", type=Path, help="repository to sweep (default: the one we are in)"
    )
    parser.add_argument("--alloc", type=Path, help="allocation registry (default: this clone's)")
    parser.add_argument("--detail", action="store_true", help="list every unlanded claim")
    parser.add_argument(
        "--titles", action="store_true", help="report titles holding more than one number"
    )
    parser.add_argument(
        "--skip-written",
        action="store_true",
        help="skip the local-head scan (the slow half) and leave the written column unfilled",
    )
    args = parser.parse_args(argv)

    try:
        repo = args.repo or Path(
            git("rev-parse", "--path-format=absolute", "--show-toplevel").strip()
        )
        alloc = args.alloc or (
            Path(git("rev-parse", "--path-format=absolute", "--git-common-dir", repo=repo).strip())
            / "mefor-coord"
            / "alloc"
        )
    except OSError as exc:
        print(f"cannot locate the repository: {exc}", file=sys.stderr)
        return 2
    if not alloc.is_dir():
        print(f"no allocation registry at {alloc}", file=sys.stderr)
        return 2
    kinds = (args.kind,) if args.kind else ("adr", "backlog")
    try:
        findings = sweep(repo, alloc, kinds, args.base, scan_refs=not args.skip_written)
    except OSError as exc:
        print(f"sweep failed: {exc}", file=sys.stderr)
        return 2
    report(findings, args.detail, args.titles, scanned_refs=not args.skip_written)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
