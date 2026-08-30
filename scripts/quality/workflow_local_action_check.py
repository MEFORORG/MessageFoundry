# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Refuse a workflow that calls a local action the tree does not contain.

A remote ``uses: owner/repo@sha`` is fetched by the runner and needs no working copy. A LOCAL
``uses: ./path`` resolves against ``GITHUB_WORKSPACE``, so it needs an ``actions/checkout`` step
first and it needs the directory to exist. Swapping one form for the other changes the RESOLUTION
MECHANISM, and nothing in the diff says so.

MEASURED 2026-08-29, and it locked the repository. PR #621 vendored the archived
``contributor-assistant/github-action`` into ``.github/actions/cla-assistant-lite`` and rewrote
``.github/workflows/cla.yml`` to ``uses: ./.github/actions/cla-assistant-lite``. It added no
checkout: ``grep -c actions/checkout`` gave 0 for ``cla.yml`` against 11 for ``ci.yml``. Every
``pull_request_target`` run then died in about three seconds with::

    Can't find 'action.yml', 'action.yaml' or 'Dockerfile' under
    '.../.github/actions/cla-assistant-lite'. Did you forget to run actions/checkout
    before running your local action?

``cla`` is a REQUIRED context, so 7 of 21 open pull requests were blocked by it at once, and the
set grew with every push and rebase.

WHY NO EXISTING CHECK COULD HAVE CAUGHT IT, AND THIS IS THE POINT OF RUNNING ON ``pull_request``.
``cla.yml`` runs only on ``pull_request_target``, ``merge_group`` and ``issue_comment`` -- all three
execute the workflow from the DEFAULT BRANCH. So a pull request that edits that file is tested with
the OLD copy of it. #621's own ``cla`` check passed three times, on 2026-08-26 21:18Z, 00:14Z and
03:44Z, before merging at 05:26Z; every one of those runs exercised the remote action it was
deleting.

    A ``pull_request_target`` WORKFLOW CANNOT BE TESTED BY THE PULL REQUEST THAT CHANGES IT.
    Its green certifies the version being replaced.

And the fix could not merge either: the repair for a required check is itself a pull request, gated
by the broken check. That deadlock needed an administrator, which is a capability no automated seat
holds.

WHAT THIS CHECKS, AND WHAT IT DELIBERATELY DOES NOT.

Checked, because each is decidable from the tree alone:

* every local ``uses: ./path`` resolves to a directory holding ``action.yml``, ``action.yaml`` or
  ``Dockerfile``;
* the job containing it has an ``actions/checkout`` step, because without one the workspace is
  empty however present the directory is.

NOT checked, deliberately: whether the checkout is correctly configured, whether a ``ref:`` is safe,
or anything about remote actions. A gate that guesses at intent produces confident wrong answers,
and this repository has spent a night on those. It answers one question and says which.

ON ``pull_request_target`` AND ``ref:``. This checker does not police it, but the rule is worth
stating where somebody fixing a failure will read it: under ``pull_request_target`` the DEFAULT
checkout takes the BASE, which is the safe form. Adding ``ref: ${{ github.event.pull_request.head.sha }}``
checks out untrusted code into a privileged context, which is the classic escalation footgun.

Usage::

    python scripts/quality/workflow_local_action_check.py
    python scripts/quality/workflow_local_action_check.py --self-test
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

# ``uses:`` whose value starts with ``./`` -- the only form that resolves against the workspace.
# Anchored at the start of the value so a remote ``uses:`` and any prose mentioning "./" are ignored.
_LOCAL_USES = re.compile(r"^\s*(?:-\s*)?uses:\s*['\"]?(\./[^'\"\s#]+)")
_CHECKOUT = re.compile(r"^\s*(?:-\s*)?uses:\s*['\"]?actions/checkout@")
# A job key: two-space indented, non-list, ending in a colon, inside the jobs: block.
_JOB_KEY = re.compile(r"^  ([A-Za-z_][\w-]*):\s*$")
_JOBS_BLOCK = re.compile(r"^jobs:\s*$")

_ACTION_FILES = ("action.yml", "action.yaml", "Dockerfile")


def _strip_comment(line: str) -> str:
    """Drop a trailing ``#`` comment when it is not inside quotes.

    Cheap and sufficient: this file only ever asks whether a line STARTS a ``uses:`` mapping, and a
    ``uses:`` value containing a quoted ``#`` is not a thing. It exists so that a comment such as
    ``# vendored ca4a40a7 (v2.6.1)`` after a real ``uses:`` cannot change the parse, and so that a
    commented-out ``# uses: ./gone`` is never read as code -- the failure that made three separate
    scanners wrong in this repository on 2026-08-28.
    """
    out, quote = [], ""
    for ch in line:
        if quote:
            out.append(ch)
            if ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
            out.append(ch)
        elif ch == "#":
            break
        else:
            out.append(ch)
    return "".join(out)


def scan_workflow(text: str) -> list[tuple[str, str, int]]:
    """Return ``(job, local_action_path, line_number)`` for every local ``uses:`` in one workflow.

    The job attribution is what lets the caller answer "does THIS job check out", rather than "does
    the file mention a checkout somewhere" -- a file-level answer would pass ``cla.yml`` the moment
    any unrelated job gained a checkout.
    """
    found: list[tuple[str, str, int]] = []
    job = ""
    in_jobs = False
    for n, raw in enumerate(text.splitlines(), start=1):
        line = _strip_comment(raw)
        if _JOBS_BLOCK.match(line):
            in_jobs = True
            continue
        if in_jobs:
            m = _JOB_KEY.match(line)
            if m:
                job = m.group(1)
        m = _LOCAL_USES.match(line)
        if m:
            found.append((job, m.group(1), n))
    return found


def job_has_checkout(text: str, job: str) -> bool:
    """True when ``job``'s own step list contains an ``actions/checkout``."""
    lines = [_strip_comment(x) for x in text.splitlines()]
    inside = False
    for line in lines:
        m = _JOB_KEY.match(line)
        if m:
            inside = m.group(1) == job
            continue
        if inside and _CHECKOUT.match(line):
            return True
    return False


def check_tree(root: pathlib.Path) -> tuple[list[str], int, int]:
    """Return (problems, workflows_scanned, local_uses_seen).

    The two counts are returned so the caller can PRINT WHAT IT SCANNED. A gate that reports "0
    problems" having read 0 files is indistinguishable from a clean tree, and that is the single
    most common way an instrument lies here.
    """
    wf_dir = root / ".github" / "workflows"
    problems: list[str] = []
    files = sorted(p for p in wf_dir.glob("*.y*ml")) if wf_dir.is_dir() else []
    seen = 0
    for wf in files:
        text = wf.read_text(encoding="utf-8", errors="replace")
        for job, rel, line in scan_workflow(text):
            seen += 1
            # rel[2:], NOT lstrip("./"). str.lstrip takes a SET OF CHARACTERS, not a prefix, so
            # "./.github/actions/x".lstrip("./") eats the leading dot of ".github" and yields
            # "github/actions/x" -- a path that never exists, so every local action reports as
            # missing and the checkout arm becomes unreachable. Caught by this file's own self-test
            # on its first run, which is the only reason it is not in the shipped gate.
            target = root / rel[2:]
            if not any((target / f).is_file() for f in _ACTION_FILES):
                problems.append(
                    f"{wf.relative_to(root)}:{line}: job '{job}' uses local action '{rel}', "
                    f"but no {' / '.join(_ACTION_FILES)} exists there"
                )
            elif not job_has_checkout(text, job):
                problems.append(
                    f"{wf.relative_to(root)}:{line}: job '{job}' uses local action '{rel}' "
                    f"but has no actions/checkout step, so the workspace is empty when it resolves"
                )
    return problems, len(files), seen


_PROBE_BROKEN = """\
name: probe
on: [push]
jobs:
  a:
    steps:
      - uses: ./.github/actions/does-not-exist
  b:
    steps:
      - uses: ./.github/actions/present-but-no-checkout
  c:
    steps:
      # uses: ./.github/actions/commented-out-must-be-ignored
      - uses: some/remote@bbbb # ./this-is-prose-not-a-path
"""

# The clean arm: job a removed, and job b given the checkout it was missing. Both failure modes
# repaired, nothing else changed. Written out in full rather than string-patched, because a probe
# built by editing another probe is one typo away from asserting nothing.
_PROBE_CLEAN = """\
name: probe
on: [push]
jobs:
  b:
    steps:
      - uses: actions/checkout@aaaa
      - uses: ./.github/actions/present-but-no-checkout
  c:
    steps:
      # uses: ./.github/actions/commented-out-must-be-ignored
      - uses: some/remote@bbbb # ./this-is-prose-not-a-path
"""


def _self_test() -> int:
    """Prove the discrimination rather than asserting it. Both arms, and the prose arm."""
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        root = pathlib.Path(d)
        (root / ".github" / "workflows").mkdir(parents=True)
        (root / ".github" / "workflows" / "probe.yml").write_text(_PROBE_BROKEN, encoding="utf-8")
        present = root / ".github" / "actions" / "present-but-no-checkout"
        present.mkdir(parents=True)
        (present / "action.yml").write_text("name: x\n", encoding="utf-8")

        hits = scan_workflow(_PROBE_BROKEN)
        paths = [p for _, p, _ in hits]
        if len(hits) != 2:
            print(f"self-test FAILED: expected 2 local uses, got {len(hits)}: {paths}")
            return 1
        if any("commented-out" in p or "prose" in p for p in paths):
            print(f"self-test FAILED: a comment or prose was read as code: {paths}")
            return 1

        problems, files, seen = check_tree(root)
        if files != 1 or seen != 2:
            print(f"self-test FAILED: scanned {files} file(s), {seen} local uses; expected 1 and 2")
            return 1
        joined = " | ".join(problems)
        if "does-not-exist" not in joined:
            print(f"self-test FAILED: a missing action must trip. got: {joined}")
            return 1
        if "no actions/checkout" not in joined:
            print(
                f"self-test FAILED: a present action in a job with no checkout must trip. got: {joined}"
            )
            return 1

        # MUST-NOT-TRIP arm, and it is the half that matters: DELETING this whole check would
        # satisfy both failure arms above, so without a case that must stay silent the gate would
        # pass on its own removal.
        (root / ".github" / "workflows" / "probe.yml").write_text(_PROBE_CLEAN, encoding="utf-8")
        problems2, _, seen2 = check_tree(root)
        if problems2:
            print(f"self-test FAILED: the clean arm must report nothing. got: {problems2}")
            return 1
        if seen2 != 1:
            print(f"self-test FAILED: the clean arm must still SEE 1 local uses, got {seen2}")
            return 1

    print(
        "workflow-local-action self-test: 2 local uses found, 1 comment and 1 prose mention "
        "ignored, both failure arms trip, the clean arm reports nothing and still scans 1."
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default=".", help="repository root to scan")
    ap.add_argument("--self-test", action="store_true", help="prove the checker discriminates")
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()

    root = pathlib.Path(args.root).resolve()
    problems, files, seen = check_tree(root)
    # Always say what was examined. "0 problems" over 0 files is not a pass.
    print(
        f"workflow-local-action: scanned {files} workflow file(s), {seen} local 'uses: ./' reference(s)."
    )
    if files == 0:
        print(
            "no .github/workflows/*.yml under this root -- NOTHING WAS EXAMINED, which is not a pass."
        )
        return 1
    if not problems:
        return 0
    print("")
    for p in problems:
        print(f"  {p}")
    print("")
    print(
        "A local 'uses: ./...' resolves against GITHUB_WORKSPACE. It needs the directory to exist"
    )
    print(
        "AND an actions/checkout step in the same job. A remote 'uses:' needs neither, so swapping"
    )
    print("one for the other changes the resolution mechanism with nothing in the diff to say so.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
