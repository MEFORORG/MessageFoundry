# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

* every local action it resolves declares a ``runs.using`` that GitHub still runs, and one whose
  revisit date below has not passed (BACKLOG #1868). See ``check_runtimes``.

NOT checked, deliberately: whether the checkout is correctly configured, whether a ``ref:`` is safe,
or anything about remote actions. A gate that guesses at intent produces confident wrong answers,
and this repository has spent a night on those. It answers one question and says which.

WHY THE RUNTIME ARM LIVES HERE. ``cla.yml`` runs on ``pull_request_target``, so the same rule
applies: a pull request that edits the vendored ``action.yml`` is tested with main's copy. This step
runs on ``pull_request`` against the branch's own files, which is the only place a bad runtime can
be caught before it lands. Before #1868 nothing read ``runs.using`` at all, and the Node 20 deadline
rested on a person opening ADR 0034.

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
import datetime
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
_ACTION_METADATA = ("action.yml", "action.yaml")

# ``runs.using`` values GitHub no longer runs. Node 20 left the hosted runners on 2026-09-23 (GitHub
# changelog of that date, "Node 20 is no longer available in GitHub Actions"); Node 12 and 16 went
# before it. Since the default switch on 2026-06-16 the runner has run a node20 action on Node 24 by
# force and warned about it, which is why this repository's `cla` stayed green. That shim is a
# courtesy GitHub has not promised to keep, so a retired value is refused rather than trusted to it.
_RETIRED_NODE_RUNTIMES = frozenset({"node12", "node16", "node20"})

# Every Node runtime this gate accepts, mapped to the date it must be looked at again. A date, not
# just a name, because a named runtime with no date rots the same way ADR 0034's contingency did.
#
# node24: Node.js 24 reaches end of life on 2028-04-30 (nodejs/Release schedule.json). GitHub's
# Node 20 timeline ran end of life 2026-04-30, default switch 2026-06-16, removal 2026-09-23, so it
# acts AFTER end of life. 2027-10-31 is six months before Node 24's, which leaves room to move to
# whatever GitHub then recommends. On that date this gate goes red for every pull request, on
# purpose: a red names its own fix, which a wedge does not. The fix is the runtime line in the
# action, a row here, and for the vendored CLA action its provenance pin; the message says so.
#
# A Node runtime missing from this table is refused, so adding one forces somebody to pick its date.
_NODE_RUNTIME_REVISIT: dict[str, datetime.date] = {
    "node24": datetime.date(2027, 10, 31),
}

# Non-Node runtimes GitHub accepts. They carry no Node deadline, so they have no date here.
_NON_NODE_RUNTIMES = frozenset({"composite", "docker"})

# Days before a revisit date when the gate starts WARNING without failing, so the red is not the
# first anyone hears of it.
_REVISIT_WARNING_DAYS = 90

_TOP_LEVEL_KEY = re.compile(r"^['\"]?[A-Za-z_][\w-]*['\"]?\s*:")
_RUNS_KEY = re.compile(r"^runs:\s*$")
_USING = re.compile(r"^\s+using:\s*['\"]?([^'\"\s]+)")


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


def _workflow_files(root: pathlib.Path) -> list[pathlib.Path]:
    """Every workflow file under ``root``. One definition, so both checks scan the same set."""
    wf_dir = root / ".github" / "workflows"
    return sorted(wf_dir.glob("*.y*ml")) if wf_dir.is_dir() else []


def _action_dir(root: pathlib.Path, rel: str) -> pathlib.Path:
    """The directory a local ``uses: ./path`` names.

    rel[2:], NOT lstrip("./"). str.lstrip takes a SET OF CHARACTERS, not a prefix, so
    "./.github/actions/x".lstrip("./") eats the leading dot of ".github" and yields
    "github/actions/x" -- a path that never exists, so every local action reports as missing and the
    checkout arm becomes unreachable. Caught by this file's own self-test on its first run, which is
    the only reason it is not in the shipped gate.
    """
    return root / rel[2:]


def check_tree(root: pathlib.Path) -> tuple[list[str], int, int]:
    """Return (problems, workflows_scanned, local_uses_seen).

    The two counts are returned so the caller can PRINT WHAT IT SCANNED. A gate that reports "0
    problems" having read 0 files is indistinguishable from a clean tree, and that is the single
    most common way an instrument lies here.
    """
    problems: list[str] = []
    files = _workflow_files(root)
    seen = 0
    for wf in files:
        text = wf.read_text(encoding="utf-8", errors="replace")
        for job, rel, line in scan_workflow(text):
            seen += 1
            target = _action_dir(root, rel)
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


def read_runs_using(text: str) -> str | None:
    """Return the ``runs.using`` value of one action metadata file, or None when it has none.

    Comments are stripped first. The vendored CLA ``action.yml`` carries a comment naming the old
    value right above the real key, so a reader that did not strip them could return the retired
    runtime from prose.
    """
    in_runs = False
    child_indent = 0
    for raw in text.splitlines():
        line = _strip_comment(raw).rstrip()
        if not line:
            continue
        if _RUNS_KEY.match(line):
            in_runs = True
            continue
        if not in_runs:
            continue
        if _TOP_LEVEL_KEY.match(line):
            return None  # left the runs: block without finding the key
        # Only a DIRECT child of runs: counts. A `using:` nested deeper -- under env:, or in a
        # composite step's with: -- is some other key, and reading it would let a node20 action
        # pass on a nested node24 that happens to come first.
        indent = len(line) - len(line.lstrip(" "))
        child_indent = child_indent or indent
        if indent != child_indent:
            continue
        m = _USING.match(line)
        if m:
            # Lower-cased so `Node20` is refused as node20 rather than waved through as unknown.
            return m.group(1).lower()
    return None


def runtime_problem(action: str, using: str | None, today: datetime.date) -> str | None:
    """One sentence saying why ``using`` cannot stand, or None when it can."""
    if using is None:
        return (
            f"local action '{action}' declares no runs.using this gate can read (it reads a "
            "block-style `runs:` mapping), so nothing says what runs it"
        )
    if using in _RETIRED_NODE_RUNTIMES:
        current = ", ".join(sorted(r for r, due in _NODE_RUNTIME_REVISIT.items() if today < due))
        return (
            f"local action '{action}' declares runs.using '{using}', a runtime GitHub has removed "
            f"from its runners. Declare {current or 'the runtime GitHub now recommends'}"
        )
    if using in _NODE_RUNTIME_REVISIT:
        due = _NODE_RUNTIME_REVISIT[using]
        if today >= due:
            return (
                f"local action '{action}' declares runs.using '{using}', whose revisit date {due} "
                "has passed. Check GitHub's changelog for the runtime it now recommends, move the "
                "action to it, and add that runtime to _NODE_RUNTIME_REVISIT with its own date. "
                "For the vendored CLA action, also move the action.yml pin in "
                "scripts/security/build_cla_action_provenance.py and re-run it with --write. If "
                "GitHub has named no successor yet, move this runtime's date instead and record why"
            )
        return None
    if using in _NON_NODE_RUNTIMES:
        return None
    return (
        f"local action '{action}' declares runs.using '{using}', which this gate does not know. "
        "If GitHub supports it, add it to _NODE_RUNTIME_REVISIT with a revisit date"
    )


def check_runtimes(
    root: pathlib.Path, today: datetime.date | None = None
) -> tuple[list[str], dict[str, str | None]]:
    """Return (problems, runtime read per local action) for every local action a workflow uses.

    DIRECT calls only. A local action called from inside a composite local action is not read; none
    exists in this repository today, and this sentence is where to start if one is added.

    The map is returned so the caller can print what it READ, not just what it concluded: a runtime
    check that found no action metadata is silent in exactly the way the deleted ``archived-uses``
    rule was once the CLA reference went local.
    """
    when = today if today is not None else datetime.datetime.now(datetime.UTC).date()
    read: dict[str, str | None] = {}
    for wf in _workflow_files(root):
        text = wf.read_text(encoding="utf-8", errors="replace")
        for _job, rel, _line in scan_workflow(text):
            if rel in read:
                continue
            target = _action_dir(root, rel)
            meta = next((target / f for f in _ACTION_METADATA if (target / f).is_file()), None)
            if meta is None:
                continue  # missing, or a Dockerfile-only action; check_tree reports the former
            read[rel] = read_runs_using(meta.read_text(encoding="utf-8", errors="replace"))
    problems = [p for rel, using in read.items() if (p := runtime_problem(rel, using, when))]
    return problems, read


def revisit_warnings(read: dict[str, str | None], today: datetime.date) -> list[str]:
    """Runtimes whose revisit date falls within :data:`_REVISIT_WARNING_DAYS`, not yet due."""
    out = []
    for rel, using in sorted(read.items()):
        due = _NODE_RUNTIME_REVISIT.get(using or "")
        if due is not None and today < due <= today + datetime.timedelta(
            days=_REVISIT_WARNING_DAYS
        ):
            out.append(
                f"WARNING: local action '{rel}' declares '{using}', whose revisit date {due} is "
                f"{(due - today).days} day(s) away. On that date this step fails every pull request."
            )
    return out


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

        # RUNTIME ARMS. The comment names the retired value right above the real key, the shape
        # the vendored CLA action.yml has, so a reader that kept comments would return 'node20'.
        # Dates are derived from the table, so moving a revisit date cannot silently break an arm.
        if not _NODE_RUNTIME_REVISIT:
            print("self-test FAILED: _NODE_RUNTIME_REVISIT is empty, so no runtime can pass")
            return 1
        current, due = min(_NODE_RUNTIME_REVISIT.items(), key=lambda kv: kv[1])
        before = due - datetime.timedelta(days=1)
        meta = present / "action.yml"
        meta.write_text(
            'name: x\nruns:\n  # upstream said "node20"\n  using: "node20"\n  main: i.js\n',
            encoding="utf-8",
        )
        bad, read = check_runtimes(root, today=before)
        if read != {"./.github/actions/present-but-no-checkout": "node20"} or not bad:
            print(f"self-test FAILED: a node20 action must trip. read {read}, got {bad}")
            return 1
        meta.write_text(
            f'name: x\nruns:\n  # upstream said "node20"\n  using: "{current}"\n  main: i.js\n',
            encoding="utf-8",
        )
        good, read = check_runtimes(root, today=before)
        if good or read != {"./.github/actions/present-but-no-checkout": current}:
            print(f"self-test FAILED: {current} must pass and be READ. read {read}, got {good}")
            return 1
        late, _ = check_runtimes(root, today=due)
        if not late:
            print(f"self-test FAILED: {current} must trip on its revisit date {due}")
            return 1

    print(
        "workflow-local-action self-test: 2 local uses found, 1 comment and 1 prose mention "
        "ignored, both failure arms trip, the clean arm reports nothing and still scans 1. "
        f"Runtime: node20 trips; {current} passes, is read past a comment naming node20, and "
        f"trips on its revisit date {due}."
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default=".", help="repository root to scan")
    ap.add_argument("--self-test", action="store_true", help="prove the checker discriminates")
    ap.add_argument(
        "--today",
        type=datetime.date.fromisoformat,
        default=None,
        help="judge revisit dates as of this YYYY-MM-DD (default: today, UTC). For tests and "
        "rehearsals; CI runs without it, which is what makes a revisit date bite",
    )
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()

    root = pathlib.Path(args.root).resolve()
    problems, files, seen = check_tree(root)
    today = args.today or datetime.datetime.now(datetime.UTC).date()
    runtime_problems, runtimes = check_runtimes(root, today=today)
    # Always say what was examined. "0 problems" over 0 files is not a pass.
    print(
        f"workflow-local-action: scanned {files} workflow file(s), {seen} local 'uses: ./' reference(s)."
    )
    read = ", ".join(f"{rel}={using}" for rel, using in sorted(runtimes.items())) or "none"
    print(f"workflow-local-action: runs.using read from {len(runtimes)} local action(s): {read}")
    for warning in revisit_warnings(runtimes, today):
        print(warning)
    if files == 0:
        print(
            "no .github/workflows/*.yml under this root -- NOTHING WAS EXAMINED, which is not a pass."
        )
        return 1
    if runtime_problems:
        print("")
        for p in runtime_problems:
            print(f"  {p}")
        print("")
        print(
            "A local action's runs.using is read from THIS branch. A pull_request_target workflow"
        )
        print("that calls it runs main's copy, so this step is the only place a bad runtime shows")
        print("before it lands. BACKLOG #1868 and ADR 0034 (amendment 2026-09-25) have the dates.")
    if not problems:
        return 1 if runtime_problems else 0
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
