#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Push guard -- refuse a DIRECT push to a protected branch, a push to a ref outside
``refs/heads/``/``refs/tags/``, or a push whose tip tree carries private documents.

THE DEFECT THIS EXISTS FOR. Since the MEFORORG cutover this repository IS the published artifact:
there is no publish step left between a push and the public internet. A push to ``main`` is therefore
publication, immediately and irreversibly (deleting a ref later does not un-publish content that was
fetched, mirrored or indexed in between).

Branch protection on the server requires a PR and a set of required status checks, and `strict` is ON
(a PR must be up to date with ``main`` to merge). The required set is deliberately NOT enumerated or
counted here -- it has moved repeatedly inside a single day (``.github/required-contexts.txt`` records
the sequence), so a number written down here rots. That file is the checked-in claim, and
``tests/test_required_contexts.py`` checks the in-repo statements listed in its ``_CLAIM_FILES``
tuple, this file among them, against it. Note what those checks gate: MERGING a pull request, never
the push this hook sees.

``enforce_admins`` was enabled 2026-07-28 and DISABLED again on 2026-07-29 via the escape hatch in
the HISTORY note below, so ``gh pr merge --admin`` works once more and, for an admin, protection does
not apply to a direct push at all. This hook is therefore the ONLY thing refusing that one path, not
merely defence-in-depth. Where the server WOULD refuse -- a non-admin, or if the setting is flipped
back -- it still earns its place by failing FAST and LOCALLY, with an explanation, instead of after a
round-trip; and it covers ``cla-signatures``, which branch protection does not cover either way.

The realistic trigger was never malice, it is one click: VS Code's Sync/Push button does not
distinguish "my feature branch" from "main", and the editor is where most pushes originate.

This is the guard the old mirror clone's Gate-Provenance pre-push hook used to provide. That clone was
quarantined at cutover, and nothing replaced it.

TWO FURTHER GUARDS, added 2026-08-05. The check above asks WHERE a push lands. These ask WHICH REFS it
offers and WHAT THEY CARRY, which is a different question and was answered by nothing.

GUARD A -- namespace allowlist (``PUSHABLE_NAMESPACES``). Refuse any push whose REMOTE ref is outside
``refs/heads/`` or ``refs/tags/``. That is the shape ``git push --mirror`` has: it offers every ref
under ``refs/``, remote-tracking namespaces (``refs/remotes/<name>/**``) included, which an ordinary
push never names. Before this, a mirror push was refused only INCIDENTALLY -- it offers local ``main``
as an update of ``refs/heads/main``, so the PROTECTED check happened to fire. That is a coincidence of
one branch's state, not a rule: it says nothing whatever about ``refs/remotes/**``, and it evaporates
the moment ``main`` is already up to date. State plainly what this does NOT cover: ``git push --all``
is ``refs/heads`` only, so every ref ``--all`` offers is INSIDE this allowlist and passes it.
``--all`` and ``--mirror`` are not interchangeable; only ``--mirror`` is what Guard A is for.

GUARD B -- content check (``PRIVATE_TREES``). For each pushed ref, inspect the tree at the LOCAL tip
and refuse if it carries anything under ``docs/security``. That directory is git-ignored (the
``/docs/security/`` rule in ``.gitignore``; what belongs there is stated once, in
``docs/SECURITY-DOCS-POLICY.md``) -- and an ignore rule governs only UNTRACKED paths, so it does
nothing about a ref whose history already tracks those files. The path this closes is therefore not a
mirror at all and is the likeliest of the set: branch off a ref of that lineage, push it as an
ordinary branch, and every other check here waves it through. Structurally it is the sdist allowlist
gate in ``.github/workflows/release.yml`` transposed from tar members onto refs -- same posture
(enumerate what may go out, refuse the rest), different transport. That gate is the repo's precedent
for this class, and it is also the record of what the class costs: without it the release workflow
swept the whole tree into the sdist and published it.

WHAT GUARD B DOES NOT DO, stated because the difference decides what a green run entitles anyone to
conclude. It reads the TIP TREE, one ``git ls-tree`` per pushed ref. A branch that added those files
in one commit and removed them in the next has a clean tip and PASSES, while its history still
carries them -- so this is not a history check and may never be cited as one. It matches PATHS, not
content: the same bytes at some other path are invisible to it. A deletion carries no tip to read and
is skipped. And an object git cannot resolve is treated as clean, which is the guard failing open on
an input it cannot read.

WHAT THIS IS NOT. A guardrail, not a security boundary -- all three checks, not just the first.
Every one of them is skipped by ``git push --no-verify``; by ``MEFOR_ALLOW_DIRECT_PUSH=1``, which
reads like "allow one direct push to main" and in fact returns 0 before any guard runs at all; and by
the installed shim's own fail-open -- where python does not resolve, ``.git/hooks/pre-push`` prints
"THE PUSH GUARD IS OFF for this push" and exits 0, so the loudest failure mode here is the silent
one. It is local-only, so a different machine or a fresh clone has nothing but the server-side rule --
which, with ``enforce_admins`` OFF, is nothing at all when the pusher is an admin. Do not read "the
server would have caught it" into any of those gaps.

HISTORY, because the reasoning inverted. This note used to say ``enforce_admins=true`` was deliberately
NOT enabled, because an intermittent harness-monitor failure was blocking consecutive PRs and removing
the admin override while a flake can strand a merge trades an accidental-push risk for a cannot-ship
risk. That failure turned out to be a LIVELOCK in ``MessagesPanel._apply``, not a flake
(``tests/test_console_messages_refresh.py``), so the premise dissolved and the setting was flipped. The
cannot-ship risk is real but now accepted: a required check that goes permanently red blocks every
merge until it is fixed or protection is relaxed --
``gh api -X DELETE repos/MEFORORG/MessageFoundry/branches/main/protection/enforce_admins``.
(An earlier revision cited "BACKLOG #17" for the failure; that is the py3.11 pytest/aiosqlite deadlock,
OBSOLETE and unrelated.)

Stdlib only, like the other gates -- most worktrees have no project .venv.

git hands a pre-push hook one line per ref on STDIN:
    <local ref> <local sha> <remote ref> <remote sha>
A deletion has an all-zero local sha; it is refused too, since deleting main is worse than pushing to
it. Exit 0 allows the push, 1 refuses it.
"""

from __future__ import annotations

import os
import subprocess
import sys
from typing import NamedTuple

#: Refuse a direct push to any of these. `main` is the published branch; `cla-signatures` holds the
#: CLA Assistant's signature store and is written by the action, never by a human.
PROTECTED = frozenset({"refs/heads/main", "refs/heads/cla-signatures"})

#: GUARD A. The only REMOTE-ref namespaces an ordinary push writes. Everything else -- notably
#: `refs/remotes/**`, which only `--mirror` offers -- is refused. An allowlist rather than a
#: denylist of known-bad namespaces, for the same reason the release sdist gate is one: a denylist
#: has to be extended for every namespace anyone invents, and is silently wrong until someone does.
PUSHABLE_NAMESPACES = ("refs/heads/", "refs/tags/")

#: GUARD B. Path prefixes that must not leave this clone. Matched against the tree at the pushed
#: ref's LOCAL TIP -- see the module docstring for exactly what that does and does not cover.
PRIVATE_TREES = ("docs/security",)

_ZERO = "0" * 40

#: How many offending paths to name per ref before summarising the rest. The names are the operator's
#: only handle on WHICH ref went wrong, and this output is a local terminal -- but a mirror-shaped
#: push can offer hundreds of refs, and a screenful of paths scrolls the remedy off the top.
_MAX_PATHS_SHOWN = 3


class Refusal(NamedTuple):
    """One reason one ref is being refused. `guard` selects which explanation paragraph prints."""

    guard: str  # "protected" | "namespace" | "content"
    line: str  # the already-formatted one-line report


def _private_paths_in_tip(local_sha: str) -> list[str] | None:
    """Paths under a `PRIVATE_TREES` prefix in the tree at `local_sha`.

    Empty list if there are none; ``None`` if the question could not be ANSWERED. The caller refuses
    on ``None``.

    FAILS CLOSED, reversing an earlier decision, and the reversal is the point. "There is nothing
    there" and "I could not look" are different facts, and returning ``[]`` for both is how a guard
    reports clean without having looked -- the same shape as the shim that printed "THE PUSH GUARD IS
    OFF" and exited 0 (BACKLOG #1034).

    The previous docstring argued the unreadable case "does not arise" because git only hands a
    pre-push hook objects that exist locally. That holds for the OBJECT, and it does not cover the
    other branch: this resolves ``git`` through PATH, while the hook itself is invoked by git through
    an absolute path. A GUI client (VS Code, GitHub Desktop) can therefore run this hook in an
    environment where bare ``git`` does not resolve -- ``OSError``, ``[]``, clean, push allowed,
    nothing printed. That is a realistic silent-off, not a test artifact.

    The cost is real and is stated rather than left to be discovered: a genuinely unreadable object
    or an environment with no ``git`` on PATH now BLOCKS the push instead of waving it through. The
    refusal says which of the two happened and names ``--no-verify``, so the stoppage is recoverable
    in the one situation where it is spurious.

    No `-C <dir>`: git runs a pre-push hook from the top of the work tree, so the inherited cwd is
    already the right repository. One `ls-tree` per ref makes this O(refs) subprocesses -- measured on
    this repo 2026-08-05, ~47ms per ref on Windows, so 9.2s for a push offering all 196 local
    branches. An ordinary push carries one ref and pays ~50ms; the case that pays seconds is a push
    offering every ref in the clone, which is precisely the one worth slowing down.
    """
    try:
        proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell, no caller-supplied executable
            ["git", "ls-tree", "-r", "--name-only", local_sha, "--", *PRIVATE_TREES],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]


def _safe_for_message(value: object, limit: int = 400) -> str:
    """Fold a value about to be INTERPOLATED INTO PROSE AN AGENT IS TOLD TO ACT ON (BACKLOG #1040).

    This gate's deny text is read by a model that then does what it says, so a value carrying a line
    break can forge a SECOND remedy block -- and a forged block placed FIRST is the one a reader going
    top-down obeys. Proven on ``worktree_gate.ps1``, where a ``Write`` whose ``file_path`` held embedded
    line breaks produced a reason with two ``Do this instead:`` blocks, the injected one first. It needed
    nothing on disk -- only the JSON field -- so no other gate saw it.

    A LOCAL COPY RATHER THAN AN IMPORT, and the reason is mechanical rather than stylistic:
    ``install-git-hooks.ps1`` COPIES this file into the git hooks directory and runs it from there, so an
    import of anything under ``scripts/hooks/`` resolves at development time and fails at the moment the
    gate actually runs. ``claim_check.py`` carries the same helper for the same reason.

    Folds line breaks to spaces, collapses whitespace runs, strips control characters and truncates --
    the value stays READABLE and can no longer add a line.
    """
    text = "" if value is None else str(value)
    # EVERY control character, not only the line breaks: a lone ESC can rewrite a terminal line and a
    # backspace can erase what precedes it, so a value that "contains no newline" is not therefore inert.
    text = "".join(" " if ch < " " or ch == chr(127) else ch for ch in text)
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return text


def _describe(paths: list[str]) -> str:
    shown = ", ".join(paths[:_MAX_PATHS_SHOWN])
    extra = len(paths) - _MAX_PATHS_SHOWN
    return f"{shown} (+{extra} more)" if extra > 0 else shown


def main(argv: list[str]) -> int:
    # Escape hatch for the rare legitimate case, distinct from --no-verify so it is greppable in
    # history and cannot be set by muscle memory.
    #
    # SCOPED to the protected-branch guard. It used to return here, before every guard, and the
    # comment said so -- but documenting a fail-open is not closing one, and BACKLOG #1034 lists this
    # among the adjacent gaps. The variable's NAME is the argument: "allow direct push" is a claim
    # about where a push lands, so letting it also decide what a push CARRIES is a bypass nobody
    # asked for. "I mean to push to main" is a decision a human can sensibly make; "I mean to publish
    # the private security corpus" is not, and one variable must not silently grant both.
    allow_direct = os.environ.get("MEFOR_ALLOW_DIRECT_PUSH") == "1"
    if allow_direct:
        print(
            "push_guard: MEFOR_ALLOW_DIRECT_PUSH=1 -- protected-branch guard SKIPPED. "
            "The namespace and content guards still run.",
            file=sys.stderr,
        )

    refusals: list[Refusal] = []
    for line in sys.stdin:
        parts = line.split()
        if len(parts) != 4:
            continue
        local_sha, remote_ref = parts[1], parts[2]
        deleting = local_sha.strip("0") == ""

        if remote_ref in PROTECTED and not allow_direct:
            what = "DELETE" if deleting else "direct push"
            refusals.append(Refusal("protected", f"{what} to {_safe_for_message(remote_ref)}"))

        # GUARD A. Independent of PROTECTED on purpose: a mirror push is refused because of the
        # namespace it names, not because local main happens to present as a forced update.
        if not remote_ref.startswith(PUSHABLE_NAMESPACES):
            refusals.append(
                Refusal(
                    "namespace", f"push to a non-branch/tag ref: {_safe_for_message(remote_ref)}"
                )
            )

        # GUARD B. A deletion has no local tip to inspect, and removing a ref cannot publish anything.
        if not deleting:
            hits = _private_paths_in_tip(local_sha)
            if hits is None:
                refusals.append(
                    Refusal(
                        "content",
                        f"could not inspect the tip tree of {_safe_for_message(remote_ref)} "
                        f"({local_sha[:12]}) -- "
                        f"git was unusable or the object did not resolve, so this ref is UNJUDGED "
                        f"rather than clean",
                    )
                )
            elif hits:
                refusals.append(
                    Refusal(
                        "content",
                        f"private docs in the tip tree of {_safe_for_message(remote_ref)}: "
                        f"{_safe_for_message(_describe(hits))}",
                    )
                )

    if not refusals:
        return 0

    fired = {r.guard for r in refusals}
    print("", file=sys.stderr)
    print("MessageFoundry push guard -- REFUSED", file=sys.stderr)
    for r in refusals:
        print(f"  {r.line}", file=sys.stderr)
    print("", file=sys.stderr)

    if "protected" in fired:
        # This paragraph is a COMPENSATING-CONTROL claim, read at the one moment it can still change
        # what the operator does, so it has to be true THEN. It used to say protection would refuse the
        # push server-side anyway -- "a PR + 12 checks, enforce_admins ON" -- which the live API
        # contradicts on both halves: the count was stale, and enforce_admins is FALSE, so for an admin
        # there is no server-side refusal to fall back on and this hook is the whole control.
        # Reassurance about a guard that is switched off is worse than saying nothing: it invites
        # --no-verify on the belief that something downstream still catches it.
        #
        # It points at .github/required-contexts.txt instead of quoting a count, because the set has
        # moved repeatedly inside one day and a number here would be a future lie -- that file's own
        # header records four in-repo counts that had already disagreed with the live set.
        #
        # Do NOT treat tests/test_required_contexts.py as the backstop for a count re-introduced here.
        # It scans this file, but only for "N required checks/contexts" or "N status checks" on ONE
        # line; the count this string used to carry, "a PR + 12 checks" and split across a \n at that,
        # matched neither pattern. That is exactly why the 12 went stale unnoticed. The pointer is the
        # control.
        print(
            "  This repo IS the published artifact -- a push to main is publication, immediately, and\n"
            "  cannot be taken back. Do NOT expect the server to stop it: enforce_admins is OFF, so\n"
            "  branch protection does not apply to an admin's direct push, and this hook is the only\n"
            "  thing refusing it. Required checks gate MERGING a PR (see .github/required-contexts.txt),\n"
            "  not this push -- and cla-signatures is not covered by protection at all.\n"
            "\n"
            "  Push a branch and open a PR instead:\n"
            "      git switch -c <branch> && git push -u origin <branch>",
            file=sys.stderr,
        )
        print("", file=sys.stderr)

    if "namespace" in fired:
        print(
            "  That remote ref is outside refs/heads/ and refs/tags/. An ordinary push never names\n"
            "  one; `git push --mirror` names ALL of them, so this is what a mirror push looks like\n"
            "  from inside the hook -- every ref this clone holds, remote-tracking namespaces\n"
            "  included, offered to the remote as-is. Push the branch or tag you actually mean, by\n"
            "  name:\n"
            "      git push origin <branch>\n"
            "\n"
            "  (`git push --all` is refs/heads only and does NOT trip this. The two flags are not\n"
            "  interchangeable, and treating them as if they were is how a mirror push gets typed.)",
            file=sys.stderr,
        )
        print("", file=sys.stderr)

    if "content" in fired:
        print(
            "  The tip tree of that ref carries a private-document path (docs/security). It is\n"
            "  git-ignored, which stops an UNTRACKED file being added and does nothing about a ref\n"
            "  whose history already tracks one -- so the likely cause is a branch taken from a ref of\n"
            "  that lineage. Since the cutover a push is publication, so look before you do anything\n"
            "  else:\n"
            "      git ls-tree -r --name-only <ref> -- docs/security\n"
            "\n"
            "  This reads the TIP TREE ONLY. A ref that passes is not thereby a ref whose HISTORY is\n"
            "  clean -- for that, git log --all -- docs/security, or rewrite the branch.",
            file=sys.stderr,
        )
        print("", file=sys.stderr)

    print(
        "  If you genuinely mean it:  MEFOR_ALLOW_DIRECT_PUSH=1 git push ...\n"
        "  (that switches off every check above, not only the one that fired)",
        file=sys.stderr,
    )
    print("", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
