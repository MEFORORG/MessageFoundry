#!/usr/bin/env python3
"""Push guard -- refuse a DIRECT push to a protected branch.

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

WHAT THIS IS NOT. A guardrail, not a security boundary: ``git push --no-verify`` skips it, and it is
local-only, so a different machine has nothing but the server-side rule -- which, with
``enforce_admins`` OFF, is nothing at all when the pusher is an admin. Do not read "the server would
have caught it" into either gap.

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
import sys

#: Refuse a direct push to any of these. `main` is the published branch; `cla-signatures` holds the
#: CLA Assistant's signature store and is written by the action, never by a human.
PROTECTED = frozenset({"refs/heads/main", "refs/heads/cla-signatures"})

_ZERO = "0" * 40


def main(argv: list[str]) -> int:
    # Escape hatch for the rare legitimate case, distinct from --no-verify so it is greppable in
    # history and cannot be set by muscle memory.
    if os.environ.get("MEFOR_ALLOW_DIRECT_PUSH") == "1":
        print("push_guard: MEFOR_ALLOW_DIRECT_PUSH=1 -- direct push ALLOWED.", file=sys.stderr)
        return 0

    offenders: list[tuple[str, bool]] = []
    for line in sys.stdin:
        parts = line.split()
        if len(parts) != 4:
            continue
        local_sha, remote_ref = parts[1], parts[2]
        if remote_ref in PROTECTED:
            offenders.append((remote_ref, local_sha.strip("0") == ""))

    if not offenders:
        return 0

    print("", file=sys.stderr)
    print("MessageFoundry push guard -- REFUSED", file=sys.stderr)
    for ref, is_delete in offenders:
        what = "DELETE" if is_delete else "direct push"
        print(f"  {what} to {ref}", file=sys.stderr)
    print("", file=sys.stderr)
    # This paragraph is a COMPENSATING-CONTROL claim, read at the one moment it can still change what
    # the operator does, so it has to be true THEN. It used to say protection would refuse the push
    # server-side anyway -- "a PR + 12 checks, enforce_admins ON" -- which the live API contradicts on
    # both halves: the count was stale, and enforce_admins is FALSE, so for an admin there is no
    # server-side refusal to fall back on and this hook is the whole control. Reassurance about a
    # guard that is switched off is worse than saying nothing: it invites --no-verify on the belief
    # that something downstream still catches it.
    #
    # It points at .github/required-contexts.txt instead of quoting a count, because the set has moved
    # repeatedly inside one day and a number here would be a future lie -- that file's own header
    # records four in-repo counts that had already disagreed with the live set.
    #
    # Do NOT treat tests/test_required_contexts.py as the backstop for a count re-introduced here. It
    # scans this file, but only for "N required checks/contexts" or "N status checks" on ONE line; the
    # count this string used to carry, "a PR + 12 checks" and split across a \n at that, matched
    # neither pattern. That is exactly why the 12 went stale unnoticed. The pointer is the control.
    print(
        "  This repo IS the published artifact -- a push to main is publication, immediately, and\n"
        "  cannot be taken back. Do NOT expect the server to stop it: enforce_admins is OFF, so\n"
        "  branch protection does not apply to an admin's direct push, and this hook is the only\n"
        "  thing refusing it. Required checks gate MERGING a PR (see .github/required-contexts.txt),\n"
        "  not this push -- and cla-signatures is not covered by protection at all.\n"
        "\n"
        "  Push a branch and open a PR instead:\n"
        "      git switch -c <branch> && git push -u origin <branch>\n"
        "\n"
        "  If you genuinely mean it:  MEFOR_ALLOW_DIRECT_PUSH=1 git push ...",
        file=sys.stderr,
    )
    print("", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
