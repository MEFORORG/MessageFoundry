#!/usr/bin/env python3
"""Push guard — refuse a DIRECT push to a protected branch.

THE DEFECT THIS EXISTS FOR. Since the MEFORORG cutover this repository IS the published artifact:
there is no publish step left between a push and the public internet. A push to ``main`` is therefore
publication, immediately and irreversibly (deleting a ref later does not un-publish content that was
fetched, mirrored or indexed in between).

Branch protection on the server requires a PR and 13 status checks. ``enforce_admins`` is now TRUE
(enabled 2026-07-28), so a direct push to ``main`` is refused server-side and ``gh pr merge --admin``
no longer works. This hook is therefore DEFENCE-IN-DEPTH rather than the only guard -- it still earns
its place by failing FAST and LOCALLY, with an explanation, instead of after a round-trip; and it
covers ``cla-signatures``, which branch protection does not.

The realistic trigger was never malice, it is one click: VS Code's Sync/Push button does not
distinguish "my feature branch" from "main", and the editor is where most pushes originate.

This is the guard the old mirror clone's Gate-Provenance pre-push hook used to provide. That clone was
quarantined at cutover, and nothing replaced it.

WHAT THIS IS NOT. A guardrail, not a security boundary: ``git push --no-verify`` skips it, and it is
local-only, so a different machine relies on the server-side rule alone.

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
        print("push_guard: MEFOR_ALLOW_DIRECT_PUSH=1 — direct push ALLOWED.", file=sys.stderr)
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
    print("MessageFoundry push guard — REFUSED", file=sys.stderr)
    for ref, is_delete in offenders:
        what = "DELETE" if is_delete else "direct push"
        print(f"  {what} to {ref}", file=sys.stderr)
    print("", file=sys.stderr)
    print(
        "  This repo IS the published artifact — a push to main is publication, immediately, and\n"
        "  cannot be taken back. Branch protection would refuse this server-side too (a PR + 12\n"
        "  checks, enforce_admins ON); this hook just tells you now, locally, instead of after a\n"
        "  round-trip — and it also covers cla-signatures, which protection does not.\n"
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
