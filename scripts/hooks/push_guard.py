#!/usr/bin/env python3
"""Push guard — refuse a DIRECT push to a protected branch.

THE DEFECT THIS EXISTS FOR. Since the MEFORORG cutover this repository IS the published artifact:
there is no publish step left between a push and the public internet. A push to ``main`` is therefore
publication, immediately and irreversibly (deleting a ref later does not un-publish content that was
fetched, mirrored or indexed in between).

Branch protection on the server requires a PR and 12 status checks -- but ``enforce_admins`` is false,
so the repository owner BYPASSES all of it. The realistic trigger is not malice, it is one click:
VS Code's Sync/Push button does not distinguish "my feature branch" from "main", and the editor is
where most pushes originate.

This is the guard the old mirror clone's Gate-Provenance pre-push hook used to provide. That clone was
quarantined at cutover, and nothing replaced it.

WHAT THIS IS NOT. A guardrail, not a security boundary: ``git push --no-verify`` skips it, and it is
local-only, so a different machine is unprotected. It removes the ACCIDENT, not the capability. The
durable server-side fix is ``enforce_admins=true``, which was deliberately NOT enabled while an
intermittent harness-monitor failure was blocking consecutive PRs -- removing the admin override while
a flake can strand a merge trades an accidental-push risk for a cannot-ship risk. That failure turned
out to be a livelock in ``MessagesPanel._apply`` rather than a flake, and is fixed
(``tests/test_console_messages_refresh.py``), so the argument against ``enforce_admins`` is weaker now
than when this was written. (An earlier revision of this note cited "BACKLOG #17" for it; that is the
py3.11 pytest/aiosqlite deadlock, OBSOLETE and unrelated.)

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
        "  cannot be taken back. Server-side branch protection requires a PR and 12 checks, but\n"
        "  enforce_admins is false, so the owner bypasses it. Nothing else would have stopped this.\n"
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
