#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Claim gate -- stop two sessions building the same backlog item in parallel (BACKLOG #309).

`ledger_check.py` stops two sessions taking the same ADR/BACKLOG *number*. This stops them doing the same
*work*. On 2026-07-24 three sessions independently fixed one npm advisory: two PRs were closed as
duplicates, and the one that merged had not tested the failure mode the others found, so it shipped a
latent break that `npm audit` reported as clean.

The rule, deliberately narrow so it never fights you:

    A commit whose SUBJECT declares it implements `BACKLOG #N`, and whose staged diff touches CODE,
    must hold a claim on N for THIS worktree.

Three scoping decisions, each load-bearing:

* **Subject line only.** A body may reference other items freely -- this very repo's commits routinely
  cite the item they supersede or were found by. Enforcing on the body would fire on every one of those.
  The subject is where a commit *declares* what it implements.
* **Code-touching diffs only.** Banner flips, doc corrections and ledger reconciles legitimately cite an
  item without building it, and they are exactly the commits a coordination gate must not block.
* **Numbered items only.** Free-text claims (`claim.ps1 -Take npm-audit-brace-expansion`) are advisory --
  surfaced at session start, not enforced here, because there is no reliable way to map an arbitrary diff
  to a topic. Visibility is the win there; enforcement would be guesswork.

Run as a git `commit-msg` hook (argv[1] = the message file). It CANNOT be a pre-commit hook: pre-commit
never receives the commit message, so the check would look installed and silently never fire.

Stdlib only, no `messagefoundry` import: most worktrees have no .venv, and a gate that silently skips is
worse than no gate.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

# `(BACKLOG #71, #72)` is the house form, so once BACKLOG appears in the subject every `#N` after it in
# that line counts -- otherwise the second item of a paired commit would slip through unclaimed.
_BACKLOG_TOKEN = re.compile(r"\bBACKLOG\b", re.IGNORECASE)
_ITEM = re.compile(r"#(\d{1,5})\b")

# A commit touching ONLY these is documentation/ledger work: it may cite an item without implementing it.
_DOC_PREFIXES = ("docs/", ".github/")
_DOC_SUFFIXES = (".md",)

# NEVER DOCUMENTATION, WHEREVER IT LIVES (BACKLOG #1345). The prefixes above classify by LOCATION, so
# before this a file DECLARED ITSELF documentation merely by sitting under one -- and `.github/` holds
# the CI workflows. Measured on this tree: 28 `.yml`/`.yaml` under `.github/` and 2 `.py` under
# `docs/`, all of which a commit could change ALONE while the gate held it to no claim at all.
# Rewiring CI is exactly the change two sessions can collide on, which is the collision this gate
# exists to stop, so the extension decides before the directory does.
_CODE_SUFFIXES = (
    ".py",
    ".ps1",
    ".psm1",
    ".sh",
    ".yml",
    ".yaml",
    ".ts",
    ".js",
    ".mjs",
    ".cjs",
    ".toml",
    ".cfg",
    ".ini",
)


def _safe_for_message(value: object, limit: int = 400) -> str:
    """Fold a value that is about to be INTERPOLATED INTO PROSE AN AGENT IS TOLD TO ACT ON.

    BACKLOG #1040. This gate's deny text is read by a model that then does what it says, so any value
    carrying a newline can forge a second remedy block -- and a forged block placed FIRST is the one a
    reader reaching top-down obeys. That is not hypothetical: the same defect was proven on
    ``worktree_gate.ps1``, where a ``Write`` whose ``file_path`` held embedded newlines produced a
    reason with two ``Do this instead:`` blocks, the injected one first. It needed nothing on disk --
    only the JSON field -- so no other gate saw it.

    THE VALUE MOST WORTH FOLDING HERE IS ``note``. It is free text any peer writes with
    ``claim.ps1 -Take <n> -Note "<what>"``, it is routinely hundreds of characters, and nothing
    constrains its content. ``worktree`` and ``branch`` are folded too: a refname is not inert either,
    because ``git check-ref-format`` accepts ``;``, ``$``, ``|``, ``"`` and ``'``.

    A LOCAL HELPER RATHER THAN A SHARED MODULE, and the reason is mechanical rather than stylistic.
    ``install-git-hooks.ps1`` COPIES this file into the git hooks directory and runs it from there
    (``exec "$PY" "$HOOK_DIR/claim_check.py"``), so an import of anything under ``scripts/hooks/``
    resolves at development time and fails at the moment the gate actually runs. ``collision_gate.ps1``
    took a local copy of its PowerShell equivalent for exactly this reason, recorded on #1040.

    Folds every line break to a space, collapses runs of whitespace, strips control characters, and
    truncates -- so the value can still be READ, but it can no longer add a line.
    """
    text = "" if value is None else str(value)
    # Control characters, not just \n and \r: a lone \x1b can rewrite a terminal line, and \x08 can
    # erase what precedes it, so a value that "contains no newline" is not therefore inert.
    text = "".join(" " if ch < " " or ch == "\x7f" else ch for ch in text)
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return text


class GitReadError(RuntimeError):
    """git could not answer, so nothing downstream may treat its silence as an answer."""


def _git(*args: str) -> str:
    """Run a git read and REFUSE TO RETURN ITS SILENCE AS DATA.

    This used to return `.stdout` and never look at `returncode`. A failed read therefore
    returned "" -- indistinguishable from a genuinely empty diff -- and that emptiness flowed
    straight through `_staged_paths()` to `_touches_code([])`, which is False BY DESIGN so an
    `--amend` of a message is never blocked. The gate then took its docs-only exit and PASSED a
    commit citing an unclaimed item, printing nothing.

    MEASURED, with a control on the same box: outside a repository this read exits 129 with
    empty stdout, while inside the repository it exits 0 -- so the emptiness IS the failure and
    not the normal case, and the old code could not tell the two apart.

    Low odds, and that is the point rather than a reason to shrug: git normally invokes this hook
    from inside a repository. It fails on `index.lock` contention, a corrupt index, git missing
    from the hook's PATH, or GIT_DIR oddities in a worktree -- rare states that arrive exactly
    when several sessions are committing at once, which is when a duplicate-work gate matters
    most. A gate disarmed by the one condition it cannot detect is worse than no gate, because
    its silence reads as approval.
    """
    proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell, no caller-supplied executable
        ["git", *args], capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    if proc.returncode != 0:
        detail = (proc.stderr or "").strip().splitlines()
        raise GitReadError(
            f"git {' '.join(args)} exited {proc.returncode}: {detail[0] if detail else 'no output'}"
        )
    return proc.stdout


def _staged_paths() -> list[str]:
    out = _git("diff", "--cached", "--name-only")
    return [p.strip().replace("\\", "/") for p in out.splitlines() if p.strip()]


def _touches_code(paths: list[str]) -> bool:
    """True if any staged path is not documentation. An empty diff counts as no code (e.g. --amend of a
    message), so a message-only fixup is never blocked."""
    for p in paths:
        # THE EXTENSION IS CHECKED FIRST, ON PURPOSE. It must OVERRIDE the location: the whole defect
        # is that a prefix let an executable declare itself documentation.
        #
        # CASEFOLDED, because a case-SENSITIVE match here is the same defect one keystroke lower down:
        # `_CODE_SUFFIXES` is all-lowercase, so a bare `endswith` reads `docs/Tool.PY` as documentation
        # and hands back the hole this test just closed. #1345's own row names that shape -- "a test on
        # the SPELLING of a path standing in for a question about what the file IS" -- and a suffix is
        # every bit as spellable as a prefix.
        if p.casefold().endswith(_CODE_SUFFIXES):
            return True
        if p.startswith(_DOC_PREFIXES):
            continue
        if p.endswith(_DOC_SUFFIXES):
            continue
        return True
    return False


def _claims_dir() -> Path:
    common = _git("rev-parse", "--path-format=absolute", "--git-common-dir").strip()
    return Path(common) / "mefor-coord" / "claims"


def _repo() -> str:
    return _git("rev-parse", "--path-format=absolute", "--show-toplevel").strip()


def _norm(p: str) -> str:
    return p.replace("\\", "/").rstrip("/").casefold()


def _holder(item: str) -> dict[str, object] | None:
    """The claim record for `item`, or None if unclaimed/unreadable. A malformed claim reads as UNCLAIMED
    on purpose: the gate then asks for a claim rather than silently passing on a corrupt one. A non-object
    payload (a bare list/string) is treated the same way -- it cannot name a holder, so it grants nothing."""
    f = _claims_dir() / f"{item}.json"
    try:
        loaded = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return loaded if isinstance(loaded, dict) else None


def main() -> int:
    if len(sys.argv) < 2:
        return 0  # not wired as a commit-msg hook; do nothing rather than guess
    try:
        message = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0

    subject = next((ln for ln in message.splitlines() if ln.strip() and not ln.startswith("#")), "")
    m = _BACKLOG_TOKEN.search(subject)
    if not m:
        return 0
    items = _ITEM.findall(subject[m.start() :])
    if not items:
        return 0

    # FAIL CLOSED FROM HERE, because from here a wrong answer is a SILENT PASS.
    #
    # Every exit above this line is reached WITHOUT calling git, so a commit that does not cite a
    # BACKLOG number is untouched by this. Only a commit that DOES cite one, on a box where git
    # cannot answer, is refused -- and refusing it costs a re-run, while passing it costs the
    # duplicate build this gate exists to stop.
    #
    # Fail-closed is the right choice HERE specifically because _git has three callers and all of
    # them are in this file. The sibling case that argued for care -- a board tool with sixty
    # callers written against a function that could not fail -- would trade a silent wrong number
    # for a dead board. A commit hook has no such surface.
    try:
        paths = _staged_paths()
        me = _norm(_repo())
    except GitReadError as exc:
        sys.stderr.write(
            f"\nCLAIM GATE: git could not be read, so this commit was NOT checked.\n"
            f"  {exc}\n"
            f"  The subject cites BACKLOG #{items[0]}, and the gate cannot tell whether this commit\n"
            f"  touches code -- so it refuses rather than pass unchecked. Its usual causes are an\n"
            f"  index.lock held by another session, a corrupt index, or git missing from the hook's\n"
            f"  PATH. Fix that and commit again; the check itself has not failed you.\n"
        )
        return 1

    if not _touches_code(paths):
        return 0  # docs/ledger-only: cites the item, does not build it

    problems: list[str] = []
    for item in dict.fromkeys(items):  # de-dupe, keep order
        claim = _holder(item)
        if claim is None:
            problems.append(
                f"  BACKLOG #{item} is NOT CLAIMED.\n"
                f"      Another session may already be building it -- that is the duplicate work this\n"
                f"      gate exists to stop. Claim it, then commit again:\n"
                f'          pwsh -NoProfile -File scripts\\coord\\claim.ps1 -Take {item} -Note "<what>"'
            )
            continue
        if _norm(str(claim.get("worktree", ""))) != me:
            problems.append(
                f"  BACKLOG #{item} is claimed by ANOTHER worktree:\n"
                f"      held by: {_safe_for_message(claim.get('worktree'))} "
                f"[{_safe_for_message(claim.get('branch'))}]\n"
                f"      since  : {_safe_for_message(claim.get('claimed'))}\n"
                f"      note   : {_safe_for_message(claim.get('note'))}\n"
                f"      Do not build it in parallel. Coordinate with that session, or if it is dead:\n"
                f"          pwsh -NoProfile -File scripts\\coord\\claim.ps1 -Release {item} -Force"
            )

    if not problems:
        return 0

    sys.stderr.write("\nMessageFoundry claim gate\n\n")
    sys.stderr.write("\n\n".join(problems))
    sys.stderr.write(
        "\n\n  See who is building what:  pwsh -NoProfile -File scripts\\coord\\claim.ps1 -List\n"
        "  This fires only on a code-touching commit whose SUBJECT says 'BACKLOG #N'.\n"
        "  A docs-only commit (banner flip, ledger reconcile) is never blocked.\n\n"
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
