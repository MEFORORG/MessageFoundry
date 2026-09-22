# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The durability hook's public-repo refusal must name ONE repository, in every spelling git stores.

``scripts/hooks/durability_push.sh`` force-pushes a rescue tag to whatever remote
``mefor.durabilityRemote`` names. That is allowed to skip review for one reason: the nominated
remote is private, so the push opens no pull request and publishes nothing. The refusal in that
script is the only thing standing between that mechanism and an unreviewed push to the canonical
PUBLIC repository, and it failed in BOTH directions inside one day.

**IT REFUSED A PRIVATE REMOTE.** The matcher was the unanchored glob ``*MEFORORG/MessageFoundry*``,
which also matches ``MEFORORG/MessageFoundry-vault`` -- a different, private repository, and the
vault clone's only remote. Because the refusal is ``exit 0``, every commit there still succeeded
with durability silently off, reported by one stderr line that reads like a false alarm.

**THEN THE FIX FOR THAT LEFT THE OPPOSITE HOLE OPEN, AND IT IS THE WORSE ONE.** Anchoring on three
literal spellings accepted ``https://github.com/mefororg/messagefoundry.git`` -- the same public
repository, differing only in case, since GitHub resolves owner and name case-insensitively.
Over-refusing turns a durability mechanism off quietly; under-refusing publishes.

**AND THE GUARD READ A URL THE PUSH DOES NOT USE.** ``git remote get-url`` returns the FETCH url;
``git push`` resolves ``remote.<name>.pushurl`` when one is set. So the entire refusal was
bypassable by one config line, silently. ``test_a_public_PUSHURL_is_refused`` is that arm.

**NO URL IN THIS FILE NAMES A REACHABLE HOST. THAT IS A SAFETY PROPERTY, NOT TIDINESS.** An
ACCEPTED url is pushed to, and a REFUSED one becomes an accepted one the moment the matcher
regresses -- which is the regression this file exists to catch. With a real host in the list, the
first run after such a regression force-pushes a rescue tag into the public repository and only
then goes red. The red-first control below makes that worse: it runs the PRE-FIX hook, which
accepts the lowercase spelling by construction. Git Credential Manager is configured at SYSTEM
scope on at least one box here, so it supplies credentials before ``GIT_ASKPASS`` is consulted and
neither that variable nor ``GIT_CONFIG_GLOBAL`` would stop the push. ``.invalid`` is reserved by
RFC 2606 and resolves nowhere. The guard does not examine the host by design, and
``test_the_host_is_not_examined`` pins that, which is what makes the substitution sound rather than
merely convenient. **Do not put github.com back in these lists.**

**EVERY CASE IS ASSERTED IN BOTH DIRECTIONS.** A test that only checked the refusals would be green
against a matcher that refuses everything -- which is the defect that turned the vault's durability
off -- and one that only checked acceptance would be green against a matcher that refuses nothing.

**ACCEPTANCE IS WITNESSED, NOT INFERRED FROM SILENCE.** Past the guard the hook writes a provenance
tag object into the LOCAL object store before it pushes; where it cannot, it says so on stderr and
pushes the bare commit. Either is proof control reached the push. Asserting only that ``REFUSING``
is absent would grade a hook that died on the next line as an acceptance, and the push itself is
backgrounded and discarded, so it cannot be read without turning the assertion into a timing
measurement.

**WHY THIS IS A SEPARATE FILE FROM ``test_durability_hook_provenance.py``**, which already carries a
three-case version of the refusal battery: that file had uncommitted work in another live session's
worktree when this was written, so editing it would have made one of the two changes lose its work
at merge. The duplication is real and the right end state is one file owning the guard -- moving
the sibling's cases here rather than the reverse, since the signals below are the stronger ones.

Red-first control, one command, no edit to this file::

    git show <pre-fix-sha>:scripts/hooks/durability_push.sh > /tmp/old.sh
    MEFOR_DURABILITY_HOOK=/tmp/old.sh pytest tests/test_durability_hook_remote_guard.py

The fixtures build throwaway repositories under ``tmp_path`` and never touch the real
``.git/hooks``: the suite runs under ``pytest-xdist``, so shared state would race.
"""

from __future__ import annotations

import functools
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HOOK = Path(
    os.environ.get("MEFOR_DURABILITY_HOOK") or (ROOT / "scripts" / "hooks" / "durability_push.sh")
)
INSTALLER = ROOT / "scripts" / "coord" / "install-git-hooks.ps1"
TIMEOUT = 180

#: Spellings of the canonical PUBLIC repository. Every one must be refused. Host is `.invalid`
#: throughout -- see the module docstring; this is a safety property.
PUBLIC = [
    "https://github.invalid/MEFORORG/MessageFoundry",
    "https://github.invalid/MEFORORG/MessageFoundry.git",
    "https://github.invalid/MEFORORG/MessageFoundry/",
    "https://github.invalid/MEFORORG/MessageFoundry.git/",
    # Composed suffixes. A one-pass strip let all three of these through.
    "https://github.invalid/MEFORORG/MessageFoundry//",
    "https://github.invalid/MEFORORG/MessageFoundry.git//",
    "https://github.invalid/MEFORORG/MessageFoundry.wiki.git",
    # Case. GitHub resolves owner and name case-insensitively, so these are the same repository.
    "https://github.invalid/mefororg/messagefoundry.git",
    "https://github.invalid/MeforOrg/MessageFoundry.GIT",
    "git@github.invalid:MEFORORG/MessageFoundry.git",
    "git@github.invalid:mefororg/messagefoundry",
    "ssh://git@github.invalid/MEFORORG/MessageFoundry.git",
    "git://github.invalid/MEFORORG/MessageFoundry.git",
    "https://x-access-token:redacted@github.invalid/MEFORORG/MessageFoundry.git",
]

#: Private or unrelated remotes. Every one must reach the push.
PRIVATE = [
    "https://example.invalid/MEFORORG/MessageFoundry-vault",
    "https://example.invalid/MEFORORG/MessageFoundry-vault.git",
    "https://example.invalid/MEFORORG/MessageFoundry-vault/",
    "https://example.invalid/mefororg/messagefoundry-vault.git",
    "git@example.invalid:MEFORORG/MessageFoundry-vault.git",
    "ssh://git@example.invalid/MEFORORG/MessageFoundry-vault.git",
    # The same repository NAME under a different owner. Only the owner separates it.
    "https://example.invalid/acme/MessageFoundry.git",
    "https://example.invalid/someone/MessageFoundryFork.git",
    # A DIFFERENT owner whose name merely ends in the public one. The boundary before the owner is
    # what separates these, and a substring matcher fails here in the over-refusing direction.
    "https://example.invalid/somemefororg/messagefoundry",
]


def _isolated_env(home: Path) -> dict[str, str]:
    """Git config from this box must not decide what these tests measure.

    ``core.hooksPath`` set globally would send every fixture repo's commit to some other hook and
    every case would report neither-refused-nor-reached, blaming the matcher for a config problem.
    ``commit.gpgsign`` would fail the commit outright. Both config scopes are redirected, not just
    the global one: the credential helper on at least one box here is at SYSTEM scope.
    """
    env = dict(os.environ)
    env["GIT_CONFIG_GLOBAL"] = str(home / "gitconfig-global")
    env["GIT_CONFIG_SYSTEM"] = str(home / "gitconfig-system")
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_SSH_COMMAND"] = "false"
    env["GIT_ASKPASS"] = "false"
    return env


def git(repo: Path, env: dict[str, str], *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=True,
        env=env,
    ).stdout.strip()


@functools.cache
def _hooks_run_here() -> bool:
    """Does a post-commit hook actually FIRE on this box? Probed, not inferred from ``which sh``.

    Git for Windows runs hooks through its own bundled shell whatever PATH says, so ``which("sh")``
    answers an adjacent question. Getting it wrong skips all of this and reports green -- no
    coverage of the only guard between this hook and an unreviewed publication, indistinguishable
    from a pass.
    """
    with tempfile.TemporaryDirectory() as raw:
        home = Path(raw)
        env = _isolated_env(home)
        repo = home / "probe"
        repo.mkdir()
        subprocess.run(
            ["git", "init", "-q", "-b", "main", str(repo)], check=True, capture_output=True, env=env
        )
        git(repo, env, "config", "user.email", "t@example.invalid")
        git(repo, env, "config", "user.name", "t")
        hook = repo / ".git" / "hooks" / "post-commit"
        hook.write_text('#!/bin/sh\ntouch "$(git rev-parse --git-dir)/FIRED"\n', encoding="utf-8")
        hook.chmod(0o755)
        (repo / "f.txt").write_text("x", encoding="utf-8")
        git(repo, env, "add", "f.txt")
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-q", "-m", "c"],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            env=env,
        )
        return (repo / ".git" / "FIRED").exists()


pytestmark = pytest.mark.skipif(
    not _hooks_run_here(), reason="no post-commit hook fires on this box -- probed, not assumed"
)


def _object_types(repo: Path, env: dict[str, str]) -> list[str]:
    return subprocess.run(
        ["git", "-C", str(repo), "cat-file", "--batch-all-objects", "--batch-check=%(objecttype)"],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=True,
        env=env,
    ).stdout.split()


def _armed_repo(tmp_path: Path, env: dict[str, str]) -> Path:
    repo = tmp_path / "r"
    repo.mkdir()
    subprocess.run(
        ["git", "init", "-q", "-b", "main", str(repo)], check=True, capture_output=True, env=env
    )
    git(repo, env, "config", "user.email", "t@example.invalid")
    git(repo, env, "config", "user.name", "t")
    hook = repo / ".git" / "hooks" / "post-commit"
    shutil.copy2(HOOK, hook)
    hook.chmod(0o755)
    return repo


def _verdict(repo: Path, env: dict[str, str]) -> tuple[bool, bool]:
    """Commit once and read ``(refused, reached_push)``."""
    (repo / "f.txt").write_text("x", encoding="utf-8")
    git(repo, env, "add", "f.txt")
    done = subprocess.run(
        ["git", "-C", str(repo), "commit", "-q", "-m", "c"],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        env=env,
    )
    # DURABILITY OUTRANKS EVERYTHING: the hook must never fail a commit, whichever way it decides.
    assert done.returncode == 0, done.stderr
    assert git(repo, env, "rev-parse", "--verify", "HEAD^{commit}")

    # Either witness proves control reached the push. The hook documents the second as a sanctioned
    # degradation -- no committer identity, or a tag object git declines to write -- under which it
    # pushes the bare commit instead. Reading only the tag object would red all eight accept cases
    # on such a box and blame the publication guard for an identity problem.
    reached = "tag" in _object_types(repo, env) or "could not build a provenance tag object" in (
        done.stderr
    )
    return "REFUSING" in done.stderr, reached


def commit_under(tmp_path: Path, url: str, *, as_pushurl: bool = False) -> tuple[bool, bool]:
    env = _isolated_env(tmp_path)
    repo = _armed_repo(tmp_path, env)
    if as_pushurl:
        # The fetch url is private and only the PUSH url is public -- the bypass in finding form.
        git(repo, env, "remote", "add", "nominated", "https://example.invalid/private/ok.git")
        git(repo, env, "remote", "set-url", "--push", "nominated", url)
    else:
        git(repo, env, "remote", "add", "nominated", url)
    git(repo, env, "config", "mefor.durabilityRemote", "nominated")
    return _verdict(repo, env)


@pytest.mark.parametrize("url", PUBLIC)
def test_every_spelling_of_the_public_repo_is_refused(tmp_path: Path, url: str) -> None:
    refused, reached = commit_under(tmp_path, url)
    assert refused, f"{url} was not refused"
    assert not reached, f"{url} was refused on stderr but still reached the push"


@pytest.mark.parametrize("url", PRIVATE)
def test_a_private_or_unrelated_remote_reaches_the_push(tmp_path: Path, url: str) -> None:
    refused, reached = commit_under(tmp_path, url)
    assert not refused, f"{url} is not the public repo and must not be refused"
    assert reached, f"{url} was not refused but never reached the push either"


@pytest.mark.parametrize("url", PUBLIC[:4])
def test_a_public_PUSHURL_is_refused(tmp_path: Path, url: str) -> None:
    """``git push`` uses ``remote.<name>.pushurl``; the guard used to read only the fetch url.

    With a private fetch url the old guard saw nothing to refuse, and every commit force-pushed a
    rescue tag to whatever the pushurl named. One ``git config`` line, no output, guard intact.
    """
    refused, reached = commit_under(tmp_path, url, as_pushurl=True)
    assert refused, f"{url} as a PUSHURL was not refused -- the guard read the fetch url only"
    assert not reached


def test_a_private_pushurl_still_reaches_the_push(tmp_path: Path) -> None:
    """The control for the test above: reading both urls must not refuse an ordinary private pair."""
    refused, reached = commit_under(
        tmp_path, "https://example.invalid/MEFORORG/MessageFoundry-vault.git", as_pushurl=True
    )
    assert not refused
    assert reached


def test_the_host_is_not_examined(tmp_path: Path) -> None:
    """The refusal is on owner and name alone, which is what licenses every fake host above.

    If the guard ever started reading the host, the lists above would pass for the wrong reason and
    this one would go red.
    """
    refused, reached = commit_under(tmp_path, "https://nowhere.invalid/MEFORORG/MessageFoundry.git")
    assert refused
    assert not reached


def test_an_unset_nomination_does_nothing(tmp_path: Path) -> None:
    """Fail-safe by absence: a fresh clone, a CI checkout or a contributor's fork pushes nowhere."""
    env = _isolated_env(tmp_path)
    repo = _armed_repo(tmp_path, env)
    refused, reached = _verdict(repo, env)
    assert not refused
    assert not reached


def test_the_installer_manages_post_merge_everywhere_it_manages_post_commit() -> None:
    """One script is installed as TWO hooks, and every site must name both.

    post-commit fires on ``git commit``; post-merge fires on ``git merge`` and on a ``git pull``, so
    a clone with only the first makes an entire class of commit durable by nothing.

    THIS IS NOT HYPOTHETICAL AND THE ASYMMETRY IS HOW IT HID. Measured 2026-09-19 in the engine
    clone: ``.git/hooks/post-merge`` existed, was byte-identical to the VAULT clone's copy of the
    script, and was three weeks older than the post-commit beside it -- the vault's installer has
    always written both, this one wrote only post-commit, and a clone that had met both installers
    kept an orphan no audit here could see. ``-Status`` did not mention it, ``-Arm`` did not replace
    it and ``-Uninstall`` did not remove it, so it went on refusing that clone's private remote
    while the post-commit beside it was current.

    Structural rather than behavioural on purpose: driving ``-Arm`` writes hooks into the real
    shared ``.git/hooks`` for every worktree on the box at once, which a test must never do. What it
    buys is the regression that actually happened -- a site added for one hook and not the other.
    """
    text = INSTALLER.read_text(encoding="utf-8")
    code = [ln for ln in text.splitlines() if not ln.lstrip().startswith("#")]
    body = "\n".join(code)

    assert '$postMerge = Join-Path $hooksDir "post-merge"' in body, "no post-merge path is declared"

    # Each pair is (what the site does, the post-commit spelling, the post-merge spelling).
    sites = [
        ("install copy", 'durability_push.sh") $postCommit', 'durability_push.sh") $postMerge'),
        (
            "uninstall",
            "Remove-Item -LiteralPath $postCommit",
            "Remove-Item -LiteralPath $postMerge",
        ),
        ("overwrite guard", "already exists at $postCommit", "already exists at $postMerge"),
        ("chmod", "chmod +x $postCommit", "chmod +x $postMerge"),
    ]
    missing = [name for name, commit, merge in sites if commit in body and merge not in body]
    assert not missing, (
        f"install-git-hooks.ps1 handles post-commit but NOT post-merge at: {missing}. They are the "
        "same script installed twice; a site that names one and not the other leaves either merges "
        "or commits uncovered, and nothing else reports it."
    )

    # -Status must report the INSTALLED bytes, not merely that a marker is present. A marker sits in
    # a header that changes once in months, so it reads INSTALLED across an arbitrarily old copy --
    # and the matcher deciding whether this hook publishes lives in the body.
    assert "$durMergeInstalled" in body, "-Status does not look at post-merge at all"

    # SINCE BACKLOG #1463 THE PARITY LOOP READS A DECLARATION rather than a pair spelled out inside
    # it, so this pins the declaration and its consumption instead of the old `$durSrcSha` local.
    # Naming both halves matters: a declaration nothing reads is a second source of truth, and a
    # loop over a declaration that has lost post-merge is the 2026-09-19 orphan all over again with
    # every test here still green.
    #
    # THE ENTRY IS MATCHED INSIDE THE BLOCK, never loose in the file. An unscoped search would be
    # satisfied by the same line sitting in any other hashtable in this script, which would pin a
    # declaration the parity loop never reads.
    block = re.search(
        r"(?m)^([ \t]*)\$verbatimHooks\s*=\s*@\{[ \t]*\r?\n(.*?)^\1\}[ \t]*$", body, re.S
    )
    assert block, "no $verbatimHooks block is declared"
    decl = re.search(
        r"""(?m)^[ \t]*(['"])durability_push\.sh\1\s*=\s*@\(([^)]*)\)""", block.group(2)
    )
    assert decl, "the $verbatimHooks block declares no durability_push.sh entry"
    names = re.findall(r"""(?:['"])([^'"]+)(?:['"])""", decl.group(2))
    # A FLOOR. Both names must be there; a third one added later is a correct extension and a
    # reordering means nothing, so neither should red this.
    assert {"post-commit", "post-merge"} <= set(names), (
        f"the $verbatimHooks entry for durability_push.sh must name BOTH installed hooks -- naming "
        f"fewer leaves an entire class of commit compared to nothing: {names}"
    )
    # Consumption, matched on the STRUCTURE of the loop rather than on one spelling of a subscript,
    # so a rename of the loop variable or a switch to .GetEnumerator() does not read as a regression.
    assert re.search(r"foreach\s*\(\s*\$\w+\s+in\s+\(?\s*\$verbatimHooks\b", body), (
        "-Status reports no content parity for the durability hook -- nothing iterates the "
        "$verbatimHooks declaration, so it is a second source of truth rather than the source"
    )
    assert "Get-HookPayloadHash" in body, "-Status compares no content hashes at all"


# --- the second copy of this matcher ----------------------------------------------------------
# `install-git-hooks.ps1 -Status` decides the same question in PowerShell so it can tell an operator
# whether their nominated remote is the public one. Its own comment says to keep the two in step and
# that they "must not disagree" -- which asked a reader to remember, and nothing checked. A
# disagreement is silent in the reassuring direction: -Status calls the remote safely armed while
# the hook refuses every commit, or calls it public while the hook is publishing.

# Keyed on the PATTERN, not on the code around it. An earlier version anchored on `$durUrl -match`
# and broke the moment that line became a `Where-Object` over both url sets -- reporting zero
# patterns, which the assertion below turns into a loud failure rather than a silent pass.
_STATUS_MATCHER = re.compile(r"'([^']*MEFORORG/MessageFoundry[^']*)'")


def _status_regex() -> str:
    # COMMENTS ARE STRIPPED FIRST. That file records its own history, and the history quotes the
    # patterns it replaced -- so a reader of the raw text finds the retired `MEFORORG/MessageFoundry`
    # sitting in a comment beside the live one and cannot tell which is running. Dropping `#` lines
    # is what makes the count assertion below mean "one live pattern" rather than "one mention".
    code = [
        line
        for line in INSTALLER.read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith("#")
    ]
    found = _STATUS_MATCHER.findall("\n".join(code))
    # Guard the instrument: a rename or a requote here would leave nothing to compare, and a parity
    # test over zero patterns passes.
    assert len(found) == 1, f"expected exactly one -match pattern in {INSTALLER.name}, got {found}"
    return str(found[0])


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh (PowerShell 7) not on PATH")
def test_the_installer_status_matcher_agrees_with_the_hook(tmp_path: Path) -> None:
    """The PowerShell twin must reach the same verdict as the sh hook on every URL above.

    Run through real ``pwsh`` rather than re-implemented in Python: the property under test is what
    PowerShell's ``-match`` does -- notably that it folds case, which is what the hook's
    ``tr '[:upper:]' '[:lower:]'`` buys on the other side. A Python ``re`` stand-in would be a
    different engine answering a similar question, which is how a parity test comes to agree with
    nothing.
    """
    urls = tmp_path / "urls.txt"
    urls.write_text("\n".join(PUBLIC + PRIVATE), encoding="utf-8")
    script = tmp_path / "check.ps1"
    script.write_text(
        "param($Path, $Pattern)\n"
        "foreach ($u in (Get-Content -LiteralPath $Path)) {\n"
        "  if ($u -match $Pattern) { Write-Output 'MATCH' } else { Write-Output 'NOMATCH' }\n"
        "}\n",
        encoding="utf-8",
    )
    out = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-File",
            str(script),
            "-Path",
            str(urls),
            "-Pattern",
            _status_regex(),
        ],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=True,
    ).stdout.split()

    assert len(out) == len(PUBLIC) + len(PRIVATE), out
    disagree = [
        (url, verdict, "refuse" if i < len(PUBLIC) else "accept")
        for i, (url, verdict) in enumerate(zip(PUBLIC + PRIVATE, out, strict=True))
        if (verdict == "MATCH") != (i < len(PUBLIC))
    ]
    assert not disagree, (
        "install-git-hooks.ps1 -Status and scripts/hooks/durability_push.sh disagree on "
        f"{len(disagree)} URL(s): {disagree}. They answer the same question and a divergence is "
        "silent in the reassuring direction -- fix whichever one is wrong, do not relax this test."
    )
