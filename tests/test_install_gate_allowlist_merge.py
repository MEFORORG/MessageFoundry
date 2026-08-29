# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The installer must MERGE the worktree gate's allowlist, never overwrite it (BACKLOG #1375).

THE DEFECT. install-gate.ps1 wrote the allowlist with a bare Set-Content of only THIS run's resolved
repos, and nothing between the parameter block and that write ever read the existing file. A bare run
resolves to exactly ONE repo -- the main worktree, via ``git worktree list`` -- so on a box whose
allowlist named two roots (measured live: the engine checkout AND the vault clone) a bare re-install
DROPPED one.

AND A DROPPED ROOT FAILS OPEN SILENTLY. The gate exits zero when the root count is zero, BY DESIGN,
because the allowlist doubles as the kill switch. The gate honouring an empty list is correct. The
installer manufacturing that state without saying so is the defect, and it is the shape this repo keeps
finding: a clean exit code over a wrong answer.

HOW THIS IS TESTED, AND THE GAP THAT LEAVES. install-gate.ps1 REFUSES to run inside Claude Code -- a
session that can install its own gate can uninstall it -- so the install path cannot be executed here at
all, and that constraint is deliberate and is not worked around. So the merge, the announcement and the
write are PURE, PARAMETER-FED functions, and these tests lift them out of the script by AST and run them
in isolation under ``Set-StrictMode -Version Latest``. ParseFile parses; it never runs the file, so no
line of the install path executes.

WHAT THAT CANNOT REACH: the call sites. Extracting a function proves the function is right and says
nothing about whether the install path calls it, feeds it the merge, or throws the answer away -- and
measured on this branch, it did not say so: the exact defect could be restored by changing ONE argument
at the write site with the whole suite green. So the call sites are covered by reading the PowerShell
AST (the section at the bottom), which follows VALUES through the variables and parameters that carry
them rather than matching command text, because matching text is defeated by a rename or a local alias.

WHAT NOTHING HERE REACHES: the exact bytes a real install run prints to a terminal, and the order the
operating system performs the writes in. That gap is imposed by the refusal, not chosen, and it is
stated here rather than papered over with a test-only switch.

Scope note: this is a separate file from tests/test_install_gate_wiring.py, whose module docstring scopes
it to matcher WIRING.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "hooks" / "worktree_gate.ps1"
INSTALLER = ROOT / "scripts" / "worktree" / "install-gate.ps1"

MERGE_FNS = ["Get-RootKey", "Merge-GovernedRoots"]
PRINT_FNS = ["Get-RootKey", "Show-AllowlistResult"]
WRITE_FNS = ["Get-RootKey", "Write-GovernedRoots"]


# --------------------------------------------------------------------------------- the AST harness


def _psq(value: str) -> str:
    """One PowerShell single-quoted literal. Backslashes are literal inside single quotes."""
    return "'" + value.replace("'", "''") + "'"


def _ps_array(items: list[str]) -> str:
    return "@(" + ", ".join(_psq(i) for i in items) + ")"


def _harness(specs: list[tuple[Path, list[str]]], body: str) -> str:
    """A script that EXTRACTS named functions from a .ps1 by AST and then runs ``body`` against them.

    This is a smaller step than it looks. tests/test_install_gate_wiring.py already reads
    install-gate.ps1 as text and string-splits ``$matchers = @(`` out of it; this uses the parser
    instead and then EXECUTES the region, so it tests behaviour rather than shape, needs no marker
    comments, and survives the function being moved.

    ``Set-StrictMode -Version Latest`` is scoped inside the ``& { }`` so it cannot leak into anything
    else, and it is the point: every function under test is parameter-fed and reads no script-scope
    variable, so a future edit that reaches for ``$ReposFile`` throws here instead of quietly yielding
    ``$null``.
    """
    out = ["& {", "  Set-StrictMode -Version Latest"]
    for idx, (path, names) in enumerate(specs):
        out += [
            f"  $src{idx} = {_psq(str(path))}",
            f"  $ast{idx} = [System.Management.Automation.Language.Parser]::ParseFile("
            f"$src{idx}, [ref]$null, [ref]$null)",
            f"  foreach ($n in {_ps_array(names)}) {{",
            f"    $fn = $ast{idx}.Find({{ $args[0] -is "
            f"[System.Management.Automation.Language.FunctionDefinitionAst] -and "
            f"$args[0].Name -eq $n }}, $true)",
            f'    if (-not $fn) {{ throw "not defined in $(Split-Path -Leaf $src{idx}): $n" }}',
            "    . ([scriptblock]::Create($fn.Extent.Text))",
            "  }",
        ]
    out.append(body)
    out.append("}")
    return "\n".join(out)


def _run(script: str, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    if shutil.which("pwsh") is None:
        pytest.skip("SKIP (nothing run): pwsh not on PATH")
    f = tmp_path / f"harness-{uuid.uuid4().hex}.ps1"
    f.write_text(script, encoding="utf-8")
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(f)],
        capture_output=True,
        text=True,
        timeout=180,
    )


def _ok(script: str, tmp_path: Path) -> str:
    r = _run(script, tmp_path)
    assert r.returncode == 0, f"harness failed:\n{(r.stderr + r.stdout)[:2000]}"
    return r.stdout


def _merge(
    tmp_path: Path,
    existing: list[str],
    incoming: list[str],
    *,
    remove: bool = False,
) -> dict[str, Any]:
    """Run the REAL Merge-GovernedRoots over one fixture and hand back its result as a dict."""
    flag = " -Remove" if remove else ""
    body = (
        f"  $r = Merge-GovernedRoots -Existing {_ps_array(existing)} "
        f"-Incoming {_ps_array(incoming)}{flag}\n"
        "  $r | ConvertTo-Json -Depth 6 -Compress"
    )
    out = _ok(_harness([(INSTALLER, MERGE_FNS)], body), tmp_path)
    return json.loads(out.strip().splitlines()[-1])


def _show(tmp_path: Path, result: dict[str, list[str]], *, switches: str = "") -> str:
    """Call the REAL Show-AllowlistResult on a synthetic result object."""
    fields = "; ".join(f"{k}={_ps_array(v)}" for k, v in result.items())
    body = (
        f"  $r = [pscustomobject]@{{ {fields} }}\n"
        f"  Show-AllowlistResult -Result $r -Path 'C:\\home\\.claude\\hooks\\"
        f"worktree-gate.repos.txt'{switches}"
    )
    return _ok(_harness([(INSTALLER, PRINT_FNS)], body), tmp_path)


def _result(
    *,
    lines: list[str] | None = None,
    roots: list[str] | None = None,
    added: list[str] | None = None,
    dropped: list[str] | None = None,
    missing: list[str] | None = None,
    duplicated: list[str] | None = None,
) -> dict[str, list[str]]:
    return {
        "Lines": lines or [],
        "Roots": roots or [],
        "Added": added or [],
        "Dropped": dropped or [],
        "Missing": missing or [],
        "Duplicated": duplicated or [],
    }


MF = r"C:\Repos\Code\MessageFoundry"
VAULT = r"C:\Repos\Code\MessageFoundry-vault"
HEADER = "# Primary checkouts governed by the worktree gate (scripts\\hooks\\worktree_gate.ps1)."


# ------------------------------------------------------------------------------------- pure merge


def test_a_bare_install_keeps_a_root_it_did_not_name(tmp_path: Path) -> None:
    """THE defect. A run that names one root must not remove the roots it said nothing about.

    Before the merge this was a bare Set-Content of the run's own resolved repos, so the second root
    left the file, the gate stopped governing that tree, and nothing anywhere said so -- an empty or
    shortened allowlist is indistinguishable from the deliberate kill switch.
    """
    r = _merge(tmp_path, [HEADER, MF, VAULT], [MF])
    assert r["Roots"] == [MF, VAULT], f"a root the run did not name was dropped: {r['Roots']}"
    assert r["Added"] == []
    assert MF in r["Lines"] and VAULT in r["Lines"]


def test_the_measured_two_root_box_does_not_lose_a_root(tmp_path: Path) -> None:
    """The live shape this item was filed from: the engine checkout plus the vault clone, and a bare
    run that resolves to the engine checkout alone."""
    r = _merge(tmp_path, [MF, VAULT], [MF])
    assert r["Roots"] == [MF, VAULT]
    assert r["Added"] == [], "the root this run named is already governed; nothing to add"
    assert r["Lines"] == [MF, VAULT], "an unchanged file must be written back byte-identical"


def test_case_and_slash_variants_are_one_root_and_the_existing_spelling_survives(
    tmp_path: Path,
) -> None:
    """One root, spelled differently, is one root -- and the operator's spelling is not rewritten.

    The gate quotes the spelling back in its deny messages, so silently recasing a path changes what a
    reader sees for no reason at all.
    """
    r = _merge(tmp_path, [MF], ["c:/repos/code/messagefoundry/"])
    assert r["Added"] == [], "a case/slash variant of a governed root is not a new root"
    assert r["Roots"] == [MF], f"the existing spelling was rewritten: {r['Roots']}"
    assert r["Lines"] == [MF]


def test_a_root_that_no_longer_exists_on_disk_is_still_kept(tmp_path: Path) -> None:
    """Nothing resolves, stats or git-checks an existing line.

    A root is often listed precisely BECAUSE its checkout is gone or its drive is unmounted, and
    resolving one could throw and take the whole install down -- or drop it.
    """
    gone = r"Z:\gone\MessageFoundry-archived"
    r = _merge(tmp_path, [gone, MF], [MF])
    assert gone in r["Roots"], f"a root on a missing drive was dropped: {r['Roots']}"


def test_comments_and_blank_lines_survive_verbatim_and_are_not_roots(tmp_path: Path) -> None:
    """This installer does not tidy lines it was not asked to touch.

    That keeps a hand-written comment beside a root alive -- the one loss a regenerate-the-header
    design concedes -- and it keeps the contract to one sentence.
    """
    existing = [HEADER, "", "  # ops: retired 2026-08, keep the line", MF, ""]
    r = _merge(tmp_path, existing, [VAULT])
    assert r["Lines"][: len(existing)] == existing, (
        f"existing lines were not preserved verbatim in file order: {r['Lines']}"
    )
    assert r["Lines"][-1] == VAULT, "an added root goes at the end"
    assert r["Roots"] == [MF, VAULT], "comments and blanks must never count as roots"
    assert r["Added"] == [VAULT]


def test_two_existing_lines_naming_one_root_are_both_kept_and_reported(tmp_path: Path) -> None:
    """Collapsing them removes no governance, so it is not this defect -- and it removes a line the
    operator wrote and was not asked to remove. Keep both, say so, and let the gate pay one string
    compare."""
    r = _merge(tmp_path, [MF, "c:/repos/code/messagefoundry"], [VAULT])
    assert r["Lines"][:2] == [MF, "c:/repos/code/messagefoundry"], (
        "neither duplicate line may be removed"
    )
    assert r["Duplicated"] == ["c:/repos/code/messagefoundry"], (
        f"the second spelling must be reported: {r['Duplicated']}"
    )


def test_removing_a_root_leaves_the_others_and_keeps_the_comments(tmp_path: Path) -> None:
    """-Uninstall -Repo <path> narrows the allowlist and touches nothing else."""
    existing = [HEADER, "# ops note", MF, VAULT]
    r = _merge(tmp_path, existing, ["C:/Repos/Code/MessageFoundry-vault/"], remove=True)
    assert r["Dropped"] == [VAULT]
    assert r["Roots"] == [MF]
    assert r["Missing"] == []
    assert r["Lines"] == [HEADER, "# ops note", MF], (
        f"removal must take the named root and nothing else: {r['Lines']}"
    )


def test_removing_a_root_that_is_not_listed_reports_it_and_changes_nothing(
    tmp_path: Path,
) -> None:
    """The unmatched value is REPORTED, so the caller can refuse the whole removal.

    A partial removal leaves the operator's model of which roots are governed wrong, which is the exact
    class of defect this item is about.
    """
    existing = [HEADER, MF, VAULT]
    typo = r"C:\Repos\Code\Typo"
    r = _merge(tmp_path, existing, [typo], remove=True)
    assert r["Missing"] == [typo]
    assert r["Dropped"] == []
    assert r["Lines"] == existing, f"nothing may change while a value is unmatched: {r['Lines']}"
    assert r["Roots"] == [MF, VAULT]


def test_repo_a_a_writes_one_line(tmp_path: Path) -> None:
    """PowerShell binds a comma-separated argument to a [string[]] parameter as two elements, so
    ``-Repo a,b`` really does govern two repos -- and ``-Repo a,a`` must still write one line."""
    r = _merge(tmp_path, [], [MF, MF])
    assert r["Added"] == [MF]
    assert r["Roots"] == [MF]
    assert r["Lines"].count(MF) == 1, f"a repeated -Repo value was written twice: {r['Lines']}"


def test_a_fresh_allowlist_gets_the_header_and_an_existing_one_keeps_its_own(
    tmp_path: Path,
) -> None:
    """The header is emitted only when there is no file to merge into.

    Re-emitting it on every run is what destroys a hand-written comment, and it is why the header lives
    behind this condition rather than at the top of the writer.
    """
    fresh = _merge(tmp_path, [], [MF])
    assert fresh["Lines"][0] == HEADER
    assert any("MERGES this list" in ln for ln in fresh["Lines"]), (
        "a fresh header must state that a run adds rather than replaces"
    )
    assert any("-Uninstall -Repo" in ln for ln in fresh["Lines"]), (
        "a fresh header must name the command that stops governing one root"
    )
    assert fresh["Lines"][-1] == MF

    merged = _merge(tmp_path, ["# my own header", MF], [VAULT])
    assert merged["Lines"][0] == "# my own header"
    assert HEADER not in merged["Lines"], "a merge must not staple a second header on"


def test_the_installer_key_is_never_coarser_than_the_gates(tmp_path: Path) -> None:
    """The one-directional agreement control.

    Get-RootKey deliberately omits the GetFullPath step the gate's Get-ComparablePath performs, because
    it runs over lines naming checkouts that may be gone. The omission can only make this key FINER than
    the gate's, never coarser -- and that asymmetry is the whole safety argument. Installer-COARSER is
    the shape that silently drops a root, and in ``-Remove`` mode it un-governs a root THE OPERATOR DID
    NOT NAME; installer-FINER only ever writes a harmless duplicate line. Measured: ``C:\\A\\..\\B``
    folds to ``c:/b`` under the gate and stays ``c:/a/../b`` here.

    So the assertion is an IMPLICATION, not an equality: installer-same-root implies gate-same-root, and
    the converse is allowed to differ. Both normalizers are EXTRACTED from their own scripts rather than
    restated here -- a restated predicate is a third predicate, and a disagreement between two
    predicates is what this whole area keeps producing.

    THE CORPUS CARRIES THE COUNTEREXAMPLE THIS INVARIANT WAS ASSERTED NOT TO HAVE. Measured 2026-08-29:
    a bare ``TrimEnd('/')`` erased the separator that tells a drive ROOT from a drive-RELATIVE path, so
    ``C:\\`` and ``C:`` both keyed ``c:`` while the gate resolves them to the root of drive C and to the
    CURRENT DIRECTORY on drive C. An invariant whose corpus omits its own counterexample is a sentence,
    not a control, so the pair is here and pinned by name below.

    THE DOMAIN IS TRIMMED LINES, and that is asserted rather than assumed. Every caller trims before it
    compares: Merge-GovernedRoots trims each existing line and each incoming value, Write-GovernedRoots
    trims each line it reads back, and the gate trims each line before Get-ComparablePath. A
    leading-space spelling is therefore a pair neither normalizer is ever asked about, and putting one
    in this corpus would test the harness rather than the code.
    """
    if os.name == "nt":
        corpus = [
            MF,
            MF + "\\",
            "c:/repos/code/messagefoundry",
            "C:/Repos/Code/MessageFoundry//",
            r"C:\Repos\Code\Other\..\MessageFoundry",
            VAULT,
            r"\\server\share\repo",
            "//server/share/repo",
            "\\\\server\\share\\repo\\",
            "C:",  # drive-RELATIVE: the gate resolves this to the current directory on drive C
            "C:\\",  # the drive ROOT, which is a different place
            "C:/",
        ]
    else:
        corpus = [
            "/srv/code/messagefoundry",
            "/srv/code/messagefoundry/",
            "/SRV/code/MessageFoundry",
            "/srv/code/other/../messagefoundry",
            "/srv/code/messagefoundry-vault",
        ]

    assert all(c == c.strip() for c in corpus), (
        "the corpus must hold TRIMMED lines. Both callers trim before they compare, so an untrimmed "
        "pair asks these two functions a question neither is ever asked in production."
    )

    body = (
        f"  $corpus = {_ps_array(corpus)}\n"
        "  $rows = foreach ($a in $corpus) { foreach ($b in $corpus) {\n"
        "    [pscustomobject]@{\n"
        "      a  = $a\n"
        "      b  = $b\n"
        "      ik = ((Get-RootKey $a) -eq (Get-RootKey $b))\n"
        "      ga = (Get-ComparablePath $a)\n"
        "      gb = (Get-ComparablePath $b)\n"
        "    }\n"
        "  } }\n"
        "  @($rows) | ConvertTo-Json -Depth 4 -Compress"
    )
    out = _ok(
        _harness(
            [
                (INSTALLER, ["Get-RootKey"]),
                (GATE, ["Get-FullPathRaw", "Get-ComparablePath"]),
            ],
            body,
        ),
        tmp_path,
    )
    rows = json.loads(out.strip().splitlines()[-1])

    coarser = [r for r in rows if r["ik"] and (r["ga"] != r["gb"] or not r["ga"] or not r["gb"])]
    assert not coarser, (
        "the installer's key called two paths the SAME root where the gate calls them different "
        "roots. That direction silently drops a root from the allowlist.\n"
        + "\n".join(
            f"  {c['a']!r} vs {c['b']!r} -> gate {c['ga']!r} vs {c['gb']!r}" for c in coarser
        )
    )

    # Guard the guard. An implication over a corpus that agrees on nothing, or that contains no
    # asymmetric pair, proves nothing at all.
    assert any(r["ik"] and r["a"] != r["b"] for r in rows), (
        "the corpus contains no two DIFFERENT spellings the installer folds together -- the "
        "implication is vacuous"
    )
    assert any(not r["ik"] and r["ga"] == r["gb"] for r in rows), (
        "the corpus contains no pair where the gate is coarser than the installer, so the direction "
        "under test is never exercised"
    )

    if os.name == "nt":
        # Pin the measured counterexample BY NAME, so a future corpus edit cannot quietly drop the one
        # pair that made this invariant false. The assertion above would go green again the moment the
        # pair left the list, and green would mean "not asked" rather than "does not happen".
        drive = [r for r in rows if {r["a"], r["b"]} == {"C:", "C:\\"}]
        assert len(drive) == 2, f"the drive-root pair is not in the corpus: {len(drive)} row(s)"
        assert all(not r["ik"] for r in drive), (
            "the installer keys `C:` and `C:\\` as ONE root. The gate keys them as two -- the drive "
            "root against the current directory on that drive -- so this is installer-COARSER, and in "
            "-Remove mode it un-governs a root the operator did not name."
        )
        assert all(r["ga"] != r["gb"] for r in drive), (
            "the gate now folds `C:` and `C:\\` too, so this pair no longer exercises the direction "
            "under test and a new counterexample is needed"
        )


def test_the_extraction_harness_fails_loudly_on_a_missing_function(tmp_path: Path) -> None:
    """Guard the guard. Without this, renaming a function makes every test above pass while testing
    nothing: the extraction would find nothing, define nothing, and the body would never run."""
    r = _run(_harness([(INSTALLER, ["Merge-GovernedRootsXX"])], "  'never'"), tmp_path)
    assert r.returncode != 0, (
        f"the harness accepted a function name that does not exist:\n{r.stdout}\n{r.stderr}"
    )
    assert "Merge-GovernedRootsXX" in (r.stderr + r.stdout), (
        "the failure must name the function it could not find"
    )


# ------------------------------------------------------------------------------ pure announcement


def test_a_removing_result_prints_narrowing_and_names_each_removed_root(tmp_path: Path) -> None:
    """A removal is a change of posture, and the removed root is ungoverned the instant the file is
    written. Nothing else on the box reports that, so this line has to."""
    out = _show(
        tmp_path,
        _result(lines=[MF], roots=[MF], dropped=[VAULT]),
        switches=" -BackupPath 'C:\\home\\.claude\\hooks\\worktree-gate.repos.txt.bak' -Narrowed",
    )
    assert "allowlist NARROWED" in out
    assert f"removed   : {VAULT}" in out
    assert "1 root(s) REMOVED, 1 still governed" in out
    assert "UNGOVERNED the instant the file is written" in out
    assert f"governing : {MF}" in out
    assert "worktree-gate.repos.txt.bak" in out
    assert "The hook wiring, the installed gate and every other root are untouched." in out


def test_a_merge_only_result_does_not_print_narrowing(tmp_path: Path) -> None:
    """NEGATIVE CONTROL. The loud arm must be discriminating, not constant -- a line that appears on
    every run is one readers learn to skip, which is how the real one goes unnoticed."""
    out = _show(tmp_path, _result(lines=[MF, VAULT], roots=[MF, VAULT], added=[VAULT]))
    assert "NARROWED" not in out
    assert "removed" not in out
    assert "UNGOVERNED" not in out
    assert "(2 root(s); 1 added by this run)" in out
    assert f"governing : {VAULT}  (ADDED by this run)" in out
    assert f"governing : {MF}\n" in out, "a root this run did not add carries no ADDED marker"
    assert "allowlist CREATED" not in out, "no file was created here"


def test_a_created_allowlist_says_so_on_the_count_line(tmp_path: Path) -> None:
    """A fresh box is a different event from a merge, and it folds into the line that was going to be
    printed anyway rather than earning a banner of its own."""
    out = _show(
        tmp_path,
        _result(lines=[MF], roots=[MF], added=[MF]),
        switches=" -Created",
    )
    assert "(1 root(s); 1 added by this run) -- allowlist CREATED" in out


def test_the_count_line_counts_distinct_roots_not_allowlist_lines(tmp_path: Path) -> None:
    """Two lines naming one root are BOTH kept by design, so counting lines over-reports here.

    This is the one line an operator reads to confirm nothing was lost, so it must not answer "2
    root(s)" about one governed tree. The error can only ever overstate governance -- it could not hide
    a drop -- which is why it is a nit and not the defect, and why it is still worth fixing.
    """
    dupe = "c:/repos/code/messagefoundry"
    out = _show(
        tmp_path,
        _result(lines=[MF, dupe], roots=[MF, dupe], duplicated=[dupe]),
    )
    assert "(1 root(s); 0 added by this run)" in out, (
        f"two spellings of one root were counted as two roots:\n{out}"
    )
    # Both lines are still printed and still reported: the count changes, the contract does not.
    assert f"governing : {MF}" in out and f"governing : {dupe}" in out
    assert "1 line(s) name a root already listed above" in out


def test_a_result_with_no_roots_left_warns_that_the_gate_governs_nothing(tmp_path: Path) -> None:
    """The most important line in the change. Emptying the allowlist IS the kill switch, reached one
    root at a time -- a narrow act with an unscoped consequence. It warns and proceeds: refusing a
    deliberate act whose end state is one command away is paternalism."""
    out = _show(
        tmp_path,
        _result(lines=[HEADER], roots=[], dropped=[MF, VAULT]),
        switches=" -Narrowed",
    )
    assert "the allowlist now names NO root" in out
    assert "the gate governs NOTHING" in out
    assert "same state as -Uninstall" in out
    assert "2 root(s) REMOVED, 0 still governed" in out


def test_the_empty_warning_is_absent_while_roots_remain(tmp_path: Path) -> None:
    """NEGATIVE CONTROL for the warning above."""
    out = _show(
        tmp_path,
        _result(lines=[MF], roots=[MF], dropped=[VAULT]),
        switches=" -Narrowed",
    )
    assert "governs NOTHING" not in out
    assert "names NO root" not in out


def test_a_was_off_allowlist_is_announced_when_a_run_turns_it_back_on(tmp_path: Path) -> None:
    """An allowlist that existed and named no root meant the gate governed nothing on this box. That
    fires rarely, so it never becomes the constant line readers skip."""
    on = _show(tmp_path, _result(lines=[MF], roots=[MF], added=[MF]), switches=" -WasOff")
    assert "WAS OFF" in on and "This run turns it on." in on
    off = _show(tmp_path, _result(lines=[MF], roots=[MF], added=[MF]))
    assert "WAS OFF" not in off, "the WAS OFF line must be discriminating, not constant"


# ------------------------------------------------------------------------------------- the writer


def test_the_writer_backs_up_the_previous_content_before_every_write(tmp_path: Path) -> None:
    """One .bak, exactly one write old BY CONSTRUCTION.

    Backing up only when the content changed sounds thriftier and is what makes a .bak read as a
    recovery point two changes back. Copying unconditionally costs nothing.
    """
    target = tmp_path / "worktree-gate.repos.txt"
    body = (
        f"  $p = {_psq(str(target))}\n"
        f"  $b1 = Write-GovernedRoots -Path $p -Lines {_ps_array([MF])}\n"
        f"  $b2 = Write-GovernedRoots -Path $p -Lines {_ps_array([VAULT])}\n"
        '  Write-Output "first=$b1"\n'
        '  Write-Output "second=$b2"'
    )
    out = _ok(_harness([(INSTALLER, WRITE_FNS)], body), tmp_path)

    assert "first=\n" in out or out.splitlines()[0] == "first=", (
        f"there was no file to back up on the first write, so no backup path may be returned:\n{out}"
    )
    assert f"second={target}.bak" in out
    assert target.read_text(encoding="utf-8").strip() == VAULT
    bak = Path(str(target) + ".bak")
    assert bak.read_text(encoding="utf-8").strip() == MF, (
        "the backup must hold the content as it was BEFORE the most recent write"
    )
    assert not list(tmp_path.glob("worktree-gate.repos.txt.tmp-*")), (
        "the temp file must be moved into place, not left behind"
    )


def test_the_writer_refuses_when_the_file_reads_back_wrong(tmp_path: Path) -> None:
    """A WRITE THAT DID NOT LAND must be loud. That is the case the read-back catches, and all of it.

    This holds the target open with FileShare.Read, which is what a competing writer looks like from
    here: the copy and the temp file succeed, the move over the locked file does not land, and the
    read-back sees the old content. Without the check the run would report a governed root the file does
    not carry.

    The case it does NOT catch has its own test directly below -- two installers that both read before
    either writes, where the write lands, the read-back passes, and a root disappears anyway.
    """
    target = tmp_path / "worktree-gate.repos.txt"
    target.write_text(MF + "\n", encoding="utf-8")
    body = (
        f"  $p = {_psq(str(target))}\n"
        "  $fs = [System.IO.File]::Open($p, [System.IO.FileMode]::Open, "
        "[System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)\n"
        "  try {\n"
        f"    try {{ $null = Write-GovernedRoots -Path $p -Lines {_ps_array([MF, VAULT])}\n"
        "           Write-Output 'NO THROW' }\n"
        '    catch { Write-Output "THREW: $($_.Exception.Message)" }\n'
        "  } finally { $fs.Dispose() }"
    )
    out = _ok(_harness([(INSTALLER, WRITE_FNS)], body), tmp_path)

    assert "NO THROW" not in out, (
        f"the write did not land and the writer said nothing about it:\n{out}"
    )
    assert "THREW:" in out, f"expected a refusal:\n{out}"
    assert "reading it back does not show" in out
    assert VAULT in out, f"the refusal must name the root that is missing from the file:\n{out}"
    assert "re-run this command" in out
    assert target.read_text(encoding="utf-8").strip() == MF, "the old content is still there"

    # THE MESSAGE MUST NOT LIE ABOUT THE REST OF THE BOX. It used to end "Nothing else was changed",
    # which was false on the install path: the gate copy ran first, so by the time this could fire the
    # machine-global gate had already been overwritten and, on a first install, no hook wiring had been
    # written at all. The claim below is kept true by the call-site ORDER, which is pinned separately in
    # test_the_gate_copy_and_the_wiring_happen_after_the_allowlist_write.
    assert "Nothing else was changed" not in out, (
        f"the refusal still claims nothing else changed:\n{out}"
    )
    assert "Neither the gate script nor the hook wiring has been written yet." in out, (
        f"the refusal must say what state the box is actually in:\n{out}"
    )
    assert f"{target}.bak" in out, (
        f"the refusal must name the backup the operator can read the old list out of:\n{out}"
    )


def test_two_installers_that_both_read_first_still_lose_a_root_silently(tmp_path: Path) -> None:
    """THE RESIDUAL RACE, RUN RATHER THAN DESCRIBED. The read-back does not make every lost update loud.

    Two installers read the same allowlist, each merges its own repo into what it read, and each writes.
    Both writes land. Both read-backs pass, because each file really does carry the roots the run that
    wrote it intended. And the first installer's root is gone, with nothing anywhere saying so.

    This is the honest boundary of the read-back, and it is a test rather than a sentence in a comment
    because a comment that overclaims here is exactly the compensating-control-on-a-false-premise shape
    the repo forbids. Closing it needs a lock or a compare-and-swap against the content the merge was
    computed from, which is a design change and not this item; pinning it stops the claim drifting back.
    """
    target = tmp_path / "worktree-gate.repos.txt"
    other = r"C:\Repos\Code\Third"
    body = (
        f"  $p = {_psq(str(target))}\n"
        f"  Set-Content -LiteralPath $p -Value {_ps_array([MF])} -Encoding utf8\n"
        # Both installers read the SAME starting content, before either has written.
        "  $seen_a = @(Get-Content -LiteralPath $p)\n"
        "  $seen_b = @(Get-Content -LiteralPath $p)\n"
        f"  $a = Merge-GovernedRoots -Existing $seen_a -Incoming {_ps_array([VAULT])}\n"
        f"  $b = Merge-GovernedRoots -Existing $seen_b -Incoming {_ps_array([other])}\n"
        "  $null = Write-GovernedRoots -Path $p -Lines $a.Lines\n"
        "  try { $null = Write-GovernedRoots -Path $p -Lines $b.Lines; Write-Output 'B: NO THROW' }\n"
        '  catch { Write-Output "B: THREW: $($_.Exception.Message)" }'
    )
    out = _ok(
        _harness(
            [(INSTALLER, ["Get-RootKey", "Merge-GovernedRoots", "Write-GovernedRoots"])], body
        ),
        tmp_path,
    )

    assert "B: NO THROW" in out, (
        "the second write was refused, so the read-back DOES catch this shape and this test is stale "
        f"-- and the comment in Write-GovernedRoots should be widened again:\n{out}"
    )
    final = target.read_text(encoding="utf-8").splitlines()
    assert other in final, "the second installer's own root must be there -- that is why it passed"
    assert VAULT not in final, (
        "the first installer's root survived, so this fixture no longer reproduces the lost update "
        f"and the limitation it documents is unproven:\n{final}"
    )


# -------------------------------------------------------------------------------- the source text
# As far toward "correct function, never called" as the CLAUDECODE refusal honestly allows.
#
# WHY SOURCE ASSERTIONS ARE LEGITIMATE HERE, AND WHERE THEY STOP BEING SO. install-gate.ps1 refuses to
# run inside Claude Code, so the install path cannot be EXECUTED -- not by these tests, not by a session,
# not ever. Reading the source is the only instrument left, and the alternative is no control at all on
# the call sites: with the pure functions covered and the call sites uncovered, the exact #1375 defect
# could be restored by changing ONE argument at the write site with all 37 tests still green.
#
# WHAT IS NOT LEGITIMATE is a source assertion loose enough that a rename or a local alias walks past it.
# Two of the checks below used to match COMMAND TEXT -- one required the literal "$ReposFile", the other
# the literal ".bak" -- and each was defeated by naming the same value something else, which is exactly
# how Write-GovernedRoots already refers to its own backup. So these read the PowerShell AST and follow
# VALUES through the variables and parameters that carry them. Where they name something they name a
# parameter or a property, never a spelling in a line of text.


def _ast_facts(tmp_path: Path) -> dict[str, Any]:
    """Parse install-gate.ps1 and hand back the shape of it: functions, if-blocks, assignments, calls.

    ParseFile parses; it never runs the file, so no line of the install path executes here either.
    """
    script = r"""
& {
  Set-StrictMode -Version Latest
  $src = __SRC__
  $ast = [System.Management.Automation.Language.Parser]::ParseFile($src, [ref]$null, [ref]$null)

  $varsIn = {
    param($node)
    if ($null -eq $node) { return @() }
    @($node.FindAll({ $args[0] -is [System.Management.Automation.Language.VariableExpressionAst] }, $true) |
        ForEach-Object { $_.VariablePath.UserPath } | Sort-Object -Unique)
  }

  $funcs = @(foreach ($f in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
    $ps = @()
    if ($f.Parameters) { $ps = @($f.Parameters) }
    elseif ($f.Body -and $f.Body.ParamBlock) { $ps = @($f.Body.ParamBlock.Parameters) }
    [pscustomobject]@{
      name   = $f.Name
      line   = $f.Extent.StartLineNumber
      start  = $f.Extent.StartOffset
      end    = $f.Extent.EndOffset
      text   = $f.Extent.Text
      params = @($ps | ForEach-Object { $_.Name.VariablePath.UserPath })
    }
  })

  $ifs = @(foreach ($i in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.IfStatementAst] }, $true)) {
    [pscustomobject]@{
      cond  = $i.Clauses[0].Item1.Extent.Text
      line  = $i.Extent.StartLineNumber
      start = $i.Extent.StartOffset
      end   = $i.Extent.EndOffset
    }
  })

  $assigns = @(foreach ($a in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)) {
    $lhs = $null
    if ($a.Left -is [System.Management.Automation.Language.VariableExpressionAst]) { $lhs = $a.Left.VariablePath.UserPath }
    $rhsCmd = $null
    $firstCmd = $a.Right.Find({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)
    if ($firstCmd) { $rhsCmd = $firstCmd.GetCommandName() }
    [pscustomobject]@{
      lhs      = $lhs
      line     = $a.Extent.StartLineNumber
      start    = $a.Extent.StartOffset
      rhsStart = $a.Right.Extent.StartOffset
      rhsEnd   = $a.Right.Extent.EndOffset
      rhsText  = $a.Right.Extent.Text
      rhsCmd   = $rhsCmd
      rhsVars  = @(& $varsIn $a.Right)
    }
  })

  $cmds = @(foreach ($c in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)) {
    $els = @($c.CommandElements)
    $bound = [System.Collections.Generic.List[object]]::new()
    $i = 1
    while ($i -lt $els.Count) {
      $e = $els[$i]
      $pname = $null
      $argAst = $null
      if ($e -is [System.Management.Automation.Language.CommandParameterAst]) {
        $pname = $e.ParameterName
        $argAst = $e.Argument
        if (($null -eq $argAst) -and (($i + 1) -lt $els.Count) -and
            -not ($els[$i + 1] -is [System.Management.Automation.Language.CommandParameterAst])) {
          $argAst = $els[$i + 1]
          $i++
        }
      } else {
        $argAst = $e
      }
      $isMember = $argAst -is [System.Management.Automation.Language.MemberExpressionAst]
      $bound.Add([pscustomobject]@{
        param   = $pname
        text    = $(if ($argAst) { $argAst.Extent.Text } else { $null })
        type    = $(if ($argAst) { $argAst.GetType().Name } else { $null })
        member  = $(if ($isMember) { $argAst.Member.Extent.Text } else { $null })
        baseVar = $(if ($isMember -and ($argAst.Expression -is [System.Management.Automation.Language.VariableExpressionAst])) { $argAst.Expression.VariablePath.UserPath } else { $null })
        vars    = @(& $varsIn $argAst)
      })
      $i++
    }
    [pscustomobject]@{
      name  = $c.GetCommandName()
      line  = $c.Extent.StartLineNumber
      start = $c.Extent.StartOffset
      end   = $c.Extent.EndOffset
      text  = $c.Extent.Text
      vars  = @(& $varsIn $c)
      bound = @($bound)
    }
  })

  [pscustomobject]@{
    functions   = $funcs
    ifs         = $ifs
    assignments = $assigns
    commands    = $cmds
  } | ConvertTo-Json -Depth 8 -Compress
}
""".replace("__SRC__", _psq(str(INSTALLER)))
    return json.loads(_ok(script, tmp_path).strip().splitlines()[-1])


# ------------------------------------------------------------------- reading those facts, precisely


def _fn(facts: dict[str, Any], name: str) -> dict[str, Any]:
    hits = [f for f in facts["functions"] if f["name"] == name]
    assert len(hits) == 1, f"expected exactly one {name}, found {len(hits)}"
    return hits[0]


def _if_block(facts: dict[str, Any], condition: str) -> dict[str, Any]:
    hits = [b for b in facts["ifs"] if b["cond"].strip() == condition]
    assert len(hits) == 1, (
        f"expected exactly one `if ({condition})` block, found {len(hits)} -- the region every "
        "assertion below is scoped to cannot be identified"
    )
    return hits[0]


def _within(item: dict[str, Any], block: dict[str, Any]) -> bool:
    return bool(block["start"] <= item["start"] < block["end"])


def _arg(cmd: dict[str, Any], name: str) -> dict[str, Any] | None:
    """One BOUND parameter of a call, by parameter name. PowerShell matches these case-insensitively."""
    for b in cmd["bound"]:
        if b["param"] and b["param"].lower() == name.lower():
            return b
    return None


def _arg_vars(cmd: dict[str, Any], name: str) -> list[str]:
    b = _arg(cmd, name)
    return list(b["vars"]) if b else []


def _install_path(facts: dict[str, Any]) -> list[dict[str, Any]]:
    """Every command a real install run reaches: script scope, past -Status and past -Uninstall.

    Scoped by AST extent rather than by line number so moving code cannot silently change what is under
    test, and so the -Status block's own allowlist read is not mistaken for the install path's.
    """
    status = _if_block(facts, "$Status")
    uninstall = _if_block(facts, "$Uninstall")
    out = [
        c
        for c in facts["commands"]
        if not any(f["start"] <= c["start"] < f["end"] for f in facts["functions"])
        and not _within(c, status)
        and not _within(c, uninstall)
    ]
    # Guard the guard. If this region is computed wrongly, every assertion built on it passes over an
    # empty or wrong set -- the vacuous-control shape this file exists to refuse.
    names = {c["name"] for c in out}
    assert {
        "Write-GovernedRoots",
        "Show-AllowlistResult",
        "Write-Settings",
        "Copy-Item",
    } <= names, (
        f"the install-path region does not contain the install path's own calls: {sorted(names)}"
    )
    return out


def _one(cmds: list[dict[str, Any]], name: str, what: str) -> dict[str, Any]:
    hits = [c for c in cmds if c["name"] == name]
    assert len(hits) == 1, f"expected exactly one {name} call {what}, found {len(hits)}"
    return hits[0]


def _merge_var(write: dict[str, Any]) -> str:
    """The variable the writer's -Lines comes off. Named once so the tests that build on the wiring
    fail with the wiring's own message instead of a misleading downstream one."""
    lines = _arg(write, "Lines")
    assert lines is not None and lines["baseVar"], (
        "the writer's -Lines is not a property of a variable, so there is no merge result reaching it "
        "-- see test_the_install_path_writes_the_merge_result_not_just_this_runs_repos.\n"
        f"  got: {lines['text'] if lines else None}"
    )
    return str(lines["baseVar"])


def _scope_at(facts: dict[str, Any], offset: int) -> str:
    """The innermost function containing an offset, or '' for script scope."""
    best, best_span = "", None
    for f in facts["functions"]:
        if f["start"] <= offset < f["end"]:
            span = f["end"] - f["start"]
            if best_span is None or span < best_span:
                best, best_span = f["name"], span
    return best


def _locals_of(facts: dict[str, Any]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {f["name"]: set(f["params"]) for f in facts["functions"]}
    for a in facts["assignments"]:
        scope = _scope_at(facts, a["start"])
        if scope and a["lhs"]:
            out[scope].add(a["lhs"])
    return out


def _binding(locals_of: dict[str, set[str]], scope: str, var: str) -> tuple[str, str]:
    """Which binding a name refers to: the enclosing function's own, or the script's."""
    return (scope, var) if scope and var in locals_of.get(scope, set()) else ("", var)


def _declared(fn: dict[str, Any], name: str | None) -> str | None:
    """Resolve a written parameter name to the one the function declares (PowerShell allows prefixes)."""
    if not name:
        return None
    lo = name.lower()
    exact = [p for p in fn["params"] if p.lower() == lo]
    if exact:
        return exact[0]
    pref = [p for p in fn["params"] if p.lower().startswith(lo)]
    return pref[0] if len(pref) == 1 else None


def _taint(facts: dict[str, Any], seeds: set[tuple[str, str]]) -> set[tuple[str, str]]:
    """Every (scope, variable) that can be holding one of the seeded VALUES.

    Follows two hops to a fixed point: an assignment whose right-hand side reads a tainted variable,
    and an argument passed into a function DEFINED IN THIS SCRIPT, which taints the parameter it binds.
    Scope-qualified, so ``$Path`` inside one function is not confused with ``$Path`` inside another.

    This is what replaces matching command TEXT. A rename, a local alias, or a second hop through a
    third variable all keep the value, and all keep the taint.
    """
    locals_of = _locals_of(facts)
    fns = {f["name"]: f for f in facts["functions"]}
    taint = set(seeds)
    changed = True
    while changed:
        changed = False
        for a in facts["assignments"]:
            if not a["lhs"]:
                continue
            scope = _scope_at(facts, a["start"])
            target = _binding(locals_of, scope, a["lhs"])
            if target in taint:
                continue
            if any(_binding(locals_of, scope, v) in taint for v in a["rhsVars"]):
                taint.add(target)
                changed = True
        for c in facts["commands"]:
            fn = fns.get(c["name"] or "")
            if not fn:
                continue
            scope = _scope_at(facts, c["start"])
            for idx, b in enumerate(c["bound"]):
                if not any(_binding(locals_of, scope, v) in taint for v in b["vars"]):
                    continue
                name = _declared(fn, b["param"])
                if name is None and b["param"] is None and idx < len(fn["params"]):
                    name = fn["params"][idx]
                if name and (fn["name"], name) not in taint:
                    taint.add((fn["name"], name))
                    changed = True
    return taint


def _touches(facts: dict[str, Any], cmd: dict[str, Any], taint: set[tuple[str, str]]) -> bool:
    locals_of = _locals_of(facts)
    scope = _scope_at(facts, cmd["start"])
    return any(_binding(locals_of, scope, v) in taint for v in cmd["vars"])


# ------------------------------------------------------------ the install path's own wiring (#1375)


def test_the_install_path_writes_the_merge_result_not_just_this_runs_repos(tmp_path: Path) -> None:
    """THE #1375 DEFECT AT ITS CALL SITE -- the one thing the pure-function tests above cannot see.

    Merging correctly and then writing something else is the same lost root as never merging at all.
    Measured on this branch: changing the install path's write from ``-Lines $result.Lines`` to
    ``-Lines @($resolved)`` restored the defect exactly, and the whole suite stayed green -- the merge
    was computed and thrown away, and a two-root box lost the vault root on the next bare install.

    So this follows the VALUE: the argument must be the merge result's own ``Lines`` property, and the
    variable it comes from must be assigned from Merge-GovernedRoots. Renaming ``$result`` is fine.
    Handing the writer this run's repos, a filtered copy, or any other property is not.
    """
    facts = _ast_facts(tmp_path)
    write = _one(_install_path(facts), "Write-GovernedRoots", "on the install path")

    lines = _arg(write, "Lines")
    assert lines is not None, "the install path's write passes no -Lines at all"
    assert lines["type"] == "MemberExpressionAst" and lines["member"] == "Lines", (
        "the install path does not write the MERGE RESULT. -Lines must be the result object's own "
        "Lines property; anything else writes a list the merge did not produce, which is the #1375 "
        f"defect however correct the merge above it is.\n  got: {lines['text']} ({lines['type']})"
    )
    var = lines["baseVar"]
    assert var, f"-Lines is a property of something other than a variable: {lines['text']}"

    assigns = [a for a in facts["assignments"] if a["lhs"] == var]
    assert assigns, f"nothing in the script assigns ${var}, so -Lines reads an empty value"
    for a in assigns:
        assert a["rhsCmd"] == "Merge-GovernedRoots", (
            f"${var} reaches the writer but is not the merge's output (line {a['line']}: "
            f"{a['rhsText'][:120]})"
        )


def test_the_install_path_reads_the_existing_allowlist_and_will_not_read_it_quietly(
    tmp_path: Path,
) -> None:
    """A merge with nothing to merge INTO is an overwrite wearing a merge's name.

    Two mutations this catches, both of which left the suite green before it existed: deleting the read,
    and downgrading it to ``-ErrorAction SilentlyContinue``. The second is the nastier one and the
    installer's own comment already names it -- a read that fails quietly turns an UNREADABLE allowlist
    into an EMPTY one, and an empty one is how the gate is switched off.

    The allowlist is identified by the variable the writer is given as ``-Path``, not by the name
    ``$ReposFile``, and the read is tied to the merge by EXTENT: the value the merge is handed must be
    the one this read produced.
    """
    facts = _ast_facts(tmp_path)
    path = _install_path(facts)
    write = _one(path, "Write-GovernedRoots", "on the install path")

    target = _arg_vars(write, "Path")
    assert len(target) == 1, f"the writer's -Path is not one variable: {_arg(write, 'Path')}"
    allowlist = target[0]

    reads = [
        c for c in path if c["name"] == "Get-Content" and allowlist in _arg_vars(c, "LiteralPath")
    ]
    assert reads, (
        "the install path never reads the existing allowlist, so the merge has nothing to merge into "
        "and the write is a plain overwrite -- BACKLOG #1375 exactly"
    )
    for r in reads:
        ea = _arg(r, "ErrorAction")
        assert ea is not None and ea["text"] == "Stop", (
            f"line {r['line']}: the allowlist read must be -ErrorAction Stop. A read that fails "
            "quietly turns an unreadable allowlist into an empty one, and an empty allowlist is the "
            f"kill switch.\n  got: {r['text']}"
        )

    merged = _merge_var(write)
    merge_assign = next(a for a in facts["assignments"] if a["lhs"] == merged)
    merge = _one(
        [
            c
            for c in facts["commands"]
            if merge_assign["rhsStart"] <= c["start"] < merge_assign["rhsEnd"]
        ],
        "Merge-GovernedRoots",
        "inside the assignment that feeds the writer",
    )
    existing = _arg_vars(merge, "Existing")
    assert existing, f"the merge is not fed any existing content: {merge['text']}"
    fed_by = [a for a in facts["assignments"] if a["lhs"] in existing]
    assert any(a["rhsStart"] <= r["start"] < a["rhsEnd"] for a in fed_by for r in reads), (
        "the value handed to -Existing is not the one the allowlist read produced, so the file is "
        f"read and then ignored: {merge['text']}"
    )


def test_the_install_path_announces_a_created_or_previously_empty_allowlist(tmp_path: Path) -> None:
    """The two states an operator cannot recover from the count line, both computed at the call site.

    ``-WasOff`` says the gate governed NOTHING until this run; ``-Created`` says there was no allowlist
    at all. Deleting either switch leaves Show-AllowlistResult perfectly correct and silent about the
    thing that matters, and the printer's own tests cannot see it -- they pass the switches themselves.
    """
    facts = _ast_facts(tmp_path)
    path = _install_path(facts)
    write = _one(path, "Write-GovernedRoots", "on the install path")
    show = _one(path, "Show-AllowlistResult", "on the install path")

    for switch in ("WasOff", "Created"):
        bound = _arg(show, switch)
        assert bound is not None, (
            f"the install path does not pass -{switch}, so that state is never announced"
        )
        assert bound["text"], (
            f"-{switch} is passed as a bare switch, which makes it constant rather than a report of "
            "what this run found"
        )

    assert _arg_vars(show, "Result") == [_merge_var(write)], (
        "the announcement describes a different object from the one that was written"
    )
    backup = [a["lhs"] for a in facts["assignments"] if a["rhsCmd"] == "Write-GovernedRoots"]
    assert _arg_vars(show, "BackupPath") and set(_arg_vars(show, "BackupPath")) <= set(backup), (
        "the backup path printed to the operator is not the one the writer returned"
    )


def test_the_gate_copy_and_the_wiring_happen_after_the_allowlist_write(tmp_path: Path) -> None:
    """What makes the writer's refusal message TRUE rather than reassuring.

    Write-GovernedRoots can refuse, and it tells the operator that neither the gate script nor the hook
    wiring has been written yet. That is a claim about the CALLER, so the caller has to keep it: the
    machine-global gate copy and every settings.json write must come after the allowlist write. They
    used to come before, so a refusal left this box carrying a refreshed gate -- and on a first install
    no matchers at all -- under a message that said nothing had changed.

    The MESSAGE is pinned where it can be watched failing, in
    test_the_writer_refuses_when_the_file_reads_back_wrong, which runs the writer and reads what it
    actually throws. This test pins only the ordering that makes that message true.
    """
    facts = _ast_facts(tmp_path)
    path = _install_path(facts)
    write = _one(path, "Write-GovernedRoots", "on the install path")

    gate_copies = [c for c in path if c["name"] == "Copy-Item" and "worktree_gate.ps1" in c["text"]]
    assert len(gate_copies) == 1, (
        f"expected one gate copy on the install path, found {len(gate_copies)}"
    )
    assert gate_copies[0]["start"] > write["start"], (
        f"the machine-global gate is copied (line {gate_copies[0]['line']}) BEFORE the allowlist write "
        f"(line {write['line']}), so the write's refusal lies about the state of the box"
    )
    wiring = [c for c in path if c["name"] == "Write-Settings"]
    assert wiring and min(c["start"] for c in wiring) > write["start"], (
        "hook wiring is written before the allowlist write, so the refusal's claim is false"
    )


def test_the_bare_uninstall_backs_up_the_allowlist_before_deleting_it(tmp_path: Path) -> None:
    """The largest data loss this script performs takes the same one-write-old backup as every other.

    Bare ``-Uninstall`` deletes the allowlist outright -- the kill switch -- and for a long time it left
    nothing behind at all. The backup has to be taken BEFORE the delete, which is the only ordering that
    means anything here.
    """
    facts = _ast_facts(tmp_path)
    uninstall = _if_block(facts, "$Uninstall")
    scoped = next(
        b for b in facts["ifs"] if _within(b, uninstall) and b["cond"].strip().startswith("$Repo")
    )
    bare = [
        c
        for c in facts["commands"]
        if _within(c, uninstall)
        and not _within(c, scoped)
        and not any(f["start"] <= c["start"] < f["end"] for f in facts["functions"])
    ]

    removes = [
        c for c in bare if c["name"] == "Remove-Item" and "ReposFile" in _arg_vars(c, "LiteralPath")
    ]
    assert removes, (
        "bare -Uninstall no longer deletes the allowlist -- this test is measuring nothing"
    )
    copies = [
        c for c in bare if c["name"] == "Copy-Item" and "ReposFile" in _arg_vars(c, "LiteralPath")
    ]
    assert copies, (
        "bare -Uninstall deletes the allowlist with no backup. Every other write here keeps one, and "
        "this is the biggest loss of the lot"
    )
    assert min(c["start"] for c in copies) < min(c["start"] for c in removes), (
        "the backup is taken after the delete, which backs up nothing"
    )
    dest = _arg(copies[0], "Destination")
    assert dest is not None and ".bak" in dest["text"], (
        f"the uninstall backup does not go to a .bak sibling: {copies[0]['text']}"
    )


# ------------------------------------------------------------------ the two properties of the file


def test_only_one_site_writes_the_allowlist(tmp_path: Path) -> None:
    """A bare overwrite must not be able to reappear beside the merge.

    That is what the defect WAS: a Set-Content of this run's repos, sitting in the install path with
    nothing having read the file first.

    THE CHECK FOLLOWS THE PATH, NOT ITS SPELLING. This used to require the literal ``$ReposFile`` in the
    command text, which one local alias -- ``$rf = $ReposFile`` -- walks straight past, and an alias is
    the ordinary way that line would get written. So the allowlist path is TAINTED from its assignment
    and carried through every variable and parameter that receives it.
    """
    facts = _ast_facts(tmp_path)
    assert any(a["lhs"] == "ReposFile" for a in facts["assignments"]), (
        "nothing assigns $ReposFile, so the taint below starts from nothing and finds nothing"
    )
    allowlist = _taint(facts, {("", "ReposFile")})
    writer = _fn(facts, "Write-GovernedRoots")
    writers = {"Set-Content", "Add-Content", "Out-File", "Move-Item"}
    outside = [
        c
        for c in facts["commands"]
        if c["name"] in writers
        and _touches(facts, c, allowlist)
        and not (writer["start"] <= c["start"] < writer["end"])
    ]
    assert not outside, (
        "the allowlist is written outside Write-GovernedRoots, which is where the backup, the atomic "
        "move and the read-back live:\n"
        + "\n".join(f"  line {c['line']}: {c['text']}" for c in outside)
    )
    # Guard the guard: the assertion above is satisfied by a writer that writes nothing at all.
    assert "Set-Content" in writer["text"] and "Move-Item" in writer["text"], (
        "Write-GovernedRoots no longer performs the write, so the check above is vacuous"
    )
    # And by a taint that never left its seed -- the alias hole this replaced.
    assert len(allowlist) > 1, (
        "the allowlist path is never passed anywhere, so the taint proves only that one variable is "
        "not written twice"
    )
    calls = [c for c in facts["commands"] if c["name"] == "Write-GovernedRoots"]
    assert len(calls) >= 2, (
        "the install path and the scoped removal must both go through the one writer; "
        f"found {len(calls)} call site(s)"
    )


def test_the_installer_never_reads_the_backup_back(tmp_path: Path) -> None:
    """The .bak is WRITE-ONLY, and that is a security property, not tidiness.

    Gate rule 1a protects the allowlist and the gate script by EXACT FILENAME and explicitly refuses to
    key on the parent directory, so a sibling worktree-gate.repos.txt.bak is NOT protected -- a session
    can write to it. That is harmless only while nothing reads it. The moment anything does, the backup
    becomes a route around rule 1a.

    THE OLD VERSION PINNED NOTHING. It matched the literal ``.bak`` in command text, so a read through
    the variable holding that path -- which is exactly how Write-GovernedRoots names its own backup, and
    how the printer receives it -- was invisible to it. A docstring calling that a security property was
    the whole of the property. This follows the VALUE instead: from the two places a backup path is
    born, through every variable and parameter that carries it.

    Copy-Item is the write. Write-Host PRINTS the path, which is not a read of the file. Anything else
    touching that value is the route this test exists to keep closed.
    """
    facts = _ast_facts(tmp_path)
    seeds = {
        (_scope_at(facts, a["start"]), a["lhs"])
        for a in facts["assignments"]
        if a["lhs"] and (".bak" in a["rhsText"] or a["rhsCmd"] == "Write-GovernedRoots")
    }
    assert seeds, "nothing in the script derives a backup path -- this check would be vacuous"
    backup = _taint(facts, seeds)
    assert ("Write-GovernedRoots", "bak") in backup, (
        f"the writer's own backup variable is not tainted; seeds were {sorted(seeds)}"
    )
    assert ("Show-AllowlistResult", "BackupPath") in backup, (
        "the backup path reaches the printer as a parameter and the taint did not follow it, so a "
        "read added inside the printer would be invisible here"
    )

    allowed = {"Copy-Item", "Write-Host", "Show-AllowlistResult"}
    touching = [c for c in facts["commands"] if ".bak" in c["text"] or _touches(facts, c, backup)]
    assert touching, "no command touches a backup path at all -- this check is vacuous"
    offenders = [c for c in touching if c["name"] not in allowed]
    assert not offenders, (
        "something other than the backup COPY or a printer touches the .bak. Nothing may read it "
        "back:\n" + "\n".join(f"  line {c['line']}: {c['name']}: {c['text']}" for c in offenders)
    )


def test_the_footer_states_the_deliberate_removal_command() -> None:
    """The remedy has to be printed where the operator already looks, beside the kill switch."""
    text = INSTALLER.read_text(encoding="utf-8")
    assert "To stop governing ONE:" in text
    assert "-Uninstall -Repo" in text
    assert "This installer MERGES the allowlist" in text
    assert "never drops one it did not name" in text
