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

WHAT THAT CANNOT REACH: the call sites and the exact strings a real install run prints. They are covered
by reading the source, plus the three source-text tests at the bottom. That gap is imposed by the
refusal, not chosen, and it is stated here rather than papered over with a test-only switch.

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
    the shape that silently drops a root; installer-FINER only ever writes a harmless duplicate line.
    Measured: ``C:\\A\\..\\B`` folds to ``c:/b`` under the gate and stays ``c:/a/../b`` here.

    So the assertion is an IMPLICATION, not an equality: installer-same-root implies gate-same-root, and
    the converse is allowed to differ. Both normalizers are EXTRACTED from their own scripts rather than
    restated here -- a restated predicate is a third predicate, and a disagreement between two
    predicates is what this whole area keeps producing.
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
        ]
    else:
        corpus = [
            "/srv/code/messagefoundry",
            "/srv/code/messagefoundry/",
            "/SRV/code/MessageFoundry",
            "/srv/code/other/../messagefoundry",
            "/srv/code/messagefoundry-vault",
        ]

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
    """A lost update must be LOUD.

    The read-back narrows the concurrent-installer race; it does not close it. This holds the target
    open with FileShare.Read, which is what a competing writer looks like from here: the copy and the
    temp file succeed, the move over the locked file does not land, and the read-back sees the old
    content. Without the check the run would report a governed root the file does not carry.
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


# -------------------------------------------------------------------------------- the source text
# As far toward "correct function, never called" as the CLAUDECODE refusal honestly allows.


def _ast_facts(tmp_path: Path) -> dict[str, Any]:
    script = "\n".join(
        [
            "& {",
            "  Set-StrictMode -Version Latest",
            f"  $src = {_psq(str(INSTALLER))}",
            "  $ast = [System.Management.Automation.Language.Parser]::ParseFile("
            "$src, [ref]$null, [ref]$null)",
            "  $w = $ast.Find({ $args[0] -is "
            "[System.Management.Automation.Language.FunctionDefinitionAst] -and "
            "$args[0].Name -eq 'Write-GovernedRoots' }, $true)",
            "  if (-not $w) { throw 'Write-GovernedRoots is not defined' }",
            "  $cmds = @($ast.FindAll({ $args[0] -is "
            "[System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object {",
            "    [pscustomobject]@{ name = $_.GetCommandName(); "
            "start = $_.Extent.StartOffset; line = $_.Extent.StartLineNumber; "
            "text = $_.Extent.Text }",
            "  })",
            "  [pscustomobject]@{",
            "    writerStart = $w.Extent.StartOffset",
            "    writerEnd   = $w.Extent.EndOffset",
            "    writerText  = $w.Extent.Text",
            "    commands    = $cmds",
            "  } | ConvertTo-Json -Depth 6 -Compress",
            "}",
        ]
    )
    return json.loads(_ok(script, tmp_path).strip().splitlines()[-1])


def test_only_one_site_writes_the_allowlist(tmp_path: Path) -> None:
    """A bare overwrite must not be able to reappear beside the merge.

    That is what the defect WAS: a Set-Content of this run's repos, sitting in the install path with
    nothing having read the file first.
    """
    facts = _ast_facts(tmp_path)
    writers = {"Set-Content", "Add-Content", "Out-File", "Move-Item"}
    outside = [
        c
        for c in facts["commands"]
        if c["name"] in writers
        and "$ReposFile" in c["text"]
        and not (facts["writerStart"] <= c["start"] < facts["writerEnd"])
    ]
    assert not outside, (
        "the allowlist is written outside Write-GovernedRoots, which is where the backup, the atomic "
        "move and the read-back live:\n"
        + "\n".join(f"  line {c['line']}: {c['text']}" for c in outside)
    )
    # Guard the guard: the assertion above is satisfied by a writer that writes nothing at all.
    assert "Set-Content" in facts["writerText"] and "Move-Item" in facts["writerText"], (
        "Write-GovernedRoots no longer performs the write, so the check above is vacuous"
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
    """
    facts = _ast_facts(tmp_path)
    touching = [c for c in facts["commands"] if ".bak" in c["text"]]
    assert touching, "no command mentions a .bak at all -- this check is vacuous"
    offenders = [c for c in touching if c["name"] != "Copy-Item"]
    assert not offenders, (
        "something other than the backup COPY names a .bak file. Nothing may read it back:\n"
        + "\n".join(f"  line {c['line']}: {c['name']}: {c['text']}" for c in offenders)
    )


def test_the_footer_states_the_deliberate_removal_command() -> None:
    """The remedy has to be printed where the operator already looks, beside the kill switch."""
    text = INSTALLER.read_text(encoding="utf-8")
    assert "To stop governing ONE:" in text
    assert "-Uninstall -Repo" in text
    assert "This installer MERGES the allowlist" in text
    assert "never drops one it did not name" in text
