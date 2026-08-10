# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The gate-rule text scan exists THREE times. Nothing tied the three together (BACKLOG #1018).

Each reads ``worktree_gate.ps1`` as text and extracts every tool name the gate branches on, with the
same pair of regexes:

1. :func:`test_install_gate_wiring.tools_the_gate_handles` -- Python, raw text.
2. :func:`test_gate_installed_parity.handled_tools` -- Python, over ``_code_lines()`` (whole-line ``#``
   comments dropped).
3. ``Get-HandledTools`` in ``scripts/worktree/install-gate.ps1`` -- PowerShell, raw text, and the one
   that decides what ``-Status`` prints.

They compute the same quantity, so this is duplication rather than resemblance. **This file does not
unify them** -- a shared Python helper could never absorb the PowerShell copy, so the honest end state
is one helper plus a cross-language agreement test, and without that second half the item would read
done while two implementations still floated. This is that second half, standing on its own.

WHAT IT BUYS, which is not "they might disagree today" -- they do not. It is the FAILURE DIRECTION of a
future one-sided edit:

* an under-matching copy 2 shrinks ``required`` in ``test_every_non_optional_rule_is_wired_in_every_
  config_dir``, so that test passes having checked less;
* an under-matching copy 3 prints no UNWIRED line from ``-Status``.

Both are false greens, in the files written *because* a rule once shipped dead while 85 tests stayed
green. Neither is visible from inside the copy that changed.

HOW THE THREE ARE DRIVEN. Copies 1 and 3 read a PATH and copy 2 takes TEXT, so the corpus is written to
a file and each real implementation is invoked as it stands -- copy 1 through its module constant, copy
3 by lifting its function out of the installer with the PowerShell AST and defining it in a fresh
session. Nothing here re-implements the regexes; a fourth copy written to test the other three would be
the same defect with better manners.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
import test_gate_installed_parity as parity
import test_install_gate_wiring as wiring

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "hooks" / "worktree_gate.ps1"
INSTALLER = ROOT / "scripts" / "worktree" / "install-gate.ps1"

# Lift the PowerShell copy out of the installer WITHOUT running the installer, which writes user-scope
# hook wiring for every session on this box. The AST is used rather than a text slice on purpose: a
# regex that carves a function body out of a script would itself be a text scan of a text scanner, and
# it would break on the next brace someone adds.
_EXTRACT = r"""
param([string]$Installer, [string]$Corpus)
$ErrorActionPreference = 'Stop'
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Installer, [ref]$null, [ref]$null)
$fn = $ast.Find({
    param($n)
    $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-HandledTools'
}, $true)
if (-not $fn) { throw "Get-HandledTools is not defined in $Installer -- copy 3 moved or was renamed" }
. ([scriptblock]::Create($fn.Extent.Text))
@(Get-HandledTools $Corpus) | Sort-Object | ConvertTo-Json -AsArray
"""


def _powershell_copy(corpus: Path, tmp_path: Path) -> set[str]:
    runner = tmp_path / "extract-handled-tools.ps1"
    runner.write_text(_EXTRACT, encoding="utf-8")
    r = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(runner),
            "-Installer",
            str(INSTALLER),
            "-Corpus",
            str(corpus),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert r.returncode == 0, f"lifting Get-HandledTools failed:\n{r.stderr}\n{r.stdout}"
    return set(json.loads(r.stdout or "[]"))


def _all_three(
    corpus: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> dict[str, set[str]]:
    """Every implementation, run as it stands, over one corpus."""
    text = corpus.read_text(encoding="utf-8")
    monkeypatch.setattr(wiring, "GATE", corpus)
    return {
        "1 test_install_gate_wiring.tools_the_gate_handles": wiring.tools_the_gate_handles(),
        "2 test_gate_installed_parity.handled_tools": parity.handled_tools(text),
        "3 install-gate.ps1 Get-HandledTools": _powershell_copy(corpus, tmp_path),
    }


def _report(results: dict[str, set[str]]) -> str:
    return "\n".join(f"  {name}: {sorted(tools)}" for name, tools in results.items())


pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None,
    reason="copy 3 is PowerShell; without pwsh only two of the three can be compared, and a "
    "two-way agreement reported as a three-way one is exactly the class this file exists for",
)


def test_the_three_gate_rule_scanners_agree_on_the_real_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The corpus that matters: the actual gate all three are pointed at in production.

    Non-emptiness is asserted first, and it is not decoration -- three implementations that all return
    the empty set agree perfectly and measure nothing, which is the shape of a regex that stopped
    matching after a syntax change in the gate.
    """
    results = _all_three(GATE, tmp_path, monkeypatch)
    print(f"corpus: {GATE}\n{_report(results)}")

    for name, tools in results.items():
        assert tools, f"{name} extracted NOTHING from the real gate -- agreement would be vacuous"

    distinct = {frozenset(t) for t in results.values()}
    assert len(distinct) == 1, (
        f"the three gate-rule scanners disagree about the REAL gate:\n{_report(results)}\n"
        f"Whichever is under-matching produces a FALSE GREEN, not a red: a smaller set shrinks "
        f"`required` in test_gate_installed_parity, and it removes UNWIRED lines from "
        f"install-gate.ps1 -Status. Fix the copy that moved; do not adjust this test to accept it."
    )


@pytest.mark.parametrize(
    ("label", "body", "expected"),
    [
        (
            "-in with two names",
            '\nif ($tool -in @("Bash", "PowerShell")) { }\n',
            {"Bash", "PowerShell"},
        ),
        (
            "-notin, the negated form",
            '\nif ($tool -notin @("Write", "Edit")) { }\n',
            {"Write", "Edit"},
        ),
        (
            "extra whitespace either side of the operator",
            '\nif ($tool   -in   @( "Task" )) { }\n',
            {"Task"},
        ),
        (
            "a single-quoted name, which the QUOTED regex does not admit",
            "\nif ($tool -in @('Agent')) { }\n",
            set(),
        ),
        (
            "a name carrying a hyphen",
            '\nif ($tool -in @("Notebook-Edit")) { }\n',
            {"Notebook-Edit"},
        ),
        (
            "two branches on separate lines",
            '\nif ($tool -in @("A")) { }\nif ($tool -notin @("B")) { }\n',
            {"A", "B"},
        ),
    ],
)
def test_the_three_agree_on_each_regex_shape(
    label: str,
    body: str,
    expected: set[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Shape by shape, so a disagreement names the construct that caused it.

    ``expected`` is asserted too, not just mutual agreement: three copies that agree on the WRONG answer
    is a state this file would otherwise call healthy.
    """
    corpus = tmp_path / "corpus.ps1"
    corpus.write_text(body, encoding="utf-8")
    results = _all_three(corpus, tmp_path, monkeypatch)
    print(f"{label}\n{_report(results)}")

    for name, tools in results.items():
        assert tools == expected, (
            f"{label}: {name} read {sorted(tools)}, expected {sorted(expected)}"
        )


def test_the_one_known_divergence_is_the_comment_filter_and_is_pinned_here(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The three are NOT identical, and pretending otherwise is how the difference goes unexamined.

    Copy 2 alone drops whole-line ``#`` comments before scanning, deliberately: the real gate quotes
    rule 4's condition verbatim in a comment as well as in the rule, so a raw scan credits the gate with
    a rule on the strength of PROSE. Copies 1 and 3 have no such filter.

    On the real gate the difference is invisible -- the commented condition names a tool the code
    branches on anyway -- which is exactly why it needs a corpus that separates them. Pinning it here
    means the divergence is a stated property with a reason attached, and any change to it (a filter
    added to copies 1 or 3, or removed from copy 2) fails this test and has to be argued rather than
    absorbed.
    """
    corpus = tmp_path / "corpus.ps1"
    corpus.write_text(
        '\n# A dead branch quoted in prose: if ($tool -in @("GhostTool")) { }\n'
        'if ($tool -in @("RealTool")) { }\n',
        encoding="utf-8",
    )
    results = _all_three(corpus, tmp_path, monkeypatch)
    print(_report(results))

    assert results["1 test_install_gate_wiring.tools_the_gate_handles"] == {
        "GhostTool",
        "RealTool",
    }
    assert results["3 install-gate.ps1 Get-HandledTools"] == {"GhostTool", "RealTool"}
    assert results["2 test_gate_installed_parity.handled_tools"] == {"RealTool"}, (
        "copy 2's comment filter is the ONE documented difference between the three scanners. If it is "
        "gone, the credit-a-rule-from-prose failure it was added for is back; if copies 1 or 3 grew one "
        "too, delete this pin and say so."
    )
