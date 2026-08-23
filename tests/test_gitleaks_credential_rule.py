# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Guard the `mefor-defaulted-credential` gitleaks rule (BACKLOG #1091) by RUNNING it.

The two required secret gates share a blind spot over most of the places a credential would actually
live: bandit is a Python AST scanner and does not parse `.yaml` or `.ps1` at all, and gitleaks'
operative generic rule is ENTROPY-GATED, so `changeme` or a short dev default falls below the
threshold. The rule added for #1091 keys on the SHAPE of a defaulted secret instead.

WHY THESE TESTS EXECUTE THE SCANNER RATHER THAN READING THE CONFIG. A text assertion that the rule
is PRESENT cannot tell a working rule from a regex that matches nothing -- which is the same
"control that cannot fire" defect BACKLOG #1313 found in the sdist leak gate, where every text check
passed over a step that reported clean without inspecting anything. So each test builds a fixture
tree and runs the real `gitleaks` against the repository's real `.gitleaks.toml`.

THE MUST-BE-SILENT CASES ARE NOT DECORATION. `.github/workflows/release.yml` carries NINE
`id-token: write` lines. Those are GitHub PERMISSIONS, not credentials, and a naive `token\\s*[:=]`
rule reddens a REQUIRED gate nine times on its first run -- which is how a security control gets
disabled rather than fixed. The negative rows are what keep the rule narrow enough to survive.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
CONFIG = _REPO / ".gitleaks.toml"
RULE_ID = "mefor-defaulted-credential"

pytestmark = pytest.mark.skipif(
    shutil.which("gitleaks") is None,
    reason="gitleaks is not on PATH; this guard needs the real scanner, not a text match",
)


def _findings(tmp_path: Path, files: dict[str, str]) -> list[dict]:
    """Run the REAL gitleaks with the REPO's config over a fixture tree; return this rule's hits."""
    src = tmp_path / "src"
    src.mkdir()
    for name, body in files.items():
        (src / name).write_text(body, encoding="utf-8")
    report = tmp_path / "report.json"
    proc = subprocess.run(
        [
            "gitleaks",
            "detect",
            "--no-git",
            "--source",
            str(src),
            "--config",
            str(CONFIG),
            "--report-format",
            "json",
            "--report-path",
            str(report),
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    # A config gitleaks refuses to load exits non-zero with FTL and writes no report. That must fail
    # the test loudly rather than read as "no findings" -- the whole point of this module.
    assert report.exists(), (
        f"gitleaks wrote no report; it likely rejected the config:\n{proc.stderr}"
    )
    return [f for f in json.loads(report.read_text(encoding="utf-8")) if f["RuleID"] == RULE_ID]


#: The defect shape. The env indirection is fine; the FALLBACK is what ships on first deployment.
_DEFECT = (
    'services:\n  db:\n    environment:\n      DB_PASSWORD: "${REAL_SECRET:-mefor-dev-password}"\n'
)


def test_a_defaulted_credential_is_detected(tmp_path: Path) -> None:
    """The positive control for this whole module. If this fails, every silence below means nothing."""
    hits = _findings(tmp_path, {"compose.yaml": _DEFECT})
    assert len(hits) == 1, f"expected the defaulted credential to be caught, got {hits}"


def test_it_catches_the_shape_in_a_powershell_file_too(tmp_path: Path) -> None:
    """bandit cannot parse .ps1 at all, which is half of why this rule exists."""
    body = '$env:API_TOKEN = "${API_TOKEN:-changeme}"\n'
    assert len(_findings(tmp_path, {"dev.ps1": body})) == 1


def test_a_low_entropy_value_is_still_caught(tmp_path: Path) -> None:
    """The entropy gate is the other half. `changeme` is below any useful threshold and is exactly
    the credential a first deployment would carry."""
    body = 'db_password: "${DB_PASSWORD:-changeme}"\n'
    assert len(_findings(tmp_path, {"values.yaml": body})) == 1


def test_a_plain_env_reference_is_not_a_finding(tmp_path: Path) -> None:
    """`${VAR}` with no fallback is CORRECT usage -- it is what the rule wants people to write."""
    body = 'services:\n  db:\n    environment:\n      DB_PASSWORD: "${REAL_SECRET}"\n'
    assert _findings(tmp_path, {"compose.yaml": body}) == []


def test_github_permission_blocks_are_not_credentials(tmp_path: Path) -> None:
    """THE LOAD-BEARING NEGATIVE. `id-token: write` is a GitHub permission, and release.yml carries
    nine of them. A rule that matches these reddens a required gate on every run."""
    body = (
        "jobs:\n  publish:\n    permissions:\n"
        "      contents: write\n      id-token: write   # PyPI Trusted Publishing (OIDC)\n"
    )
    assert _findings(tmp_path, {"release.yml": body}) == []


def test_documented_placeholders_are_allowlisted(tmp_path: Path) -> None:
    """The example manifest's fill-me-in markers exist to be replaced and are not secrets."""
    body = 'stringData:\n  store-password: "${STORE_PASSWORD:-REPLACE_or_omit_for_sqlite}"\n'
    assert _findings(tmp_path, {"secret.example.yaml": body}) == []


def test_the_tracked_demonstration_is_caught(tmp_path: Path) -> None:
    """docker/compose.yaml carries the shape today. If it is ever cleaned up this test should be
    retired deliberately rather than left asserting over a file that no longer demonstrates it."""
    tracked = _REPO / "docker" / "compose.yaml"
    if not tracked.exists():  # pragma: no cover - the file is tracked; this is a honest guard
        pytest.skip("docker/compose.yaml is absent from this checkout")
    hits = _findings(tmp_path, {"compose.yaml": tracked.read_text(encoding="utf-8")})
    assert len(hits) >= 1, "the tracked demonstration stopped being detected"
