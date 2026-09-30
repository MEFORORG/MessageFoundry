# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The windows-service-smoke password screen runs the policy provision-admin runs.

``scripts/service/measure-store-access.ps1`` embeds a Python probe. Its ``screen`` mode vets each
synthetic administrator password before the smoke hands it to ``provision-admin``; the comment on
``New-SyntheticPassword`` in that script says why. The smoke itself runs only on a hosted Windows
runner, so this test runs the embedded probe here: a rename of the policy or settings symbols it
imports, or a change to its exit-code contract, fails on the engine legs instead of only on that one.

The PowerShell side reads exit 3 as "refused, draw again" and any other non-zero as "the screen
broke, stop". Both halves of that contract are pinned below, and a differential arm runs the probe's
``provision`` mode (the real ``provision-admin`` entry point) on the same inputs, so the screen and
the command it stands in for are compared rather than assumed equal.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from messagefoundry.auth.policy import CONTEXT_WORDS

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "service" / "measure-store-access.ps1"
_PROBE = re.compile(r"^\$ProbeSource = @'\r?\n(.*?)\r?\n'@", re.MULTILINE | re.DOTALL)
# Synthetic, and the same shape the smoke draws: 32 characters of base64 alphanumerics.
_CLEAN = "qZ8rT2vKbM3mN4pX9sW1cY6bJ3dF5gA0"
_HAS_HL7 = "qZ8rT2vKhL7mN4pX9sW1cY6bJ3dF5gA0"
_CONTEXT_CLAUSE = "not contain a word from the context-word deny-list"
# Below the suite's 60 s per-test watchdog, so a hung probe surfaces as TimeoutExpired.
_PROBE_TIMEOUT_S = 45


def _run_probe(
    tmp_path: Path, args: list[str], password: str, extra_env: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    match = _PROBE.search(_SCRIPT.read_text(encoding="utf-8"))
    assert match, "the $ProbeSource here-string was not found in measure-store-access.ps1"
    probe = tmp_path / "probe.py"
    probe.write_text(match.group(1), encoding="ascii")
    # No inherited MEFOR_* setting may reach the settings load, so the result is the default policy
    # plus exactly what each case adds. The two the smoke passes are set as it sets them.
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("MEFOR_")}
    env.update(
        {
            "MEFOR_W0_ADMIN_PASSWORD": password,
            "MEFOR_STORE_ENCRYPTION_KEY": "unused-before-the-store-opens",
            "MEFOR_SECURITY_REQUIRE_MFA": "false",
        }
    )
    env.update(extra_env)
    return subprocess.run(
        [sys.executable, str(probe), *args],
        cwd=tmp_path,  # no messagefoundry.toml here, as on the runner's checkout root
        env=env,
        capture_output=True,
        text=True,
        timeout=_PROBE_TIMEOUT_S,
        check=False,
    )


def _db(tmp_path: Path) -> str:
    return str(tmp_path / "data" / "messagefoundry.db")


def _screen(
    tmp_path: Path, password: str, extra_env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return _run_probe(tmp_path, ["screen", "w0admin", _db(tmp_path)], password, extra_env or {})


def _provision(
    tmp_path: Path, password: str, extra_env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    # The smoke's own provision arguments (measure-store-access.ps1, $provisionArgs).
    args = ["provision", "--username", "w0admin", "--email", "w0-admin@example.invalid"]
    args += ["--db", _db(tmp_path), "--json", "--no-totp"]
    return _run_probe(tmp_path, args, password, extra_env or {})


def test_the_refused_fixture_really_holds_a_shipped_context_word() -> None:
    assert "hl7" in CONTEXT_WORDS
    assert "hl7" in _HAS_HL7.lower()
    assert not any(word in _CLEAN.lower() for word in CONTEXT_WORDS)


def test_a_clean_candidate_passes(tmp_path: Path) -> None:
    result = _screen(tmp_path, _CLEAN)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "screen passed" in result.stdout
    # The screen runs before the service is installed, and the StartFirst arms measure a store the
    # SERVICE creates, so the screen must leave the data directory untouched: not even the folder.
    assert not (tmp_path / "data").exists()


def test_a_context_word_is_refused_with_exit_3_and_the_password_is_not_printed(
    tmp_path: Path,
) -> None:
    result = _screen(tmp_path, _HAS_HL7)
    assert result.returncode == 3, result.stdout + result.stderr
    assert _CONTEXT_CLAUSE in result.stdout
    assert _HAS_HL7 not in result.stdout + result.stderr


@pytest.mark.parametrize(
    ("password", "extra_env", "clause"),
    [
        # The failure merge group 36766996620 hit.
        (_HAS_HL7, {}, _CONTEXT_CLAUSE),
        # Settings come from the environment on both sides: a stricter minimum refuses a
        # 32-character candidate in the screen exactly where provision-admin refuses it.
        (_CLEAN, {"MEFOR_AUTH_PASSWORD_MIN_LENGTH": "33"}, "be at least 33 characters"),
    ],
)
def test_the_screen_refuses_what_provision_admin_refuses(
    tmp_path: Path, password: str, extra_env: dict[str, str], clause: str
) -> None:
    (tmp_path / "s").mkdir()
    (tmp_path / "p").mkdir()
    screened = _screen(tmp_path / "s", password, extra_env)
    provisioned = _provision(tmp_path / "p", password, extra_env)
    assert screened.returncode == 3, screened.stdout + screened.stderr
    assert clause in screened.stdout
    assert provisioned.returncode != 0, provisioned.stdout + provisioned.stderr
    assert clause in json.loads(provisioned.stdout)["error"]
    # Refused before the open, so neither created the store.
    assert not (tmp_path / "s" / "data").exists()
    assert not (tmp_path / "p" / "data").exists()


def test_a_settings_load_that_fails_is_a_broken_screen_not_a_refusal(tmp_path: Path) -> None:
    result = _screen(tmp_path, _CLEAN, {"MEFOR_AUTH_PASSWORD_MIN_LENGTH": "not-a-number"})
    assert result.returncode not in (0, 3), result.stdout + result.stderr
    # The failure is the settings load, not an import or argument error that happens to exit 1.
    assert "password_min_length" in result.stderr
