# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The windows-service-smoke password screen runs the policy provision-admin runs.

``scripts/service/measure-store-access.ps1`` embeds a Python probe. Its ``screen`` mode vets each
synthetic administrator password before the smoke hands it to ``provision-admin``, because an
unscreened random string holds a shipped context word (usually ``hl7``) about once in 1,900 draws
and the provision step then refuses it. The smoke itself runs only on a hosted Windows runner, so
this test runs the embedded probe here: a rename of the policy or settings symbols it imports, or a
change to its exit-code contract, fails on every leg instead of only on that one.

The PowerShell side reads exit 3 as "refused, draw again" and any other non-zero as "the screen
broke, stop". Both halves of that contract are pinned below.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "service" / "measure-store-access.ps1"
_PROBE = re.compile(r"^\$ProbeSource = @'\r?\n(.*?)\r?\n'@", re.MULTILINE | re.DOTALL)
# Synthetic, and the same shape the smoke draws: 32 characters of base64 alphanumerics.
_CLEAN = "qZ8rT2vKbM3mN4pX9sW1cY6bJ3dF5gA0"
_HAS_HL7 = "qZ8rT2vKhL7mN4pX9sW1cY6bJ3dF5gA0"


def _run_screen(
    tmp_path: Path, password: str, extra_env: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    match = _PROBE.search(_SCRIPT.read_text(encoding="utf-8"))
    assert match, "the $ProbeSource here-string was not found in measure-store-access.ps1"
    probe = tmp_path / "probe.py"
    probe.write_text(match.group(1), encoding="ascii")
    # No inherited MEFOR_* setting may reach the settings load, so the result is the default policy
    # plus exactly what each case adds. The two the smoke passes are set as it sets them.
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("MEFOR_")}
    env.update(
        MEFOR_W0_ADMIN_PASSWORD=password,
        MEFOR_STORE_ENCRYPTION_KEY="unused-by-the-screen",
        MEFOR_SECURITY_REQUIRE_MFA="false",
        **extra_env,
    )
    return subprocess.run(
        [
            sys.executable,
            str(probe),
            "screen",
            "w0admin",
            str(tmp_path / "data" / "messagefoundry.db"),
        ],
        cwd=tmp_path,  # no messagefoundry.toml here, as on the runner's checkout root
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def test_a_clean_candidate_passes(tmp_path: Path) -> None:
    result = _run_screen(tmp_path, _CLEAN, {})
    assert result.returncode == 0, result.stdout + result.stderr
    assert "screen passed" in result.stdout
    # The screen runs before the service is installed, and the StartFirst arms measure a store the
    # SERVICE creates, so the screen must leave the data directory untouched: not even the folder.
    assert not (tmp_path / "data").exists()


def test_a_context_word_is_refused_with_exit_3_and_the_password_is_not_printed(
    tmp_path: Path,
) -> None:
    result = _run_screen(tmp_path, _HAS_HL7, {})
    assert result.returncode == 3, result.stdout + result.stderr
    assert "not contain a word from the context-word deny-list" in result.stdout
    assert _HAS_HL7 not in result.stdout + result.stderr


@pytest.mark.parametrize(
    ("extra_env", "want"),
    [
        # The screen reads settings the way provision-admin does, so a stricter site minimum refuses
        # a 32-character candidate as a refusal (retry), not as a crash.
        ({"MEFOR_AUTH_PASSWORD_MIN_LENGTH": "33"}, 3),
        # A settings load that cannot complete is the screen breaking, which must not read as 3.
        ({"MEFOR_AUTH_PASSWORD_MIN_LENGTH": "not-a-number"}, None),
    ],
)
def test_the_screen_loads_settings_like_provision_admin(
    tmp_path: Path, extra_env: dict[str, str], want: int | None
) -> None:
    result = _run_screen(tmp_path, _CLEAN, extra_env)
    if want is None:
        assert result.returncode not in (0, 3), result.stdout + result.stderr
    else:
        assert result.returncode == want, result.stdout + result.stderr
