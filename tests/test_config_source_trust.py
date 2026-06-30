# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""SEC-003 (CWE-732): the Windows config-source trust guard must actively refuse a config dir/module
that a broad/low-privilege principal can write — it used to be a silent no-op on Windows.

Three tiers:
  1. Platform-independent unit tests of the pure DACL policy (``_evaluate_config_dacl``) — full logic
     coverage on the Linux CI leg.
  2. A Windows-gated integration test using ``icacls`` to add a world-writable ACE and asserting
     ``load_config`` refuses it.
  3. A test that a Win32 API error makes the guard fail OPEN with a WARNING (caplog), not raise.
"""

from __future__ import annotations

import logging
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from messagefoundry.config.settings import INSECURE_CONFIG_SOURCE_ESCAPE_ENV
from messagefoundry.config.wiring import (
    WiringError,
    _evaluate_config_dacl,
    load_config,
)

# Well-known SIDs used across the policy tests.
_OWNER = "S-1-5-21-1-2-3-1001"  # an arbitrary domain/local user that owns the files
_SELF = "S-1-5-21-1-2-3-2002"  # the current process user (also trusted)
_SYSTEM = "S-1-5-18"
_ADMINS = "S-1-5-32-544"
_EVERYONE = "S-1-1-0"
_AUTH_USERS = "S-1-5-11"
_USERS = "S-1-5-32-545"
_FOREIGN = "S-1-5-21-9-9-9-1234"  # a non-owner, non-admin principal

_ALLOW = 0x00  # ACCESS_ALLOWED_ACE_TYPE
_DENY = 0x01  # ACCESS_DENIED_ACE_TYPE
_FULL = 0x10000000 | 0x40000000 | 0x1FF  # GENERIC_ALL|GENERIC_WRITE|standard-ish
_MODIFY = 0x00000002 | 0x00000004 | 0x00000010 | 0x00010000  # write/append/write_ea/delete
_WRITE = 0x00000002  # FILE_WRITE_DATA
_READ_EXEC = 0x00000001 | 0x00000020 | 0x00000080  # read_data|execute|read_ea (no write bit)
_GENERIC_ALL = 0x10000000


# ---- Tier 1: pure DACL policy (runs everywhere) -----------------------------


def test_owner_only_dacl_passes() -> None:
    aces = [(_ALLOW, _FULL, _OWNER)]
    assert _evaluate_config_dacl(_OWNER, aces, _SELF) is None


def test_admins_and_system_full_passes() -> None:
    aces = [(_ALLOW, _FULL, _SYSTEM), (_ALLOW, _FULL, _ADMINS), (_ALLOW, _FULL, _OWNER)]
    assert _evaluate_config_dacl(_OWNER, aces, _SELF) is None


def test_self_sid_write_passes() -> None:
    # The current process user (service account) controlling its own config dir is fine.
    aces = [(_ALLOW, _MODIFY, _SELF)]
    assert _evaluate_config_dacl(_OWNER, aces, _SELF) is None


def test_everyone_modify_is_refused() -> None:
    aces = [(_ALLOW, _MODIFY, _EVERYONE)]
    reason = _evaluate_config_dacl(_OWNER, aces, _SELF)
    assert reason is not None
    assert _EVERYONE in reason


def test_authenticated_users_write_refused() -> None:
    aces = [(_ALLOW, _WRITE, _AUTH_USERS)]
    assert _evaluate_config_dacl(_OWNER, aces, _SELF) is not None


def test_builtin_users_read_exec_passes() -> None:
    # A repo-checkout dir typically grants Users:(RX) — read-only, no write bits, MUST pass.
    aces = [(_ALLOW, _READ_EXEC, _USERS), (_ALLOW, _FULL, _OWNER)]
    assert _evaluate_config_dacl(_OWNER, aces, _SELF) is None


def test_builtin_users_modify_refused() -> None:
    aces = [(_ALLOW, _MODIFY, _USERS)]
    assert _evaluate_config_dacl(_OWNER, aces, _SELF) is not None


def test_foreign_nonadmin_write_refused() -> None:
    aces = [(_ALLOW, _WRITE, _FOREIGN)]
    reason = _evaluate_config_dacl(_OWNER, aces, _SELF)
    assert reason is not None
    assert _FOREIGN in reason


def test_everyone_generic_all_refused() -> None:
    aces = [(_ALLOW, _GENERIC_ALL, _EVERYONE)]
    assert _evaluate_config_dacl(_OWNER, aces, _SELF) is not None


def test_deny_ace_with_write_is_ignored() -> None:
    # A DENY ACE never grants a right — it must not trigger a refusal.
    aces = [(_DENY, _FULL, _EVERYONE), (_ALLOW, _FULL, _OWNER)]
    assert _evaluate_config_dacl(_OWNER, aces, _SELF) is None


def test_self_sid_none_still_refuses_everyone() -> None:
    # Even when the current-user SID can't be resolved, a broad principal write is refused.
    aces = [(_ALLOW, _MODIFY, _EVERYONE)]
    assert _evaluate_config_dacl(_OWNER, aces, None) is not None


# ---- Tier 3: fail-open-with-WARNING on a Win32 API error --------------------


def test_api_error_fails_open_with_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A failure inside the Windows ACL check must WARN and proceed, not raise (fail-open posture)."""
    import messagefoundry.config.wiring as wiring

    (tmp_path / "cfg.py").write_text(
        "from messagefoundry import outbound, File\noutbound('o', File(directory='./out'))\n",
        encoding="utf-8",
    )

    def _boom(directory: Path) -> None:
        # Simulate the ctypes boundary blowing up (e.g. an OSError from a Win32 call).
        wiring._logger.warning(
            "config-source trust guard could not evaluate the DACL of %s (simulated); proceeding "
            "WITHOUT the Windows ACL check (see docs/SERVICE.md)",
            directory,
        )

    # Force the load to take the Windows path regardless of host, then make that path "fail open".
    monkeypatch.setattr(wiring, "_assert_safe_config_source_windows", _boom)
    monkeypatch.setattr(wiring.sys, "platform", "win32")

    with caplog.at_level(logging.WARNING, logger="messagefoundry.config.wiring"):
        registry = load_config(tmp_path)

    assert "o" in registry.outbound  # the service still loaded (did not brick)
    assert any("proceeding WITHOUT the Windows ACL check" in r.message for r in caplog.records)


# ---- Tier 2: Windows-gated integration via icacls ---------------------------


@pytest.mark.skipif(sys.platform != "win32", reason="real NTFS DACL manipulation needs Windows")
def test_world_writable_config_dir_refused_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Grant Authenticated Users Modify on the dir via icacls; load_config must refuse it."""
    # The suite-wide win32 fixture sets the dev/test escape ON; pin it OFF to assert the fail-closed path.
    monkeypatch.delenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, raising=False)
    (tmp_path / "cfg.py").write_text(
        "from messagefoundry import outbound, File\noutbound('o', File(directory='./out'))\n",
        encoding="utf-8",
    )
    # *S-1-5-11 = Authenticated Users (present on every box); (OI)(CI)M = Modify, inherited.
    proc = subprocess.run(
        ["icacls", str(tmp_path), "/grant", "*S-1-5-11:(OI)(CI)M"],
        capture_output=True,
        text=True,
        # Bound the subprocess (#55): icacls is normally sub-second, but an unbounded subprocess.run
        # blocks in a C-level wait that --timeout-method=thread CANNOT interrupt, so a wedged child
        # (AV scan / locked DACL on a CI runner) would hang the leg silently. A timeout raises
        # TimeoutExpired = a fast, named failure instead.
        timeout=30,
    )
    assert proc.returncode == 0, f"icacls grant failed: {proc.stdout}{proc.stderr}"
    with pytest.raises(WiringError, match="writable-by-others|write access|see docs/SERVICE.md"):
        load_config(tmp_path)


@pytest.mark.skipif(sys.platform != "win32", reason="real NTFS DACL manipulation needs Windows")
def test_world_writable_config_dir_warns_with_escape_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """With MEFOR_ALLOW_INSECURE_CONFIG_SOURCE set, the same writable dir loads with a WARNING.

    Validates the dev/test escape: fail-closed in production, but a user-writable dev/CI checkout
    (the default Windows-runner ACL) proceeds loudly instead of bricking the load."""
    monkeypatch.setenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, "1")
    (tmp_path / "cfg.py").write_text(
        "from messagefoundry import outbound, File\noutbound('o', File(directory='./out'))\n",
        encoding="utf-8",
    )
    proc = subprocess.run(
        ["icacls", str(tmp_path), "/grant", "*S-1-5-11:(OI)(CI)M"],
        capture_output=True,
        text=True,
        # Bound the subprocess (#55): icacls is normally sub-second, but an unbounded subprocess.run
        # blocks in a C-level wait that --timeout-method=thread CANNOT interrupt, so a wedged child
        # (AV scan / locked DACL on a CI runner) would hang the leg silently. A timeout raises
        # TimeoutExpired = a fast, named failure instead.
        timeout=30,
    )
    assert proc.returncode == 0, f"icacls grant failed: {proc.stdout}{proc.stderr}"
    with caplog.at_level(logging.WARNING, logger="messagefoundry.config.wiring"):
        registry = load_config(tmp_path)
    assert "o" in registry.outbound  # loaded despite the broad-write ACE
    assert any("dev/test override" in r.message for r in caplog.records)


@pytest.mark.skipif(sys.platform != "win32", reason="real NTFS DACL check needs Windows")
def test_owner_only_config_dir_loads_windows(tmp_path: Path) -> None:
    """A freshly-created owner-controlled tmp dir (no broad write ACE) loads cleanly on Windows."""
    d = tmp_path / "cfg_ok"
    d.mkdir()
    (d / "cfg.py").write_text(
        textwrap.dedent(
            """
            from messagefoundry import outbound, File
            outbound("o", File(directory="./out"))
            """
        ),
        encoding="utf-8",
    )
    registry = load_config(d)
    assert "o" in registry.outbound
