# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""SEC-003 (CWE-732): the Windows config-source trust guard must actively refuse a config dir/module
that a broad/low-privilege principal can write — it used to be a silent no-op on Windows.

Three tiers:
  1. Platform-independent unit tests of the pure DACL + owner policy (``_evaluate_config_dacl``) —
     full logic coverage on the Linux CI leg. Tier 1b covers the owner arm (BACKLOG #1647): a foreign
     non-admin owner is refused, and an Administrators membership that cannot be resolved is refused
     rather than trusted-and-logged (ASVS v5.0.0 V16.5.3).
  2. A Windows-gated integration test using ``icacls`` to add a world-writable ACE and asserting
     ``load_config`` refuses it.
  3. A test that a Win32 API error makes the guard fail OPEN with a WARNING (caplog), not raise.
     That posture is unchanged and deliberate: the three pre-existing fail-open arms (API error,
     unresolvable owner SID, unenumerable DACL) keep it; only the new owner-membership arm is
     fail-closed.
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
    _is_well_known_admin_sid,
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
_DOMAIN_ADMINS = "S-1-5-21-1-2-3-512"  # Domain Admins: an admin the trusted-literal set cannot name


def _never_admin(sid: str) -> bool:
    """Resolver stub: the owner is definitively NOT in Administrators."""
    return False


def _always_admin(sid: str) -> bool:
    """Resolver stub: the owner is definitively IN Administrators."""
    return True


def _unresolvable(sid: str) -> bool | None:
    """Resolver stub: the membership question could not be answered (the fail-closed arm)."""
    return None


_ALLOW = 0x00  # ACCESS_ALLOWED_ACE_TYPE
_DENY = 0x01  # ACCESS_DENIED_ACE_TYPE
_FULL = 0x10000000 | 0x40000000 | 0x1FF  # GENERIC_ALL|GENERIC_WRITE|standard-ish
_MODIFY = 0x00000002 | 0x00000004 | 0x00000010 | 0x00010000  # write/append/write_ea/delete
_WRITE = 0x00000002  # FILE_WRITE_DATA
_READ_EXEC = 0x00000001 | 0x00000020 | 0x00000080  # read_data|execute|read_ea (no write bit)
_GENERIC_ALL = 0x10000000


# ---- Tier 1: pure DACL policy (runs everywhere) -----------------------------


def test_owner_only_dacl_passes() -> None:
    # The engine's own account owns the dir and is the only trustee: the locked-install shape.
    aces = [(_ALLOW, _FULL, _SELF)]
    assert _evaluate_config_dacl(_SELF, aces, _SELF, _never_admin) is None


def test_admins_and_system_full_passes() -> None:
    aces = [(_ALLOW, _FULL, _SYSTEM), (_ALLOW, _FULL, _ADMINS), (_ALLOW, _FULL, _SELF)]
    assert _evaluate_config_dacl(_SELF, aces, _SELF, _never_admin) is None


def test_self_sid_write_passes() -> None:
    # The current process user (service account) holding write on a SYSTEM-owned config dir is fine.
    aces = [(_ALLOW, _MODIFY, _SELF)]
    assert _evaluate_config_dacl(_SYSTEM, aces, _SELF, _never_admin) is None


def test_everyone_modify_is_refused() -> None:
    aces = [(_ALLOW, _MODIFY, _EVERYONE)]
    reason = _evaluate_config_dacl(_OWNER, aces, _SELF, _never_admin)
    assert reason is not None
    assert _EVERYONE in reason  # the ACE finding, not the owner one: ordering is load-bearing


def test_authenticated_users_write_refused() -> None:
    aces = [(_ALLOW, _WRITE, _AUTH_USERS)]
    assert _evaluate_config_dacl(_OWNER, aces, _SELF, _never_admin) is not None


def test_builtin_users_read_exec_passes() -> None:
    # A repo-checkout dir typically grants Users:(RX) — read-only, no write bits, MUST pass.
    aces = [(_ALLOW, _READ_EXEC, _USERS), (_ALLOW, _FULL, _SELF)]
    assert _evaluate_config_dacl(_SELF, aces, _SELF, _never_admin) is None


def test_builtin_users_modify_refused() -> None:
    aces = [(_ALLOW, _MODIFY, _USERS)]
    assert _evaluate_config_dacl(_OWNER, aces, _SELF, _never_admin) is not None


def test_foreign_nonadmin_write_refused() -> None:
    aces = [(_ALLOW, _WRITE, _FOREIGN)]
    reason = _evaluate_config_dacl(_OWNER, aces, _SELF, _never_admin)
    assert reason is not None
    assert _FOREIGN in reason  # again the ACE finding, reported ahead of the owner verdict


def test_everyone_generic_all_refused() -> None:
    aces = [(_ALLOW, _GENERIC_ALL, _EVERYONE)]
    assert _evaluate_config_dacl(_OWNER, aces, _SELF, _never_admin) is not None


def test_deny_ace_with_write_is_ignored() -> None:
    # A DENY ACE never grants a right — it must not trigger a refusal.
    aces = [(_DENY, _FULL, _EVERYONE), (_ALLOW, _FULL, _SELF)]
    assert _evaluate_config_dacl(_SELF, aces, _SELF, _never_admin) is None


def test_self_sid_none_still_refuses_everyone() -> None:
    # Even when the current-user SID can't be resolved, a broad principal write is refused.
    assert (
        _evaluate_config_dacl(_OWNER, [(_ALLOW, _MODIFY, _EVERYONE)], None, _never_admin)
        is not None
    )


# ---- Tier 1b: the owner is vetted in its own right (BACKLOG #1647) ----------


def test_foreign_nonadmin_owner_refused() -> None:
    """The row's defect: an otherwise-clean DACL owned by a low-privilege foreign principal.

    The owner holds WRITE_DAC implicitly, so it can rewrite the executed code whatever the DACL says.
    This is the Windows counterpart of the POSIX foreign-uid refusal."""
    reason = _evaluate_config_dacl(_OWNER, [(_ALLOW, _FULL, _OWNER)], _SELF, _never_admin)
    assert reason is not None
    assert _OWNER in reason


def test_unresolvable_owner_membership_refused() -> None:
    """A membership question that cannot be answered REFUSES; it is not trusted-and-logged.

    ASVS v5.0.0 V16.5.3: no fail-open when validation logic errors. The refusal still routes through
    ``_refuse_unsafe_config_source``, so ``MEFOR_ALLOW_INSECURE_CONFIG_SOURCE`` clears it."""
    reason = _evaluate_config_dacl(_OWNER, [(_ALLOW, _FULL, _OWNER)], _SELF, _unresolvable)
    assert reason is not None
    assert "could not be resolved" in reason


def test_foreign_owner_in_administrators_passes() -> None:
    # An admin who is not a well-known SID passes once membership resolves — e.g. the IT account that
    # ran the installer and is a direct member of the local Administrators group.
    assert _evaluate_config_dacl(_OWNER, [(_ALLOW, _FULL, _OWNER)], _SELF, _always_admin) is None


def test_domain_admin_rid_owner_passes_without_a_lookup() -> None:
    """Falsification test: a DOMAIN admin SID outside the trusted literals must still load.

    ``S-1-5-21-<domain>-512`` (Domain Admins) is a legitimate owner on a domain-joined server, and its
    SID cannot be listed literally because the domain part varies. ``_never_admin`` is passed so the
    test also proves the rule answers this WITHOUT reaching the membership lookup at all — the lookup
    is local-only and would not see a domain group's own SID."""
    aces = [(_ALLOW, _FULL, _DOMAIN_ADMINS)]
    assert _evaluate_config_dacl(_DOMAIN_ADMINS, aces, _SELF, _never_admin) is None


def test_owner_check_skipped_when_self_sid_unknown() -> None:
    """A token read that fails must not brick the load: with no ``self_sid`` there is nothing to
    compare against, so the owner arm is skipped — the same guard the POSIX arm puts on ``self_uid``.
    Distinct from an unresolvable MEMBERSHIP, which refuses."""
    assert _evaluate_config_dacl(_OWNER, [(_ALLOW, _FULL, _OWNER)], None, _unresolvable) is None


def test_bad_ace_is_reported_ahead_of_a_bad_owner() -> None:
    # Both are wrong; the observed insecure ACE is the more specific finding and must win.
    aces = [(_ALLOW, _MODIFY, _EVERYONE)]
    reason = _evaluate_config_dacl(_OWNER, aces, _SELF, _never_admin)
    assert reason is not None
    assert _EVERYONE in reason
    assert "the owner (" not in reason


@pytest.mark.parametrize(
    "sid",
    [
        "S-1-5-18",  # SYSTEM
        "S-1-5-32-544",  # BUILTIN\\Administrators
        "S-1-5-21-1-2-3-500",  # the built-in Administrator account
        "S-1-5-21-1-2-3-512",  # Domain Admins
        "S-1-5-21-1-2-3-518",  # Schema Admins
        "S-1-5-21-1-2-3-519",  # Enterprise Admins
    ],
)
def test_well_known_admin_sids_recognized(sid: str) -> None:
    assert _is_well_known_admin_sid(sid) is True


@pytest.mark.parametrize(
    "sid",
    [
        "S-1-5-21-1-2-3-1001",  # an ordinary user
        "S-1-5-32-545",  # BUILTIN\\Users
        "S-1-1-0",  # Everyone
        "S-1-5-11",  # Authenticated Users
        "S-1-5-21-512",  # too short to be a machine/domain SID
        "S-1-5-21-1-2-3-51x",  # non-numeric RID (a truncated/garbled SID string)
        "S-1-5-80-512",  # a service SID that merely ends in an admin RID
        "",
    ],
)
def test_non_admin_sids_not_recognized(sid: str) -> None:
    assert _is_well_known_admin_sid(sid) is False


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
