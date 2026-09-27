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
  3. Tests that a Win32 read which cannot finish REFUSES the load, and that the documented
     ``MEFOR_ALLOW_INSECURE_CONFIG_SOURCE`` escape downgrades that refusal to a WARNING (BACKLOG
     #1654). They replace only the ctypes readers, so the real Windows branch runs on every host.
     Which arms these are and why is stated once, in ADR 0036 Amendment B - this module does not
     restate the argument (CLAUDE.md section 11, SDS-3.5).
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
    _WinConfigSourceProbes,
    _WinPathSecurity,
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
    # Match the OWNER arm's own wording, not just the SID. _OWNER appears in the ACE refusal too
    # ("a non-owner, non-admin principal (...) has write access"), so asserting the SID alone would
    # still pass if `trusted.add(owner_sid)` were deleted and the ACE arm fired instead - the test
    # would silently change which arm it covers.
    assert "so it can rewrite the code this loader executes" in reason


def test_foreign_nonadmin_owner_refused_with_no_write_ace_at_all() -> None:
    """The owner arm in isolation: a read-only DACL whose OWNER is a foreign low-privilege principal.

    This is the shape the POSIX arm refuses as a 0644 file owned by another uid - every ACE is clean,
    and the refusal rests entirely on ownership. The sibling cases all pair the foreign owner with an
    owner-write ACE, so without this one no test separates the owner arm from the ACE arm."""
    reason = _evaluate_config_dacl(_OWNER, [(_ALLOW, _READ_EXEC, _USERS)], _SELF, _never_admin)
    assert reason is not None
    assert "so it can rewrite the code this loader executes" in reason


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
    """The pure policy skips the owner arm when ``self_sid`` is ``None``: there is nothing to compare
    against. The CALLER refuses an unreadable token first (Tier 3), so this skip is reached only once
    the dev/test escape has downgraded that refusal. Distinct from an unresolvable MEMBERSHIP, which
    the policy itself refuses."""
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
        # A machine/domain SID is S-1-5-21 plus THREE sub-authorities plus the RID. Anything with a
        # different count is malformed, and int() would happily parse the RID off it.
        "S-1-5-21-1-500",  # one sub-authority: too short, but long enough for a `len < 6` check
        "S-1-5-21-1-2-500",  # two sub-authorities
        "S-1-5-21-1-2-3-4-500",  # four sub-authorities
        # int() accepts all three of these and returns 500; str.isdigit() alone accepts the last.
        "S-1-5-21-1-2-3-+500",
        "S-1-5-21-1-2-3- 500",
        # Arabic-Indic digits, written as escapes so this file stays ASCII (a stock Windows cp1252
        # console raises UnicodeEncodeError on the literal form). int() reads them as 500 and
        # str.isdigit() returns True for them, which is why the check also requires isascii().
        "S-1-5-21-1-2-3-\u0665\u0660\u0660",
    ],
)
def test_non_admin_sids_not_recognized(sid: str) -> None:
    assert _is_well_known_admin_sid(sid) is False


# ---- Tier 3: a Win32 read that fails REFUSES (BACKLOG #1654) ----------------
#
# These replace the ctypes readers and nothing else: load_config runs the real Windows dispatch in
# _assert_safe_config_source_windows and the real decisions in _enforce_windows_config_source, so
# every error arm is exercised on the Linux CI leg too.

# A read that is clean in every respect: owned by the engine's own account, which alone holds write.
_CLEAN_READ = _WinPathSecurity(owner_sid=_SELF, aces=((_ALLOW, _FULL, _SELF),))

# arm name -> (what the path read returns, the process SID, text the refusal must carry)
_READ_FAILURES: dict[str, tuple[_WinPathSecurity, str | None, str]] = {
    "GetNamedSecurityInfoW error": (_WinPathSecurity(status=5), _SELF, "(Win32 error 5)"),
    "owner SID unresolvable": (
        _WinPathSecurity(owner_sid=None),
        _SELF,
        "its owner SID could not be resolved",
    ),
    "DACL not enumerable": (
        _WinPathSecurity(owner_sid=_SELF, aces=None),
        _SELF,
        "its DACL could not be enumerated",
    ),
    "process token unreadable": (_CLEAN_READ, None, "own user SID could not be read"),
    # Not a read failure, but the NULL DACL arm had no Linux-runnable test before this seam existed.
    # The message avoids the capitalised pair "NULL DACL": once the engine's logging is configured,
    # redact_untrusted rewrites that pair to "[redacted]" in the escape-downgraded WARNING.
    "NULL DACL": (_WinPathSecurity(dacl_present=False), _SELF, "it has no DACL at all"),
}


def _write_cfg(directory: Path) -> None:
    (directory / "cfg.py").write_text(
        "from messagefoundry import outbound, File\noutbound('o', File(directory='./out'))\n",
        encoding="utf-8",
    )


def _take_windows_path(
    monkeypatch: pytest.MonkeyPatch,
    read: _WinPathSecurity,
    self_sid: str | None,
    by_name: dict[str, _WinPathSecurity] | None = None,
) -> list[Path]:
    """Route load_config down the Windows branch with fake readers; return the paths read.

    ``read`` answers every path unless ``by_name`` names that path's file name."""
    import messagefoundry.config.wiring as wiring

    seen: list[Path] = []
    overrides = by_name or {}

    def _read_path(path: Path) -> _WinPathSecurity:
        seen.append(path)
        return overrides.get(path.name, read)

    probes = _WinConfigSourceProbes(
        self_sid=self_sid, read_path=_read_path, owner_in_admins=_never_admin
    )
    monkeypatch.setattr(wiring, "_win32_config_source_probes", lambda: probes)
    monkeypatch.setattr("messagefoundry.config.wiring.sys.platform", "win32")
    return seen


def test_clean_windows_read_loads(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Positive control for the refusal cases below: the same harness with a clean read loads.

    Without it, a harness that refused everything would make every refusal test pass for the wrong
    reason. It also proves the fake reader is what the real branch consulted, for the dir and cfg.py."""
    monkeypatch.delenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, raising=False)
    _write_cfg(tmp_path)
    seen = _take_windows_path(monkeypatch, _CLEAN_READ, _SELF)
    registry = load_config(tmp_path)
    assert "o" in registry.outbound
    assert seen == [tmp_path, tmp_path / "cfg.py"]


@pytest.mark.parametrize("arm", sorted(_READ_FAILURES))
def test_windows_read_failure_refuses(
    arm: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each read that cannot finish REFUSES the load; none of them warns and proceeds.

    ASVS v5.0.0 V16.5.3: no fail-open when validation logic errors (ADR 0036 Amendment B)."""
    read, self_sid, expected = _READ_FAILURES[arm]
    monkeypatch.delenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, raising=False)
    _write_cfg(tmp_path)
    _take_windows_path(monkeypatch, read, self_sid)
    with pytest.raises(WiringError) as excinfo:
        load_config(tmp_path)
    assert expected in str(excinfo.value)


@pytest.mark.parametrize("arm", sorted(_READ_FAILURES))
def test_windows_read_failure_downgraded_by_escape(
    arm: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The documented dev/test escape turns each of those refusals into a WARNING, and the load runs.

    This is what routing through ``_refuse_unsafe_config_source`` buys, and it is the same shape as the
    owner-membership arm."""
    read, self_sid, expected = _READ_FAILURES[arm]
    monkeypatch.setenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, "1")
    _write_cfg(tmp_path)
    _take_windows_path(monkeypatch, read, self_sid)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.config.wiring"):
        registry = load_config(tmp_path)
    assert "o" in registry.outbound
    assert any(
        expected in r.getMessage() and "dev/test override" in r.getMessage() for r in caplog.records
    )


_EVERYONE_WRITE_READ = _WinPathSecurity(owner_sid=_SELF, aces=((_ALLOW, _MODIFY, _EVERYONE),))


def test_escaped_read_failure_skips_only_that_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """With the escape set, a failed read skips ONE path; the paths after it are still checked.

    The directory's read fails and cfg.py grants Everyone write. Both findings must be reported, so an
    enforcer that stopped at the first downgraded refusal would fail here."""
    monkeypatch.setenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, "1")
    _write_cfg(tmp_path)
    _take_windows_path(
        monkeypatch,
        _WinPathSecurity(status=5),
        _SELF,
        by_name={"cfg.py": _EVERYONE_WRITE_READ},
    )
    with caplog.at_level(logging.WARNING, logger="messagefoundry.config.wiring"):
        load_config(tmp_path)
    messages = [r.getMessage() for r in caplog.records]
    assert any("(Win32 error 5)" in m for m in messages)
    assert any(_EVERYONE in m and "cfg.py" in m for m in messages)


def test_escaped_unreadable_token_still_runs_the_ace_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """An unreadable token costs the owner comparison only. The ACE pass must still run."""
    monkeypatch.setenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, "1")
    _write_cfg(tmp_path)
    _take_windows_path(monkeypatch, _EVERYONE_WRITE_READ, None)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.config.wiring"):
        load_config(tmp_path)
    messages = [r.getMessage() for r in caplog.records]
    assert any("own user SID could not be read" in m for m in messages)
    assert any(_EVERYONE in m and "write access" in m for m in messages)


@pytest.mark.parametrize("gone", [2, 3])  # ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND
def test_module_gone_before_its_read_is_skipped(
    gone: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A *.py removed between the glob and the read is skipped, as the POSIX arm skips it."""
    import messagefoundry.config.wiring as wiring

    monkeypatch.delenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, raising=False)
    _write_cfg(tmp_path)
    (tmp_path / "gone.py").write_text("raise RuntimeError('must not run')\n", encoding="utf-8")

    def _read_path(path: Path) -> _WinPathSecurity:
        if path.name == "gone.py":
            path.unlink()  # the race: the file disappears between the glob and the read
            return _WinPathSecurity(status=gone)
        return _CLEAN_READ

    probes = _WinConfigSourceProbes(
        self_sid=_SELF, read_path=_read_path, owner_in_admins=_never_admin
    )
    monkeypatch.setattr(wiring, "_win32_config_source_probes", lambda: probes)
    monkeypatch.setattr("messagefoundry.config.wiring.sys.platform", "win32")
    assert "o" in load_config(tmp_path).outbound


def test_not_found_on_a_path_that_still_exists_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A not-found read on a path that is still there refuses. A dangling link has this shape."""
    monkeypatch.delenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, raising=False)
    _write_cfg(tmp_path)
    _take_windows_path(
        monkeypatch, _CLEAN_READ, _SELF, by_name={"cfg.py": _WinPathSecurity(status=2)}
    )
    with pytest.raises(WiringError, match=r"\(Win32 error 2\)"):
        load_config(tmp_path)


def test_win32_error_text_is_named_in_the_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The refusal carries the system's text for the error, not the number alone."""
    monkeypatch.delenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, raising=False)
    _write_cfg(tmp_path)
    denied = _WinPathSecurity(status=5, status_text="Access is denied.")
    _take_windows_path(monkeypatch, denied, _SELF)
    with pytest.raises(WiringError, match=r"\(Win32 error 5: Access is denied\.\)"):
        load_config(tmp_path)


def test_config_directory_not_found_still_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The not-found skip is for a vanished module only. The directory itself still refuses."""
    monkeypatch.delenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, raising=False)
    _write_cfg(tmp_path)
    _take_windows_path(
        monkeypatch, _CLEAN_READ, _SELF, by_name={tmp_path.name: _WinPathSecurity(status=2)}
    )
    with pytest.raises(WiringError, match=r"\(Win32 error 2\)"):
        load_config(tmp_path)


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
