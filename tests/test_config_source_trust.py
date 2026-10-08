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
  4. The escape is clamped by the enforcement dial (vault BACKLOG #2599): it downgrades a refusal
     only when ``MEFOR_SECURITY_ENFORCEMENT=warn`` sits in the same environment. Under ``enforce``
     it is inert, the refusal names it, and the loosening registry names it only while it is live.

On win32 the suite's session fixture replaces the gate's own Windows call with one that reads a
clean access list. Every test here is a test of that gate, so the whole module asks for the real
call back (``real_config_source_readers``): tiers 3 and 4 then hand it their own readers, and tier 2
reads the real access list.
"""

from __future__ import annotations

import ast
import logging
import os
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.settings import (
    INSECURE_CONFIG_SOURCE_ESCAPE_ENV,
    SECURITY_ENFORCEMENT_ENV,
    AlertsSettings,
    ApiSettings,
    ApprovalsSettings,
    AuthSettings,
    BackupSettings,
    CertMonitorSettings,
    SecretRotationSettings,
    SecurityEnforcement,
    SecuritySettings,
    StoreSettings,
    insecure_config_source_escape_permitted,
    load_settings,
    security_loosenings,
)
from messagefoundry.config.wiring import (
    WiringError,
    _evaluate_config_dacl,
    _is_well_known_admin_sid,
    _WinConfigSourceProbes,
    _WinPathSecurity,
    load_config,
    validate_config,
)
from messagefoundry.pipeline.sandbox import (
    SandboxError,
    SandboxMode,
    SandboxPolicy,
    SandboxSession,
)

pytestmark = pytest.mark.usefixtures("real_config_source_readers")

_REPO = Path(__file__).resolve().parent.parent


@pytest.fixture
def escape_honoured(monkeypatch: pytest.MonkeyPatch) -> None:
    """The escape AND the ``warn`` dial in the environment: the one shape that downgrades a refusal."""
    monkeypatch.setenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, "1")
    monkeypatch.setenv(SECURITY_ENFORCEMENT_ENV, "warn")


@pytest.fixture
def escape_under_enforce(monkeypatch: pytest.MonkeyPatch) -> None:
    """The escape set with no ``warn`` dial beside it, which is ``enforce``, the shipped default."""
    monkeypatch.setenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, "1")
    monkeypatch.delenv(SECURITY_ENFORCEMENT_ENV, raising=False)


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


@pytest.mark.usefixtures("escape_honoured")
@pytest.mark.parametrize("arm", sorted(_READ_FAILURES))
def test_windows_read_failure_downgraded_by_escape(
    arm: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The documented dev/test escape turns each of those refusals into a WARNING, and the load runs.

    This is what routing through ``_refuse_unsafe_config_source`` buys, and it is the same shape as the
    owner-membership arm. The escape needs the ``warn`` dial beside it (tier 4)."""
    read, self_sid, expected = _READ_FAILURES[arm]
    _write_cfg(tmp_path)
    _take_windows_path(monkeypatch, read, self_sid)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.config.wiring"):
        registry = load_config(tmp_path)
    assert "o" in registry.outbound
    assert any(
        expected in r.getMessage() and "dev/test override" in r.getMessage() for r in caplog.records
    )


_EVERYONE_WRITE_READ = _WinPathSecurity(owner_sid=_SELF, aces=((_ALLOW, _MODIFY, _EVERYONE),))


@pytest.mark.usefixtures("escape_honoured")
def test_escaped_read_failure_skips_only_that_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """With the escape honoured, a failed read skips ONE path; the paths after it are still checked.

    The directory's read fails and cfg.py grants Everyone write. Both findings must be reported, so an
    enforcer that stopped at the first downgraded refusal would fail here."""
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


@pytest.mark.usefixtures("escape_honoured")
def test_escaped_unreadable_token_still_runs_the_ace_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """An unreadable token costs the owner comparison only. The ACE pass must still run."""
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


def _grant_others_write(path: Path) -> None:
    """Give a broad principal write on ``path`` for real, by the platform's own means."""
    if sys.platform != "win32":
        path.chmod(0o777)
        return
    # *S-1-5-11 = Authenticated Users (present on every box); (OI)(CI)M = Modify, inherited.
    proc = subprocess.run(
        ["icacls", str(path), "/grant", "*S-1-5-11:(OI)(CI)M"],
        capture_output=True,
        text=True,
        # Bound the subprocess (#55): icacls is normally sub-second, but an unbounded subprocess.run
        # blocks in a C-level wait that --timeout-method=thread CANNOT interrupt, so a wedged child
        # (AV scan / locked DACL on a CI runner) would hang the leg silently. A timeout raises
        # TimeoutExpired = a fast, named failure instead.
        timeout=30,
    )
    assert proc.returncode == 0, f"icacls grant failed: {proc.stdout}{proc.stderr}"


@pytest.mark.skipif(sys.platform != "win32", reason="real NTFS DACL manipulation needs Windows")
@pytest.mark.usefixtures("real_config_source_readers")
def test_world_writable_config_dir_refused_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Grant Authenticated Users Modify on the dir via icacls; load_config must refuse it."""
    # Pin the escape OFF, so a developer shell that carries it cannot turn this into a pass.
    monkeypatch.delenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, raising=False)
    _write_cfg(tmp_path)
    _grant_others_write(tmp_path)
    with pytest.raises(WiringError, match="writable-by-others|write access|see docs/SERVICE.md"):
        load_config(tmp_path)


@pytest.mark.skipif(sys.platform != "win32", reason="real NTFS DACL manipulation needs Windows")
@pytest.mark.usefixtures("real_config_source_readers", "escape_honoured")
def test_world_writable_config_dir_warns_with_escape_windows(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """With the escape set on a ``warn`` instance, the same writable dir loads with a WARNING.

    Validates the dev/test escape: fail-closed in production, but a user-writable dev/CI checkout
    (the default Windows-runner ACL) proceeds loudly instead of bricking the load."""
    _write_cfg(tmp_path)
    _grant_others_write(tmp_path)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.config.wiring"):
        registry = load_config(tmp_path)
    assert "o" in registry.outbound  # loaded despite the broad-write ACE
    assert any("dev/test override" in r.message for r in caplog.records)


@pytest.mark.skipif(sys.platform != "win32", reason="real NTFS DACL check needs Windows")
@pytest.mark.usefixtures("real_config_source_readers")
def test_owner_only_config_dir_loads_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A freshly-created owner-controlled tmp dir (no broad write ACE) loads cleanly on Windows,
    through the real readers and with no escape.

    It used to run with the suite-wide escape on, so it could not fail. ``tmp_path`` is a mode
    ``0o700`` directory, whose access list on Windows names SYSTEM, Administrators and the owner
    alone, so this does not depend on what the host's ``%TEMP%`` grants."""
    monkeypatch.delenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, raising=False)
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


# ---- Tier 4: the escape is clamped by the enforcement dial (vault BACKLOG #2599) ----
#
# The escape is an environment variable, and the check runs in every process that executes config:
# serve, a reload, the sandbox worker, and offline commands that load config before any settings.
# So the dial that unlocks it is read from the same environment. These tests use the tier 3 seam
# for the in-process cases and a real access list for the child-process ones.


def _loosening_names(sec: SecuritySettings | None = None) -> list[str]:
    """The loosening names for ``[security]`` ``sec`` with every other input at its default."""
    pairs = security_loosenings(
        sec if sec is not None else SecuritySettings(),
        StoreSettings(),
        AuthSettings(),
        AlertsSettings(),
        SecretRotationSettings(),
        cleartext_hops=(),
        expiry_relaxed_hops=(),
        hostname_unchecked_hops=(),
        query_credential_hops=(),
        unverified_db_hops=(),
        attested_hops=(),
        revocation_attested_hops=(),
        api=ApiSettings(),
        approvals=ApprovalsSettings(),
        cert_monitor=CertMonitorSettings(),
        backup=BackupSettings(),
        store_privilege=None,
        audit_chain_unkeyed=None,
        remote_debug=None,
        startup=None,
    )
    return [name for name, _ in pairs]


def _unsafe_source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A config dir whose module grants Everyone write, through the tier 3 seam."""
    _write_cfg(tmp_path)
    _take_windows_path(monkeypatch, _EVERYONE_WRITE_READ, _SELF)
    return tmp_path


@pytest.mark.parametrize("dial", [None, "enforce", "", "WARN", " warn"])
def test_escape_is_refused_under_enforce(
    dial: str | None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With the escape set and the dial not at ``warn``, an unsafe source refuses and names both.

    ``WARN`` and a padded value are here because settings refuse them too: only the exact value the
    settings loader accepts unlocks the escape."""
    monkeypatch.setenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, "1")
    if dial is None:
        monkeypatch.delenv(SECURITY_ENFORCEMENT_ENV, raising=False)
    else:
        monkeypatch.setenv(SECURITY_ENFORCEMENT_ENV, dial)
    source = _unsafe_source(tmp_path, monkeypatch)
    with pytest.raises(WiringError) as excinfo:
        load_config(source)
    refusal = str(excinfo.value)
    assert "write access" in refusal
    assert INSECURE_CONFIG_SOURCE_ESCAPE_ENV in refusal
    assert f"{SECURITY_ENFORCEMENT_ENV}=warn" in refusal
    assert INSECURE_CONFIG_SOURCE_ESCAPE_ENV not in _loosening_names()


@pytest.mark.usefixtures("escape_honoured")
def test_escape_is_honoured_under_warn_and_named_as_a_loosening(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Control for the refusal above: the same source loads at ``warn``, loudly, and is reported."""
    source = _unsafe_source(tmp_path, monkeypatch)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.config.wiring"):
        registry = load_config(source)
    assert "o" in registry.outbound
    assert any("dev/test override" in r.getMessage() for r in caplog.records)
    # An explicit, empty settings file, so a stray ./messagefoundry.toml cannot answer instead.
    empty = tmp_path / "empty.toml"
    empty.write_text("", encoding="utf-8")
    settings = load_settings(config_path=empty, environ=dict(os.environ))
    assert settings.security.enforcement is SecurityEnforcement.WARN
    names = _loosening_names(settings.security)
    assert INSECURE_CONFIG_SOURCE_ESCAPE_ENV in names
    assert "enforcement" in names


def test_safe_source_loads_with_the_escape_unset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Control: nothing set and a clean read. The load runs and the registry names nothing."""
    monkeypatch.delenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, raising=False)
    monkeypatch.delenv(SECURITY_ENFORCEMENT_ENV, raising=False)
    _write_cfg(tmp_path)
    _take_windows_path(monkeypatch, _CLEAN_READ, _SELF)
    assert "o" in load_config(tmp_path).outbound
    assert _loosening_names() == []


@pytest.mark.usefixtures("escape_under_enforce")
def test_inert_escape_does_not_refuse_a_safe_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Under ``enforce`` the escape is inert, as the TLS escape is. A safe source still loads."""
    _write_cfg(tmp_path)
    _take_windows_path(monkeypatch, _CLEAN_READ, _SELF)
    assert "o" in load_config(tmp_path).outbound


def test_unsafe_source_refusal_does_not_advertise_the_escape_when_it_is_unset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With no escape set, the refusal is the plain one. It does not point at the escape."""
    monkeypatch.delenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, raising=False)
    source = _unsafe_source(tmp_path, monkeypatch)
    with pytest.raises(WiringError) as excinfo:
        load_config(source)
    assert INSECURE_CONFIG_SOURCE_ESCAPE_ENV not in str(excinfo.value)


@pytest.mark.usefixtures("escape_under_enforce")
def test_validate_config_honours_the_clamp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``validate_config`` is the load ``check`` and ``validate`` run first. It refuses the same way,
    as a diagnostic, and executes nothing."""
    marker = tmp_path / "ran.txt"
    (tmp_path / "cfg.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran')\n", encoding="utf-8"
    )
    _take_windows_path(monkeypatch, _EVERYONE_WRITE_READ, _SELF)
    diagnostics = validate_config(tmp_path)
    assert len(diagnostics) == 1
    assert INSECURE_CONFIG_SOURCE_ESCAPE_ENV in diagnostics[0].message
    assert not marker.exists()


@pytest.mark.parametrize(
    ("escape", "dial", "permitted"),
    [
        ("1", "warn", True),
        ("true", "warn", True),
        ("1", None, False),
        ("1", "enforce", False),
        (None, "warn", False),
        ("0", "warn", False),
        (None, None, False),
    ],
)
def test_the_clamp_predicate(escape: str | None, dial: str | None, permitted: bool) -> None:
    """Both halves, and each alone. The predicate reads only the mapping it is given."""
    environ = {
        name: value
        for name, value in (
            (INSECURE_CONFIG_SOURCE_ESCAPE_ENV, escape),
            (SECURITY_ENFORCEMENT_ENV, dial),
        )
        if value is not None
    }
    assert insecure_config_source_escape_permitted(environ) is permitted


def test_the_environment_dial_is_the_dial_settings_resolve(tmp_path: Path) -> None:
    """The clamp reads the dial from the environment, so pin that the documented name is one
    settings read, and that it outranks the file. The two-spellings test below covers the other
    names the loader accepts."""
    strict = tmp_path / "strict.toml"
    strict.write_text('[security]\nenforcement = "enforce"\n', encoding="utf-8")
    resolved = load_settings(config_path=strict, environ={SECURITY_ENFORCEMENT_ENV: "warn"})
    assert resolved.security.enforcement is SecurityEnforcement.WARN
    assert load_settings(config_path=strict, environ={}).security.enforcement is (
        SecurityEnforcement.ENFORCE
    )


def test_a_file_only_warn_dial_does_not_unlock_the_escape(tmp_path: Path) -> None:
    """The stated limit: ``warn`` in the settings file alone leaves the escape inert. The check runs
    in processes that read no settings file, so the dial has to be where the escape is."""
    relaxed = tmp_path / "relaxed.toml"
    relaxed.write_text('[security]\nenforcement = "warn"\n', encoding="utf-8")
    environ = {INSECURE_CONFIG_SOURCE_ESCAPE_ENV: "1"}
    resolved = load_settings(config_path=relaxed, environ=environ)
    assert resolved.security.enforcement is SecurityEnforcement.WARN
    assert insecure_config_source_escape_permitted(environ) is False


def test_two_spellings_of_the_dial_that_disagree_leave_the_escape_inert() -> None:
    """The settings loader lowercases variable names, so on POSIX two spellings of the dial can sit
    in one environment and either may win. If any spelling it would read is not ``warn``, the
    instance may resolve to ``enforce``, so the escape must stay inert."""
    lower = SECURITY_ENFORCEMENT_ENV.replace("ENFORCEMENT", "enforcement")
    assert lower != SECURITY_ENFORCEMENT_ENV
    environ = {
        INSECURE_CONFIG_SOURCE_ESCAPE_ENV: "1",
        SECURITY_ENFORCEMENT_ENV: "warn",
        lower: "enforce",
    }
    # Control: this is a real disagreement to the loader, not a name it ignores.
    assert load_settings(environ=environ).security.enforcement is SecurityEnforcement.ENFORCE
    assert insecure_config_source_escape_permitted(environ) is False
    # The other spelling alone, at warn, is the dial too, and unlocks the escape.
    assert insecure_config_source_escape_permitted(
        {INSECURE_CONFIG_SOURCE_ESCAPE_ENV: "1", lower: "warn"}
    )


def _cli_override_sections(source: str) -> set[str]:
    """The section names a module writes as settings overrides, in these shapes: a dict literal
    whose value is a dict literal, ``x["section"]``, ``x.setdefault("section", ...)``, and a
    ``section=`` keyword to ``dict(...)`` or ``.update(...)``.

    A screen, not a proof. It misses at least a section name held in a variable or a constant, a
    dict comprehension, and a dict literal whose value is a name. It also reports any read of
    ``x["section"]``, override or not, and it does not check that the dict reaches
    ``load_settings(cli=...)``."""
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call) and (
            (isinstance(node.func, ast.Name) and node.func.id == "dict")
            or (isinstance(node.func, ast.Attribute) and node.func.attr == "update")
        ):
            found.update(kw.arg for kw in node.keywords if kw.arg is not None)
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values, strict=True):
                if (
                    isinstance(key, ast.Constant)
                    and isinstance(key.value, str)
                    and isinstance(value, ast.Dict)
                ):
                    found.add(key.value)
        elif isinstance(node, ast.Subscript):
            if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                found.add(node.slice.value)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "setdefault"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            found.add(node.args[0].value)
    return found


def test_no_command_line_override_sets_the_dial() -> None:
    """The clamp is sound because nothing outranks the environment for this dial. A command-line
    override would, so screen the two modules that build one for a ``security`` section. The
    helper's docstring lists the shapes this cannot see."""
    package = _REPO / "messagefoundry"
    main = _cli_override_sections((package / "__main__.py").read_text(encoding="utf-8"))
    checks = _cli_override_sections((package / "checks.py").read_text(encoding="utf-8"))
    # Controls first, one per module and per shape it uses, so a blind detector fails here.
    assert "store" in main
    assert "environments" in checks
    assert "security" not in main
    assert "security" not in checks


_CHILD_LOAD = (
    "import sys\n"
    "from messagefoundry.config.wiring import WiringError, load_config\n"
    "try:\n"
    "    load_config(sys.argv[1])\n"
    "except WiringError as exc:\n"
    "    print('REFUSED', exc)\n"
    "    raise SystemExit(3)\n"
    "print('LOADED')\n"
)


def _child_env(**extra: str) -> dict[str, str]:
    env = {
        name: value
        for name, value in os.environ.items()
        if name not in (INSECURE_CONFIG_SOURCE_ESCAPE_ENV, SECURITY_ENFORCEMENT_ENV)
    }
    env.update(extra)
    return env


def _load_in_a_child(source: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", _CHILD_LOAD, str(source)],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(_REPO),
        # Two of these run in one test. 25s each keeps the sum under the 60s pytest-timeout
        # watchdog, so a hung child is a named TimeoutExpired here, and leaves room for a cold
        # import on a starved runner. A warm child import takes about 1s.
        timeout=25,
    )


def test_a_fresh_process_honours_the_clamp(tmp_path: Path) -> None:
    """A child process shares nothing with this one but the environment, which is why the dial is
    read there. Two runs over one really-writable directory: refused with the escape alone, loaded
    with the escape and the ``warn`` dial. Tier 2 holds the refusal with nothing set."""
    _write_cfg(tmp_path)
    _grant_others_write(tmp_path)

    clamped = _load_in_a_child(tmp_path, _child_env(**{INSECURE_CONFIG_SOURCE_ESCAPE_ENV: "1"}))
    assert clamped.returncode == 3, clamped.stdout + clamped.stderr
    assert INSECURE_CONFIG_SOURCE_ESCAPE_ENV in clamped.stdout

    honoured = _load_in_a_child(
        tmp_path,
        _child_env(**{INSECURE_CONFIG_SOURCE_ESCAPE_ENV: "1", SECURITY_ENFORCEMENT_ENV: "warn"}),
    )
    assert honoured.returncode == 0, honoured.stdout + honoured.stderr
    assert "LOADED" in honoured.stdout


def _worker_session(config_dir: Path) -> SandboxSession:
    """A real sandbox session over ``config_dir``. ``graph=None``: these tests hold no engine graph,
    and what they read is whether the worker's own boot load ran."""
    return SandboxSession(
        SandboxPolicy(mode=SandboxMode.SUBPROCESS, wall_seconds=15.0),
        inbound="IB_T",
        config_dir=config_dir,
        env=None,
        graph=None,
    )


@pytest.mark.usefixtures("escape_under_enforce")
def test_the_sandbox_worker_boot_load_honours_the_clamp(tmp_path: Path) -> None:
    """The worker loads config in its own process at boot. With the escape set under ``enforce`` it
    refuses a writable source, and the parent sees the refusal instead of a running worker."""
    _write_cfg(tmp_path)
    _grant_others_write(tmp_path)
    session = _worker_session(tmp_path)
    try:
        with pytest.raises(SandboxError) as excinfo:
            session._spawn()
    finally:
        session.close()
    assert INSECURE_CONFIG_SOURCE_ESCAPE_ENV in str(excinfo.value)


@pytest.mark.usefixtures("escape_honoured")
def test_the_sandbox_worker_decides_as_the_engine_did_at_warn(tmp_path: Path) -> None:
    """The worker's environment is an allowlist. The escape crosses it, and so must the dial that
    unlocks it, or the worker would refuse a directory the engine loaded at ``warn``. Through the
    real spawn: with both set, the worker boots over a really-writable directory. The test above is
    the other arm, and it would pass whether or not the dial crossed."""
    _write_cfg(tmp_path)
    _grant_others_write(tmp_path)
    session = _worker_session(tmp_path)
    try:
        session._spawn()
        assert session._proc is not None and session._proc.poll() is None
    finally:
        session.close()


@pytest.mark.usefixtures("real_config_source_readers", "escape_under_enforce")
def test_the_engine_refuses_the_same_directory_with_the_escape_alone(tmp_path: Path) -> None:
    """Control for the test above. With the escape alone, the engine's own load of the same
    really-writable directory refuses, through the real readers. An engine that cannot load its
    graph has no inbound to start a worker for."""
    _write_cfg(tmp_path)
    _grant_others_write(tmp_path)
    with pytest.raises(WiringError) as excinfo:
        load_config(tmp_path)
    assert INSECURE_CONFIG_SOURCE_ESCAPE_ENV in str(excinfo.value)


@pytest.mark.parametrize("spelling", ["MEFOR_SECURITY_ENFORCEMENT", "MEFOR_SECURITY_enforcement"])
def test_every_spelling_of_the_dial_reaches_the_worker_environment(
    spelling: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The engine's check reads every spelling of the dial the settings loader would. The worker's
    environment carries each one that is set, read off the real spawn call, and nothing else of
    the engine's but the escape."""
    captured: dict[str, dict[str, str]] = {}

    class _Stop(Exception):
        pass

    def fake_popen(argv: list[str], **kwargs: Any) -> None:
        captured["env"] = kwargs["env"]
        raise _Stop

    monkeypatch.delenv(SECURITY_ENFORCEMENT_ENV, raising=False)
    monkeypatch.setenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, "1")
    monkeypatch.setenv(spelling, "warn")
    monkeypatch.setenv("MEFOR_STORE_POOL_SIZE", "7")  # any other engine variable: must not cross
    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    with pytest.raises(_Stop):
        _worker_session(tmp_path)._spawn()
    crossed = {name: value for name, value in captured["env"].items() if name.startswith("MEFOR_")}
    # Windows holds one variable under an upper-cased name, whichever spelling set it.
    as_stored = spelling.upper() if sys.platform == "win32" else spelling
    assert crossed == {INSECURE_CONFIG_SOURCE_ESCAPE_ENV: "1", as_stored: "warn"}


def test_the_loosening_page_lists_the_escape() -> None:
    """``docs/SECURITY-LOOSENING.md`` carries the variable in its switch table and as an entry, and
    the entry names the dial it needs."""
    page = (_REPO / "docs" / "SECURITY-LOOSENING.md").read_text(encoding="utf-8")
    assert f"| `{INSECURE_CONFIG_SOURCE_ESCAPE_ENV}` |" in page
    heading = f"### `{INSECURE_CONFIG_SOURCE_ESCAPE_ENV}=1`"
    assert heading in page
    entry = page.split(heading, 1)[1].split("\n### ", 1)[0]
    assert f"{SECURITY_ENFORCEMENT_ENV}=warn" in entry
