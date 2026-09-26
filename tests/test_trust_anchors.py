# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ASVS 6.7.1 (BACKLOG #285): operator-supplied trust-anchor integrity — the read-only ACL preflight,
the optional SHA-256 pin, the anchor-changed audit event, and dormant-when-unconfigured."""

from __future__ import annotations

import hashlib
import json
import os
import re
import ssl
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.api.tls import build_api_ssl_context
from messagefoundry.auth import trust_anchors as ta
from messagefoundry.auth.anchor_path import PathVerdict
from messagefoundry.auth.trust_anchors import (
    AUDIT_ACTION,
    AnchorSpec,
    TrustAnchorError,
    anchor_fingerprint,
    collect_anchor_specs,
    dacl_is_owner_only,
    enforce_anchor,
    owner_only_from_icacls,
    run_anchor_preflight,
)
from messagefoundry.config.settings import ApiSettings, AuthSettings
from messagefoundry.store import MessageStore

_posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits (icacls is the nt path)")


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "audit.db")
    yield s
    await s.close()


def _pem(tmp_path: Path, body: bytes = b"-----BEGIN CERTIFICATE-----\nAAAA\n") -> Path:
    p = tmp_path / "anchor.pem"
    p.write_bytes(body)
    return p


def _block(body: bytes) -> bytes:
    """A body the central preflight's PEM shape check accepts. Since BACKLOG #1142 slice 3 that
    preflight refuses a file with no PEM block, as every consumer does, so its tests need one."""
    return b"-----BEGIN CERTIFICATE-----\n" + body + b"\n"


def _path_ok(_p: object) -> PathVerdict:
    """A path check that passes. The row-count tests stub it for the reason they stub the ACL read:
    the real answer depends on the host's temp directory, not on the test (BACKLOG #1142)."""
    return PathVerdict(True)


async def _rows(store: MessageStore, label: str | None = None) -> list[dict]:
    rows = await store.list_audit(action=AUDIT_ACTION, limit=200)
    out = [json.loads(r["detail"]) for r in rows]
    return [d for d in out if label is None or d.get("label") == label]


# --- fingerprint + pin normalization ------------------------------------------------------------


def test_fingerprint_is_sha256_of_bytes(tmp_path: Path) -> None:
    body = b"anchor-pem-bytes"
    p = _pem(tmp_path, body)
    assert anchor_fingerprint(p) == hashlib.sha256(body).hexdigest()


def test_fingerprint_missing_raises_oserror(tmp_path: Path) -> None:
    # A missing/unreadable anchor keeps the engine's existing fail-closed OSError contract.
    with pytest.raises(OSError):
        anchor_fingerprint(tmp_path / "nope.pem")


def test_pin_accepts_colons_and_uppercase(tmp_path: Path) -> None:
    p = _pem(tmp_path, b"body")
    fp = hashlib.sha256(b"body").hexdigest()
    # Uppercase, colon-separated — normalized and matched.
    colonized = ":".join(fp[i : i + 2] for i in range(0, len(fp), 2)).upper()
    assert enforce_anchor(AnchorSpec("t", "[x]", str(p), colonized), enforcing=True) == fp


def test_malformed_pin_raises(tmp_path: Path) -> None:
    p = _pem(tmp_path, b"body")
    with pytest.raises(TrustAnchorError, match="SHA-256 hex digest"):
        enforce_anchor(AnchorSpec("t", "[x]", str(p), "not-a-real-pin"), enforcing=False)


# --- pin enforcement (always refuses on mismatch, independent of enforcement) --------------------


def test_pin_match_ok(tmp_path: Path) -> None:
    p = _pem(tmp_path, b"body")
    fp = hashlib.sha256(b"body").hexdigest()
    assert enforce_anchor(AnchorSpec("t", "[x]", str(p), fp), enforcing=True) == fp


@pytest.mark.parametrize("enforcing", [True, False])
def test_pin_mismatch_always_refuses(tmp_path: Path, enforcing: bool) -> None:
    p = _pem(tmp_path, b"body")
    wrong = hashlib.sha256(b"other").hexdigest()
    with pytest.raises(TrustAnchorError, match="does not match its configured SHA-256 pin"):
        enforce_anchor(AnchorSpec("t", "[x]", str(p), wrong), enforcing=enforcing)


def test_no_pin_is_allowed(tmp_path: Path) -> None:
    p = _pem(tmp_path, b"body")
    # Owner-only tmp file (verified: no broad-group write), no pin → passes.
    assert enforce_anchor(AnchorSpec("t", "[x]", str(p), None), enforcing=True)


# --- icacls DACL parser (pure, cross-platform) --------------------------------------------------

_PATH = r"C:\Users\svc\anchor.pem"


def _icacls(*aces: str) -> str:
    first = f"{_PATH} {aces[0]}"
    rest = "\n".join(f"    {a}" for a in aces[1:])
    body = first + ("\n" + rest if rest else "")
    return body + "\n\nSuccessfully processed 1 files; Failed processing 0 files.\n"


def test_icacls_owner_and_privileged_only_is_owner_only() -> None:
    text = _icacls(
        r"NT AUTHORITY\SYSTEM:(I)(F)",
        r"BUILTIN\Administrators:(I)(F)",
        r"DESKTOP-A\svc:(F)",
    )
    assert owner_only_from_icacls(text, anchor_path=_PATH) is True


def test_icacls_everyone_write_is_not_owner_only() -> None:
    text = _icacls(r"DESKTOP-A\svc:(F)", r"Everyone:(F)")
    assert owner_only_from_icacls(text, anchor_path=_PATH) is False


def test_icacls_users_modify_is_not_owner_only() -> None:
    text = _icacls(r"DESKTOP-A\svc:(F)", r"BUILTIN\Users:(M)")
    assert owner_only_from_icacls(text, anchor_path=_PATH) is False


def test_icacls_users_read_only_is_owner_only() -> None:
    # A CA is public; group READ is fine — only group WRITE is the tamper threat.
    text = _icacls(r"DESKTOP-A\svc:(F)", r"BUILTIN\Users:(RX)")
    assert owner_only_from_icacls(text, anchor_path=_PATH) is True


def test_icacls_path_containing_users_is_not_a_false_positive() -> None:
    # The path literally contains \Users; only the owner has an ACE → owner-only.
    text = _icacls(r"DESKTOP-A\svc:(F)")
    assert owner_only_from_icacls(text, anchor_path=_PATH) is True


def test_icacls_deny_ace_is_ignored() -> None:
    text = _icacls(r"DESKTOP-A\svc:(F)", r"Everyone:(DENY)(W)")
    assert owner_only_from_icacls(text, anchor_path=_PATH) is True


def test_icacls_unresolved_broad_sid_write_is_not_owner_only() -> None:
    text = _icacls(r"DESKTOP-A\svc:(F)", r"*S-1-1-0:(W)")
    assert owner_only_from_icacls(text, anchor_path=_PATH) is False


# The nt branch shells out; the POSIX branch reads mode bits. Run this where os.name == "nt" is REAL
# rather than monkeypatched, matching tests/test_store.py's _windows_only note (forcing it makes
# pathlib instantiate WindowsPath and crash pytest on Linux).
_windows_only = pytest.mark.skipif(os.name != "nt", reason="the icacls DACL read is the nt path")


@_windows_only
def test_dacl_read_pins_icacls_to_the_system_directory(monkeypatch: pytest.MonkeyPatch) -> None:
    # This call's OUTPUT decides whether a TLS trust anchor is owner-only, so it must name icacls by
    # absolute path: CreateProcess resolves an unqualified name through a search path that reaches the
    # caller's working directory, and a planted icacls.exe printing a clean DACL would turn a
    # group-writable anchor into an accepted one (BACKLOG #1769). Same pin as store._secure_file,
    # which writes a DACL rather than reading one.
    from messagefoundry import service_status

    captured: list[list[str]] = []

    class _R:
        returncode = 0
        stdout = _icacls(r"DESKTOP-A\svc:(F)")
        stderr = ""

    monkeypatch.setattr(ta.subprocess, "run", lambda argv, **kw: (captured.append(argv), _R())[1])
    # _PATH keeps the faked stdout's own prefix, so the parse behaves as it would on a real read.
    assert dacl_is_owner_only(_PATH) is True
    # Guard the guard: with no call recorded, every assertion below passes over nothing.
    assert captured, "icacls was never invoked; the pin assertions would pass vacuously"
    program = captured[0][0]
    assert os.path.isabs(program), f"icacls must be pinned to an absolute path, got {program!r}"
    assert os.path.basename(program).lower() == "icacls.exe"
    # It must be the OS-reported system directory, not merely some absolute path. Compared against
    # _system_dir rather than a literal "System32" because GetSystemDirectoryW answers "SysWOW64" to
    # a 32-bit process, and that is the correct system directory there; _system_dir's own behaviour
    # is tested beside it in tests/test_service_control.py.
    assert os.path.dirname(program) == service_status._system_dir()


# --- tri-state: "I could not determine this" is not "yes" (BACKLOG #1142, ASVS 6.7.1) -----------


def test_icacls_empty_output_is_indeterminate() -> None:
    # No output at all: the parser saw nothing it could attribute to a principal, so it must not
    # assert owner-only storage. Before #1142 this returned True.
    assert owner_only_from_icacls("", anchor_path=_PATH) is None


def test_icacls_unparseable_output_is_indeterminate() -> None:
    text = "this is not icacls output\nnor is this line\n"
    assert owner_only_from_icacls(text, anchor_path=_PATH) is None


def test_icacls_trailer_without_any_ace_is_indeterminate() -> None:
    # The success trailer alone proves icacls ran; it proves nothing about the DACL.
    text = f"{_PATH}\n\nSuccessfully processed 1 files; Failed processing 0 files.\n"
    assert owner_only_from_icacls(text, anchor_path=_PATH) is None


def test_icacls_ace_with_no_principal_token_is_indeterminate() -> None:
    # A rights blob with nothing in front of it cannot be attributed to anybody.
    text = f"{_PATH} :(F)\n\nSuccessfully processed 1 files; Failed processing 0 files.\n"
    assert owner_only_from_icacls(text, anchor_path=_PATH) is None


def test_icacls_one_parsed_ace_is_determined() -> None:
    # The control for the four tests above: one attributable ACE and no broad-principal write is a
    # real, determined "owner-only".
    assert owner_only_from_icacls(_icacls(r"DESKTOP-A\svc:(F)"), anchor_path=_PATH) is True


# --- broad principals beyond Everyone / Users (BACKLOG #1142) -----------------------------------


def test_icacls_interactive_modify_is_not_owner_only() -> None:
    text = _icacls(r"DESKTOP-A\svc:(F)", r"NT AUTHORITY\INTERACTIVE:(I)(M)")
    assert owner_only_from_icacls(text, anchor_path=_PATH) is False


def test_icacls_service_modify_is_not_owner_only() -> None:
    text = _icacls(r"DESKTOP-A\svc:(F)", r"NT AUTHORITY\SERVICE:(I)(M)")
    assert owner_only_from_icacls(text, anchor_path=_PATH) is False


def test_icacls_batch_modify_is_not_owner_only() -> None:
    text = _icacls(r"DESKTOP-A\svc:(F)", r"NT AUTHORITY\BATCH:(I)(M)")
    assert owner_only_from_icacls(text, anchor_path=_PATH) is False


def test_icacls_creator_owner_grants_nobody_so_stays_owner_only() -> None:
    # CREATOR OWNER (S-1-3-0) is a placeholder no logon token carries, so an ACE for it on a file
    # grants nobody anything. wiring.py trusts it for the same reason. Reading it as broad would make
    # enforce refuse a secure anchor.
    text = _icacls(r"DESKTOP-A\svc:(F)", r"CREATOR OWNER:(I)(F)")
    assert owner_only_from_icacls(text, anchor_path=_PATH) is True
    text = _icacls(r"DESKTOP-A\svc:(F)", r"*S-1-3-0:(F)")
    assert owner_only_from_icacls(text, anchor_path=_PATH) is True


@pytest.mark.parametrize(
    "principal",
    [
        r"NT AUTHORITY\NETWORK",
        r"NT AUTHORITY\ANONYMOUS LOGON",
        r"NT AUTHORITY\Local account",
        r"BUILTIN\Guests",
        r"CORP\Domain Users",
        r"CORP\Domain Guests",
    ],
)
def test_icacls_more_broad_names_write_is_not_owner_only(principal: str) -> None:
    text = _icacls(r"DESKTOP-A\svc:(F)", f"{principal}:(M)")
    assert owner_only_from_icacls(text, anchor_path=_PATH) is False


@pytest.mark.parametrize(
    "principal",
    [
        r"DESKTOP-A\usersync",
        r"CORP\everyone-admins",
        r"NT AUTHORITY\Local account and member of Administrators group",
        r"NT AUTHORITY\NETWORK SERVICE",
    ],
)
def test_icacls_broad_names_match_whole_not_as_substrings(principal: str) -> None:
    # A substring match read an ordinary account such as DESKTOP-A\usersync as \Users, and a false
    # "broad" makes enforce refuse a secure anchor.
    text = _icacls(r"DESKTOP-A\svc:(F)", f"{principal}:(F)")
    assert owner_only_from_icacls(text, anchor_path=_PATH) is True


@pytest.mark.parametrize("rights", ["(D)", "(DE)", "(I)(DE,RC)"])
def test_icacls_broad_delete_is_not_owner_only(rights: str) -> None:
    # Delete-then-plant replaces the anchor, and wiring.py's write mask counts DELETE too.
    text = _icacls(r"DESKTOP-A\svc:(F)", f"Everyone:{rights}")
    assert owner_only_from_icacls(text, anchor_path=_PATH) is False


@pytest.mark.parametrize(
    "sid",
    [
        "*S-1-5-4",
        "*S-1-5-6",
        "*S-1-5-3",
        "*S-1-1-0",
        "*S-1-5-11",
        "*S-1-5-32-545",
        "*S-1-5-32-546",
        "*S-1-5-2",
        "*S-1-5-7",
        "*S-1-5-113",
        "S-1-5-21-1-2-3-513",
        "S-1-5-21-1-2-3-514",
    ],
)
def test_icacls_broad_sid_write_is_not_owner_only(sid: str) -> None:
    text = _icacls(r"DESKTOP-A\svc:(F)", f"{sid}:(F)")
    assert owner_only_from_icacls(text, anchor_path=_PATH) is False


@pytest.mark.parametrize(
    "sid", ["*S-1-5-32-544", "*S-1-5-18", "*S-1-5-64", "*S-1-5-114", "S-1-5-21-1-2-3-5130"]
)
def test_icacls_trusted_or_unrelated_sid_is_not_matched_as_broad(sid: str) -> None:
    # A SID is matched WHOLE, never as a substring: "S-1-5-3" (BATCH) is a leading substring of
    # "S-1-5-32-544" (BUILTIN\Administrators, deliberately trusted) and "S-1-5-6" (SERVICE) of
    # "S-1-5-64", and "S-1-5-11" (Authenticated Users) of "S-1-5-114" (local administrators). A
    # substring set would refuse the administrators ACE that ships on every anchor. The last case
    # checks a domain RID is matched whole too: RID 5130 is not Domain Users (513).
    text = _icacls(r"DESKTOP-A\svc:(F)", f"{sid}:(F)")
    assert owner_only_from_icacls(text, anchor_path=_PATH) is True


def test_icacls_localized_broad_name_is_indeterminate_not_owner_only() -> None:
    # icacls resolves SIDs to LOCALIZED names by default, so the name half of the broad-principal
    # set cannot be complete across locales: a German "Jeder" (Everyone) is not recognised by name.
    # It is a BARE name, though, and the owner always prints qualified (COMPUTER\user), so a bare
    # name the parser does not know holding a write right is an unrecognised group: "cannot tell",
    # never "owner-only". The SID form of the same principal is recognised and settles it.
    assert owner_only_from_icacls(_icacls(r"Jeder:(F)"), anchor_path=_PATH) is None
    assert owner_only_from_icacls(_icacls(r"*S-1-1-0:(F)"), anchor_path=_PATH) is False


def test_icacls_unknown_bare_name_without_write_stays_owner_only() -> None:
    # The control for the test above: the rule fires on a WRITE right, not on the bare name alone.
    text = _icacls(r"DESKTOP-A\svc:(F)", r"Jeder:(RX)")
    assert owner_only_from_icacls(text, anchor_path=_PATH) is True


def test_icacls_bare_unresolved_sid_is_not_an_unknown_bare_name() -> None:
    # Measured on Windows 11: plain icacls prints an unresolvable SID with no leading "*". It is a
    # SID, not a bare display name, so the bare-name rule must not fire on it; only the well-known
    # broad SIDs flag, as before.
    text = _icacls(r"DESKTOP-A\svc:(F)", r"S-1-5-21-1-2-3-1001:(I)(M)", r"S-1-15-3-1-2:(I)(F)")
    assert owner_only_from_icacls(text, anchor_path=_PATH) is True
    assert owner_only_from_icacls(_icacls(r"S-1-1-0:(F)"), anchor_path=_PATH) is False


def test_icacls_owner_rights_is_the_owner_not_an_unknown_bare_name() -> None:
    # Measured on Windows 11: a pytest temp file lists SYSTEM, Administrators and OWNER RIGHTS only.
    # OWNER RIGHTS (S-1-3-4) is the owner itself, so it must not make the read indeterminate.
    text = _icacls(
        r"NT AUTHORITY\SYSTEM:(I)(F)", r"BUILTIN\Administrators:(I)(F)", r"OWNER RIGHTS:(I)(F)"
    )
    assert owner_only_from_icacls(text, anchor_path=_PATH) is True


def test_icacls_unknown_bare_name_does_not_outvote_a_recognised_broad_write() -> None:
    # A recognised broad write is a determined False, whatever else the DACL holds.
    text = _icacls(r"Jeder:(F)", r"BUILTIN\Users:(M)")
    assert owner_only_from_icacls(text, anchor_path=_PATH) is False


# The six raw inputs the BACKLOG #1142 slice-1 verification probed against the unfixed parser, which
# returned True for the first four. Passed raw, with no path line, exactly as probed.
@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("", None),
        ("garbage", None),
        ("Jeder:(F)", None),
        (r"NT AUTHORITY\INTERACTIVE:(I)(M)", False),
        ("Everyone:(F)", False),
        (r"BUILTIN\Users:(M)", False),
    ],
)
def test_icacls_slice1_probes_never_read_as_owner_only(text: str, expected: bool | None) -> None:
    assert owner_only_from_icacls(text, anchor_path=_PATH) is expected


@_windows_only
def test_dacl_read_of_a_non_ascii_path_does_not_crash(tmp_path: Path) -> None:
    # icacls writes the OEM code page. Decoded as ANSI, a u-umlaut came back as byte 0x81, stdout
    # arrived as None, and the parse raised AttributeError, which no caller catches: a startup crash
    # rather than a degrade. The echoed path must also decode to the path passed, so it is stripped
    # and the verdict matches the same file under an ASCII name.
    d = tmp_path / "Schlüssel"
    d.mkdir()
    p = _pem(d, b"x")
    ascii_twin = _pem(tmp_path, b"x")
    assert dacl_is_owner_only(p) == dacl_is_owner_only(ascii_twin)


# --- line 1: the path echo icacls prints is not always the path we passed (BACKLOG #1142) --------
# icacls echoes the path in the OEM code page. A character outside it comes back as "?" (two for a
# character outside the BMP) or as a best-fit look-alike, so the exact path cannot be stripped from
# line 1. Measured on Windows 11 (OEM 437): "icprobe_<CJK x2>" echoed "icprobe_??", an emoji "??",
# and "<l-stroke><A-macron>" "lA". Continuation lines are padded to the ECHOED width.

_CJK_PATH = "C:\\Users\\svc\\\u65e5\u672c\\anchor.pem"
_CJK_ECHO = "C:\\Users\\svc\\??\\anchor.pem"


def _icacls_echo(echo: str, *aces: str) -> str:
    pad = " " * (len(echo) + 1)
    body = "\n".join([f"{echo} {aces[0]}", *(pad + a for a in aces[1:])])
    return body + "\n\nSuccessfully processed 1 files; Failed processing 0 files\n"


@pytest.mark.parametrize(
    "principal",
    ["Everyone", r"NT AUTHORITY\INTERACTIVE", "*S-1-1-0", "S-1-1-0", r"BUILTIN\Users"],
)
def test_icacls_line1_broad_write_behind_an_oem_path_echo_is_not_owner_only(
    principal: str,
) -> None:
    # The regression this slice's first cut introduced: the echo did not match the path passed, so
    # nothing was stripped, the principal read as "<path> everyone", and whole-token matching missed
    # it. The head before this fix answered True for Everyone; the base 8d08d420c answered False.
    text = _icacls_echo(_CJK_ECHO, f"{principal}:(M)", r"DESKTOP-A\svc:(F)")
    assert owner_only_from_icacls(text, anchor_path=_CJK_PATH) is False


@pytest.mark.parametrize(
    "principal",
    [
        "Everyone",
        r"NT AUTHORITY\INTERACTIVE",
        "*S-1-1-0",
        "S-1-5-21-1-2-3-513",
        r"BUILTIN\Users",
        r"CORP\Domain Users",
    ],
)
def test_icacls_line1_broad_write_behind_an_echo_that_matches_nothing_is_not_owner_only(
    principal: str,
) -> None:
    # Where not even the lenient pattern matches, nobody knows where the principal starts. A broad
    # principal at the END of line 1 must still be seen: the principal always comes last.
    text = _icacls_echo(r"C:\Other\place.pem", f"{principal}:(M)", r"DESKTOP-A\svc:(F)")
    assert owner_only_from_icacls(text, anchor_path=_PATH) is False


def test_icacls_unmatched_echo_does_not_read_a_multi_word_group_by_its_last_word() -> None:
    # The fallback takes a group's leaf after the last backslash, never after the last space, so
    # "Power Users" is not read as "Users". Its write is still unattributable, so None.
    text = _icacls_echo(r"C:\Other\place.pem", r"CORP\Power Users:(M)", r"DESKTOP-A\svc:(F)")
    assert owner_only_from_icacls(text, anchor_path=_PATH) is None


def test_icacls_lenient_echo_match_must_agree_with_the_continuation_indent() -> None:
    # An echo NARROWER than the path lets the lenient pattern run past it into a principal that has
    # a space in it: five wildcards eat "?? NT", and "AUTHORITY\INTERACTIVE" is a name no set knows.
    # The continuation indent is where icacls says the principal starts, so a disagreement is caught.
    path = "C:\\x\\" + "\u65e5" * 5
    echo = "C:\\x\\??"
    text = _icacls_echo(echo, r"NT AUTHORITY\INTERACTIVE:(M)", r"DESKTOP-A\svc:(F)")
    assert owner_only_from_icacls(text, anchor_path=path) is False
    # The same line with no continuation line to check against: the end-of-line check catches it.
    single = f"{echo} NT AUTHORITY\\INTERACTIVE:(M)\n"
    assert owner_only_from_icacls(single, anchor_path=path) is False
    # A non-broad principal behind a disagreeing indent is unattributable, never owner-only. Without
    # the indent check this read "AUTHORITY\SYSTEM", a qualified name, and answered True.
    text = _icacls_echo(echo, r"NT AUTHORITY\SYSTEM:(F)", r"DESKTOP-A\svc:(F)")
    assert owner_only_from_icacls(text, anchor_path=path) is None


@pytest.mark.parametrize("sep", ["\u2028", "\u2029", "\x85", "\x1c"])
def test_icacls_path_holding_a_unicode_line_separator_stays_on_line_1(sep: str) -> None:
    # str.splitlines() splits on these as well as on newline, so a path holding one split line 1
    # in two and read its ACE as a continuation line with the path still on its front.
    path = f"C:\\x\\a{sep}b\\anchor.pem"
    text = _icacls_echo(path, "Everyone:(M)", r"DESKTOP-A\svc:(F)")
    assert owner_only_from_icacls(text, anchor_path=path) is False


def test_icacls_unmatched_echo_of_a_long_non_bmp_path_does_not_backtrack() -> None:
    # A one-or-two quantifier per character outside the BMP backtracked through 2^n splits on a
    # failed match: measured 2 s at 28 emoji. The pattern is fixed-width now, so this is instant;
    # the suite's 60 s per-test timeout is the guard.
    path = "C:\\x\\" + "\U0001f600" * 40 + "\\a.pem"
    text = _icacls_echo("C:\\x\\" + "?" * 80 + "\\b.pem", r"DESKTOP-A\svc:(F)")
    assert owner_only_from_icacls(text, anchor_path=path) is None


@pytest.mark.parametrize(
    ("path", "echo"),
    [
        (_CJK_PATH, _CJK_ECHO),
        ("C:\\Users\\svc\\\U0001f600\\anchor.pem", "C:\\Users\\svc\\??\\anchor.pem"),
        ("C:\\Users\\svc\\\u0142\u0100\\anchor.pem", "C:\\Users\\svc\\lA\\anchor.pem"),
    ],
)
def test_icacls_line1_owner_behind_an_oem_echo_is_still_read(path: str, echo: str) -> None:
    # The control for the test above: the echo is matched leniently, so the owner's line-1 ACE is
    # still attributed and a clean DACL is a determined True, not an indeterminate one.
    text = _icacls_echo(echo, r"DESKTOP-A\svc:(F)", r"NT AUTHORITY\SYSTEM:(I)(F)")
    assert owner_only_from_icacls(text, anchor_path=path) is True
    # And the lenient match is real: a broad write on line 1 is still seen through it.
    text = _icacls_echo(echo, r"CORP\Domain Users:(M)", r"DESKTOP-A\svc:(F)")
    assert owner_only_from_icacls(text, anchor_path=path) is False


def test_icacls_line1_write_that_cannot_be_attributed_is_indeterminate() -> None:
    # An echo that matches nothing leaves line 1's principal unknown. A write grant there must never
    # read as owner-only, even when the principal it ends in is not a broad one.
    text = _icacls_echo(r"C:\Other\place.pem", r"DESKTOP-A\svc:(F)", r"NT AUTHORITY\SYSTEM:(I)(F)")
    assert owner_only_from_icacls(text, anchor_path=_PATH) is None
    # A line-1 ACE with no write right cannot grant write, whoever holds it.
    text = _icacls_echo(r"C:\Other\place.pem", r"DESKTOP-A\svc:(RX)", r"NT AUTHORITY\SYSTEM:(I)(F)")
    assert owner_only_from_icacls(text, anchor_path=_PATH) is True


def test_icacls_path_is_stripped_from_line_1_only() -> None:
    # A short relative path must not cut the front off a principal on a later line: "NT" stripped
    # from "NT AUTHORITY\INTERACTIVE" left "AUTHORITY\INTERACTIVE", which no set knows.
    text = _icacls_echo("NT", r"DESKTOP-A\svc:(F)", r"NT AUTHORITY\INTERACTIVE:(I)(M)")
    assert owner_only_from_icacls(text, anchor_path="NT") is False


@_windows_only
def test_dacl_read_sees_a_line1_broad_write_on_a_path_outside_the_oem_code_page(
    tmp_path: Path,
) -> None:
    # The end-to-end form of the tests above, on a real icacls read. An explicit ACE lists before
    # the inherited ones, so the Everyone grant lands on line 1, behind a path echo of "??" wherever
    # the OEM code page lacks these characters.
    import subprocess

    name = "\u65e5\u672c"
    try:
        name.encode("oem")
    except UnicodeEncodeError:
        pass
    else:
        pytest.skip("this host's OEM code page holds the path, so icacls echoes it verbatim")
    d = tmp_path / name
    d.mkdir()
    p = _pem(d, b"x")
    subprocess.run(["icacls", str(p), "/grant", "*S-1-1-0:(M)"], check=True, capture_output=True)
    listing = subprocess.run(
        ["icacls", str(p)], capture_output=True, encoding="oem", errors="replace", check=True
    ).stdout
    # Where icacls prints the English name, the grant must be seen: False. A host that localizes
    # Everyone may answer None (an unrecognised bare name), but never True.
    if " Everyone:(M)" in listing.split("\n", 1)[0]:
        assert dacl_is_owner_only(p) is False
    else:
        assert dacl_is_owner_only(p) is not True


@_posix_only
def test_posix_mode_owner_only(tmp_path: Path) -> None:
    p = _pem(tmp_path, b"x")
    os.chmod(p, 0o600)
    assert dacl_is_owner_only(p) is True
    os.chmod(p, 0o644)  # group/other READ but not write → still owner-only-writable
    assert dacl_is_owner_only(p) is True
    os.chmod(p, 0o666)  # group + other WRITE → not owner-only
    assert dacl_is_owner_only(p) is False
    os.chmod(p, 0o620)  # group WRITE → not owner-only
    assert dacl_is_owner_only(p) is False


# --- ACL enforcement fork: refuse at enforce, warn at warn (dacl monkeypatched) -----------------


def test_group_writable_refuses_at_enforce(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    p = _pem(tmp_path, b"body")
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: False)
    with pytest.raises(TrustAnchorError, match="writable by a non-owner"):
        enforce_anchor(AnchorSpec("t", "[x]", str(p), None), enforcing=True)


def test_group_writable_warns_at_warn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    p = _pem(tmp_path, b"body")
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: False)
    fp = enforce_anchor(AnchorSpec("t", "[x]", str(p), None), enforcing=False)
    assert fp == hashlib.sha256(b"body").hexdigest()  # started anyway
    assert any("writable by a non-owner" in r.message for r in caplog.records)


def test_indeterminate_dacl_refuses_at_enforce_and_names_both_fixes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #1142, slice 3 inverts the degrade this test used to pin. A DACL the engine could not
    read refuses at enforce, and the refusal names both ways out: move the anchor, or pin it."""
    p = _pem(tmp_path, b"body")
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: None)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)  # the ACL arm alone
    spec = AnchorSpec("t", "[api].tls_client_ca_file", str(p), None, "[api].tls_client_ca_pin")
    with pytest.raises(TrustAnchorError) as err:
        enforce_anchor(spec, enforcing=True)
    text = str(err.value)
    assert "could not settle" in text and "its permissions could not be read" in text
    assert "move the anchor" in text
    assert "set [api].tls_client_ca_pin to" in text
    assert hashlib.sha256(b"body").hexdigest() in text
    assert "enforce refuses to start" in text and text.isascii()


def test_indeterminate_dacl_with_a_matching_pin_loads_with_a_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The escape. Since slice 2 the pinned bytes are the bytes the context loads, so a matching pin
    defeats a substitution the file system would not let the engine rule out."""
    p = _pem(tmp_path, b"body")
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: None)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)
    fp = hashlib.sha256(b"body").hexdigest()
    spec = AnchorSpec("t", "[api].tls_client_ca_file", str(p), fp, "[api].tls_client_ca_pin")
    assert enforce_anchor(spec, enforcing=True) == fp
    assert "[api].tls_client_ca_pin matches the bytes read" in caplog.text


def test_indeterminate_dacl_with_a_wrong_pin_still_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The escape is a MATCHING pin, never merely a configured one."""
    p = _pem(tmp_path, b"body")
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: None)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)
    spec = AnchorSpec("t", "[x]", str(p), hashlib.sha256(b"other").hexdigest())
    for enforcing in (True, False):
        with pytest.raises(TrustAnchorError, match="does not match its configured SHA-256 pin"):
            enforce_anchor(spec, enforcing=enforcing)


def test_indeterminate_dacl_warns_at_warn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    p = _pem(tmp_path, b"body")
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: None)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)
    assert enforce_anchor(AnchorSpec("t", "[x]", str(p), None), enforcing=False)
    assert "could not settle" in caplog.text and "starting anyway" in caplog.text
    assert "pin it to" in caplog.text  # no pin setting named, so the generic spelling


def test_a_pin_does_not_excuse_an_anchor_anyone_can_replace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The escape covers what could not be READ, not what was read as insecure. Whether a pin may
    excuse a replaceable anchor is the Owner's question in the design memo, and it is not ruled."""
    p = _pem(tmp_path, b"body")
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: False)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)
    spec = AnchorSpec("t", "[x]", str(p), hashlib.sha256(b"body").hexdigest())
    with pytest.raises(TrustAnchorError, match="writable by a non-owner"):
        enforce_anchor(spec, enforcing=True)


# --- spec collection + dormancy -----------------------------------------------------------------


def test_collect_specs_dormant_when_unconfigured() -> None:
    assert collect_anchor_specs(AuthSettings(), ApiSettings()) == []


def test_collect_specs_includes_each_configured_anchor(tmp_path: Path) -> None:
    a = _pem(tmp_path, b"a")
    specs = collect_anchor_specs(
        AuthSettings(oidc_tls_ca_cert_file=str(a), ad_tls_ca_cert_file=str(a)),
        ApiSettings(tls_cert_file=str(a), tls_client_ca_file=str(a), tls_client_ca_pin="ab" * 32),
    )
    labels = {s.label for s in specs}
    assert labels == {"oidc", "ad", "api_client"}
    assert next(s for s in specs if s.label == "api_client").pin == "ab" * 32


# --- central preflight: dormant, baseline, changed, unchanged -----------------------------------


async def test_preflight_dormant_writes_no_audit(store: MessageStore) -> None:
    await run_anchor_preflight([], store, enforcing=True)
    assert await _rows(store) == []


async def test_preflight_baseline_then_unchanged_then_changed(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The row counts below are about fingerprints. Pin the ACL read so a host whose temp ACL reads
    # as indeterminate (an extra acl_indeterminate row) cannot change them.
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)  # the path arm adds rows the same way
    p = _pem(tmp_path, _block(b"v1"))
    spec = AnchorSpec("api_client", "[api].tls_client_ca_file", str(p), None)

    await run_anchor_preflight([spec], store, enforcing=True)
    rows = await _rows(store, "api_client")
    assert len(rows) == 1 and rows[0]["event"] == "observed"

    # Second load, unchanged → no new row.
    await run_anchor_preflight([spec], store, enforcing=True)
    assert len(await _rows(store, "api_client")) == 1

    # Swap the PEM on disk → the reload seam records a first-class "changed" row.
    p.write_bytes(_block(b"v2-different"))
    await run_anchor_preflight([spec], store, enforcing=True)
    rows = await _rows(store, "api_client")
    assert len(rows) == 2
    changed = rows[0]  # most-recent-first
    assert changed["event"] == "changed"
    assert changed["fingerprint"] == hashlib.sha256(_block(b"v2-different")).hexdigest()
    assert changed["previous"] == hashlib.sha256(_block(b"v1")).hexdigest()


async def test_preflight_pin_mismatch_refuses_at_reload_and_audits(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)  # same reason as the test above
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)
    p = _pem(tmp_path, _block(b"orig"))
    spec = AnchorSpec(
        "oidc", "[auth].oidc_tls_ca_cert_file", str(p), hashlib.sha256(_block(b"orig")).hexdigest()
    )
    # First load: pin matches → observed, no raise.
    await run_anchor_preflight([spec], store, enforcing=False)
    assert (await _rows(store, "oidc"))[0]["event"] == "observed"

    # The anchor is swapped out-of-band to a non-matching PEM: reload REFUSES (pin, always), and the
    # change + the pin_mismatch are both audited before the refusal.
    p.write_bytes(_block(b"substituted"))
    with pytest.raises(TrustAnchorError, match="does not match its configured SHA-256 pin"):
        await run_anchor_preflight([spec], store, enforcing=False)
    events = [r["event"] for r in await _rows(store, "oidc")]
    assert "changed" in events and "pin_mismatch" in events


async def test_preflight_acl_insecure_audited_at_warn(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    p = _pem(tmp_path, _block(b"body"))
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: False)
    spec = AnchorSpec("ad", "[auth].ad_tls_ca_cert_file", str(p), None)
    await run_anchor_preflight([spec], store, enforcing=False)  # warn: no raise
    events = {r["event"] for r in await _rows(store, "ad")}
    assert "acl_insecure" in events and "observed" in events


async def test_preflight_acl_insecure_refuses_at_enforce_after_auditing(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    p = _pem(tmp_path, _block(b"body"))
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: False)
    spec = AnchorSpec("ad", "[auth].ad_tls_ca_cert_file", str(p), None)
    with pytest.raises(TrustAnchorError, match="writable by a non-owner"):
        await run_anchor_preflight([spec], store, enforcing=True)
    # The violation is durably audited even though start is refused.
    assert "acl_insecure" in {r["event"] for r in await _rows(store, "ad")}


async def test_preflight_acl_indeterminate_is_audited_then_refuses_at_enforce(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An undeterminable ACL read writes its own audit row (BACKLOG #1142), and since slice 3 it
    then refuses at enforce. The row is written first, so the refusal is on the record."""
    p = _pem(tmp_path, _block(b"body"))
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: None)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)
    spec = AnchorSpec("api_client", "[api].tls_client_ca_file", str(p), None)
    with pytest.raises(TrustAnchorError, match="could not settle"):
        await run_anchor_preflight([spec], store, enforcing=True)
    rows = await _rows(store, "api_client")
    events = {r["event"] for r in rows}
    assert "acl_indeterminate" in events and "observed" in events
    row = next(r for r in rows if r["event"] == "acl_indeterminate")
    assert row["fingerprint"] == hashlib.sha256(_block(b"body")).hexdigest()
    assert row["enforcing"] is True and row["pinned"] is False


async def test_preflight_acl_indeterminate_loads_with_a_pin_or_at_warn(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = _block(b"body")
    p = _pem(tmp_path, body)
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: None)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)
    pinned = AnchorSpec("api_client", "[x]", str(p), hashlib.sha256(body).hexdigest())
    await run_anchor_preflight([pinned], store, enforcing=True)
    unpinned = AnchorSpec("api_client", "[x]", str(p), None)
    await run_anchor_preflight([unpinned], store, enforcing=False)
    rows = [r for r in await _rows(store, "api_client") if r["event"] == "acl_indeterminate"]
    assert [(r["pinned"], r["enforcing"]) for r in rows] == [(False, False), (True, True)]


@pytest.mark.parametrize(
    "body",
    [b"", b"# just a comment\n", b"-----BEGIN TRUSTED CERTIFICATE-----\nAAAA\n"],
)
async def test_preflight_refuses_what_the_consumer_refuses(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: bytes
) -> None:
    """Reload == start (BACKLOG #1142, slice 3, from slice 2's QA). The reload route runs only this
    preflight, so before this it accepted an anchor the next start's context builder refuses: no PEM
    block, or a TRUSTED CERTIFICATE one. It refuses at both dials, as the consumer does, after an
    audit row."""
    p = _pem(tmp_path, body)
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)
    spec = AnchorSpec("api_client", "[api].tls_client_ca_file", str(p), None)
    for enforcing in (True, False):
        with pytest.raises(TrustAnchorError) as central:
            await run_anchor_preflight([spec], store, enforcing=enforcing)
        with pytest.raises(TrustAnchorError) as consumer:
            ta.verified_anchor_cadata(spec, enforcing=enforcing)
        assert str(central.value) == str(consumer.value)
    assert "pem_refused" in {r["event"] for r in await _rows(store, "api_client")}


async def test_preflight_acl_determined_ok_writes_no_indeterminate_row(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The control for the test above: a determined, owner-only read must stay silent.
    p = _pem(tmp_path, _block(b"body"))
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)
    spec = AnchorSpec("api_client", "[api].tls_client_ca_file", str(p), None)
    await run_anchor_preflight([spec], store, enforcing=True)
    assert {r["event"] for r in await _rows(store, "api_client")} == {"observed"}


# --- construction-site enforcement in build_api_ssl_context --------------------------------------


def _self_signed_ca(tmp_path: Path) -> tuple[Path, Path]:
    """A self-signed cert + key PEM (the cert also stands in as the mTLS client-CA bundle)."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2040, 1, 1, tzinfo=datetime.UTC))
        .sign(key, hashes.SHA256())
    )
    ca = tmp_path / "ca.pem"
    ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_pem = tmp_path / "srv-key.pem"
    key_pem.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return ca, key_pem


def test_build_api_ssl_context_client_ca_pin_match(tmp_path: Path) -> None:
    ca, key = _self_signed_ca(tmp_path)
    pin = hashlib.sha256(ca.read_bytes()).hexdigest()
    ctx = build_api_ssl_context(
        ApiSettings(
            tls_cert_file=str(ca),
            tls_key_file=str(key),
            tls_client_ca_file=str(ca),
            tls_client_ca_pin=pin,
        ),
        enforcing=True,
    )
    assert ctx.verify_mode == ssl.CERT_REQUIRED


def test_build_api_ssl_context_client_ca_pin_mismatch_refuses(tmp_path: Path) -> None:
    ca, key = _self_signed_ca(tmp_path)
    with pytest.raises(TrustAnchorError, match="does not match its configured SHA-256 pin"):
        build_api_ssl_context(
            ApiSettings(
                tls_cert_file=str(ca),
                tls_key_file=str(key),
                tls_client_ca_file=str(ca),
                tls_client_ca_pin="00" * 32,
            ),
            enforcing=True,
        )


# --- the per-connection inbound CAs: collection and the graph-load preflight (BACKLOG #1142) ----------


def test_connection_anchor_spec_is_every_inbound_that_requires_a_peer_certificate(
    tmp_path: Path,
) -> None:
    """The row's predicate: tls AND tls_ca_file, whatever the connector. Not intake_auth, which only
    the HTTP listener has."""
    ca = str(tmp_path / "ca.pem")
    spec = ta.connection_anchor_spec("adt-in", {"tls": True, "tls_ca_file": ca, "tls_ca_pin": "ab"})
    assert spec == AnchorSpec(
        "inbound:adt-in",
        "inbound connection 'adt-in' tls_ca_file",
        ca,
        "ab",
        "inbound connection 'adt-in' tls_ca_pin",
    )
    assert ta.connection_anchor_spec("x", {"tls": True, "tls_ca_file": tmp_path / "ca.pem"})
    assert ta.connection_anchor_spec("x", {"tls": True}) is None  # TLS, no client certificate asked
    assert ta.connection_anchor_spec("x", {"tls": False, "tls_ca_file": ca}) is None  # no TLS
    assert ta.connection_anchor_spec("x", {"tls": True, "tls_ca_file": ""}) is None


_GRAPH_TAIL = (
    "@router('r')\n"
    "def route(msg):\n"
    "    return ['h']\n"
    "@handler('h')\n"
    "def handle(msg):\n"
    "    return Send('OUT', msg)\n"
)


def _anchored_graph(cfg: Path, ca: Path) -> None:
    """One graph with every inbound shape: MLLP, Http (its CA from env()) and DICOM require a peer
    certificate; a second MLLP has TLS and no CA; an undeployed MLLP names one and is skipped."""
    cfg.mkdir()
    (cfg / "feed.py").write_text(
        "from messagefoundry import DICOM, MLLP, File, Http, Send, env, handler, inbound, outbound\n"
        "from messagefoundry import router\n"
        f"CA = {str(ca)!r}\n"
        "inbound('ADT_IN', MLLP(port=21575, tls=True, tls_cert_file=CA, tls_ca_file=CA), "
        "router='r')\n"
        "inbound('ORDERS_IN', Http(port=21580, tls=True, tls_cert_file=CA, "
        "tls_ca_file=env('orders_ca')), router='r')\n"
        "inbound('PACS_IN', DICOM(ae_title='MEFOR', port=21104, tls=True, tls_cert_file=CA, "
        "tls_ca_file=CA, tls_ca_pin='00' * 32), router='r')\n"
        "inbound('PLAIN_IN', MLLP(port=21576, tls=True, tls_cert_file=CA), router='r')\n"
        "inbound('PARKED_IN', MLLP(port=21577, tls=True, tls_cert_file=CA, tls_ca_file=CA), "
        "router='r', deployed=False)\n"
        f"outbound('OUT', File(directory={str(cfg.parent / 'out')!r}))\n" + _GRAPH_TAIL,
        encoding="utf-8",
    )


def test_registry_anchor_specs_collects_the_three_inbound_listeners(tmp_path: Path) -> None:
    from messagefoundry.config.wiring import load_config

    ca = _pem(tmp_path, _block(b"ca"))
    cfg = tmp_path / "cfg"
    _anchored_graph(cfg, ca)
    specs = ta.registry_anchor_specs(load_config(cfg), {"orders_ca": str(ca)})
    assert {s.label: (s.path, s.pin) for s in specs} == {
        "inbound:ADT_IN": (str(ca), None),
        "inbound:ORDERS_IN": (str(ca), None),
        "inbound:PACS_IN": (str(ca), "00" * 32),
    }
    # An env() value this instance does not define is skipped here; the connector's build names it.
    assert {s.label for s in ta.registry_anchor_specs(load_config(cfg), {})} == {
        "inbound:ADT_IN",
        "inbound:PACS_IN",
    }


def _one_listener_graph(cfg: Path, ca: Path | None) -> None:
    tls = f", tls=True, tls_cert_file={str(ca)!r}, tls_ca_file={str(ca)!r}" if ca else ""
    cfg.mkdir()
    (cfg / "feed.py").write_text(
        "from messagefoundry import MLLP, File, Send, handler, inbound, outbound, router\n"
        f"inbound('ADT_IN', MLLP(port=21575{tls}), router='r')\n"
        f"outbound('OUT', File(directory={str(cfg.parent / 'out')!r}))\n" + _GRAPH_TAIL,
        encoding="utf-8",
    )


async def test_start_and_reload_refuse_an_unjudged_inbound_ca_alike(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reload == start for the per-connection anchors. The managed app's first load and an engine
    reload run the same preflight, refuse with the same text, and audit before refusing."""
    from messagefoundry.api.app import create_managed_app
    from messagefoundry.config.wiring import WiringError
    from messagefoundry.pipeline import Engine

    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: None)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)
    ca = _pem(tmp_path, _block(b"ca"))
    cfg = tmp_path / "cfg"
    _one_listener_graph(cfg, ca)

    app = create_managed_app(db_path=tmp_path / "m.db", config_dir=cfg)
    with pytest.raises(WiringError) as at_start:
        async with app.router.lifespan_context(app):
            pass

    store = await MessageStore.open(tmp_path / "e.db")
    preflight = ta.make_registry_anchor_preflight(store, enforcing=True)
    engine = Engine(store, registry_preflight=preflight)
    try:
        with pytest.raises(WiringError) as at_reload:
            await engine.reload_detail(cfg)
        assert engine.registry_runner is None  # nothing went live
        assert "acl_indeterminate" in {r["event"] for r in await _rows(store, "inbound:ADT_IN")}
    finally:
        await engine.stop()
    assert str(at_start.value) == str(at_reload.value)
    assert "inbound connection 'ADT_IN' tls_ca_file: could not settle" in str(at_start.value)


async def test_the_graph_preflight_is_dormant_without_an_inbound_ca(
    store: MessageStore, tmp_path: Path
) -> None:
    from messagefoundry.config.wiring import load_config

    cfg = tmp_path / "cfg"
    _one_listener_graph(cfg, None)
    await ta.make_registry_anchor_preflight(store, enforcing=True)(load_config(cfg), {})
    assert await _rows(store) == []


# --- QA round one (BACKLOG #1142, slice 3) ---------------------------------------------------------


def test_the_ad_anchor_has_the_pin_escape(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """BACKLOG #2034 changed this deliberately. Until then ldap3 read [auth].ad_tls_ca_cert_file by
    path on every bind, so the bytes a pin matched were not the bytes loaded, and this test pinned
    the AD anchor OUT of the pin escape. The bind now loads the checked bytes as ca_certs_data, so a
    matching pin vouches for what is loaded, exactly as it does for every other anchor. Red under:
    the AD spec still declaring loads_verified_bytes=False."""
    body = _block(b"body")
    p = _pem(tmp_path, body)
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: None)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)
    auth = AuthSettings(
        ad_tls_ca_cert_file=str(p), ad_tls_ca_cert_pin=hashlib.sha256(body).hexdigest()
    )
    (spec,) = collect_anchor_specs(auth, ApiSettings())
    assert spec.label == "ad" and spec.loads_verified_bytes is True
    enforce_anchor(spec, enforcing=True)
    # The control: with no pin, the same unjudged anchor still refuses at enforce and offers the pin.
    (unpinned,) = collect_anchor_specs(AuthSettings(ad_tls_ca_cert_file=str(p)), ApiSettings())
    with pytest.raises(TrustAnchorError) as err:
        enforce_anchor(unpinned, enforcing=True)
    text = str(err.value)
    assert "set [auth].ad_tls_ca_cert_pin to" in text and "A pin does not help here" not in text


async def test_the_start_and_the_reload_refuse_an_ad_trusted_certificate_block_alike(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #2034 changed this deliberately. The AD consumer used to read cafile=, which loads a
    TRUSTED CERTIFICATE block, so the reload let one through. It now loads cadata=, which skips the
    block silently, so the bind refuses it at construction and the reload must refuse it too."""
    from messagefoundry.auth.ldap import LdapAuthenticator

    p = _pem(tmp_path, b"-----BEGIN TRUSTED CERTIFICATE-----\nAAAA\n")
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)
    settings = AuthSettings(
        ad_enabled=True,
        ad_server="ldaps://dc1.example.test:636",
        ad_user_search_base="DC=example,DC=test",
        ad_bind_dn="CN=svc,DC=example,DC=test",
        ad_bind_password="not-a-real-password",
        ad_tls_ca_cert_file=str(p),
    )
    (ad,) = collect_anchor_specs(settings, ApiSettings())
    with pytest.raises(TrustAnchorError, match="TRUSTED CERTIFICATE"):
        await run_anchor_preflight([ad], store, enforcing=True)
    with pytest.raises(TrustAnchorError, match="TRUSTED CERTIFICATE"):
        LdapAuthenticator(settings)


@pytest.mark.parametrize(
    ("settings", "inbound"),
    [
        ({"tls": True, "tls_ca_file": "ca.pem", "tls_ca_pin": "ab" * 32}, False),  # outbound
        ({"tls": True, "tls_ca_pin": "ab" * 32}, True),  # inbound, no CA to pin
        ({"tls": False, "tls_ca_file": "ca.pem", "tls_ca_pin": "ab" * 32}, True),  # no TLS
    ],
)
def test_a_ca_pin_nothing_reads_is_refused(settings: dict, inbound: bool) -> None:
    """A tls_ca_pin set where no check reads it would read as a pin and enforce nothing."""
    with pytest.raises(ValueError, match="tls_ca_pin is set on"):
        ta.refuse_an_unread_ca_pin(settings, inbound=inbound, connector="x")
    # The control: the one place it is read, and every place it is absent.
    ta.refuse_an_unread_ca_pin(
        {"tls": True, "tls_ca_file": "ca.pem", "tls_ca_pin": "ab" * 32}, inbound=True, connector="x"
    )
    ta.refuse_an_unread_ca_pin({**settings, "tls_ca_pin": None}, inbound=inbound, connector="x")


def test_the_builders_refuse_a_ca_pin_nothing_reads() -> None:
    """Wired into both MLLP directions and both DICOM directions, before the tls check."""
    from messagefoundry.transports.dicom import _client_ssl_context, _server_ssl_context
    from messagefoundry.transports.mllp import _mllp_ssl_context

    pinned = {"tls": True, "tls_ca_file": "ca.pem", "tls_ca_pin": "ab" * 32}
    with pytest.raises(ValueError, match="MLLP destination: tls_ca_pin"):
        _mllp_ssl_context(pinned, server=False)
    with pytest.raises(ValueError, match="DICOM destination: tls_ca_pin"):
        _client_ssl_context(pinned)
    with pytest.raises(ValueError, match="MLLP listener: tls_ca_pin"):
        _mllp_ssl_context({"tls_ca_pin": "ab" * 32}, server=True)
    with pytest.raises(ValueError, match="DICOM listener: tls_ca_pin"):
        _server_ssl_context({"tls_ca_pin": "ab" * 32})


async def test_a_nul_in_an_inbound_ca_path_is_a_refused_config_not_a_crash(
    store: MessageStore, tmp_path: Path
) -> None:
    """Path.read_bytes raises ValueError on a NUL. The hook turns it into a WiringError, which the
    reload route answers with a 422 and an audit row rather than an unaudited 500."""
    from messagefoundry.config.wiring import WiringError, load_config

    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / "feed.py").write_text(
        "from messagefoundry import MLLP, File, Send, handler, inbound, outbound, router\n"
        "inbound('ADT_IN', MLLP(port=21575, tls=True, tls_cert_file='c.pem', "
        "tls_ca_file='bad\\x00path.pem'), router='r')\n"
        f"outbound('OUT', File(directory={str(tmp_path / 'out')!r}))\n" + _GRAPH_TAIL,
        encoding="utf-8",
    )
    with pytest.raises(WiringError, match="an inbound trust anchor was refused"):
        await ta.make_registry_anchor_preflight(store, enforcing=True)(load_config(cfg), {})


async def test_the_reload_route_audits_an_inbound_anchor_refusal_as_trust_anchor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One audit filter, reason="trust_anchor", sees an inbound CA refusal as it sees a settings
    anchor's. The control is the route's own invalid_config row for an empty graph."""
    import httpx

    from messagefoundry.api import create_app
    from messagefoundry.pipeline import Engine

    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: None)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)
    cfg = tmp_path / "cfg"
    _one_listener_graph(cfg, _pem(tmp_path, _block(b"ca")))
    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / "cfg.py").write_text("x = 1  # declares no connections\n", encoding="utf-8")

    store = await MessageStore.open(tmp_path / "e.db")
    engine = Engine(
        store, registry_preflight=ta.make_registry_anchor_preflight(store, enforcing=True)
    )
    try:
        transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            for target in (cfg, empty):
                r = await client.post("/config/reload", json={"config_dir": str(target)})
                assert r.status_code == 422, r.text
        rows = await store.list_audit(action="config_reload_failed", limit=10)
        reasons = sorted(json.loads(r["detail"])["reason"] for r in rows)
        assert reasons == ["invalid_config", "trust_anchor"]
    finally:
        await engine.stop()


# --- every reload route runs the settings-anchor preflight (BACKLOG #2034) -------------------------
#
# Before #2034 only the direct /config/reload route ran it, from api/, so a held reload a second
# approver released, a cluster convergence reload and a DR profile reload all skipped it. The engine
# now runs it first on every real reload, through a callback `serve` hands it, since pipeline/ must
# never import api/. Each test swaps a pinned AD anchor after "startup" and drives one route.


def _file_graph(cfg: Path) -> None:
    """A graph with a File inbound: going live binds no port, so a control can run it in parallel."""
    cfg.mkdir()
    (cfg.parent / "in").mkdir()
    (cfg / "feed.py").write_text(
        "from messagefoundry import File, Send, handler, inbound, outbound, router\n"
        f"inbound('IB_IN', File(directory={str(cfg.parent / 'in')!r}, poll_seconds=1.0), "
        "router='r')\n"
        f"outbound('OUT', File(directory={str(cfg.parent / 'out')!r}))\n" + _GRAPH_TAIL,
        encoding="utf-8",
    )


def _pinned_ad_anchor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[AnchorSpec, Path]:
    """The AD settings anchor, pinned to the bytes on disk, with its ACL and path judged clean."""
    good = _block(b"good")
    p = tmp_path / "ad-ca.pem"
    p.write_bytes(good)
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)
    auth = AuthSettings(ad_tls_ca_cert_file=str(p), ad_tls_ca_cert_pin=_sha(good))
    (spec,) = collect_anchor_specs(auth, ApiSettings())
    return spec, p


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


async def _anchored_engine(
    tmp_path: Path, spec: AnchorSpec, *, with_config_dir: bool = True
) -> tuple[Any, Path]:
    from messagefoundry.pipeline import Engine

    cfg = tmp_path / "cfg"
    _file_graph(cfg)
    store = await MessageStore.open(tmp_path / "e.db")
    engine = Engine(
        store,
        config_dir=cfg if with_config_dir else None,
        settings_preflight=ta.make_settings_anchor_preflight([spec], store, enforcing=True),
    )
    return engine, cfg


async def _convergence(engine: Any, _cfg: Path) -> None:
    await engine._converge_reload()


async def _dr_profile(engine: Any, _cfg: Path) -> None:
    await engine._dr_activate_profile()


async def _direct(engine: Any, cfg: Path) -> None:
    await engine.reload_detail(cfg, propagate=True)


_ROUTES = [
    pytest.param(_direct, id="direct"),
    pytest.param(_convergence, id="convergence"),
    pytest.param(_dr_profile, id="dr"),
]


@pytest.mark.parametrize("route", _ROUTES)
async def test_every_reload_route_refuses_a_swapped_settings_anchor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, route: Any
) -> None:
    """Red under: the engine not running the settings preflight (the convergence and DR routes then
    go live on a substituted anchor). The control is the same route before the swap, which goes
    live and records no pin mismatch."""
    from messagefoundry.config.wiring import WiringError

    spec, anchor = _pinned_ad_anchor(tmp_path, monkeypatch)
    engine, cfg = await _anchored_engine(tmp_path, spec)
    try:
        await engine.reload_detail(cfg)  # a graph goes live; the DR route only acts on a live one
        before = engine.registry_runner.registry
        await route(engine, cfg)  # the control: an unchanged anchor reloads
        live = engine.registry_runner.registry
        assert live is not before  # the control really reloaded
        assert "pin_mismatch" not in {r["event"] for r in await _rows(engine.store, "ad")}

        anchor.write_bytes(_block(b"evil"))  # swapped after the check that started it
        with pytest.raises(WiringError, match="a settings trust anchor was refused") as err:
            await route(engine, cfg)
        assert isinstance(err.value.__cause__, TrustAnchorError)
        assert engine.registry_runner.registry is live  # nothing was swapped
        assert "pin_mismatch" in {r["event"] for r in await _rows(engine.store, "ad")}
    finally:
        await engine.stop()


async def test_the_dr_profile_reload_without_a_config_dir_refuses_too(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The DR profile reload re-runs the live graph in place when the engine has no config dir, and
    that branch never reaches reload_detail, so it runs the preflight itself."""
    from messagefoundry.config.wiring import WiringError, load_config

    spec, anchor = _pinned_ad_anchor(tmp_path, monkeypatch)
    engine, cfg = await _anchored_engine(tmp_path, spec, with_config_dir=False)
    reloaded: list[object] = []
    try:
        rr = engine.add_registry(load_config(cfg))

        async def spy(registry: object) -> None:
            reloaded.append(registry)

        monkeypatch.setattr(rr, "reload", spy)
        await engine._dr_activate_profile()  # the control: an unchanged anchor re-applies
        assert len(reloaded) == 1

        anchor.write_bytes(_block(b"evil"))
        with pytest.raises(WiringError, match="a settings trust anchor was refused"):
            await engine._dr_activate_profile()
        assert len(reloaded) == 1  # the graph was not re-applied
    finally:
        await engine.stop()


async def test_a_dry_run_skips_the_settings_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """As the reload route always did: a dry run swaps nothing, and the preflight writes audit rows."""
    spec, anchor = _pinned_ad_anchor(tmp_path, monkeypatch)
    anchor.write_bytes(_block(b"evil"))
    engine, cfg = await _anchored_engine(tmp_path, spec)
    try:
        outcome = await engine.reload_detail(cfg, dry_run=True)
        assert outcome.applied is False
        assert await _rows(engine.store) == []
    finally:
        await engine.stop()


def test_the_settings_preflight_is_dormant_without_a_settings_anchor(tmp_path: Path) -> None:
    assert ta.make_settings_anchor_preflight([], object(), enforcing=True) is None  # type: ignore[arg-type]


async def test_the_settings_preflight_refuses_an_unreadable_anchor_as_an_anchor(
    store: MessageStore, tmp_path: Path
) -> None:
    """The reload route counted a missing anchor file as reason="trust_anchor"; it still does."""
    from messagefoundry.config.wiring import WiringError

    missing = AnchorSpec("ad", "[auth].ad_tls_ca_cert_file", str(tmp_path / "gone.pem"), None)
    preflight = ta.make_settings_anchor_preflight([missing], store, enforcing=True)
    assert preflight is not None
    with pytest.raises(WiringError) as err:
        await preflight()
    assert isinstance(err.value.__cause__, TrustAnchorError)
    assert isinstance(err.value.__cause__.__cause__, OSError)


async def test_the_reload_route_still_refuses_a_swapped_settings_anchor_the_same_way(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control for the move: the direct route, through the real managed-app wiring, refuses a
    swapped settings anchor with a 422 and a config_reload_failed row whose reason is trust_anchor,
    exactly as it did when it ran the preflight itself. A dry run still passes."""
    import httpx

    from messagefoundry.api.app import create_managed_app

    spec, anchor = _pinned_ad_anchor(tmp_path, monkeypatch)
    cfg = tmp_path / "cfg"
    _file_graph(cfg)
    app = create_managed_app(db_path=tmp_path / "m.db", config_dir=cfg, trust_anchor_specs=[spec])
    async with app.router.lifespan_context(app):
        engine = app.state.engine
        live = engine.registry_runner.registry
        anchor.write_bytes(_block(b"evil"))
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            r = await client.post("/config/reload", json={})
            assert r.status_code == 422, r.text
            assert r.json()["detail"] == "invalid configuration"
            dry = await client.post("/config/reload", json={"dry_run": True})
            assert dry.status_code == 200, dry.text
        assert engine.registry_runner.registry is live
        rows = await engine.store.list_audit(action="config_reload_failed", limit=10)
        assert [json.loads(r["detail"]) for r in rows] == [
            {"requested": None, "dry_run": False, "reason": "trust_anchor"}
        ]


# --- QA round two: a blank pin refuses, never reads as no pin (BACKLOG #1142) ----------------------

_BLANK_PINS = [pytest.param("", id="empty"), pytest.param("   ", id="whitespace")]

_SETTINGS_PINS = [
    pytest.param(ApiSettings, "tls_client_ca_pin", "[api].tls_client_ca_pin", id="api-client"),
    pytest.param(AuthSettings, "ad_tls_ca_cert_pin", "[auth].ad_tls_ca_cert_pin", id="ad"),
    pytest.param(AuthSettings, "oidc_tls_ca_cert_pin", "[auth].oidc_tls_ca_cert_pin", id="oidc"),
]


@pytest.mark.parametrize("blank", _BLANK_PINS)
@pytest.mark.parametrize(("model", "field", "setting"), _SETTINGS_PINS)
def test_a_blank_settings_pin_refuses_at_load(
    model: type, field: str, setting: str, blank: str
) -> None:
    """An empty or whitespace pin is a mistake, not "no pin". Absent is the only way to say none.
    Red under: the validator removed, where the blank loads and waits for the anchor code."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match=re.escape(setting) + " is set but empty"):
        model.model_validate({field: blank})
    # The controls: absent means no pin, and a real pin loads unchanged.
    assert getattr(model.model_validate({}), field) is None
    assert getattr(model.model_validate({field: "ab" * 32}), field) == "ab" * 32


def test_a_blank_settings_pin_from_the_environment_refuses(tmp_path: Path) -> None:
    """The case the finding named: an environment variable set to nothing."""
    from messagefoundry.config.settings import load_settings

    toml = tmp_path / "m.toml"
    toml.write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match=re.escape("[auth].oidc_tls_ca_cert_pin is set but empty")):
        load_settings(config_path=toml, environ={"MEFOR_AUTH_OIDC_TLS_CA_CERT_PIN": ""})
    assert load_settings(config_path=toml, environ={}).auth.oidc_tls_ca_cert_pin is None


def _mtls(pin: object) -> dict[str, object]:
    return {"tls": True, "tls_ca_file": "ca.pem", "tls_ca_pin": pin}


@pytest.mark.parametrize("blank", _BLANK_PINS)
def test_a_blank_connection_pin_refuses_in_every_builder(blank: str) -> None:
    """MLLP (and the HTTP listener, which uses its builder) and DICOM, both directions, with mTLS
    on and with TLS off. Red under: the old ``if not settings.get("tls_ca_pin")`` early return,
    which read the blank as no pin and built an unpinned context."""
    from messagefoundry.transports.dicom import _client_ssl_context, _server_ssl_context
    from messagefoundry.transports.mllp import _mllp_ssl_context

    for s in (_mtls(blank), {"tls_ca_pin": blank}):
        with pytest.raises(ValueError, match="MLLP listener: tls_ca_pin is set but empty"):
            _mllp_ssl_context(dict(s), server=True)
        with pytest.raises(ValueError, match="MLLP destination: tls_ca_pin is set but empty"):
            _mllp_ssl_context(dict(s), server=False)
        with pytest.raises(ValueError, match="DICOM listener: tls_ca_pin is set but empty"):
            _server_ssl_context(dict(s))
        with pytest.raises(ValueError, match="DICOM destination: tls_ca_pin is set but empty"):
            _client_ssl_context(dict(s))


@pytest.mark.parametrize("blank", _BLANK_PINS)
def test_a_blank_connection_pin_refuses_where_the_spec_is_built(blank: str) -> None:
    """The graph preflight reads the pin through connection_anchor_spec, so it refuses there too,
    naming the connection. Absent still means no pin."""
    with pytest.raises(ValueError, match="inbound connection 'adt-in' tls_ca_pin is set but empty"):
        ta.connection_anchor_spec("adt-in", _mtls(blank))
    with pytest.raises(ValueError, match="must be text"):
        ta.connection_anchor_spec("adt-in", _mtls(123))
    spec = ta.connection_anchor_spec("adt-in", {"tls": True, "tls_ca_file": "ca.pem"})
    assert spec is not None and spec.pin is None
    spec = ta.connection_anchor_spec("adt-in", _mtls(None))
    assert spec is not None and spec.pin is None
    ta.refuse_an_unread_ca_pin({"tls": True}, inbound=True, connector="x")  # absent: no refusal


async def test_a_blank_env_pin_refuses_the_graph_load(store: MessageStore, tmp_path: Path) -> None:
    """An env() pin whose value is empty. The preflight turns the refusal into a WiringError, which
    the reload route answers with a 422 and an audit row, and writes no anchor row first."""
    from messagefoundry.config.wiring import WiringError, load_config

    ca = _pem(tmp_path, _block(b"ca"))
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / "feed.py").write_text(
        "from messagefoundry import MLLP, File, Send, env, handler, inbound, outbound, router\n"
        f"inbound('ADT_IN', MLLP(port=21575, tls=True, tls_cert_file={str(ca)!r}, "
        f"tls_ca_file={str(ca)!r}, tls_ca_pin=env('adt_pin')), router='r')\n"
        f"outbound('OUT', File(directory={str(tmp_path / 'out')!r}))\n" + _GRAPH_TAIL,
        encoding="utf-8",
    )
    preflight = ta.make_registry_anchor_preflight(store, enforcing=True)
    with pytest.raises(
        WiringError, match="inbound connection 'ADT_IN' tls_ca_pin is set but empty"
    ):
        await preflight(load_config(cfg), {"adt_pin": ""})
    assert await _rows(store) == []


def test_a_blank_pin_without_mtls_fails_its_own_lane_not_the_graph() -> None:
    """Without tls and tls_ca_file the graph preflight does not collect the connection, so a blank
    pin there fails that connection's build alone, as an unused real pin does."""
    from messagefoundry.transports.mllp import _mllp_ssl_context

    plain = {"port": 2575, "tls_ca_pin": ""}
    assert ta.connection_anchor_spec("PLAIN", plain) is None
    with pytest.raises(ValueError, match="MLLP listener: tls_ca_pin is set but empty"):
        _mllp_ssl_context(plain, server=True)
