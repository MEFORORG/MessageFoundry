# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ASVS 6.7.1 (BACKLOG #285): operator-supplied trust-anchor integrity — the read-only ACL preflight,
the optional SHA-256 pin, the anchor-changed audit event, and dormant-when-unconfigured."""

from __future__ import annotations

import functools
import hashlib
import json
import os
import re
import shlex
import ssl
import subprocess
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel

from messagefoundry.api.tls import build_api_ssl_context
from messagefoundry.auth import trust_anchors as ta
from messagefoundry.auth.anchor_path import DIRECTORY, ChainFinding, PathVerdict
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
from messagefoundry.config.settings import ApiSettings, AuthSettings, EgressSettings
from messagefoundry.store import MessageStore

_posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits (icacls is the nt path)")


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "audit.db")
    yield s
    await s.close()


@pytest.fixture(autouse=True)
def _fresh_loaded_anchors(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each test starts with no consumer load recorded (BACKLOG #2185), whatever ran before it."""
    monkeypatch.setattr(ta, "_LOADED", {})


def _pem(tmp_path: Path, body: bytes | None = None) -> Path:
    p = tmp_path / "anchor.pem"
    p.write_bytes(_block(b"anchor") if body is None else body)
    return p


@functools.cache
def _real_ca(name: str) -> tuple[bytes, bytes]:
    """A real self-signed CA certificate named ``name`` and a real CRL it signed, both as PEM.

    Cached, so one name gives the same bytes, and so the same fingerprint, for the whole run. The
    preflight loads an anchor's text the way the consumer does since BACKLOG #2025, so a fake body
    under a CERTIFICATE label no longer passes it."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(subject)
        .last_update(now - datetime.timedelta(days=1))
        .next_update(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        crl.public_bytes(serialization.Encoding.PEM),
    )


def _block(body: bytes) -> bytes:
    """A real CA certificate PEM, one per distinct ``body``, so two bodies give two fingerprints.
    The central preflight refuses what the consumer's ``cadata=`` load refuses (BACKLOG #1142
    slice 3, and #2025), so its tests need a certificate that loads."""
    return _real_ca(body.decode("ascii"))[0]


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

    def _run(argv: list[str], **kw: object) -> _R:
        captured.append(argv)
        return _R()

    monkeypatch.setattr(subprocess, "run", _run)  # the module object trust_anchors calls
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


def test_group_writable_refusal_carries_its_own_fix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #2035: the refusal used to cite docs/security/OFF-LOOPBACK-DEPLOYMENT.md, which
    ships in neither a checkout nor a wheel. It now names this platform's fix itself."""
    p = _pem(tmp_path, b"body")
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: False)
    with pytest.raises(TrustAnchorError) as info:
        enforce_anchor(AnchorSpec("t", "[x]", str(p), None), enforcing=True)
    message = str(info.value)
    assert "OFF-LOOPBACK-DEPLOYMENT" not in message
    assert "docs/security" not in message
    lines = message.split("\n")
    if os.name == "nt":
        q = ta._ps_quote(str(p))
        # List, then un-inherit, then replace each write grant with read, then read back.
        listed = lines.index(f"  icacls {q}")
        uninherit = lines.index(f"  icacls {q} /inheritance:d")
        regrant = lines.index(f"  icacls {q} /grant:r '<principal>:(R)'")
        assert listed < uninherit < regrant
        # /remove:g would take read away too, and the engine may read the anchor through the group.
        assert "/remove:g" not in message
        # The rights it names are the check's own, so the text cannot drift from the parser.
        assert ", ".join(sorted(ta._WRITE_RIGHTS)) in message
        assert any(line.startswith(f"Then run icacls {q} again.") for line in lines)
    else:
        assert f"  chmod go-w {shlex.quote(str(p))}" in lines
    assert lines[-1] == "[security].enforcement=enforce refuses to start"


@_windows_only
def test_the_windows_acl_fix_clears_the_finding_and_keeps_read(tmp_path: Path) -> None:
    """BACKLOG #2035: run the commands the refusal gives, on a real file, and read the verdict back.
    Everyone is granted by SID so the grant lands on a localized host too; the fix names it by the
    SID form icacls accepts, the way an operator would paste the principal it listed."""
    import subprocess

    def listing() -> str:
        return subprocess.run(
            ["icacls", str(p)], capture_output=True, encoding="oem", errors="replace", check=True
        ).stdout

    p = _pem(tmp_path, b"x")
    subprocess.run(["icacls", str(p), "/grant", "*S-1-1-0:(M)"], check=True, capture_output=True)
    before = listing()
    assert dacl_is_owner_only(p) is not True
    subprocess.run(["icacls", str(p), "/inheritance:d"], check=True, capture_output=True)
    subprocess.run(["icacls", str(p), "/grant:r", "*S-1-1-0:(R)"], check=True, capture_output=True)
    after = listing()
    # A pytest temp file carries only the owner, SYSTEM and Administrators besides the test's grant
    # (measured, see _is_bare_name), so with that grant read-only the file is owner-only-writable.
    assert dacl_is_owner_only(p) is True
    # The fix keeps read. /remove:g would drop the Everyone line entirely and still pass the verdict
    # above, so this leg is what tells the two apart. It needs the English name to read the listing.
    if "Everyone:(M)" not in before:
        pytest.skip("this host localizes Everyone, so the read leg cannot be read from icacls")
    assert "Everyone:(R)" in after


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


_BAD_CRL = b"-----BEGIN X509 CRL-----\n!!!!\n-----END X509 CRL-----\n"


def _crl_only() -> bytes:
    return _real_ca("crl-test-ca")[1]


def _cert_beside_a_damaged_crl() -> bytes:
    return _real_ca("crl-test-ca")[0] + _BAD_CRL


def _certificate_with_no_end_line() -> bytes:
    cert = _real_ca("crl-test-ca")[0]
    return cert[: cert.index(b"-----END ")]


def _fixed(body: bytes) -> Any:
    return lambda: body


@pytest.mark.parametrize(
    ("shape", "tls_refuses"),
    [
        pytest.param(_fixed(b""), False, id="empty"),
        pytest.param(_fixed(b"# just a comment\n"), False, id="no PEM block"),
        pytest.param(
            _fixed(b"-----BEGIN TRUSTED CERTIFICATE-----\nAAAA\n"), False, id="TRUSTED block"
        ),
        # BACKLOG #2025: each of these has a PEM block, so the older shape checks passed it, and
        # only the consumer's own cadata= load refused it, at the next start. The first is the
        # case the item names, a CRL in the CA slot.
        pytest.param(_crl_only, True, id="a CRL alone"),
        pytest.param(_cert_beside_a_damaged_crl, True, id="a certificate beside a damaged CRL"),
        pytest.param(
            _fixed(b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"),
            True,
            id="a certificate block with a junk body",
        ),
        pytest.param(_certificate_with_no_end_line, True, id="a certificate with no END line"),
    ],
)
async def test_preflight_refuses_what_the_consumer_refuses(
    store: MessageStore,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    shape: Any,
    tls_refuses: bool,
) -> None:
    """Reload == start (BACKLOG #1142, slice 3, from slice 2's QA; and #2025). The reload route runs
    only this preflight, so before those it accepted an anchor the next start's context builder
    refuses. It refuses at both dials, as the consumer does, with the consumer's words, after an
    audit row. For the shapes the TLS load refuses, the raw load is held first, so the expectation
    is OpenSSL's, not this module's."""
    data = shape()
    if tls_refuses:
        with pytest.raises(ssl.SSLError):
            ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=data.decode())
    p = _pem(tmp_path, data)
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)
    spec = AnchorSpec("api_client", "[api].tls_client_ca_file", str(p), None)
    for enforcing in (True, False):
        with pytest.raises(TrustAnchorError) as central:
            await run_anchor_preflight([spec], store, enforcing=enforcing)
        with pytest.raises(TrustAnchorError) as consumer:
            ta.verified_anchor_cadata(spec, enforcing=enforcing)
        assert str(central.value) == str(consumer.value)
        if tls_refuses:
            assert "the TLS library cannot load the trust anchor" in str(central.value)
            assert "_ssl.c" not in str(central.value)
    assert "pem_refused" in {r["event"] for r in await _rows(store, "api_client")}


def test_a_crl_only_anchor_refuses_at_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The start half, through a real context builder: the refusal is the anchor's own error,
    naming the setting and the fix, not a bare ``ssl.SSLError`` from ``load_verify_locations``."""
    ca, key = _self_signed_ca(tmp_path)
    anchor = tmp_path / "client-ca.pem"
    anchor.write_bytes(_crl_only())
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)
    api = ApiSettings(tls_cert_file=str(ca), tls_key_file=str(key), tls_client_ca_file=str(anchor))
    with pytest.raises(TrustAnchorError, match=r"^\[api\]\.tls_client_ca_file: .*no start line"):
        build_api_ssl_context(api, enforcing=True)


@pytest.mark.parametrize("order", ["cert then crl", "crl then cert"])
async def test_a_certificate_beside_a_crl_still_passes_as_it_loads(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, order: str
) -> None:
    """The mixed file keeps its behaviour (BACKLOG #2025). Measured, ``cadata=`` loads the one
    certificate and skips a well-formed CRL block in either order, so the preflight and the
    consumer pass it too. ``cadata=`` loads no CRL: revocation comes from the CRL file setting."""
    cert, crl = _real_ca("crl-test-ca")
    data = cert + crl if order == "cert then crl" else crl + cert
    loaded = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    loaded.load_verify_locations(cadata=data.decode())
    assert loaded.cert_store_stats() == {"x509": 1, "crl": 0, "x509_ca": 1}
    p = _pem(tmp_path, data)
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)
    spec = AnchorSpec("api_client", "[api].tls_client_ca_file", str(p), None)
    await run_anchor_preflight([spec], store, enforcing=True)
    via = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    via.load_verify_locations(cadata=ta.verified_anchor_cadata(spec, enforcing=True))
    assert via.cert_store_stats() == {"x509": 1, "crl": 0, "x509_ca": 1}


@pytest.mark.parametrize(
    "begin",
    [
        pytest.param(b"-----BEGIN CERTIFICATE-----", id="plain"),
        pytest.param(b"-----BEGIN X509 CERTIFICATE-----", id="old label"),
        pytest.param(b"-----BEGIN CERTIFICATE-----  \t", id="trailing whitespace"),
        pytest.param(b"-----BEGIN CERTIFICATE-----\x1a", id="trailing control byte"),
    ],
)
async def test_a_certificate_anchor_that_loads_still_passes(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, begin: bytes
) -> None:
    """The control for the refusals above: a real certificate under each BEGIN line ``cadata=``
    loads passes the preflight, and the text handed to the consumer is unchanged. A label check
    here refused the last two, which OpenSSL loads, so the verdict is OpenSSL's own load."""
    cert = _real_ca("crl-test-ca")[0]
    data = cert.replace(b"-----BEGIN CERTIFICATE-----", begin)
    if begin.startswith(b"-----BEGIN X509"):
        data = data.replace(b"-----END CERTIFICATE-----", b"-----END X509 CERTIFICATE-----")
    loaded = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    loaded.load_verify_locations(cadata=data.decode())
    assert loaded.cert_store_stats()["x509_ca"] == 1
    p = _pem(tmp_path, data)
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)
    spec = AnchorSpec("api_client", "[api].tls_client_ca_file", str(p), None)
    await run_anchor_preflight([spec], store, enforcing=True)
    assert ta.verified_anchor_cadata(spec, enforcing=True) == data.decode()


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

    app = create_managed_app(
        db_path=tmp_path / "m.db",
        config_dir=cfg,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    with pytest.raises(WiringError) as at_start:
        async with app.router.lifespan_context(app):
            pass

    store = await MessageStore.open(tmp_path / "e.db")
    preflight = ta.make_registry_anchor_preflight(store, enforcing=True)
    engine = Engine(
        store, registry_preflight=preflight, egress_settings=EgressSettings(deny_by_default=False)
    )
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
    the pin escape still refusing the AD anchor."""
    body = _block(b"body")
    p = _pem(tmp_path, body)
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: None)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)
    auth = AuthSettings(
        ad_tls_ca_cert_file=str(p), ad_tls_ca_cert_pin=hashlib.sha256(body).hexdigest()
    )
    (spec,) = collect_anchor_specs(auth, ApiSettings())
    assert spec.label == "ad"
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
    from tests.test_tls_cipher_assertion_sites import _ad_settings

    p = _pem(tmp_path, b"-----BEGIN TRUSTED CERTIFICATE-----\nAAAA\n")
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)
    settings = _ad_settings(ad_tls_ca_cert_file=str(p))
    (ad,) = collect_anchor_specs(settings, ApiSettings())
    with pytest.raises(TrustAnchorError, match="trusted-certificate"):
        await run_anchor_preflight([ad], store, enforcing=True)
    with pytest.raises(TrustAnchorError, match="trusted-certificate"):
        LdapAuthenticator(settings)


@pytest.mark.parametrize(
    ("settings", "inbound"),
    [
        ({"tls": True, "tls_ca_pin": "ab" * 32}, False),  # outbound, no CA to pin
        ({"tls": False, "tls_ca_file": "ca.pem", "tls_ca_pin": "ab" * 32}, False),  # no TLS
        ({"tls": True, "tls_ca_pin": "ab" * 32}, True),  # inbound, no CA to pin
        ({"tls": False, "tls_ca_file": "ca.pem", "tls_ca_pin": "ab" * 32}, True),  # no TLS
    ],
)
def test_a_ca_pin_nothing_reads_is_refused(settings: dict, inbound: bool) -> None:
    """A tls_ca_pin set where no check reads it would read as a pin and enforce nothing."""
    with pytest.raises(ValueError, match="tls_ca_pin is set"):
        ta.refuse_an_unread_ca_pin(settings, inbound=inbound, connector="x")
    # The control: the places it is read, in both directions since vault BACKLOG #2371, and every
    # place it is absent.
    for direction in (True, False):
        ta.refuse_an_unread_ca_pin(
            {"tls": True, "tls_ca_file": "ca.pem", "tls_ca_pin": "ab" * 32},
            inbound=direction,
            connector="x",
        )
    ta.refuse_an_unread_ca_pin({**settings, "tls_ca_pin": None}, inbound=inbound, connector="x")


def test_the_builders_refuse_a_ca_pin_nothing_reads() -> None:
    """Wired into both MLLP directions and both DICOM directions, before the tls check. Since vault
    BACKLOG #2371 an outbound reads a pin beside tls and a tls_ca_file, so the outbound arm here is
    a pin with no CA."""
    from messagefoundry.transports.dicom import _client_ssl_context, _server_ssl_context
    from messagefoundry.transports.mllp import _mllp_ssl_context

    pinned = {"tls": True, "tls_ca_pin": "ab" * 32}
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
    with pytest.raises(WiringError, match="a connection trust anchor was refused") as err:
        await ta.make_registry_anchor_preflight(store, enforcing=True)(load_config(cfg), {})
    # BACKLOG #2183: the cause is an anchor refusal, as the settings preflight's is.
    assert isinstance(err.value.__cause__, TrustAnchorError)
    assert isinstance(err.value.__cause__.__cause__, ValueError)


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
        store,
        registry_preflight=ta.make_registry_anchor_preflight(store, enforcing=True),
        egress_settings=EgressSettings(deny_by_default=False),
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
    auth = AuthSettings(
        ad_tls_ca_cert_file=str(p), ad_tls_ca_cert_pin=hashlib.sha256(good).hexdigest()
    )
    (spec,) = collect_anchor_specs(auth, ApiSettings())
    return spec, p


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
        egress_settings=EgressSettings(deny_by_default=False),
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
        rr = engine.registry_runner
        real_reload = rr.reload
        applied: list[object] = []

        async def counting(registry: Any = None) -> None:
            applied.append(registry)
            await real_reload(registry)

        # Counted at the runner, not by registry identity: the DR route re-applies the graph it
        # already holds (vault BACKLOG #3067), so its registry object never changes.
        monkeypatch.setattr(rr, "reload", counting)
        await route(engine, cfg)  # the control: an unchanged anchor reloads
        live = engine.registry_runner.registry
        assert len(applied) == 1  # the control really reloaded
        assert "pin_mismatch" not in {r["event"] for r in await _rows(engine.store, "ad")}

        anchor.write_bytes(_block(b"evil"))  # swapped after the check that started it
        with pytest.raises(WiringError, match="a settings trust anchor was refused") as err:
            await route(engine, cfg)
        assert isinstance(err.value.__cause__, TrustAnchorError)
        assert len(applied) == 1  # nothing was re-applied
        assert engine.registry_runner.registry is live  # nothing was swapped
        assert "pin_mismatch" in {r["event"] for r in await _rows(engine.store, "ad")}
    finally:
        await engine.stop()


async def test_a_reload_refuses_a_settings_anchor_swapped_for_a_crl(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #2025 through the engine's own reload: an unpinned AD anchor swapped for a file
    holding only a CRL. The pin cannot catch it, so only the load check can. Before #2025 this
    reload went live, and the next start refused the file."""
    from messagefoundry.config.wiring import WiringError

    p = tmp_path / "ad-ca.pem"
    p.write_bytes(_block(b"good"))
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)
    (spec,) = collect_anchor_specs(AuthSettings(ad_tls_ca_cert_file=str(p)), ApiSettings())
    engine, cfg = await _anchored_engine(tmp_path, spec)
    try:
        await engine.reload_detail(cfg)  # the control: the real certificate goes live
        live = engine.registry_runner.registry
        p.write_bytes(_real_ca("good")[1])  # the same CA's CRL, in the CA slot
        with pytest.raises(WiringError, match="a settings trust anchor was refused") as err:
            await engine.reload_detail(cfg, propagate=True)
        assert isinstance(err.value.__cause__, TrustAnchorError)
        assert "the TLS library cannot load the trust anchor" in str(err.value.__cause__)
        assert engine.registry_runner.registry is live  # nothing was swapped
        assert "pem_refused" in {r["event"] for r in await _rows(engine.store, "ad")}
    finally:
        await engine.stop()


async def test_the_dr_profile_reload_without_a_config_dir_refuses_too(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The DR profile reload re-runs the live graph in place, with or without a config dir (vault
    BACKLOG #3067), and never reaches reload_detail, so it runs the preflight itself. A refusal also leaves
    the DR latch off, or the next reload would park feeds on a box that is not DR-active."""
    from messagefoundry.config.wiring import WiringError, load_config

    spec, anchor = _pinned_ad_anchor(tmp_path, monkeypatch)
    good = anchor.read_bytes()
    engine, cfg = await _anchored_engine(tmp_path, spec, with_config_dir=False)
    reloaded: list[object] = []
    try:
        rr = engine.add_registry(load_config(cfg))

        async def spy(registry: object = None) -> None:
            reloaded.append(registry)

        monkeypatch.setattr(rr, "reload", spy)
        anchor.write_bytes(_block(b"evil"))
        with pytest.raises(WiringError, match="a settings trust anchor was refused"):
            await engine._dr_activate_profile()
        assert reloaded == []  # the graph was not re-applied
        assert engine.dr_active is False  # and the latch did not stay on

        anchor.write_bytes(good)  # the control: the pinned anchor back, and it re-applies
        await engine._dr_activate_profile()
        assert len(reloaded) == 1 and engine.dr_active is True
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
    app = create_managed_app(
        db_path=tmp_path / "m.db",
        config_dir=cfg,
        trust_anchor_specs=[spec],
        allow_no_auth=True,
        egress_settings=EgressSettings(deny_by_default=False),
    )
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


# --- BACKLOG #2185: a changed settings anchor takes a restart, and a reload says so ---------------


def _events(rows: list[dict], event: str) -> list[dict]:
    return [r for r in rows if r["event"] == event]


def _settings_spec(kind: str, path: Path) -> AnchorSpec:
    """One settings anchor of each kind, through the builder ``serve`` uses for it."""
    if kind == "ad":
        spec = ta.ad_anchor_spec(AuthSettings(ad_tls_ca_cert_file=str(path)))
    elif kind == "oidc":
        spec = ta.oidc_anchor_spec(str(path), None)
    else:
        spec = ta.api_client_anchor_spec(
            ApiSettings(tls_cert_file=str(path.parent / "server.pem"), tls_client_ca_file=str(path))
        )
    assert spec is not None
    return spec


@pytest.mark.parametrize("kind", ["ad", "oidc", "api_client"])
async def test_a_reload_after_a_ca_swap_says_a_restart_is_needed_every_time(
    store: MessageStore,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    kind: str,
) -> None:
    """The consumers keep the bytes they read at start, so a reload that passes on a new CA must
    say a restart is needed, and keep saying it. Red under a compare with the last AUDITED
    fingerprint: the second reload then finds the new bytes already audited and goes quiet, which
    the ``changed`` count below shows is what that baseline does."""
    good, rotated = _block(b"good"), _block(b"rotated")
    p = tmp_path / "ca.pem"
    p.write_bytes(good)
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)
    spec = _settings_spec(kind, p)
    await run_anchor_preflight([spec], store, enforcing=True)  # serve's start preflight
    ta.verified_anchor_cadata(spec, enforcing=True)  # the consumer's load, as each one makes it
    preflight = ta.make_settings_anchor_preflight([spec], store, enforcing=True)
    assert preflight is not None

    await preflight()  # the control: an unchanged anchor says nothing
    assert _events(await _rows(store, spec.label), "restart_required") == []

    p.write_bytes(rotated)
    caplog.set_level("WARNING", logger=ta.__name__)
    await preflight()
    await preflight()  # the second reload: the audited baseline has already moved
    rows = await _rows(store, spec.label)
    assert len(_events(rows, "changed")) == 1  # the trap: the audit chain fires once
    restart = _events(rows, "restart_required")
    want = {
        "label": spec.label,
        "setting": spec.setting,
        "event": "restart_required",
        "fingerprint": hashlib.sha256(rotated).hexdigest(),
        "in_use": hashlib.sha256(good).hexdigest(),
    }
    assert restart == [want, want]
    warned = [r.getMessage() for r in caplog.records if "Restart the engine" in r.getMessage()]
    assert len(warned) == 2 and spec.setting in warned[0]

    p.write_bytes(good)  # rotated back to the bytes in use: nothing left to apply
    await preflight()
    assert len(_events(await _rows(store, spec.label), "restart_required")) == 2


async def test_a_refused_reload_writes_no_restart_row(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A swap the reload refuses is reported by the refusal. The new bytes were never accepted, so
    there is nothing a restart would apply."""
    from messagefoundry.config.wiring import WiringError

    spec, anchor = _pinned_ad_anchor(tmp_path, monkeypatch)
    ta.verified_anchor_cadata(spec, enforcing=True)  # a consumer loaded it, so a row could fire
    preflight = ta.make_settings_anchor_preflight([spec], store, enforcing=True)
    assert preflight is not None
    anchor.write_bytes(_block(b"evil"))
    with pytest.raises(WiringError):
        await preflight()
    rows = await _rows(store, "ad")
    assert _events(rows, "pin_mismatch") and not _events(rows, "restart_required")


async def test_an_anchor_no_consumer_loaded_writes_no_restart_row(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An AD CA path set while nothing binds to AD: no consumer loaded the file, so a restart would
    apply nothing, and the reload must not ask for one. The ``changed`` row is the control that the
    swap was seen."""
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)
    p = tmp_path / "unused.pem"
    p.write_bytes(_block(b"good"))
    spec = _settings_spec("ad", p)
    await run_anchor_preflight([spec], store, enforcing=True)
    preflight = ta.make_settings_anchor_preflight([spec], store, enforcing=True)
    assert preflight is not None
    p.write_bytes(_block(b"rotated"))
    await preflight()
    rows = await _rows(store, "ad")
    assert _events(rows, "changed") and not _events(rows, "restart_required")


async def test_the_reload_route_says_a_rotated_ad_ca_needs_a_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Through the real managed-app wiring and a real LDAPS authenticator: the swap lands after
    the authenticator loaded the CA, so two reloads after it both pass and both write the row."""
    import httpx

    from messagefoundry.api.app import create_managed_app
    from messagefoundry.auth.ldap import LdapAuthenticator
    from tests.test_tls_cipher_assertion_sites import _ad_settings

    p = tmp_path / "ad-ca.pem"
    p.write_bytes(_block(b"good"))
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)
    settings = _ad_settings(ad_tls_ca_cert_file=str(p))
    LdapAuthenticator(settings)  # the consumer: it loads the checked bytes and keeps them
    (spec,) = collect_anchor_specs(settings, ApiSettings())
    cfg = tmp_path / "cfg"
    _file_graph(cfg)
    app = create_managed_app(
        db_path=tmp_path / "m.db",
        config_dir=cfg,
        trust_anchor_specs=[spec],
        allow_no_auth=True,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    async with app.router.lifespan_context(app):
        p.write_bytes(_block(b"rotated"))
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            for _ in range(2):
                r = await client.post("/config/reload", json={})
                assert r.status_code == 200, r.text
        rows = await _rows(app.state.engine.store, "ad")
    assert len(_events(rows, "restart_required")) == 2


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
    model: type[BaseModel], field: str, setting: str, blank: str
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


# --- BACKLOG #2358: a path in a refusal or a log line is quoted with repr -------------------------
#
# Engine PR 1744 rewrote one refusal and dropped its ``!r``, and most of the others never had it. A
# newline or an escape byte in a configured anchor path then reached the refusal, and every log line
# that carries it, raw: a refusal could be split into a second, forged-looking line. ``repr`` escapes
# both. The fix commands keep their own shell quoting (``_ps_quote``, ``shlex.quote``) unchanged.

_CONTROL_PATH = "C:/anchors/evil\nFORGED: line\x1b[31m.pem"


def _quoted(text: str) -> None:
    """``text`` names the control-character path only in its escaped form."""
    assert repr(_CONTROL_PATH) in text, text
    assert "\x1b" not in text and "\nFORGED" not in text, text


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(b"", id="no PEM block"),
        pytest.param(b"-----BEGIN TRUSTED CERTIFICATE-----\nAAAA\n", id="TRUSTED block"),
        pytest.param(
            b"-----BEGIN CERTIFICATE-----\n\xff\n-----END CERTIFICATE-----\n", id="non-ASCII"
        ),
        pytest.param(
            b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", id="TLS refuses"
        ),
    ],
)
def test_a_pem_shape_refusal_quotes_the_path(data: bytes) -> None:
    spec = AnchorSpec("api_client", "[api].tls_client_ca_file", _CONTROL_PATH, None)
    with pytest.raises(TrustAnchorError) as err:
        ta.anchor_cadata(data, spec)
    _quoted(str(err.value))


def test_the_verdict_refusals_quote_the_path() -> None:
    """The pin, file, path and indeterminate messages. The control is the pin message, which kept
    its ``!r`` through PR 1744."""
    spec = AnchorSpec("t", "[api].tls_client_ca_file", _CONTROL_PATH, None)
    finding = ChainFinding(_CONTROL_PATH, DIRECTORY, True, "Users can delete entries", ("S-1-1-0",))
    unsure = ChainFinding(_CONTROL_PATH, DIRECTORY, False, "access denied")
    insecure = ta.AnchorVerdict(
        "ab" * 32,
        acl_ok=False,
        pin_ok=False,
        path_ok=False,
        path_check=PathVerdict(False, (finding,)),
    )
    unknown = ta.AnchorVerdict(
        "ab" * 32, acl_ok=None, pin_ok=None, path_ok=None, path_check=PathVerdict(None, (unsure,))
    )
    _quoted(ta._pin_mismatch_message(spec, insecure))
    # The prose lines only: the fix lines below them are commands, quoted for their shell.
    _quoted(ta._acl_message(spec).split("\n")[0])
    path_lines = ta._path_message(spec, insecure).split("\n")
    _quoted(path_lines[0])
    _quoted(path_lines[1])
    assert path_lines[1].startswith(f"  {DIRECTORY} ")
    _quoted(ta._indeterminate_message(spec, unknown))
    assert len(ta._indeterminate_message(spec, unknown).split("\n")) == 3  # header, file, finding


def test_an_unreadable_inbound_ca_refusal_quotes_the_path() -> None:
    settings = {"tls": True, "tls_ca_file": _CONTROL_PATH}
    with pytest.raises(TrustAnchorError, match="could not read the trust anchor") as err:
        ta.inbound_ca_cadata("ADT_IN", settings, enforcing=True)
    _quoted(str(err.value))


def test_the_dacl_read_log_quotes_the_path(caplog: pytest.LogCaptureFixture) -> None:
    """The DACL read cannot answer for a path that cannot exist. On Windows icacls echoes the path
    in its own error text, so that text is quoted as well."""
    with caplog.at_level("WARNING", logger=ta.log.name):
        assert dacl_is_owner_only(_CONTROL_PATH) is None
    (record,) = [r for r in caplog.records if r.name == ta.log.name]
    _quoted(record.getMessage())


def test_a_chain_walk_reason_quotes_the_path() -> None:
    """The reasons anchor_path builds reach the same refusals, so they quote the path too."""
    from messagefoundry.auth import anchor_path as ap

    def unreadable(_p: str) -> tuple[str, str | None]:
        raise OSError(13, "denied")

    _chain, cause = ap.windows_chain("C:\\evil\nFORGED line\x1b[31m.pem", "C:\\", unreadable)
    assert cause is not None and repr("C:\\evil\nFORGED line\x1b[31m.pem") in cause
    assert "\x1b" not in cause and "\nFORGED" not in cause

    def a_file(_p: str) -> tuple[str, str | None]:
        return ap.FILE, None

    _chain, cause = ap.windows_chain("C:\\evil\nFORGED\x1b\\ca.pem", "C:\\", a_file)
    assert cause is not None and cause.endswith("is not a directory")
    assert "\x1b" not in cause and "\nFORGED" not in cause


async def test_the_restart_required_log_quotes_the_path(
    store: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    spec = AnchorSpec("ad", "[auth].ad_tls_ca_cert_file", _CONTROL_PATH, None)
    ta._LOADED[(spec.label, spec.path)] = "00" * 32
    with caplog.at_level("WARNING", logger=ta.log.name):
        await ta._report_restart_required([spec], store, seen={"ad": "ab" * 32})
    (record,) = [r for r in caplog.records if r.name == ta.log.name]
    _quoted(record.getMessage())


# --- BACKLOG #2270: an encrypted PEM block refuses before OpenSSL can ask for a password -----------
#
# Why a header inside a block must never reach OpenSSL, and what was measured, is in
# anchor_cadata's docstring. Every refusal test here swaps in _NoTlsLoad, so a regression fails at
# once instead of waiting on a password. The one exception is the control below it, which needs
# the real load to show that OpenSSL skips a header outside a block.

_ENCRYPTED = b"Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,00112233445566778899AABBCCDDEEFF\n\n"
_BEGIN_CERT = b"-----BEGIN CERTIFICATE-----\n"


def _with_headers(headers: bytes) -> bytes:
    return _real_ca("crl-test-ca")[0].replace(_BEGIN_CERT, _BEGIN_CERT + headers)


def _begin_past_a_long_line(end_line: bytes) -> Any:
    """Code review round 2's measured bypasses of a line-based check. The BEGIN sits after 254
    bytes of one line, where OpenSSL reads it and anchor_cadata's own line loop does not, and the
    line after it looked like an END line to that check. With the real load, each shape did not
    return within 15 seconds."""
    second = _real_ca("second-ca")[0].replace(_BEGIN_CERT, b"")  # the body and its END line
    return lambda: (
        _real_ca("crl-test-ca")[0] + b"#" * 254 + _BEGIN_CERT + end_line + _ENCRYPTED + second
    )


def _byte_order_mark_before_the_block() -> bytes:
    return b"\xef\xbb\xbf" + _with_headers(_ENCRYPTED)


def _encrypted_key_beside_the_certificate() -> bytes:
    """Manager decision: a key block refuses too, though cadata= loads the certificate beside it.
    A trust anchor has no use for a key, and the header is refused in a block of any label."""
    label = b"RSA PRIVATE" + b" KEY"  # split, so the secret scanner does not read a real key
    key = b"-----BEGIN " + label + b"-----\n" + _ENCRYPTED + b"AAAA\n-----END " + label + b"-----\n"
    return _real_ca("crl-test-ca")[0] + key


class _NoTlsLoad:
    """Stands in for the ssl module: a refusal must come before OpenSSL is handed the text."""

    PROTOCOL_TLS_CLIENT = ssl.PROTOCOL_TLS_CLIENT
    SSLError = ssl.SSLError

    @staticmethod
    def SSLContext(_protocol: object) -> Any:
        raise AssertionError("the TLS library was handed an encrypted block")


@pytest.mark.parametrize(
    "shape",
    [
        pytest.param(lambda: _with_headers(_ENCRYPTED), id="Proc-Type and DEK-Info"),
        pytest.param(
            lambda: _with_headers(b"DEK-Info: AES-256-CBC,00112233445566778899AABBCCDDEEFF\n\n"),
            id="DEK-Info",
        ),
        pytest.param(lambda: _with_headers(b"proc-type: 4,ENCRYPTED\n\n"), id="lower case"),
        pytest.param(lambda: _with_headers(b"  Proc-Type: 4,ENCRYPTED\n\n"), id="leading space"),
        pytest.param(_begin_past_a_long_line(b"-----END X\xff\n"), id="long line, non-ASCII END"),
        pytest.param(
            _begin_past_a_long_line(b"\xef-----END X\n"), id="long line, stray byte before END"
        ),
        pytest.param(_byte_order_mark_before_the_block, id="byte-order mark"),
        pytest.param(_encrypted_key_beside_the_certificate, id="encrypted key block"),
    ],
)
def test_an_encrypted_pem_block_refuses_before_the_tls_load(
    monkeypatch: pytest.MonkeyPatch, shape: Any
) -> None:
    spec = AnchorSpec("api_client", "[api].tls_client_ca_file", "ca.pem", None)
    monkeypatch.setattr(ta, "ssl", _NoTlsLoad)
    with pytest.raises(TrustAnchorError, match="holds a PEM block with an encryption header"):
        ta.anchor_cadata(shape(), spec)


def test_an_encryption_header_outside_a_block_still_passes() -> None:
    """The control: OpenSSL skips every line outside a block, so the same text in a comment above
    the certificate loads, and the shape check passes it too."""
    data = b"Proc-Type: 4,ENCRYPTED\n" + _real_ca("crl-test-ca")[0]
    ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=data.decode())
    spec = AnchorSpec("api_client", "[api].tls_client_ca_file", "ca.pem", None)
    assert ta.anchor_cadata(data, spec) == data.decode()


async def test_the_preflight_refuses_an_encrypted_anchor_as_the_consumer_does(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    p = _pem(tmp_path, _with_headers(_ENCRYPTED))
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)
    monkeypatch.setattr(ta, "ssl", _NoTlsLoad)
    spec = AnchorSpec("api_client", "[api].tls_client_ca_file", str(p), None)
    with pytest.raises(TrustAnchorError) as central:
        await run_anchor_preflight([spec], store, enforcing=True)
    with pytest.raises(TrustAnchorError) as consumer:
        ta.verified_anchor_cadata(spec, enforcing=True)
    assert str(central.value) == str(consumer.value)
    assert "encryption header" in str(central.value)
    assert "pem_refused" in {r["event"] for r in await _rows(store, "api_client")}


# --- BACKLOG #2183: an unreadable inbound CA audits as trust_anchor, as a settings anchor does ------


async def test_the_registry_preflight_refuses_an_unreadable_ca_as_an_anchor(
    store: MessageStore, tmp_path: Path
) -> None:
    """The registry twin of the settings test above. Red under: the OSError as the direct cause,
    which the reload routes read as invalid_config. The text keeps the read error."""
    from messagefoundry.config.wiring import WiringError, load_config

    cfg = tmp_path / "cfg"
    _one_listener_graph(cfg, tmp_path / "gone.pem")
    with pytest.raises(WiringError, match="a connection trust anchor was refused") as err:
        await ta.make_registry_anchor_preflight(store, enforcing=True)(load_config(cfg), {})
    assert isinstance(err.value.__cause__, TrustAnchorError)
    assert isinstance(err.value.__cause__.__cause__, FileNotFoundError)
    assert "gone.pem" in str(err.value)


async def test_the_reload_route_audits_an_unreadable_inbound_ca_as_trust_anchor(
    tmp_path: Path,
) -> None:
    """The direct /config/reload route. The control is the route's own invalid_config row for a
    graph that declares nothing, so the route still tells the two apart."""
    import httpx

    from messagefoundry.api import create_app
    from messagefoundry.pipeline import Engine

    cfg = tmp_path / "cfg"
    _one_listener_graph(cfg, tmp_path / "gone.pem")
    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / "cfg.py").write_text("x = 1  # declares no connections\n", encoding="utf-8")

    store = await MessageStore.open(tmp_path / "e.db")
    engine = Engine(
        store,
        registry_preflight=ta.make_registry_anchor_preflight(store, enforcing=True),
        egress_settings=EgressSettings(deny_by_default=False),
    )
    try:
        transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            for target in (cfg, empty):
                r = await client.post("/config/reload", json={"config_dir": str(target)})
                assert r.status_code == 422, r.text
        rows = await store.list_audit(action="config_reload_failed", limit=10)
        reasons = {
            json.loads(r["detail"])["requested"]: json.loads(r["detail"])["reason"] for r in rows
        }
        assert reasons == {str(cfg): "trust_anchor", str(empty): "invalid_config"}
    finally:
        await engine.stop()


# --- BACKLOG #2269: a set anchor path that nothing loads still refuses when it cannot load ---------
#
# Manager decision, recorded in docs/CONFIGURATION.md: keep the refusal. The preflight checks every
# anchor path that is set, whether or not a consumer uses it, as refuse_an_unread_ca_pin already
# refuses a pin nothing reads. It fails closed, and unsetting the path is the way out.


def _ad_off(ca: str) -> dict[str, Any]:
    return {"ad_tls_ca_cert_file": ca}


def _ad_on_plain_ldap(ca: str) -> dict[str, Any]:
    return {
        "ad_enabled": True,
        "ad_server": "ldap://dc1.example.com",
        "ad_allow_insecure_ldap": True,
        "ad_domain": "example.com",
        "ad_user_search_base": "DC=example,DC=com",
        "ad_bind_dn": "CN=svc,DC=example,DC=com",
        "ad_bind_password": "not-a-real-password",
        "ad_tls_ca_cert_file": ca,
    }


def _oidc_off(ca: str) -> dict[str, Any]:
    return {"oidc_tls_ca_cert_file": ca}


@pytest.mark.parametrize(
    "unused",
    [
        pytest.param(_ad_off, id="AD off"),
        pytest.param(_ad_on_plain_ldap, id="AD on plain ldap"),
        pytest.param(_oidc_off, id="OIDC off"),
    ],
)
async def test_a_set_anchor_nothing_loads_refuses_at_start_and_reload(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, unused: Any
) -> None:
    """Red under: the preflight skipping an anchor no consumer loads. The start refuses through the
    managed app's lifespan, and a reload through the engine's settings preflight, for a file that
    cannot load (a CRL alone) and for a file that is missing. The control: the same settings with
    the path unset collect no anchor, so nothing is checked."""
    from messagefoundry.api.app import create_managed_app
    from messagefoundry.config.wiring import WiringError

    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)
    crl = tmp_path / "crl-only.pem"
    crl.write_bytes(_crl_only())
    specs = collect_anchor_specs(AuthSettings(**unused(str(crl))), ApiSettings())
    assert len(specs) == 1
    cfg = tmp_path / "cfg"
    _file_graph(cfg)
    app = create_managed_app(
        db_path=tmp_path / "m.db",
        config_dir=cfg,
        trust_anchor_specs=specs,
        allow_no_auth=True,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    with pytest.raises(TrustAnchorError, match="the TLS library cannot load the trust anchor"):
        async with app.router.lifespan_context(app):
            pass

    for path in (crl, tmp_path / "gone.pem"):
        (spec,) = collect_anchor_specs(AuthSettings(**unused(str(path))), ApiSettings())
        preflight = ta.make_settings_anchor_preflight([spec], store, enforcing=True)
        assert preflight is not None
        with pytest.raises(WiringError, match="a settings trust anchor was refused") as err:
            await preflight()
        assert isinstance(err.value.__cause__, TrustAnchorError)

    unset = {k: v for k, v in unused(str(crl)).items() if not k.endswith("_tls_ca_cert_file")}
    assert collect_anchor_specs(AuthSettings(**unset), ApiSettings()) == []
