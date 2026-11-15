# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5546 to #5550: five credential shapes the scrub printed, hidden by a stage of their own.

The five, each a row: a padded Basic or Bearer token inside a quoted JSON or dict Authorization value
(#5546); a Python bytes literal after a credential label (#5547); a Digest Authorization header's
parameter list (#5548); a DSN password behind an empty username or holding an unencoded "@" (#5549);
and a PEM, OpenSSH or PGP private key block's body (#5550).

THE STAGE IS ADDITIVE. ``secretscrub.scrub_added_shapes`` runs after every pass a surface already runs,
on that surface's output, and only replaces. The per-row tests here read only the public surfaces, so
each fails on the code before the stage on its assertion. The regression guard compares each surface
with the stage on against the same surface with it off, which is the code before it, over every probe
the superseded branch ``b234-scrub-5546-5550`` collected and a seeded corpus: no secret may print that
the code before the stage hid. A surface that reads the chain's output again is held to printing
nothing the chain did not print before the stage; the guard's docstring says why it is held to less.

Every value is synthetic. A key block's type is joined from parts, so no literal key block sits in this
file for the repository's secret scanner to read."""

from __future__ import annotations

import logging
import random
import re
from collections.abc import Callable
from dataclasses import dataclass

import pytest

from messagefoundry import redaction, secretscrub
from messagefoundry.logging_setup import CredentialScrubFilter, _install_phi_filters
from messagefoundry.secretscrub import CREDENTIAL_PLACEHOLDER, scrub_credentials
from messagefoundry.support import redact as redact_mod
from messagefoundry.support.redact import REDACTION_PLACEHOLDER, redact_log_line
from tests._growth import _growth_between

#: The key type every key block in this file names, kept apart from its markers (see the docstring).
_PK = "PRIVATE" + " KEY"


def _filtered(line: str) -> str:
    """``line`` after :class:`CredentialScrubFilter` alone, as a handler would emit it."""
    record = logging.LogRecord("mefor.test", logging.ERROR, __file__, 1, line, None, None)
    assert CredentialScrubFilter().filter(record)
    return record.getMessage()


def _through_the_chain(line: str) -> str:
    """``line`` as a log message through every filter ``_install_phi_filters`` puts on a handler."""
    handler = logging.NullHandler()
    _install_phi_filters(handler)
    record = logging.LogRecord("mefor.test", logging.ERROR, __file__, 1, "%s", (line,), None)
    assert handler.filter(record)
    return record.getMessage()


#: Every surface the stage runs on, and two that read a surface's output again: a record two
#: handlers filter in turn, and a written line the support bundle reads back.
_SURFACES: tuple[tuple[str, Callable[[str], str]], ...] = (
    ("scrub_credentials", scrub_credentials),
    ("CredentialScrubFilter", _filtered),
    ("write-time chain", _through_the_chain),
    ("redact_log_line", redact_log_line),
)
#: Each applied to the write-time chain's output.
_REREAD_SURFACES_OF_CHAIN: tuple[tuple[str, Callable[[str], str]], ...] = (
    ("chain twice", _through_the_chain),
    ("bundle of chain", redact_log_line),
)


def _without_the_added_stage(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every surface as it read before the stage: the passes before it are unchanged, so switching the
    stage off is that code."""

    def identity(text: str, placeholder: str = CREDENTIAL_PLACEHOLDER) -> str:
        return text

    monkeypatch.setattr(secretscrub, "scrub_added_shapes", identity)
    monkeypatch.setattr(redact_mod, "scrub_added_shapes", identity)


def _assert_hidden(line: str, secrets: tuple[str, ...], kept: tuple[str, ...] = ()) -> None:
    for surface, apply in _SURFACES:
        out = apply(line)
        printed = [secret for secret in secrets if secret in out]
        assert not printed, f"{surface}: {printed} printed in {out!r}"
        lost = [text for text in kept if text not in out]
        assert not lost, f"{surface}: lost {lost} from {out!r}"


# --- BACKLOG #5546: a padded token after a scheme word inside a quoted value -----------------------


@pytest.mark.parametrize(
    "line",
    (
        'upstream headers {"Authorization": "Basic zq-B4sic_Pad-61=="} rejected',
        "upstream headers {'authorization': 'basic zq-B4sic_Pad-61='} rejected",
        "upstream headers {'Authorization': 'Bearer zq-B4sic_Pad-61=='} rejected",
        'upstream headers {"token": "basic zq-B4sic_Pad-61="} rejected',
        "upstream headers api_key='Bearer zq-B4sic_Pad-61==' rejected",
    ),
)
def test_5546_a_padded_token_in_a_quoted_authorization_value_is_hidden(line: str) -> None:
    _assert_hidden(line, ("zq-B4sic_Pad-61",), ("upstream headers", "rejected"))


# --- BACKLOG #5547: a Python bytes literal after a credential label --------------------------------


@pytest.mark.parametrize(
    "line",
    (
        "connect failed password=b'zq-By_A-63 zq-By_B-64' retrying",
        'connect failed token=b"zq-By_A-63 zq-By_B-64" retrying',
        "connect failed private_key=b'zq-By_A-63 zq-By_B-64' retrying",
        "connect failed MEFOR_VALUE_PW=b'zq-By_A-63 zq-By_B-64' retrying",
        'connect failed MEFOR_X=b"zq-By_A-63 zq-By_B-64" retrying',
        "connect failed access_token=b'zq-By_A-63 zq-By_B-64' retrying",
        "connect failed password=b'zq-By_A-63 it\\'s zq-By_B-64' retrying",
    ),
)
def test_5547_a_bytes_literal_after_a_credential_label_is_hidden_whole(line: str) -> None:
    _assert_hidden(line, ("zq-By_A-63", "zq-By_B-64"), ("connect failed", "retrying"))


# --- BACKLOG #5548: a Digest Authorization header ----------------------------------------------------


@pytest.mark.parametrize(
    "line",
    (
        'upstream sent Authorization: Digest username="zq-Dg_U-71", realm="api", '
        'nonce="zq-Dg_N-72", uri="/a", qop=auth, nc=00000001, cnonce="zq-Dg_C-73", '
        'response="zq-Dg_R-74"',
        'upstream sent Authorization: Digest algorithm=MD5, username="zq-Dg_U-71", '
        'nonce="zq-Dg_N-72", cnonce="zq-Dg_C-73", response="zq-Dg_R-74"',
        'upstream sent Proxy-Authorization: Digest username="zq-Dg_U-71", nonce="zq-Dg_N-72", '
        'cnonce="zq-Dg_C-73", response="zq-Dg_R-74"',
    ),
)
def test_5548_a_digest_headers_parameters_are_hidden(line: str) -> None:
    _assert_hidden(line, ("zq-Dg_U-71", "zq-Dg_N-72", "zq-Dg_C-73", "zq-Dg_R-74"), ("upstream",))


# --- BACKLOG #5549: a DSN password behind an empty username or holding an "@" -----------------------


@pytest.mark.parametrize(
    ("line", "secrets", "kept"),
    (
        (
            "store dsn redis://:zq-Dsn_P-56@cache.invalid:6379/0",
            ("zq-Dsn_P-56",),
            ("redis://:", "@cache.invalid:6379/0"),
        ),
        (
            "store dsn postgres://svc:zq-At_H-57@zq-Dsn_P-58@db.invalid:5432/mefor",
            ("zq-At_H-57", "zq-Dsn_P-58"),
            ("postgres://svc:", "@db.invalid:5432/mefor"),
        ),
        (
            "store dsn postgres://:zq-At_H-57@zq-Dsn_P-58@db.invalid/mefor",
            ("zq-At_H-57", "zq-Dsn_P-58"),
            ("postgres://:", "@db.invalid/mefor"),
        ),
    ),
)
def test_5549_an_odd_dsn_password_is_hidden(
    line: str, secrets: tuple[str, ...], kept: tuple[str, ...]
) -> None:
    _assert_hidden(line, secrets, kept)


@pytest.mark.parametrize(
    ("line", "kept"),
    (
        ("pg://u:zq-p@h|a@DOE^JANE x", "|a@"),
        ("pg://u:zq-p@h?k=a@b x", "?k=a@b"),
        ("pg://u:zq-p@h#a@b x", "#a@b"),
        ("pg://u:zq-p@h;a=b@c x", ";a=b@c"),
        ("pg://u:zq-p@h~a@b^c@d&e@f x", "~a@b"),
    ),
)
def test_5549_the_at_sign_tail_stops_at_a_separator(line: str, kept: str) -> None:
    """A segment ends at an HL7 separator, a query, a fragment, a member or "=", so the run stays
    off what another pass reads there; the text from that character on is left as it was."""
    out = scrub_credentials(line)
    assert "zq-p" not in out
    assert kept in out, out


# --- BACKLOG #5550: a private key block --------------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    (
        f"key load failed:\n-----BEGIN RSA {_PK}-----\nMIIEowIBAAKCAQEA\nzq-pem_pem-99==\n"
        f"-----END RSA {_PK}-----\nretrying now",
        f"key load failed b'-----BEGIN {_PK}-----\\nMIIEvQIBADAN\\nzq-pem_pem-99\\n"
        f"-----END {_PK}-----\\n' retrying now",
        f"key load failed:\n-----BEGIN OPENSSH {_PK}-----\nb3BlbnNz\nzq-pem_pem-99",
        f"key load failed -----BEGIN {_PK}----- MIIEab zq-pem_pem-99 -----END {_PK}----- now",
        f"key load failed:\n-----BEGIN PGP {_PK} BLOCK-----\nVersion: GnuPG v1 (GNU/Linux)\n"
        f"Comment: ops@example.invalid\n\nlQOYBF\nzq-pem_pem-99\n-----END PGP {_PK} BLOCK-----",
        f"key load failed cfg=-----BEGIN RSA {_PK}-----\\\\nMIIEpA\\\\nzq-pem_pem-99\\\\n"
        f"-----END RSA {_PK}-----",
        f"key load failed b'-----BEGIN RSA {_PK}-----\\nMIIEowIB\\nzq-pem_pem-99'",
    ),
)
def test_5550_a_private_key_body_is_hidden(line: str) -> None:
    _assert_hidden(line, ("zq-pem_pem-99", "MIIE", "b3Bl", "lQOY"), ("key load failed",))


def test_5550_the_markers_stay_and_text_after_the_block_stays() -> None:
    line = (
        f"x\n-----BEGIN EC {_PK}-----\nMHcCAQEE\nzq-pem_pem-99\n-----END EC {_PK}-----\nnext words"
    )
    out = scrub_credentials(line)
    assert out == (
        f"x\n-----BEGIN EC {_PK}-----{CREDENTIAL_PLACEHOLDER}-----END EC {_PK}-----\nnext words"
    )


@pytest.mark.parametrize(
    "line",
    (
        f"expected a -----BEGIN {_PK}----- header in the key file",
        "-----[redacted]-----\nnext words of the record",
        "loaded -----BEGIN CERTIFICATE-----\nMIIBcert\n-----END CERTIFICATE----- ok",
        f"-----BEGIN RSA {_PK}-----\nthe key file was empty",
    ),
)
def test_5550_a_marker_with_no_key_body_after_it_leaves_the_text(line: str) -> None:
    """A diagnostic naming a begin marker, text after a lone PHI marker, a certificate under its own
    marker, and a line of prose after a marker are no private key body."""
    assert scrub_credentials(line) == line


def test_5550_a_cut_short_body_ends_at_the_first_line_that_is_not_base64() -> None:
    line = f"-----BEGIN RSA {_PK}-----\nMIIEowIB\nzq-pem_pem-99\nretry in 5 s\nAAAA"
    out = scrub_credentials(line)
    assert out == f"-----BEGIN RSA {_PK}-----{CREDENTIAL_PLACEHOLDER}\nretry in 5 s\nAAAA", out


# --- Shapes the first review round found printing ---------------------------------------------------


@pytest.mark.parametrize(
    "line",
    (
        "connect failed MEFOR_DB_PASSWORD=b'zq-R1_A zq-R1_B' retrying",
        "connect failed MEFOR_API_TOKEN=b'zq-R1_A zq-R1_B' retrying",
        "x password=b'zq-R1_A zq-R1_B': y",
        "x token=b'zq-R1_A zq-R1_B':retry",
        "set MEFOR_VALUE_PW=b'zq-R1_A zq-R1_B'|next",
        "connect failed MEFOR_VALUE_PW=b'zq-R1_A zq-R1_B'.",
        'Authorization: Digest  username = "zq-R1_A" , nonce = "zq-R1_B", response="zq-R1_C"',
        f"-----BEGIN RSA {_PK}-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,AB\n\n"
        "zq-R1_A\nzq-R1_B",
        f'{{"key": "-----BEGIN RSA {_PK}-----\\nMIIE\\nzq-R1_A\\/zq-R1_B\\n"}}',
    ),
)
def test_a_round_one_shape_is_hidden(line: str) -> None:
    _assert_hidden(line, ("zq-R1_A", "zq-R1_B"))


def test_an_end_marker_the_stage_did_not_take_opens_no_body() -> None:
    """On the chain the PHI pass spells every marker ``-----[redacted]-----``, an END marker
    included, so that spelling is read only before base64-shaped lines."""
    line = (
        "-----END CERTIFICATE-----\nRetrying handshake with token=zq-v -----BEGIN CERTIFICATE-----"
    )
    for surface, apply in _SURFACES:
        assert "Retrying handshake with token=" in apply(line), surface


# --- The stage reads what an earlier pass left, and over-reads in stated places only ---------------


@pytest.mark.parametrize(
    "line",
    (
        "setting 'password' (env 'MEFOR_VALUE_PW'='zq-v'): bad",
        'token=zq-v mode="strict" level="high"',
        'MEFOR_DB_PASSWORD=zq-v user="bob"',
        '{"message": "connect failed password=zq-v", "exception": "x"}',
        "MEFOR_X=zq-v then 'quoted words' end",
        "token=zq-v rest of line 'quoted words' end",
        "MEFOR_X='zq-v', other='words'",
        "pg://u:zq-p@host/db and mail ops@example.invalid",
    ),
)
def test_the_stage_leaves_ordinary_text_after_a_placeholder(line: str) -> None:
    """Punctuation after a closed ``MEFOR_`` value, a logfmt key after a credential, the quotes
    between two JSON fields, a quoted run after a space, and an "@" past the DSN's "/" are no
    remnant: the stage changes nothing the passes before it wrote."""
    with pytest.MonkeyPatch.context() as patch:
        _without_the_added_stage(patch)
        before = scrub_credentials(line)
    assert scrub_credentials(line) == before


def test_the_stage_returns_the_same_object_when_nothing_matches() -> None:
    line = "routine heartbeat for IB_ACME_ADT -----x pg://h/db token"
    assert secretscrub.scrub_added_shapes(line) is line
    plain = "routine heartbeat for IB_ACME_ADT"
    assert scrub_credentials(plain) is plain


def test_the_stage_placeholders_are_the_ones_the_surfaces_write() -> None:
    """The patterns spell the placeholders as literals, so the static ReDoS scan reads them; these
    hold the literals to the constants."""
    assert secretscrub._STAGE_PLACEHOLDERS == (CREDENTIAL_PLACEHOLDER, REDACTION_PLACEHOLDER)
    for placeholder in secretscrub._STAGE_PLACEHOLDERS:
        assert re.fullmatch(secretscrub._STAGE_PLACEHOLDER, placeholder), placeholder
    assert re.fullmatch(secretscrub._STAGE_PHI_MARKER, redaction._REDACTED)


# --- The regression guard: nothing the code before the stage hid may print --------------------------

#: Every probe the superseded branch ``b234-scrub-5546-5550`` (head aad21ae3e2) collected, ported
#: verbatim from its tests: ``QUOTED_VALUES`` and ``FAMILIES`` rows it added to
#: ``tests/test_log_redaction_secret_domain.py`` and ``tests/test_logging_credential_scrub.py``;
#: ``test_a_padded_token_holding_a_compound_key_label_is_left_to_it``;
#: ``test_a_quoted_scheme_and_padded_token_is_taken_whole``; ``_LABEL_IN_TOKEN_LINES``;
#: ``_BYTES_LATER_LABEL_LINES``; ``test_a_b_that_opens_no_quoted_value_is_read_as_before``;
#: ``_DIGEST_LATER_LABEL_LINES`` and ``test_both_copies_read_a_digest_list_alike``'s corpus;
#: ``test_the_dsn_tail_hides_every_span_the_first_at_tail_hid``'s two rows;
#: ``test_a_private_key_block_body_is_hidden_and_its_markers_kept``; ``_WIDENED_SPAN_LINES``;
#: ``_ROUND_THREE_PROBES``; ``test_the_bundle_dsn_tail_leaves_an_hl7_run_to_the_phi_pass``;
#: ``test_a_pgp_block_with_any_armor_header_is_hidden``; and
#: ``test_a_marker_with_no_key_body_after_it_leaves_the_text``. Then one line for each of the four
#: shapes later review rounds found printing on that branch, written here from the shape's
#: description rather than copied, since that branch holds no test for them, and ``MEFOR_X=b"p w"``.
_OLD_BRANCH_PROBES: tuple[str, ...] = (
    'upstream headers {"Authorization": "Basic zq-B4sic_Pad-61=="} rejected',
    "upstream headers {'authorization': 'basic zq-B4sic_Pad-62='} rejected",
    "connect failed password=b'pw-By_A-63 pw-By_B-64' retrying",
    'rest connector token=b"tk-By_A-65 tk-By_B-66" configured',
    "signing setup private_key=b'pk-By_A-67 pk-By_B-68' for IB_ACME_ADT",
    "startup MEFOR_VALUE_PW=b'pw-By_A-69 pw-By_B-70' loaded",
    'upstream sent Authorization: Digest username="dg-Usr_A-71", realm="api", '
    'nonce="dg-Non_B-72", uri="/a", qop=auth, nc=00000001, cnonce="dg-Cno_C-73", '
    'response="dg-Rsp_D-74"',
    f"key load failed b'-----BEGIN {_PK}-----\\nMIIEvQIBADAN\\npw-pem_pem-59\\n"
    f"-----END {_PK}-----\\n' retrying",
    "store dsn redis://:pw-D5n_Pass-56@cache.invalid:6379/0",
    "store dsn postgres://svc:pw-At_Head-57@pw-D5n_Pass-58@db.invalid:5432/mefor",
    "connect failed password=b'wt-Byt_A-91 wt-Byt_B-92' retrying",
    'upstream headers {"Authorization": "Basic wt-B4sic_Pad-90=="} rejected',
    'upstream sent Authorization: Digest username="wt-Dg_Usr-93", realm="api", '
    'nonce="wt-Dg_Non-94", uri="/a", response="wt-Dg_Rsp-95"',
    "upstream access_token=b'wt-Byt_C-84 wt-Byt_D-85' configured",
    "upstream token=wt-q;password=b'wt-Byt_E-82 wt-Byt_F-83' configured",
    f"key load failed:\n-----BEGIN RSA {_PK}-----\nMIIEowIBAAKCAQEA\nwt-pem_pem-99==\n"
    f"-----END RSA {_PK}-----\nretrying",
    f"key load failed:\n-----BEGIN PGP {_PK} BLOCK-----\nVersion: GnuPG v1.4.11 (GNU/Linux)\n"
    f"Comment: ops@example.invalid\n\nlQOYBF\nwt-pgp_pgp-81==\n-----END PGP {_PK} BLOCK-----\n"
    "retrying",
    "store dsn redis://:wt-dsn_dsn-96@cache.invalid:6379/0",
    "store dsn postgres://svc:wt-At_Head-97@wt-dsn_dsn-98@db.invalid:5432/mefor",
    "token='Bearer x.AccountKey='zq-Ck_A-74 zq-Ck_B-75'",
    "{'Authorization': 'Bearer zq-Pad_Tok-71=='}",
    '{"token": "basic zq-Pad_Tok-71="}',
    "auth api_key='Bearer zq-Pad_Tok-71==' ok",
    "token='Bearer password='zq-Lt_A-72 zq-Lt_B-73'",
    'authorization: "Basic x.client_secret="zq-Lt_A-72 zq-Lt_B-73"',
    "token=zq-x;password=b'zq-Bl_A-76 zq-Bl_B-77'",
    "password='zq-x, private_key=b'zq-Bl_A-76 zq-Bl_B-77'",
    'MEFOR_X=zq-x;secret=b"zq-Bl_A-76 zq-Bl_B-77"',
    "token=zq-x;password= b'zq-Bl_A-76 zq-Bl_B-77'",
    "password=bob x",
    "token=b x",
    "password='a b' tail",
    "private_key=b' unclosed",
    "secret=b{x}",
    'Authorization: Digest username="zq-u, password="zq-Dl_A-78 zq-Dl_B-79"',
    'authorization=Digest realm="r", nonce="zq-n, token: "zq-Dl_A-78 zq-Dl_B-79"',
    'Authorization: Digest username="u", realm="r", response="h" x',
    'token=Digest a=b,c="d\\"e" , f=g x="y"',
    "session: digest x=",
    'authorization: Digest username="u\'s", password="p"',
    "pg://:zq-pw@h/db",
    "pg://u:zq-p@zq-w@h/db",
    f"-----BEGIN EC {_PK}-----\nMHcCAQEE\nzq-pem_pem-81\n-----END EC {_PK}-----",
    f"-----BEGIN OPENSSH {_PK}-----\nb3BlbnNz\nzq-pem_pem-81",
    f"env -----BEGIN {_PK}----- MIIEab zq-pem_pem-81 -----END {_PK}----- ok",
    f'{{"k": "-----BEGIN {_PK}-----\\nMIIE\\nzq-pem_pem-81\\n-----END {_PK}-----"}}',
    "-----[redacted]-----\nMIIEvQ\nzq-pem_pem-81\n-----[redacted]-----",
    f"-----BEGIN PGP {_PK} BLOCK-----\nVersion: GnuPG v1.4.11 (GNU/Linux)\n"
    f"Comment: ops@example.invalid\n\nlQOYBF\nzq-pem_pem-81\n-----END PGP {_PK} BLOCK-----",
    f"cfg=-----BEGIN RSA {_PK}-----\\\\nMIIEpA\\\\nzq-pem_pem-81\\\\n-----END RSA {_PK}-----",
    f"bad key -----BEGIN RSA {_PK}-----\nMIIEowIB\nretrying with password='zq-R2a zq-R2b'",
    f"bad key -----BEGIN RSA {_PK}-----\\nMIIEowIB\\nretrying with pwd={{zq-R2c zq-R2d}}",
    "pwd='hunter zq-R2e MEFOR_A=b'zq-R2f'",
    "store pg://u:zq-R2g@h;sslpassword=zp@zq-R2h;x=1",
    'Authorization: Digest username="zq-R2i", nonce="zq-R2j", uri="/cb?session=1", '
    'response="zq-R2k", cnonce="zq-R2l"',
    'Authorization: Digest username="u, clientSecret="v1 w1"',
    'Authorization: Digest username="u, userPassword="v1 w1"',
    'Authorization: Digest username="u, AccountKey="v2 w2"',
    "Authorization: Digest a=b_password='p w'",
    "Authorization: Digest a=x.password='p w'",
    'Authorization: Digest qop=auth/client_secret="p w"',
    "session=abc;secret='grade:b'",
    "token=x;password='a b=b'",
    "token='hello world:b'",
    "private_key='ab cd=b'",
    "pg://u:p@h?AccountKey=abc@def ghi",
    "pg://u:p@h?clientSecret=zz@qq ghi",
    "pg://u:p@h?accessToken=tk1@tk2 ghi",
    f"-----BEGIN RSA {_PK}-----\nMIIEowIB\npassword=\n'p w'",
    f'-----BEGIN RSA {_PK}-----\nMIIEowIB\ntoken=\n"p w"',
    f"b'-----BEGIN RSA {_PK}-----\\nMIIEowIB\\nQWERTYsecretline2'",
    "pg://u:p@h|a@DOE^JANE x",
    f"-----BEGIN PGP {_PK} BLOCK-----\nComment: O'Brien Jörg key\n\n"
    f"lQOYBF\nzq-pem_pem-81\n-----END PGP {_PK} BLOCK-----",
    f"expected a -----BEGIN {_PK}----- header in the key file",
    "-----[redacted]-----\nnext words of the record",
    "loaded -----BEGIN CERTIFICATE-----\nMIIBcert\n-----END CERTIFICATE----- ok",
    # The four shapes later review rounds found printing on the superseded branch and hidden on the
    # code before it: a camelCase reading discarded for a whole line, a cut-short key block taking a
    # later label, a DSN tail taking HL7 separators, and a collapsed bytes literal handing a later
    # label to the PHI pass's field-run rule.
    "accessToken=zq-Cm_A-01 password=b'zq-Cm_B-02 zq-Cm_C-03' userPassword='zq-Cm_D-04 x'",
    f"-----BEGIN RSA {_PK}-----\nMIIEowIB\nretry token=zq-Ks_A-05 password='zq-Ks_B-06 y'",
    "MSH|^~\\&|A|B pg://u:zq-Hs_A-07@x@DOE^JANE^Q|PID|1||zq-Hs_B-08^^^MRN|DOE^JOHN",
    "PID|1|password=b'zq-Bc_A-09'|secret='zq-Bc_B-10 z'|DOE^JANE||19700101",
    'MEFOR_X=b"p w"',
)

#: What a substring of a line counts as for the guard: every run of characters that are not
#: white space, a quote or a separator, and every run of letters and digits inside one.
_SECRET_RUN = re.compile(r"[^\s'\"=:;,&|^~@/(){}\[\]<>\\]{2,}")
_ALNUM_RUN = re.compile(r"[A-Za-z0-9]{2,}")


def _secrets(line: str) -> set[str]:
    """Each candidate secret in ``line``, minus any text a placeholder or marker holds."""
    runs = set(_SECRET_RUN.findall(line)) | set(_ALNUM_RUN.findall(line))
    markers = CREDENTIAL_PLACEHOLDER + REDACTION_PLACEHOLDER + redaction._REDACTED
    return {run for run in runs if run not in markers}


def _seeded_corpus(count: int, seed: int) -> list[str]:
    """Lines joined from pieces of every shape the stage reads, every label family, quotes, HL7
    separators and line breaks, in random order."""
    pieces = (
        "password=",
        "token=",
        "Authorization: ",
        "authorization=",
        "MEFOR_A_PW=",
        "private_key=",
        "accessToken=",
        "b'",
        'b"',
        "'",
        '"',
        " ",
        "Basic ",
        "Bearer ",
        "Digest ",
        'username="',
        ", nonce=",
        "==",
        "=",
        "@",
        ":",
        "pg://",
        "pg://:",
        "/",
        "|",
        "^",
        "~",
        "&",
        ";",
        "?",
        "\n",
        "\\n",
        f"-----BEGIN RSA {_PK}-----",
        f"-----END RSA {_PK}-----",
        "-----[redacted]-----",
        "MIIEow",
        "DOE^JANE",
        "PID|1|",
    )
    rng = random.Random(seed)
    lines = []
    for i in range(count):
        parts = []
        for j in range(rng.randint(2, 9)):
            parts.append(rng.choice(pieces))
            if rng.random() < 0.6:
                parts.append(f"vq{i % 97}x{j}")
        lines.append("".join(parts))
    return lines


def _surface_outputs(corpus: list[str]) -> dict[str, list[str]]:
    """Each surface's output over ``corpus``; the re-read surfaces read the chain's output once."""
    out = {name: [apply(line) for line in corpus] for name, apply in _SURFACES}
    chained = out["write-time chain"]
    for name, apply in _REREAD_SURFACES_OF_CHAIN:
        out[name] = [apply(line) for line in chained]
    return out


@dataclass
class _Reading:
    """What the stage changed over a corpus, surface by surface."""

    #: On the four surfaces: each secret printed now that the same surface hid with the stage off.
    newly: list[str]
    #: The count the other way, on the four surfaces.
    hidden_now: int
    #: On the two re-read surfaces: each secret printed now that the write-time chain did NOT print
    #: with the stage off, so a log line the code before the stage never wrote.
    beyond_first_surface: list[str]
    #: On the two re-read surfaces: each secret printed now that the same re-read hid with the stage
    #: off. Reported, not refused; the stage comment in secretscrub.py says why it can happen.
    reread_newly: list[str]


def _reading(monkeypatch: pytest.MonkeyPatch, corpus: list[str]) -> _Reading:
    after = _surface_outputs(corpus)
    with monkeypatch.context() as patch:
        _without_the_added_stage(patch)
        before = _surface_outputs(corpus)
    secrets = [_secrets(line) for line in corpus]
    direct = {name for name, _apply in _SURFACES}
    reading = _Reading([], 0, [], [])
    for name in after:
        for i, line in enumerate(corpus):
            for secret in secrets[i]:
                was, now = secret in before[name][i], secret in after[name][i]
                where = f"{name}: {secret!r} in {line!r} -> {after[name][i]!r}"
                if name in direct:
                    if now and not was:
                        reading.newly.append(where)
                    reading.hidden_now += was and not now
                    continue
                if now and secret not in before["write-time chain"][i]:
                    reading.beyond_first_surface.append(where)
                if now and not was:
                    reading.reread_newly.append(where)
    return reading


def test_the_stage_prints_nothing_the_code_before_it_hid(monkeypatch: pytest.MonkeyPatch) -> None:
    """THE REGRESSION GUARD. On every surface the stage runs on, no secret of any probe or seeded line
    may print that the same surface hid with the stage off. The reverse count must be above zero, or
    the stage hid nothing and nothing was compared.

    The two surfaces that read the chain's output again are held to less, and that is stated rather
    than hidden behind an exemption: no secret may print there that the write-time chain did not
    print with the stage off, so neither prints text the code before the stage never logged. They can
    hide less than they did, since a span the stage took can hold a label they would have read; the
    stage comment in ``secretscrub.py`` says so, and how many there are is measured, not refused."""
    corpus = [*_OLD_BRANCH_PROBES, *_seeded_corpus(3000, 5546)]
    reading = _reading(monkeypatch, corpus)
    assert not reading.newly, (
        f"{len(reading.newly)} secrets printed that were hidden, first: {reading.newly[:3]}"
    )
    assert reading.hidden_now > 0, "the stage hid nothing, so the comparison proved nothing"
    assert not reading.beyond_first_surface, reading.beyond_first_surface[:3]


def test_the_guard_can_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    """THE POSITIVE CONTROL. A stage that changes a pass it should not, here one that writes the
    password back over its placeholder, must be caught on the same corpus."""
    real = secretscrub.scrub_added_shapes

    def leaky(text: str, placeholder: str = CREDENTIAL_PLACEHOLDER) -> str:
        return real(text, placeholder).replace(f"svc:{placeholder}@", "svc:pw-At_Head-57@")

    monkeypatch.setattr(secretscrub, "scrub_added_shapes", leaky)
    monkeypatch.setattr(redact_mod, "scrub_added_shapes", leaky)
    reading = _reading(monkeypatch, list(_OLD_BRANCH_PROBES))
    assert reading.newly, "a stage that prints a hidden password went unnoticed"
    assert reading.beyond_first_surface, "the re-read arm let the restored password through"


# --- Linear growth ------------------------------------------------------------------------------------

#: The span and the bound ``tests/test_log_redaction_secret_domain.py`` measures the scrub patterns
#: with, and why, are stated there on ``_GROWTH_LENGTHS`` and ``_MAX_GROWTH``.
_GROWTH_LENGTHS = (2048, 16384)
_MAX_GROWTH = 24.0

_GROWTH_SHAPES: tuple[tuple[str, Callable[[int], str]], ...] = (
    ("_PRIVATE_KEY_BODY", lambda n: f"-----BEGIN {_PK}-----\n" + "AbC+" * (n // 4)),
    ("_PRIVATE_KEY_BODY", lambda n: "-----[redacted]-----\nAAAA" * (n // 24)),
    ("_PRIVATE_KEY_BODY", lambda n: f"-----BEGIN {_PK}----- x " * (n // 30)),
    ("_PRIVATE_KEY_BODY", lambda n: "-----[redacted]-----\n" + "Ab-" * (n // 3)),
    ("_PRIVATE_KEY_BODY", lambda n: f"-----BEGIN {_PK}-----\n" + "AbCd\n" * (n // 5) + "a b"),
    ("_PRIVATE_KEY_BODY", lambda n: f"-----BEGIN {_PK}-----\nAAAA" + "-" * n),
    ("_DSN_EMPTY_USER_PASSWORD", lambda n: "pg://:" + "a:" * (n // 2)),
    ("_DSN_EMPTY_USER_PASSWORD", lambda n: "pg://:ab " * (n // 9)),
    ("_DSN_AT_IN_PASSWORD", lambda n: "pg://u:<redacted>@" + "a@" * (n // 2) + "x"),
    ("_DSN_AT_IN_PASSWORD", lambda n: "pg://u:<redacted>@" + "a" * n),
    ("_DSN_AT_IN_PASSWORD", lambda n: "pg://u:<redacted>@a " * (n // 20)),
    ("_DSN_AT_IN_PASSWORD", lambda n: "pg://u:<redacted>@" + "@a?" * (n // 3)),
    ("_DIGEST_PARAMS_AFTER_PLACEHOLDER", lambda n: 'authorization=<redacted>"' + "x y " * (n // 4)),
    ("_DIGEST_PARAMS_AFTER_PLACEHOLDER", lambda n: "authorization=<redacted> " * (n // 25)),
    ("_DIGEST_PARAMS_AFTER_PLACEHOLDER", lambda n: 'authorization=<redacted>"' * (n // 25)),
    (
        "_DIGEST_PARAMS_AFTER_PLACEHOLDER",
        lambda n: "authorization=<redacted> " + "ab=cd" * (n // 5),
    ),
    ("_PADDED_TOKEN_AFTER_PLACEHOLDER", lambda n: "<redacted> " + "aB0+" * (n // 4) + "x"),
    ("_PADDED_TOKEN_AFTER_PLACEHOLDER", lambda n: "<redacted> aB0= " * (n // 16)),
    ("_QUOTED_AFTER_PLACEHOLDER", lambda n: "<redacted>'" + "a" * n),
    ("_QUOTED_AFTER_PLACEHOLDER", lambda n: "<redacted>'a<redacted>\"" * (n // 23)),
    ("_QUOTED_AFTER_PLACEHOLDER", lambda n: "<redacted>'" + "\\'" * (n // 2)),
    ("_MEFOR_GLUED_AFTER_PLACEHOLDER", lambda n: "MEFOR_A=<redacted>" + "a'b" * (n // 3)),
    ("_MEFOR_GLUED_AFTER_PLACEHOLDER", lambda n: "MEFOR_A=<redacted>x " * (n // 20)),
    ("_MEFOR_GLUED_AFTER_PLACEHOLDER", lambda n: "MEFOR_A=<redacted>" + "<" * n),
)


@pytest.mark.parametrize(
    ("name", "shape"), _GROWTH_SHAPES, ids=[f"{n}-{i}" for i, (n, _s) in enumerate(_GROWTH_SHAPES)]
)
def test_each_stage_pattern_grows_linearly(name: str, shape: Callable[[int], str]) -> None:
    pattern: re.Pattern[str] = getattr(secretscrub, name)

    def sub(text: str) -> str:
        return pattern.sub("x", text)

    short, long = shape(_GROWTH_LENGTHS[0]), shape(_GROWTH_LENGTHS[1])
    growth = _growth_between(sub, short, long, rounds=5)
    assert growth <= _MAX_GROWTH, f"{name} grew {growth:.1f}x for 8x the length on {short[:40]!r}"


def test_the_whole_stage_grows_linearly() -> None:
    """Every pattern at once on a line holding every shape, as a surface runs them."""
    unit = (
        'authorization=<redacted>"a", b=c MEFOR_A=<redacted>x\'y pg://:p@q@r '
        f"<redacted> aB0= <redacted>'z' -----BEGIN {_PK}-----\nAAAA\n"
    )

    short = unit * (_GROWTH_LENGTHS[0] // len(unit))
    long = unit * (_GROWTH_LENGTHS[1] // len(unit))
    growth = _growth_between(secretscrub.scrub_added_shapes, short, long, rounds=5)
    assert growth <= _MAX_GROWTH, f"the stage grew {growth:.1f}x for 8x the length"
