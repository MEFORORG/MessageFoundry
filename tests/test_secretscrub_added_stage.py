# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5546 to #5550: five credential shapes the scrub printed, hidden by a stage of their own.

The five, each a row: a padded Basic or Bearer token inside a quoted JSON or dict Authorization value
(#5546); a Python bytes literal after a credential label (#5547); a Digest Authorization header's
parameter list (#5548); a DSN password behind an empty username or holding an unencoded "@" (#5549);
and a PEM, OpenSSH or PGP private key block's body (#5550).

THE STAGE IS ADDITIVE. ``secretscrub.scrub_added_shapes`` runs after every pass a surface already runs,
on that surface's output; its docstring states what it promises. The per-row tests here read only the
public surfaces, so each fails on the code before the stage on its assertion. The regression guard
compares each surface with the stage on against the same surface with it off, which is the code before
it, over every probe the superseded branch ``b234-scrub-5546-5550`` collected and a seeded corpus: no
secret may print that the code before the stage hid. That includes surfaces that cut their text after
redaction, read on lines long enough for the cut to fall inside and past each probe. A surface that
reads the chain's output again is held to printing nothing the chain did not print before the stage;
the guard's docstring says why it is held to less.

Every value is synthetic. A key block's type is joined from parts, so no literal key block sits in this
file for the repository's secret scanner to read."""

from __future__ import annotations

import inspect
import json
import logging
import random
import re
from collections.abc import Callable
from dataclasses import dataclass

import pytest

from messagefoundry import __main__ as cli_mod
from messagefoundry import controlchars, logging_guard, redaction, secretscrub
from messagefoundry.auth.service import _new_ip_path_field
from messagefoundry.config.settings import StoreBackend
from messagefoundry.controlchars import log_field_token, scrub_control_chars
from messagefoundry.logging_setup import CredentialScrubFilter, _install_phi_filters
from messagefoundry.secretscrub import CREDENTIAL_PLACEHOLDER, scrub_credentials
from messagefoundry.store.privilege import probe_failure
from messagefoundry.support.redact import REDACTION_PLACEHOLDER, redact_log_line
from tests._growth import _growth_between
from tests._scrub_stage import REAL_STAGE, replace_the_added_stage, without_the_added_stage
from tests.test_log_redaction_secret_domain import (
    _GROWTH_LENGTHS,
    _MAX_GROWTH,
    _applied_pattern_names,
)

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


def _store_error(text: str) -> str:
    """The privilege probe's error detail, which cuts ``redact_log_line`` at 300 characters; the
    PostgreSQL and SQL Server close warnings cut the same way."""
    return probe_failure(StoreBackend.POSTGRES, RuntimeError(text)).detail


def _provision_schema_error(text: str) -> str:
    """The ``store provision-schema`` failure text, as ``__main__`` writes it;
    ``test_the_provision_schema_cut_is_the_one_read_here`` holds the two together."""
    return redact_log_line(text)[:500]


#: Surfaces that cut their text AFTER redaction, so a stage that moved later text earlier would
#: print what the cut had cut off. At least these; each takes the probe text as its input.
_CLIP_SURFACES: tuple[tuple[str, Callable[[str], str]], ...] = (
    ("new-address path", _new_ip_path_field),
    ("guard diagnostic", logging_guard._safe_diagnostic),
    ("store error", _store_error),
    ("provision-schema error", _provision_schema_error),
)
#: The cut each surface makes, in characters of its output, for building lines the cut falls in.
_CLIP_AT = {
    "new-address path": 256,
    "guard diagnostic": logging_guard._DIAGNOSTIC_LIMIT,
    "store error": 300,
    "provision-schema error": 500,
}


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
        f"key load failed -----BEGIN {_PK}----- MIIEvQIBADANBgkqhk zq-pem_pem-99-abcdef "
        f"-----END {_PK}----- now",
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
    body = "\nMHcCAQEE\nzq-pem_pem-99\n"
    line = f"x\n-----BEGIN EC {_PK}-----{body}-----END EC {_PK}-----\nnext words"
    out = scrub_credentials(line)
    filled = CREDENTIAL_PLACEHOLDER + secretscrub._fill(body)
    assert out == f"x\n-----BEGIN EC {_PK}-----{filled}-----END EC {_PK}-----\nnext words"


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
    filled = CREDENTIAL_PLACEHOLDER + secretscrub._fill("\nMIIEowIB\nzq-pem_pem-99")
    assert out == f"-----BEGIN RSA {_PK}-----{filled}\nretry in 5 s\nAAAA", out


@pytest.mark.parametrize(
    ("line", "kept"),
    (
        # A key pasted onto one line ends in a short chunk, and on the write-time chain the PHI pass
        # has spelled both markers -----[redacted]----- before the stage reads them.
        (
            f"cfg: -----BEGIN RSA {_PK}----- MIIEvQIBADANBgkqhkiG9w0BAQEFAASC zq-Ln_A-81 "
            f"-----END RSA {_PK}----- loaded",
            "loaded",
        ),
        (
            f"cfg: -----BEGIN RSA {_PK}----- MIIEvQIBADANBgkqhkiG9w0BAQEFAASC "
            f"zq-Ln_A-81zq-Ln_B-82 Ab== -----END RSA {_PK}----- loaded",
            "loaded",
        ),
        # A JSON key file: the support bundle's long-base64 sweep reads the "n" of the first
        # escaped line break into its run, so a backslash stands right before its placeholder.
        (
            f'"private_key": "-----BEGIN {_PK}-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEA'
            f'\\nzq-Ln_A-81zq-Ln_B-82Xg==\\n-----END {_PK}-----\\n", "port": 6661',
            '"port": 6661',
        ),
    ),
)
def test_5550_a_one_line_key_and_a_swept_json_key_are_hidden(line: str, kept: str) -> None:
    """Two shapes the third review found printing: a key on one line whose last chunk is short, on
    the write-time chain, and a JSON key file the support bundle's sweep reached first."""
    _assert_hidden(line, ("zq-Ln_A-81", "zq-Ln_B-82"), (kept,))


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
        "ValueError(\"password=b'zq-R1_A zq-R1_B'\")",
        "KeyError('token=b\"zq-R1_A zq-R1_B\"')",
        "env MEFOR_X=b'zq-R1_A zq-R1_B'!",
        "x password=b'zq-R1_A zq-R1_B'/next",
    ),
)
def test_a_round_one_shape_is_hidden(line: str) -> None:
    _assert_hidden(line, ("zq-R1_A", "zq-R1_B"))


@pytest.mark.parametrize(
    "line",
    (
        "-----Engine Start-----\nconnections loaded ok\n-----Engine Ready-----",
        "-----Config Summary-----\nconn IB_ACME_ADT port 6661\n-----End Summary-----",
    ),
)
def test_prose_between_two_banners_is_no_key_body(line: str) -> None:
    """The PHI pass spells a dash-wrapped banner as it spells a key marker."""
    for surface, apply in _SURFACES:
        out = apply(line)
        assert "loaded ok" in out or "port 6661" in out, f"{surface}: {out!r}"


@pytest.mark.parametrize(
    ("surface", "text"),
    (
        (
            "store error",
            "login failed password=b'" + "zq-w " * 58 + "' rejected; echoed 'zq-tail-value'",
        ),
        (
            "guard diagnostic",
            "sink failed password=b'" + "zq-w " * 195 + "' then echoed 'zq-tail-value'",
        ),
        (
            "provision-schema error",
            "ddl failed password=b'" + "zq-w " * 98 + "' rejected; echoed 'zq-tail-value'",
        ),
        ("new-address path", "/api/x token=<redacted>'" + "A" * 230 + "' x/zq-tail-value"),
        ("new-address path", "/api/x password=b'" + "A" * 230 + "' x/zq-tail-value"),
    ),
)
def test_a_long_hidden_value_pulls_no_cut_text_into_view(surface: str, text: str) -> None:
    """Each surface cuts its text after redaction, at a point past the hidden value, and the code
    before the stage cut the tail off there. The stage hides the value and must not print the tail.
    The two new-address paths are the lines the third review measured printing."""
    apply = dict(_CLIP_SURFACES)[surface]
    assert "zq-tail-value" not in apply(text)
    with pytest.MonkeyPatch.context() as patch:
        without_the_added_stage(patch)
        assert "zq-tail-value" not in apply(text)


@pytest.mark.parametrize(
    "path",
    ('/MEFOR_X=a"b"\'zq-tail-value', '/MEFOR_A_PW=vq0b"vq1pwd=-b"\'zq-tail-value'),
)
def test_a_mefor_remnant_is_hidden_to_white_space_on_the_settled_reading(path: str) -> None:
    """The bounded field reads the chain until it settles, and under the code before the stage each
    later pass took one more quote of a ``MEFOR_`` remnant until white space. The stage takes the
    whole run at once, so spaces never end it early and the settled reading hides it all."""
    assert "zq-tail-value" not in _new_ip_path_field(path)
    with pytest.MonkeyPatch.context() as patch:
        without_the_added_stage(patch)
        assert "zq-tail-value" not in _new_ip_path_field(path)


def test_a_key_body_and_an_empty_username_password_keep_a_label_a_pass_read() -> None:
    """Neither takes a ``label=`` and its placeholder: a later reading would read that label's value
    again, and the label tells the reader which credential was there."""
    out = scrub_credentials(f"-----BEGIN RSA {_PK}-----\nMIIEowIB\npassword=hunter2\nnext")
    assert f"\npassword={CREDENTIAL_PLACEHOLDER}\nnext" in out and "MIIEowIB" not in out, out
    out = scrub_credentials("redis://:MEFOR_REDIS_PW=x'y'@cache.invalid")
    assert f"MEFOR_REDIS_PW={CREDENTIAL_PLACEHOLDER}" in out, out


def test_the_guard_diagnostic_keeps_its_bound() -> None:
    """The stage can lengthen text, and the log-write guard cuts after all of its redaction, the
    stage included, so the guard's bound still holds on a line the stage lengthens."""
    out = logging_guard._safe_diagnostic("a://:p@ " * 125)
    assert len(out) <= logging_guard._DIAGNOSTIC_LIMIT
    assert "://:p@" not in out


def test_the_provision_schema_cut_is_the_one_read_here() -> None:
    """``_CLIP_SURFACES`` reads the provision-schema error as the expression ``__main__`` writes, so
    this holds the two together: if that site changes, the guard reads a site that is gone."""
    source = inspect.getsource(cli_mod._store_provision_schema)
    assert "redact_log_line(str(exc))[:500]" in source


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
        without_the_added_stage(patch)
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
    # The third review's shapes: a one-line key ending in a short chunk, a JSON key file the
    # support bundle's sweep reaches first, armor-header lines naming markers, and a value glued to a
    # placeholder before a later label and a tail the cut must not reach.
    f"cfg: -----BEGIN RSA {_PK}----- MIIEvQIBADANBgkqhkiG9w0BAQEFAASC zq-Ln_A-81 "
    f"-----END RSA {_PK}----- loaded",
    f'"k": "-----BEGIN {_PK}-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEA'
    f'\\nzq-Ln_A-81zq-Ln_B-82Xg==\\n-----END {_PK}-----\\n", "port": 6661',
    f"X: -----BEGIN RSA {_PK}-----\nX: -----BEGIN RSA {_PK}-----\na b zq-Hd_A-83",
    "/api/x token=<redacted>'zq-Gl_A-84 zq-Gl_B-85' x/zq-tail-value",
    "redis://:zq-Dsn_P-86@cache.invalid password=b'zq-Gl_C-87 w' then MEFOR_A='zq-Gl_D-88'",
    # The fourth review's shapes, each printed on a surface that reads again: a MEFOR_ remnant the
    # spaces cut short, an empty-username DSN run over a label, and a key line holding a label.
    '/MEFOR_X=a"b"\'zq-Rr_A-89',
    "redis://:MEFOR_REDIS_PW=x'y'@cache.invalid zq-Rr_B-90",
    'MEFOR_A_PW=vq0b"vq1pwd=-b"\'vq5token=zq-Rr_C-91',
    "pg://:MEFOR_A_PW=vq1<redacted>vq2'vq31970-01-01@vq5:vq6Bearer zq-Rr_D-92{",
    f"-vq0\\nvq1-----BEGIN {_PK}-----\nvq2_password: vq4\n-----END {_PK}-----zq-Rr_E-93",
    "Digest MEFOR_A_PW=vq19x1b'vq19x2b\"vq19x3'b'password=\"vq19x7\nzq-Rr_F-94",
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
    #: off.
    reread_newly: list[str]


def _reading(monkeypatch: pytest.MonkeyPatch, corpus: list[str]) -> _Reading:
    after = _surface_outputs(corpus)
    with monkeypatch.context() as patch:
        without_the_added_stage(patch)
        before = _surface_outputs(corpus)
    secrets = [_secrets(line) for line in corpus]
    direct = {name for name, _apply in _SURFACES}
    reading = _Reading([], 0, [], [])
    for name in after:
        for i, line in enumerate(corpus):
            for secret in secrets[i]:
                was, now = secret in before[name][i], secret in after[name][i]
                if name in direct:
                    if now and not was:
                        reading.newly.append(f"{name}: {secret!r} in {line!r}")
                    reading.hidden_now += was and not now
                    continue
                if now and secret not in before["write-time chain"][i]:
                    reading.beyond_first_surface.append(f"{name}: {secret!r} in {line!r}")
                if now and not was:
                    reading.reread_newly.append(f"{name}: {secret!r} in {line!r}")
    return reading


def test_the_stage_prints_nothing_the_code_before_it_hid(monkeypatch: pytest.MonkeyPatch) -> None:
    """THE REGRESSION GUARD. On every surface the stage runs on, no secret of any probe or seeded line
    may print that the same surface hid with the stage off. The reverse count must be above zero, or
    the stage hid nothing and nothing was compared.

    The two surfaces that read the chain's output again are held to the same on this corpus, and,
    beyond it, to printing nothing the write-time chain did not print with the stage off. That second
    hold is the one the stage comment in ``secretscrub.py`` states for every line: a re-read can hide
    less than it did where the spaces end a run a later pass read whole. Other seeds of the same
    generator find such lines, each a whitespace-free HL7 field run the PHI pass took whole on its
    second reading; this corpus holds none, so a shape fixed here that comes back reds."""
    corpus = [*_OLD_BRANCH_PROBES, *_seeded_corpus(3000, 5546)]
    reading = _reading(monkeypatch, corpus)
    assert not reading.newly, (
        f"{len(reading.newly)} secrets printed that were hidden, first: {reading.newly[:3]}"
    )
    assert reading.hidden_now > 0, "the stage hid nothing, so the comparison proved nothing"
    assert not reading.beyond_first_surface, reading.beyond_first_surface[:3]
    assert not reading.reread_newly, reading.reread_newly[:3]


def test_the_guard_can_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    """THE POSITIVE CONTROL. A stage that changes a pass it should not, here one that writes the
    password back over its placeholder, must be caught on the same corpus."""

    def leaky(text: str, placeholder: str = CREDENTIAL_PLACEHOLDER) -> str:
        hidden = re.escape(f"svc:{placeholder}") + " *@"
        return re.sub(hidden, "svc:pw-At_Head-57@", REAL_STAGE(text, placeholder))

    replace_the_added_stage(monkeypatch, leaky)
    reading = _reading(monkeypatch, list(_OLD_BRANCH_PROBES))
    assert reading.newly, "a stage that prints a hidden password went unnoticed"
    assert reading.beyond_first_surface, "the re-read arm let the restored password through"


def test_the_stage_is_switched_off_on_every_module_that_holds_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The off switch finds every importer, so a stage-off reading is the code before the stage on
    every surface the guard reads, ``support.redact`` included."""
    patched = without_the_added_stage(monkeypatch)
    assert "messagefoundry.support.redact" in patched, patched
    assert scrub_credentials("password=b'zq-Off_A zq-Off_B' x").count("zq-Off_B") == 1


# --- The regression guard on the surfaces that cut after redaction ---------------------------------


def _clip_corpus(surface: str) -> list[str]:
    """Each probe after a run of filler sized so the surface's cut falls at several points inside the
    probe and just past it, with a tail after the probe that the cut leaves out on the code before
    the stage. The new-address path is cut after its own escape, which writes each space, quote and
    separator as seven characters, so its points reach four times further back into the probe."""
    cut = _CLIP_AT[surface]
    reach = 4 if surface == "new-address path" else 1
    lines = []
    for i, probe in enumerate(_OLD_BRANCH_PROBES):
        tail = f" then echoed zq-tail-{i:03d}-seen"
        span = reach * len(probe) + 60
        for back in range(-40, span, max(7, span // 8)):
            lead = cut + back - len(probe)
            if lead >= 0:
                # "w/" pairs: no escape widens them, and they join no label or value.
                lines.append("w/" * (lead // 2) + probe + tail)
    return lines


#: The bounded log field's cut mark and checksum, and its escape of one UTF-16 code unit.
_FIELD_CUT_MARK = re.compile(re.escape(controlchars._LOG_FIELD_CUT_MARK) + "[0-9a-f]{8}")
_FIELD_ESCAPE = re.compile(r"_u([0-9A-F]{4})_")


def _readable(out: str) -> str:
    """``out`` with a bounded log field's escapes read back and its checksum dropped, so a secret is
    found as written and the checksum's hex, which differs whenever the text does, reads as none."""
    out = _FIELD_CUT_MARK.sub("", out)
    return _FIELD_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), out)


def _clip_newly(monkeypatch: pytest.MonkeyPatch) -> tuple[list[str], int, int]:
    """``(secrets a cut surface prints that it hid with the stage off, the count the other way, the
    lines read)``, over every surface in ``_CLIP_SURFACES``."""
    newly: list[str] = []
    hidden_now = read = 0
    for surface, apply in _CLIP_SURFACES:
        corpus = _clip_corpus(surface)
        read += len(corpus)
        after = [_readable(apply(line)) for line in corpus]
        with monkeypatch.context() as patch:
            without_the_added_stage(patch)
            before = [_readable(apply(line)) for line in corpus]
        for line, now_out, was_out in zip(corpus, after, before, strict=True):
            for secret in _secrets(line):
                was, now = secret in was_out, secret in now_out
                if now and not was:
                    newly.append(f"{surface}: {secret!r} in {line!r} -> {now_out!r}")
                hidden_now += was and not now
    return newly, hidden_now, read


def test_no_cut_surface_prints_what_the_code_before_the_stage_hid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """THE REGRESSION GUARD FOR CUT SURFACES. At least the bounded new-address path field, the
    log-write guard's diagnostic, the store error detail and the provision-schema error cut after
    redaction. On each, over every probe placed so the cut falls inside it and past it, no secret may
    print that the same surface hid with the stage off, and the stage must hide something."""
    newly, hidden_now, read = _clip_newly(monkeypatch)
    assert read > 1000, f"only {read} lines were read"
    assert not newly, f"{len(newly)} secrets printed that were hidden, first: {newly[:3]}"
    assert hidden_now > 0, "the stage hid nothing on a cut surface, so nothing was compared"


def test_the_cut_guard_can_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    """THE POSITIVE CONTROL. A stage that drops the span it hides instead of filling it, as the
    branch's first two rounds did, moves later text before the cut, and that must be caught."""

    def shortening(text: str, placeholder: str = CREDENTIAL_PLACEHOLDER) -> str:
        return re.sub(r"(?<=>|\]) {2,}", "", REAL_STAGE(text, placeholder))

    replace_the_added_stage(monkeypatch, shortening)
    newly, _hidden_now, _read = _clip_newly(monkeypatch)
    assert newly, "a stage that shortens a line went unnoticed on every cut surface"


def _width_readings(text: str) -> tuple[int, ...]:
    """``text``'s length as written, and after each escape a surface applies after the stage: the
    control-character escape, a JSON string's, a repr's, and the bounded log field's."""
    literals = (CREDENTIAL_PLACEHOLDER, redaction._REDACTED)
    return (
        len(text),
        len(scrub_control_chars(text)),
        len(json.dumps(text)),
        len(repr(text)),
        len(log_field_token(text, 10**9, literals=literals)),
    )


def test_the_stage_never_shortens_what_it_reads(monkeypatch: pytest.MonkeyPatch) -> None:
    """The property ``scrub_added_shapes``'s docstring states, read on every text the stage received
    over the whole corpus on every surface, the cut ones included: its output is no shorter than its
    input as written or after any of those escapes. A probe of characters each escape widens, and of
    line breaks and characters past U+FFFF, holds the widest case."""
    seen: list[tuple[str, str]] = []

    def recording(text: str, placeholder: str = CREDENTIAL_PLACEHOLDER) -> str:
        out = REAL_STAGE(text, placeholder)
        seen.append((text, out))
        return out

    replace_the_added_stage(monkeypatch, recording)
    wide = "password=b'\\\\ \"\U0001f511\u200b\n\u00e9' tail"
    corpus = [*_OLD_BRANCH_PROBES, *_seeded_corpus(1500, 5551), wide]
    _surface_outputs(corpus)
    for surface, apply in _CLIP_SURFACES:
        for line in _clip_corpus(surface)[::5]:
            apply(line)
    changed = [(text, out) for text, out in seen if out != text]
    assert len(changed) > 100, f"only {len(changed)} texts changed, so little was compared"
    shorter = [
        (text, out)
        for text, out in changed
        if any(o < t for o, t in zip(_width_readings(out), _width_readings(text), strict=True))
    ]
    assert not shorter, f"{len(shorter)} outputs are shorter, first: {shorter[:2]}"
    assert any("\U0001f511" in text for text, _out in changed), "the wide probe was not read"


# --- Linear growth ------------------------------------------------------------------------------------

#: Timed at the span and bound ``tests/test_log_redaction_secret_domain.py`` measures the scrub
#: patterns with, imported from there; ``_GROWTH_LENGTHS`` and ``_MAX_GROWTH`` there say why.
_GROWTH_SHAPES: tuple[tuple[str, Callable[[int], str]], ...] = (
    ("_PRIVATE_KEY_BODY", lambda n: f"-----BEGIN {_PK}-----\n" + "AbC+" * (n // 4)),
    ("_PRIVATE_KEY_BODY", lambda n: "-----[redacted]-----\nAAAA" * (n // 24)),
    ("_PRIVATE_KEY_BODY", lambda n: f"-----BEGIN {_PK}----- x " * (n // 30)),
    ("_PRIVATE_KEY_BODY", lambda n: "-----[redacted]-----\n" + "Ab-" * (n // 3)),
    ("_PRIVATE_KEY_BODY", lambda n: f"-----BEGIN {_PK}-----\n" + "AbCd\n" * (n // 5) + "a b"),
    ("_PRIVATE_KEY_BODY", lambda n: f"-----BEGIN {_PK}-----\nAAAA" + "-" * n),
    ("_PRIVATE_KEY_BODY", lambda n: "-----[redacted]-----" + " AAAAAAAAAAAAAAAAAAAA" * (n // 21)),
    ("_PRIVATE_KEY_BODY", lambda n: "-----[redacted]-----\n" + "AAAA<redacted>\n" * (n // 15)),
    # The armor-header walk over later markers, which the third review measured quadratic.
    ("_PRIVATE_KEY_BODY", lambda n: f"X: -----BEGIN RSA {_PK}-----\n" * (n // 37) + "a b"),
    ("_PRIVATE_KEY_BODY", lambda n: "X: -----[redacted]-----\n" * (n // 24) + "a b"),
    ("_PRIVATE_KEY_BODY", lambda n: f"X: -----BEGIN RSA {_PK}-----\\n" * (n // 38) + "a b"),
    ("_PRIVATE_KEY_BODY", lambda n: "-----[redacted]-----\nX: " + "a-" * (n // 2) + "\na b"),
    # The one-line form's placeholder and short chunks, and an escaped break before a placeholder.
    ("_PRIVATE_KEY_BODY", lambda n: "-----[redacted]-----" + " [REDACTED]" * (n // 11) + " ab"),
    ("_PRIVATE_KEY_BODY", lambda n: "-----[redacted]-----" + " AAAAAAAAAAAAAAAA ab" * (n // 20)),
    ("_PRIVATE_KEY_BODY", lambda n: "-----[redacted]-----" + "\\[REDACTED]" * (n // 11) + " x"),
    ("_PRIVATE_KEY_BODY", lambda n: "-----[redacted]-----\n" + "\\" * n + "[REDACTED] x"),
    ("_DSN_EMPTY_USER_PASSWORD", lambda n: "pg://:" + "a:" * (n // 2)),
    ("_DSN_EMPTY_USER_PASSWORD", lambda n: "pg://:ab " * (n // 9)),
    ("_DSN_AT_IN_PASSWORD", lambda n: "pg://u:<redacted>@" + "a@" * (n // 2) + "x"),
    ("_DSN_AT_IN_PASSWORD", lambda n: "pg://u:<redacted>@" + "a" * n),
    ("_DSN_AT_IN_PASSWORD", lambda n: "pg://u:<redacted>@a " * (n // 20)),
    ("_DSN_AT_IN_PASSWORD", lambda n: "pg://u:<redacted>@" + "@a?" * (n // 3)),
    ("_DIGEST_PARAMS_AFTER_PLACEHOLDER", lambda n: 'authorization=<redacted>"' + "x y " * (n // 4)),
    ("_DIGEST_PARAMS_AFTER_PLACEHOLDER", lambda n: "authorization=<redacted> " * (n // 25)),
    ("_DIGEST_PARAMS_AFTER_PLACEHOLDER", lambda n: 'authorization=<redacted>"' * (n // 25)),
    ("_DIGEST_PARAMS_AFTER_PLACEHOLDER", lambda n: "authorization=<redacted>" * (n // 24)),
    ("_DIGEST_PARAMS_AFTER_PLACEHOLDER", lambda n: "authorization=<redacted>';" * (n // 26)),
    ("_DIGEST_PARAMS_AFTER_PLACEHOLDER", lambda n: "authorization=<redacted>'}" * (n // 26)),
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
    ("_MEFOR_GLUED_AFTER_PLACEHOLDER", lambda n: "MEFOR_A=<redacted>a\n" * (n // 20)),
    ("_MEFOR_GLUED_AFTER_PLACEHOLDER", lambda n: "MEFOR_A=<redacted>a" + "b c" * (n // 3)),
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


def test_every_pattern_the_stage_applies_is_timed_and_held_here() -> None:
    """The family-table derivation in ``tests/test_log_redaction_secret_domain.py`` reads
    ``redact_log_line``'s own calls, so it does not reach the patterns the stage applies. This
    derives them from ``scrub_added_shapes`` the same way, by AST, so a pattern added to the stage
    without a growth shape here reds."""
    applied = _applied_pattern_names(secretscrub, "scrub_added_shapes")
    assert len(applied) >= 6, f"the derivation found only {sorted(applied)}"
    assert applied == {name for name, _shape in _GROWTH_SHAPES}


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
