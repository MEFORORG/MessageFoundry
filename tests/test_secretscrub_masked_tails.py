# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The masked tails of BACKLOG #5546, #5547, #5548 and #5550: shapes whose value the credential
passes printed, and which each pass now writes back masked, character for character.

Each shape below printed its value on all three surfaces before the tails: ``scrub_credentials``,
``redact_log_line`` and the filter chain ``_install_phi_filters`` installs. The mask-only invariant,
the refused shapes and the guard controls are in ``tests/test_log_redaction_secret_domain.py``,
beside the differential they extend. Every value here is synthetic.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable

import pytest

from messagefoundry import secretscrub as scrub_mod
from messagefoundry.logging_setup import _install_phi_filters
from messagefoundry.secretscrub import scrub_credentials
from messagefoundry.support.redact import redact_log_line
from tests._growth import _growth_between
from tests._pem_fixture import b64_run, pem_block, pem_marker


def _through_the_installed_chain(line: str) -> str:
    """``line`` as a record's message through every filter ``_install_phi_filters`` installs."""
    handler = logging.NullHandler()
    _install_phi_filters(handler)
    record = logging.LogRecord("mefor.test", logging.ERROR, __file__, 1, "%s", (line,), None)
    assert handler.filter(record)
    return record.getMessage()


def _through_the_chain_as_a_traceback(line: str) -> str:
    """``line`` as an exception's message, so it reaches the chain as rendered ``exc_text``."""
    handler = logging.NullHandler()
    _install_phi_filters(handler)
    try:
        raise RuntimeError(line)
    except RuntimeError as exc:
        record = logging.LogRecord(
            "mefor.test", logging.ERROR, __file__, 1, "failed", (), (type(exc), exc, None)
        )
    assert handler.filter(record)
    return record.exc_text or ""


SURFACES: tuple[tuple[str, Callable[[str], str]], ...] = (
    ("scrub_credentials", scrub_credentials),
    ("redact_log_line", redact_log_line),
    ("installed chain", _through_the_installed_chain),
    ("chain traceback", _through_the_chain_as_a_traceback),
)

#: A synthetic token68 credential: base64 of no real user or password.
_BASIC = b64_run(1, 18) + "=="
#: A synthetic base64 run for a key body, and a short padded last line that no long-run sweep
#: reaches. Generated, as ``tests/_pem_fixture.py`` says why.
_KEY_LINE = b64_run(2, 70)
_KEY_LAST = b64_run(3, 8) + "=="


def _key_block(words: str, sep: str) -> str:
    return pem_block(f"{words} PRIVATE KEY", sep, _KEY_LINE, _KEY_LINE[::-1], _KEY_LAST)


#: The RFC 7616 section 3.9.1 request header, with the example values replaced by synthetic ones.
_DIGEST = (
    'Authorization: Digest username="zqUserMf", realm="zq-realm@example.invalid", '
    'uri="/zq/index.html", algorithm=SHA-256, nonce="Zq7NonceVal9xLj2Kd", nc=00000001, '
    'cnonce="Zq7CnonceVal4wPm8", qop=auth, response="zq0d1e2a3d4b5e6e7f8a9", '
    'opaque="Zq7OpaqueVal3Hs"'
)

#: Each red shape, with the value atoms none of the surfaces may print.
RED_SHAPES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("5546-json", '{"Authorization": "Basic ' + _BASIC + '"}', (_BASIC[:-2],)),
    ("5546-dict-repr", "{'Authorization': 'Basic " + _BASIC + "'}", (_BASIC[:-2],)),
    ("5546-bearer", '{"authorization": "Bearer ' + _BASIC + '"}', (_BASIC[:-2],)),
    ("5547-single", "password=b'zqv1 zqv2'", ("zqv1", "zqv2")),
    ("5547-double", 'token=b"zqv1 zqv2"', ("zqv1", "zqv2")),
    ("5547-key", "private_key=b'zqv1 zqv2'", ("zqv1", "zqv2")),
    ("5547-mefor", "MEFOR_STORE_PW=b'zqv1 zqv2'", ("zqv1", "zqv2")),
    (
        "5548-digest",
        _DIGEST,
        ("zqUserMf", "Zq7NonceVal9xLj2Kd", "Zq7CnonceVal4wPm8", "zq0d1e2a3d4b5e6e7f8a9"),
    ),
    ("5550-rsa", _key_block("RSA", "\n"), (_KEY_LINE, _KEY_LINE[::-1], _KEY_LAST[:-2])),
    ("5550-openssh", _key_block("OPENSSH", "\n"), (_KEY_LINE, _KEY_LINE[::-1], _KEY_LAST[:-2])),
    ("5550-rsa-escaped", _key_block("RSA", "\\n"), (_KEY_LINE, _KEY_LINE[::-1], _KEY_LAST[:-2])),
    (
        "5550-openssh-escaped",
        _key_block("OPENSSH", "\\n"),
        (_KEY_LINE, _KEY_LINE[::-1], _KEY_LAST[:-2]),
    ),
)


@pytest.mark.parametrize("surface", SURFACES, ids=[name for name, _ in SURFACES])
@pytest.mark.parametrize(
    ("line", "atoms"), [s[1:] for s in RED_SHAPES], ids=[s[0] for s in RED_SHAPES]
)
def test_no_value_of_a_red_shape_prints(
    line: str, atoms: tuple[str, ...], surface: tuple[str, Callable[[str], str]]
) -> None:
    name, apply = surface
    out = apply(line)
    printed = [atom for atom in atoms if atom in out]
    assert not printed, f"{name} printed {printed} from {line!r}: {out!r}"


#: The exact write-back, through ``scrub_credentials``: the line keeps its length and its quotes,
#: whitespace and HL7 delimiters, and every other tail character reads "x".
EXACT: tuple[tuple[str, str], ...] = (
    (
        '{"Authorization": "Basic ' + _BASIC + '"}',
        '{"Authorization=<redacted> ' + "x" * len(_BASIC) + '"}',
    ),
    ("password=b'zqv1 zqv2'", "password=<redacted>'xxxx xxxx'"),
    ('token=b"zqv1 zqv2"', 'token=<redacted>"xxxx xxxx"'),
    ("MEFOR_STORE_PW=b'zqv1 zqv2'", "MEFOR_STORE_PW=<redacted>xxxx xxxx'"),
    (
        pem_block("RSA PRIVATE KEY", "\\n", "ab+/cd=="),
        pem_block("RSA PRIVATE KEY", "\\n", "xxxxxxxx"),
    ),
)


@pytest.mark.parametrize(("line", "expected"), EXACT)
def test_the_tail_is_written_back_masked_character_for_character(line: str, expected: str) -> None:
    assert scrub_credentials(line) == expected


#: Blocks that hold no private key, which the key-block pass leaves exactly as it found them.
NOT_A_PRIVATE_KEY = (
    pem_block("CERTIFICATE", "\n", _KEY_LINE),
    pem_block("PUBLIC KEY", "\n", _KEY_LINE),
    pem_block("PGP PRIVATE KEY BLOCK", "\n", _KEY_LINE),
)


@pytest.mark.parametrize("block", NOT_A_PRIVATE_KEY)
def test_a_certificate_or_public_key_block_is_left_alone(block: str) -> None:
    assert scrub_mod.mask_private_key_blocks(block) == block
    assert scrub_credentials(block) == block


def test_a_cut_short_key_block_is_masked_only_to_a_line_boundary() -> None:
    """A block cut off by a driver or a clamp has no END marker. Its whole lines are masked, and a
    last line that does not end where a line ends is left as the text left it."""
    head = pem_marker("BEGIN", "EC PRIVATE KEY") + "\n" + _KEY_LINE + "\n"
    assert (
        scrub_mod.mask_private_key_blocks(head + "Zq7w")
        == head.replace(_KEY_LINE, "x" * len(_KEY_LINE)) + "x" * 4
    )
    cut = head + "Zq7w rest of the line"
    assert scrub_mod.mask_private_key_blocks(cut) == cut.replace(_KEY_LINE, "x" * len(_KEY_LINE))


#: The tail grammar's shapes, each about ``length`` long, built to make its walk run longest.
_TAIL_GROWTH_SHAPES: tuple[Callable[[int], str], ...] = (
    lambda length: '"authorization": "Basic ' + "a." * (length // 2) + "=" * 8,
    lambda length: "password=b'" + "a " * (length // 2),
    lambda length: 'Authorization: Digest username="u"' + ', a="b:c"' * (length // 10) + ";",
    lambda length: pem_marker("BEGIN", "RSA PRIVATE KEY") + "\\nab" * (length // 4) + "==x",
)

#: The bound the timing arms in the secret-domain suite use, for 8x the length.
_MAX_GROWTH = 24.0


def test_the_tails_grow_linearly_in_line_length() -> None:
    """Relative growth, not an absolute budget: each tail's worst walk at 16 KB over its walk at 2 KB,
    for 8x the length, against a backtracking control timed the same way in the same run."""
    for shape in _TAIL_GROWTH_SHAPES:
        growth = _growth_between(scrub_credentials, shape(2048), shape(16384), rounds=5)
        assert growth <= _MAX_GROWTH, f"{shape(24)!r} grew {growth:.1f}x for 8x the length"
    control = re.compile(r"(?:a|\.)*+=(?:(?:a|\.)*)*b")
    control_growth = _growth_between(
        lambda text: control.search(text), "a." * 256, "a." * 2048, rounds=3
    )
    assert control_growth > _MAX_GROWTH, f"the control grew only {control_growth:.1f}x"
