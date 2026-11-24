# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The anonymizer salt's 32-character length floor and refusals that withhold the salt (BACKLOG #4652).

Both copies of the keyer are held: the toolkit's and the one vendored into the tee. The floor is
32 characters: ``secrets.token_hex(8)`` (16 characters, 64 bits) is refused, and
``secrets.token_hex(16)`` (32 characters, 128 bits) and ``secrets.token_urlsafe(24)`` pass. It is a
length floor, not an entropy measurement. A salt that cannot be UTF-8 encoded, as an undecodable
byte in an environment variable becomes, is refused with a message that quotes none of it and with
an empty exception chain: the codec's own error keeps the whole salt on ``.object``. The tee's
refusal names the variable the salt came from.

What these tests do not cover: the frames a refusal's traceback carries, the keyer's and its
callers', still hold the salt as a local, so a traceback renderer that captures locals would print
it.
"""

from __future__ import annotations

import importlib
from types import ModuleType

import pytest

from tee.__main__ import main as tee_main

#: FIXED draws, generated for this test and guarding nothing: a control that can fail at random is
#: not a control.
_HEX_8 = "457fee19d454b068"  # secrets.token_hex(8): 16 characters, 64 bits
_HEX_16 = "ec93f6bbc0f85c51c1ad15dc2bd6c6ef"  # secrets.token_hex(16): 32 characters, 128 bits
_URLSAFE_24 = "KwR-4smfMHodYmew3tHC4q-sf5mwBPHn"  # secrets.token_urlsafe(24): 32 characters
_URLSAFE_16 = "dMbt3MFrGIWbuBRLEO6GRA"  # secrets.token_urlsafe(16): 22 characters, 128 bits

#: What os.environ makes of an undecodable 0xFF byte on POSIX (surrogateescape); Windows can hold
#: the same unpaired surrogate in its UTF-16 environment.
_UNDECODABLE = "\udcff"

#: Ways a message could spell that byte. A lone surrogate itself cannot reach captured stderr:
#: writing one raises before any assertion could see it.
_BYTE_FORMS = ("dcff", "\\xff", "\xff", "0xff", "0xFF")


@pytest.fixture(params=["messagefoundry_toolkit.anon.keying", "tee.anon.keying"])
def keying(request: pytest.FixtureRequest) -> ModuleType:
    return importlib.import_module(request.param)


def _no_run_of(secret: str, text: str, width: int = 3) -> None:
    """No ``width``-character run of ``secret`` appears in ``text``."""
    assert len(secret) >= width, "a secret shorter than the run width checks nothing"
    for i in range(len(secret) - width + 1):
        assert secret[i : i + width] not in text, f"refusal quotes part of the salt at {i}"


def test_the_run_scan_fires_on_a_quoted_run() -> None:
    """Positive control for ``_no_run_of``: it must fail on text that quotes part of the secret."""
    with pytest.raises(AssertionError):
        _no_run_of(_HEX_8, f"refused: {_HEX_8[5:9]}")


def test_the_floor_is_32_characters(keying: ModuleType) -> None:
    assert keying.MIN_SALT_LEN == 32


@pytest.mark.parametrize("salt", [_HEX_8, _URLSAFE_16, _HEX_16[:31]])
def test_a_salt_under_32_characters_is_refused_without_quoting_it(
    keying: ModuleType, salt: str
) -> None:
    # _URLSAFE_16 carries 128 bits and is still refused: the floor counts characters.
    with pytest.raises(ValueError) as exc:
        keying.Keyer(salt)
    text = str(exc.value)
    assert "at least 32 characters" in text
    assert "secrets.token_urlsafe(24)" in text  # the generator, not a longer placeholder
    _no_run_of(salt, text)


@pytest.mark.parametrize("salt", [_HEX_16, _URLSAFE_24])
def test_a_32_character_generator_output_is_accepted(keying: ModuleType, salt: str) -> None:
    assert keying.Keyer(salt).seed("mrn", "12345") > 0


def test_an_unencodable_salt_is_refused_with_an_empty_chain(keying: ModuleType) -> None:
    salt = _HEX_16 + _UNDECODABLE
    with pytest.raises(ValueError) as exc:
        keying.Keyer(salt)
    # A UnicodeEncodeError is a ValueError and keeps the whole salt on .object.
    assert not isinstance(exc.value, UnicodeError)
    assert exc.value.__context__ is None
    assert exc.value.__cause__ is None
    text = str(exc.value)
    for form in (_UNDECODABLE, *_BYTE_FORMS):
        assert form not in text
    _no_run_of(_HEX_16, text)


@pytest.mark.parametrize("salt", [_HEX_8, _HEX_16 + _UNDECODABLE], ids=["short", "undecodable"])
@pytest.mark.parametrize("variable", ["MEFOR_ANON_SALT", "SITE_DATASET_SALT_4652"])
def test_the_tee_refusal_names_the_setting_and_withholds_the_salt(
    tmp_path, monkeypatch, capsys: pytest.CaptureFixture[str], salt: str, variable: str
) -> None:
    # The salt is checked before the store is read, so no capture is seeded. This sets the
    # in-process os.environ mapping; it does not exercise a salt read from a parent process's
    # environment block.
    monkeypatch.setenv(variable, salt)
    argv = ["anonymize-captures", "--db", str(tmp_path / "tee.db"), "--out", str(tmp_path / "o")]
    if variable != "MEFOR_ANON_SALT":
        argv += ["--salt-env", variable]
    assert tee_main(argv) == 1
    err = capsys.readouterr().err
    assert f"error: {variable}: " in err
    for form in _BYTE_FORMS:
        assert form not in err
    _no_run_of(salt.rstrip(_UNDECODABLE), err)
    assert not (tmp_path / "o").exists()
