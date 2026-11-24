# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The anonymizer salt's length floor and refusals that withhold the salt (BACKLOG #4652).

Both copies of the keyer are held: the toolkit's and the one vendored into the tee. A salt under
16 bytes is refused (the 16-character floor implies it). A salt that cannot be UTF-8 encoded, as an
undecodable byte in an environment variable becomes, is refused with a message that quotes none of
it and with an empty exception chain: the codec's own error keeps the whole salt on ``.object``.
The tee's refusal names the variable the salt came from.

What these tests do not cover: the refusing frame's locals still hold the salt, so a traceback
renderer that captures locals would print it.
"""

from __future__ import annotations

import importlib
from types import ModuleType

import pytest

from tee.__main__ import main as tee_main

#: Fifteen and sixteen characters of one random-looking ASCII draw: one byte each, and varied enough
#: that only the length floor decides. Synthetic, generated for this test, guarding nothing.
_SALT_16 = "Q7xZ9vK2mP4wR8tN"
_SALT_15 = _SALT_16[:15]

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
    for i in range(len(secret) - width + 1):
        assert secret[i : i + width] not in text, f"refusal quotes part of the salt at {i}"


def test_a_15_byte_salt_is_refused_without_quoting_it(keying: ModuleType) -> None:
    assert len(_SALT_15.encode("utf-8")) == 15
    with pytest.raises(ValueError) as exc:
        keying.Keyer(_SALT_15)
    assert str(keying.MIN_SALT_LEN) in str(exc.value)
    assert "secrets.token_urlsafe(24)" in str(exc.value)  # the generator, not a longer placeholder
    _no_run_of(_SALT_15, str(exc.value))


def test_a_16_byte_salt_is_accepted(keying: ModuleType) -> None:
    assert len(_SALT_16.encode("utf-8")) == 16
    keying.Keyer(_SALT_16)


def test_an_unencodable_salt_is_refused_with_an_empty_chain(keying: ModuleType) -> None:
    salt = _SALT_16 + _UNDECODABLE
    with pytest.raises(ValueError) as exc:
        keying.Keyer(salt)
    # A UnicodeEncodeError is a ValueError and keeps the whole salt on .object.
    assert not isinstance(exc.value, UnicodeError)
    assert exc.value.__context__ is None
    assert exc.value.__cause__ is None
    text = str(exc.value)
    for form in (_UNDECODABLE, *_BYTE_FORMS):
        assert form not in text
    _no_run_of(_SALT_16, text)


@pytest.mark.parametrize("salt", [_SALT_15, _SALT_16 + _UNDECODABLE], ids=["short", "undecodable"])
@pytest.mark.parametrize("variable", ["MEFOR_ANON_SALT", "SITE_DATASET_SALT_4652"])
def test_the_tee_refusal_names_the_setting_and_withholds_the_salt(
    tmp_path, monkeypatch, capsys: pytest.CaptureFixture[str], salt: str, variable: str
) -> None:
    # The salt is checked before the store is read, so no capture is seeded. The real environment
    # carries the lone surrogate on both platforms: surrogateescape on POSIX, UTF-16 on Windows.
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
