# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The anonymizer salt's length floor, stated in bytes, and refusals that withhold the salt (BACKLOG #4652).

The keyer refuses a salt under 16 bytes, the length of a 128-bit key. Both copies of the keyer are
held to it: the toolkit's and the one vendored into the tee. Each refusal names the floor, and the
tee's names the setting the salt came from, without quoting any of the salt. A salt that cannot be
UTF-8 encoded, as an undecodable byte in an environment variable becomes, is refused without the
offending character in the message or the traceback.
"""

from __future__ import annotations

import importlib
import traceback
from types import ModuleType

import pytest

from tee.__main__ import main as tee_main
from tests._tee_seed import SYNTHETIC_ADT
from tests._tee_seed import seed_capture as _seed_capture

#: Fifteen and sixteen characters of one random-looking ASCII draw: one byte each, and varied enough
#: that only the length floor decides. Synthetic, generated for this test, guarding nothing.
_SALT_16 = "Q7xZ9vK2mP4wR8tN"
_SALT_15 = _SALT_16[:15]


@pytest.fixture(params=["messagefoundry_toolkit.anon.keying", "tee.anon.keying"])
def keying(request: pytest.FixtureRequest) -> ModuleType:
    return importlib.import_module(request.param)


def _no_run_of(secret: str, text: str, width: int = 3) -> None:
    """No ``width``-character run of ``secret`` appears in ``text``."""
    for i in range(len(secret) - width + 1):
        assert secret[i : i + width] not in text, f"refusal quotes part of the salt at {i}"


def test_the_byte_floor_is_128_bits(keying: ModuleType) -> None:
    assert keying.MIN_SALT_BYTES == 16


def test_a_15_byte_salt_is_refused_naming_the_floor(keying: ModuleType) -> None:
    assert len(_SALT_15.encode("utf-8")) == 15
    with pytest.raises(ValueError) as exc:
        keying.Keyer(_SALT_15)
    text = str(exc.value)
    assert "16 bytes" in text
    assert "128-bit" in text
    _no_run_of(_SALT_15, text)


def test_a_16_byte_salt_is_accepted(keying: ModuleType) -> None:
    assert len(_SALT_16.encode("utf-8")) == 16
    keying.Keyer(_SALT_16)


def test_an_unencodable_salt_is_refused_without_its_character(keying: ModuleType) -> None:
    # "\udcff" is what os.environ makes of an undecodable 0xFF byte on POSIX (surrogateescape).
    salt = _SALT_16 + "\udcff"
    with pytest.raises(ValueError) as exc:
        keying.Keyer(salt)
    assert not isinstance(exc.value, UnicodeError)
    assert exc.value.__context__ is None and exc.value.__cause__ is None
    rendered = "".join(traceback.format_exception(exc.value))
    for form in ("\udcff", "\\udcff", "0xff", "dcff"):
        assert form not in rendered
    _no_run_of(_SALT_16, rendered)


def test_the_tee_refusal_names_the_setting_and_withholds_the_salt(
    tmp_path, monkeypatch, capsys: pytest.CaptureFixture[str]
) -> None:
    db = str(tmp_path / "tee.db")
    _seed_capture(db, SYNTHETIC_ADT.encode("latin-1"))
    monkeypatch.setenv("MEFOR_ANON_SALT", _SALT_15)
    out = tmp_path / "ds.jsonl"
    assert tee_main(["anonymize-captures", "--db", db, "--out", str(out)]) == 1
    err = capsys.readouterr().err
    assert "MEFOR_ANON_SALT" in err
    assert "16 bytes" in err
    _no_run_of(_SALT_15, err)
    assert not out.exists()
