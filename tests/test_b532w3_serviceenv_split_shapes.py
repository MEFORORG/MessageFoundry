# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Split secrets that the service-environment reader let through (vault BACKLOG #5394, added
items 6 and 12).

A secret split from its empty secret-class name, into the next ``REG_MULTI_SZ`` item or onto a
later line of one string below another variable, refuses unless the line below the name is
positively an ordinary variable's: the reader fails closed. The controls are the items under a
plain name that still end the empty value, and the ``MEFOR_VALUE_*`` and secrets-directory
values, which keep the plain line rule so their remedy text stays true. Each test drives
:func:`messagefoundry.serviceenv.read_service_env_posture` through a probe, so every one runs on
every platform. Synthetic values only: the stand-ins decode to synthetic text, never a real key.
"""

from __future__ import annotations

import base64
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field

import pytest

from messagefoundry import serviceenv
from messagefoundry.serviceenv import (
    KEY_CLASS_NAMES,
    ServiceEnvPosture,
    read_service_env_posture,
    service_env_refusal,
)

_EXTRA = "Parameters\\AppEnvironmentExtra"

#: A store-key-sized base64url stand-in: 32 bytes, so 43 characters and one ``=``, with ``-`` and
#: ``_`` in it, so it is outside the standard alphabet and holds no standard 43-character run.
_URL_KEY = base64.urlsafe_b64encode(b"\xfb\xffsynthetic-store-key-0123456789").decode()
#: A short base64url stand-in with one ``=`` of padding.
_URL_SHORT = base64.urlsafe_b64encode(b"\xfb\xffsynthetic").decode()
#: A store-key-sized standard base64 stand-in with one ``=`` of padding.
_STD_KEY = base64.b64encode(b"synthetic-store-key-0123456789ab").decode()

#: The split shapes item 12 names, at least: one-``=`` base64url, quoted, comma-trailed and
#: ``=``-led, each with a store-key-sized and a short body where the shape allows one.
_SHAPES = {
    "one-pad url key": _URL_KEY,
    "one-pad url short": _URL_SHORT,
    "double-quoted url key": f'"{_URL_KEY}"',
    "double-quoted std key": f'"{_STD_KEY}"',
    "single-quoted url key": f"'{_URL_KEY}'",
    "double-quoted url short": f'"{_URL_SHORT}"',
    "comma-trailed url key": f"{_URL_KEY},",
    "comma-trailed std key": f"{_STD_KEY},",
    "comma-trailed std two-pad": base64.b64encode(b"synthetic-tok-16").decode() + ",",
    "retired-keys list url": f"{_URL_KEY},{_URL_KEY}",
    "retired-keys list std": f"{_STD_KEY},{_STD_KEY}",
    "comma-trailed url short": f"{_URL_SHORT},",
    "equals-led url key": f"={_URL_KEY}",
    "equals-led std key": f"={_STD_KEY}",
    "equals-led short": "=AbCdEf",
    "double-equals-led url key": f"=={_URL_KEY}",
}


@dataclass
class _Probe:
    entries: list[tuple[str, str]] = field(default_factory=list)

    def ancestor_images(self) -> Iterator[tuple[int, str]]:
        return iter([(200, "python.exe"), (100, "nssm.exe")])

    def service_at(self, pid: int) -> str | None:
        return "MessageFoundry" if pid == 100 else None

    def environment_entries(self, service_name: str) -> list[tuple[str, str]]:
        return list(self.entries)


def _read(entries: Sequence[str]) -> ServiceEnvPosture:
    return read_service_env_posture(probe=_Probe([(_EXTRA, e) for e in entries]), environ={})


def test_the_stand_ins_have_the_shapes_they_stand_for() -> None:
    assert len(_URL_KEY) == 44 and _URL_KEY.endswith("=") and not _URL_KEY.endswith("==")
    assert "-" in _URL_KEY and "_" in _URL_KEY
    assert not serviceenv._holds_key_run(_URL_KEY)
    assert _URL_SHORT.endswith("=") and not _URL_SHORT.endswith("==") and "-" in _URL_SHORT
    assert len(_STD_KEY) == 44 and _STD_KEY.endswith("=") and not _STD_KEY.endswith("==")


@pytest.mark.parametrize("shape", sorted(_SHAPES))
@pytest.mark.parametrize("name", [KEY_CLASS_NAMES[0], "MEFOR_AUTH_OIDC_CLIENT_SECRET"])
def test_a_split_secret_in_the_next_item_refuses(name: str, shape: str) -> None:
    """``nssm set`` writes each argument as its own string, so a secret split from its name lands
    in the next item. On origin/main 9421dcbf27 most shapes here ended the empty value above it,
    the ``=``-led standard key among them; the quoted and comma-trailed standard keys already
    refused through the key-run rule, and stay as pins."""
    posture = _read([f"{name}=", _SHAPES[shape]])
    assert posture.listed == (name,), shape
    assert posture.value_runs_on, shape
    assert service_env_refusal(posture) is not None


@pytest.mark.parametrize("shape", sorted(_SHAPES))
@pytest.mark.parametrize("name", [KEY_CLASS_NAMES[0], "MEFOR_AUTH_OIDC_CLIENT_SECRET"])
def test_a_split_secret_in_the_next_item_below_another_variable_refuses(
    name: str, shape: str
) -> None:
    """The empty name on a later line of its own item, so only the line reading can keep it."""
    posture = _read([f"MEFOR_AI_ENVIRONMENT=prod\n{name}=", _SHAPES[shape]])
    assert posture.listed == (name,), shape
    assert service_env_refusal(posture) is not None


@pytest.mark.parametrize("shape", sorted(_SHAPES))
@pytest.mark.parametrize("name", [KEY_CLASS_NAMES[0], "MEFOR_AUTH_OIDC_CLIENT_SECRET"])
def test_a_split_secret_on_a_later_line_below_another_variable_refuses(
    name: str, shape: str
) -> None:
    """One string, the empty name below another variable, so the whole-string reading names the
    other variable and only the line reading can keep the secret's name."""
    posture = _read([f"MEFOR_AI_ENVIRONMENT=prod\n{name}=\n{_SHAPES[shape]}"])
    assert posture.listed == (name,), shape
    assert service_env_refusal(posture) is not None


#: Items that still end an empty value above them, because NSSM reads each item as its own
#: variable and each is under a plain name or is a nameless entry of its own. Taken from the
#: item 1 control in ``tests/test_b532r_serviceenv_reader.py``, with lower-case spellings,
#: Windows' ``=::`` and ``=ExitCode`` entries, a one-case nameless entry, names Windows sets and
#: ordinary comma-led values added.
_ORDINARY_ITEMS = (
    "MEFOR_AI_ENVIRONMENT=prod",
    "ProgramFiles(x86)=C:\\x",
    "=C:=C:\\x",
    "=::=::\\",
    "=orphan",
    "HTTP_PROXY=",
    "http_proxy=",
    "NO_PROXY=",
    "HTTP_PROXY= ",
    "NO_PROXY=\t",
    "no_proxy=\t",
    "MEFOR_SECRETS_DIRECTORY=",
    "Mefor_Secrets_Directory=",
    "NO_PROXY=,localhost",
    "no_proxy=,localhost",
    "A" * 42 + "_B=1",
    "=ExitCode=00000000",
    "PATH=C:\\x",
    "Path=C:\\x",
    "PATH=,C:\\x",
)


@pytest.mark.parametrize("item", _ORDINARY_ITEMS)
def test_an_ordinary_item_still_ends_the_empty_value_above_it(item: str) -> None:
    posture = _read([f"{KEY_CLASS_NAMES[0]}=", item])
    assert posture.listed_keys == (), item
    assert service_env_refusal(posture) is None, item


#: Lines below an empty secret-class value that are not positively an ordinary variable's, so the
#: reader cannot tell them from the secret and fails closed (added items 6 and 12). Typographic
#: quotes are written as escapes, so this file holds no glyph.
_FAIL_CLOSED = (
    "x=y",
    "Winter=2026!",
    "Http_Proxy=",
    "Http_Proxy=x",
    "ProgramFile=C:\\x",
    "\u201cabc\u201d=x",
    "\u2018abc\u2019=x",
    "`abc`=x",
    "abc`=x",
    "p@ss=word",
    "=abc123",
    "=AbCdEf",
)


@pytest.mark.parametrize("line", _FAIL_CLOSED)
@pytest.mark.parametrize("name", [KEY_CLASS_NAMES[0], "MEFOR_AUTH_AD_BIND_PASSWORD"])
def test_a_line_that_may_be_the_secret_refuses_as_an_item_and_on_a_later_line(
    name: str, line: str
) -> None:
    """Finding 1 of the round-2 review: ``Winter=2026!`` below the bind password escaped. Each
    reading refuses, and the two read the same."""
    items = _read([f"{name}=", line])
    later = _read([f"PATH=x\n{name}=\n{line}"])
    assert items.listed == later.listed == (name,), line
    assert items.value_runs_on, line
    assert service_env_refusal(items) is not None
    assert service_env_refusal(later) is not None


def test_an_empty_secret_kept_on_a_later_line_reads_the_line_below_it_too() -> None:
    """The fail-closed rule follows a kept variable, not only a string's first line."""
    name = "MEFOR_STORE_PASSWORD"
    posture = _read([f"PATH=x\n{KEY_CLASS_NAMES[0]}=\n{name}=\nWinter=2026!"])
    assert posture.listed == (name,)


def test_an_ordinary_comma_led_value_on_a_later_line_is_still_its_own_variable() -> None:
    """A conventional name with a comma-led value still ends the empty directory above it, which
    then reads as unset."""
    posture = _read(["MEFOR_SECRETS_DIRECTORY=\nNO_PROXY=,localhost", "MEFOR_VALUE_A=1"])
    assert posture.listed == ("MEFOR_VALUE_A",)
    refusal = service_env_refusal(posture)
    assert refusal is not None and "The service's lists set no" in refusal


@pytest.mark.parametrize("line", ['"x"=y', "PATH=,C:\\x", "Http_Proxy=,x", "\u201cx\u201d=y"])
def test_an_empty_directory_above_an_ordinary_line_still_reads_as_unset(line: str) -> None:
    """Finding 3 of the round-2 review, a regression at 7b2d038666: the directory's name is no
    secret, so a later line ends its empty value under the plain line rule, and the remedy still
    says the lists set no directory."""
    posture = _read([f"MEFOR_SECRETS_DIRECTORY=\n{line}", "MEFOR_VALUE_A=1"])
    assert posture.listed == ("MEFOR_VALUE_A",), line
    refusal = service_env_refusal(posture)
    assert refusal is not None and "The service's lists set no" in refusal, line


@pytest.mark.parametrize("item", ["Http_Proxy=", "=ExitCode=0", "=abc123", "ab-c_dE="])
def test_an_empty_value_name_does_not_take_the_next_item(item: str) -> None:
    """Finding 4 of the round-2 review, a regression at 7b2d038666: an empty ``MEFOR_VALUE_*``
    name refuses whatever it holds, so the next item keeps the plain rule, the empty entry is
    still named, and the remedy does not say to remove the item."""
    posture = _read(["MEFOR_VALUE_X=", item])
    assert posture.listed == ("MEFOR_VALUE_X",), item
    assert posture.empty_value_names == ("MEFOR_VALUE_X",), item
    assert not posture.value_runs_on, item
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert "An empty or blank MEFOR_VALUE_* entry is refused too" in refusal
    assert "runs on into" not in refusal


def test_a_hex_secret_led_by_an_equals_sign_in_the_next_item_refuses() -> None:
    """Lower-case hex, as ``openssl rand -hex`` mints, is of one case but holds digits."""
    name = "MEFOR_AUTH_OIDC_CLIENT_SECRET"
    assert _read([f"{name}=", "=deadbeefcafebabe0123456789abcdef"]).listed == (name,)


def test_an_empty_key_on_its_strings_first_line_above_an_ordinary_line_refuses() -> None:
    """The control for the item 6 pin below: on the string's first line the whole-string reading
    keeps the key, so it refuses."""
    key = KEY_CLASS_NAMES[0]
    assert _read([f"{key}=\nx=y"]).listed_keys == (key,)


def test_a_later_empty_secret_above_an_ordinary_line_refuses() -> None:
    """Added item 6: the same empty key below another variable refuses too, as one string and as
    items, since the reader cannot tell whether ``x=y`` is the key. Failed on origin/main
    9421dcbf27, where it was a strict xfail pin at 7b2d038666."""
    key = KEY_CLASS_NAMES[0]
    assert _read([f"PATH=x\n{key}=\nx=y"]).listed_keys == (key,)
    assert _read([f"PATH=x\n{key}=", "x=y"]).listed_keys == (key,)
    assert _read([f"{key}=", "x=y"]).listed_keys == (key,)
