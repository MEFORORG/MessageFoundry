# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Split secrets that the service-environment reader let through (vault BACKLOG #5394, added
item 12).

A secret split from its empty name, into the next ``REG_MULTI_SZ`` item or onto a later line of
one string below another variable, refuses when it is one-``=`` base64url, quoted, comma-trailed
or ``=``-led. The controls are the ordinary items that still end the empty value. Each test drives
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
    in the next item. Before this fix most shapes here ended the empty value above it; the
    standard-alphabet key shapes already refused through the key-run rule, and stay as pins."""
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
#: variable and none of these is a split secret's shape. Taken from the item 1 control in
#: ``tests/test_b532r_serviceenv_reader.py``, with lower-case spellings, Windows' ``=::`` entry,
#: a one-case nameless entry and ordinary comma-led values added.
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
)


@pytest.mark.parametrize("item", _ORDINARY_ITEMS)
def test_an_ordinary_item_still_ends_the_empty_value_above_it(item: str) -> None:
    posture = _read([f"{KEY_CLASS_NAMES[0]}=", item])
    assert posture.listed_keys == (), item
    assert service_env_refusal(posture) is None, item


def test_an_ordinary_comma_led_value_on_a_later_line_is_still_its_own_variable() -> None:
    """The line rule gains the split shapes too, so its negative control: a conventional name
    with a comma-led value still ends the empty directory above it, which then reads as unset."""
    posture = _read(["MEFOR_SECRETS_DIRECTORY=\nNO_PROXY=,localhost", "MEFOR_VALUE_A=1"])
    assert posture.listed == ("MEFOR_VALUE_A",)
    refusal = service_env_refusal(posture)
    assert refusal is not None and "The service's lists set no" in refusal


def test_a_hex_secret_led_by_an_equals_sign_in_the_next_item_refuses() -> None:
    """Lower-case hex, as ``openssl rand -hex`` mints, is of one case but holds digits."""
    name = "MEFOR_AUTH_OIDC_CLIENT_SECRET"
    assert _read([f"{name}=", "=deadbeefcafebabe0123456789abcdef"]).listed == (name,)


def test_an_empty_key_on_its_strings_first_line_above_an_ordinary_line_refuses() -> None:
    """The control for the item 6 pin below: on the string's first line the whole-string reading
    keeps the key, so it refuses."""
    key = KEY_CLASS_NAMES[0]
    assert _read([f"{key}=\nx=y"]).listed_keys == (key,)


@pytest.mark.xfail(
    strict=True,
    reason=(
        "vault BACKLOG #5394 added item 6, not built: refusing this input breaks the one-string "
        "and next-item parity that tests/test_b532r_serviceenv_reader.py pins for the same shape"
    ),
)
def test_a_later_empty_secret_above_an_ordinary_line_refuses() -> None:
    """Added item 6: the same empty key on the string's first line refuses (the control above),
    so the reading is position-dependent."""
    key = KEY_CLASS_NAMES[0]
    assert _read([f"PATH=x\n{key}=\nx=y"]).listed_keys == (key,)
