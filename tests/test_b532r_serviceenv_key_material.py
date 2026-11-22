# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Key material below an empty secret is that secret's value (vault BACKLOG #5394, added items 6
and 12).

Synthetic values only: each stand-in is ASCII text, never a real key.
"""

from __future__ import annotations

import base64
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field

import pytest

from messagefoundry.serviceenv import (
    KEY_CLASS_NAMES,
    ServiceEnvPosture,
    read_service_env_posture,
    service_env_refusal,
)

_KEY_B64 = base64.b64encode(b"synthetic-store-key-0123456789ab").decode()
#: A base64url stand-in of a 32-byte secret's length, with one ``=``, a "-" and a "_" in it, and
#: letters of both cases, as a random secret has.
_URL_ONE_PAD = "Synthetic-Store_Key-0123456789AbCdEfGhIjKlm="
_EXTRA = "Parameters\\AppEnvironmentExtra"
_KEY = "MEFOR_STORE_ENCRYPTION_KEY"


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


def test_the_stand_ins_have_a_secrets_shape() -> None:
    assert _KEY in KEY_CLASS_NAMES
    assert len(_URL_ONE_PAD) == 44 and _URL_ONE_PAD.endswith("=")
    assert not _URL_ONE_PAD.endswith("==") and "-" in _URL_ONE_PAD and "_" in _URL_ONE_PAD


#: Each as the line or the item below an empty store key. Every case above the Windows-name ones
#: already refused on main at 895925f2d3a; the Windows-name cases did not, on a later line or in
#: the next item, so only they show this change (Lander hold on PR 3142, finding 2).
_SHAPES = (
    pytest.param(f"x={_KEY_B64}", id="ordinary-name-set-to-a-key"),
    pytest.param(_URL_ONE_PAD, id="base64url-one-pad"),
    pytest.param(f"={_KEY_B64}", id="equals-led"),
    pytest.param(f"={_URL_ONE_PAD}", id="equals-led-base64url"),
    # Review round 2: a retired-keys list and a quoted key as an ordinary variable's value.
    pytest.param(f"x={_KEY_B64},{_KEY_B64}", id="ordinary-name-set-to-a-key-list"),
    pytest.param(f'x="{_KEY_B64}"', id="ordinary-name-set-to-a-quoted-key"),
    # Names that may end an empty secret-class value (``serviceenv._ends_blank_class``), each
    # set to a key, so only the value's key shape makes the empty key read as set.
    pytest.param(f"Path={_KEY_B64}", id="windows-name-set-to-a-key"),
    pytest.param(f"TEMP={_URL_ONE_PAD}", id="windows-name-set-to-a-base64url-key"),
    pytest.param(f"MEFOR_SECRETS_DIRECTORY={_KEY_B64}", id="directory-name-set-to-a-key"),
)


@pytest.mark.parametrize("shape", _SHAPES)
def test_key_material_on_the_next_line_makes_the_empty_key_read_as_set(shape: str) -> None:
    posture = _read([f"MEFOR_AI_ENVIRONMENT=prod\n{_KEY}=\n{shape}"])
    assert posture.listed_keys == (_KEY,), posture.listed
    assert service_env_refusal(posture) is not None


@pytest.mark.parametrize("shape", _SHAPES)
def test_key_material_in_the_next_item_makes_the_empty_key_read_as_set(shape: str) -> None:
    posture = _read([f"{_KEY}=", shape])
    assert posture.listed_keys == (_KEY,), posture.listed
    assert service_env_refusal(posture) is not None


@pytest.mark.parametrize("shape", _SHAPES)
def test_key_material_in_the_next_item_below_a_later_empty_line_reads_as_set(shape: str) -> None:
    """The empty key on a later line of its own item, not the item's first."""
    posture = _read([f"MEFOR_AI_ENVIRONMENT=prod\n{_KEY}=", shape])
    assert posture.listed_keys == (_KEY,), posture.listed
    assert service_env_refusal(posture) is not None


@pytest.mark.parametrize("shape", _SHAPES)
def test_key_material_below_the_name_alone_makes_the_key_read_as_set(shape: str) -> None:
    """The key's name written alone, with no equals sign, as ``nssm set ... NAME =value`` writes
    it, on the line or in the item above."""
    for entries in ([f"{_KEY}\n{shape}"], [_KEY, shape]):
        posture = _read(entries)
        assert posture.listed_keys == (_KEY,), (entries, posture.listed)
        assert service_env_refusal(posture) is not None


@pytest.mark.parametrize(
    ("name", "value"),
    [
        (_KEY, base64.b64encode(b"synthetic-store-key-abcdefghij01").decode()),
        ("MEFOR_STORE_PASSWORD", "hunter2"),
    ],
    ids=["store-key", "store-password"],
)
def test_a_secret_alone_below_an_ordinary_name_set_to_a_key_is_named(name: str, value: str) -> None:
    """A line of an ordinary variable's shape whose value is a key, ``x=<key>``, still starts a
    variable, so a secret's name alone below it, with its value on the next line, is read as that
    secret and the refusal names it, with that secret's remedy, rather than the ``MEFOR_VALUE_*``
    name the string opens with (Lander hold on PR 3142, finding 1)."""
    posture = _read([f"MEFOR_VALUE_A\nx={_KEY_B64}\n{name}\n={value}"])
    assert posture.listed == (name,), posture.listed
    refusal = service_env_refusal(posture)
    assert refusal is not None and refusal.startswith(name), refusal
    if name == _KEY:
        assert "DPAPI-protected key file" in refusal


@pytest.mark.parametrize(
    "entries",
    [
        pytest.param(["MEFOR_VALUE_A=", f"x={_KEY_B64}"], id="item"),
        pytest.param([f"MEFOR_VALUE_A=\nx={_KEY_B64}"], id="line"),
        pytest.param([f"MEFOR_VALUE_A=\nPath={_KEY_B64}"], id="line-windows-name"),
    ],
)
def test_an_ordinary_name_set_to_a_key_does_not_join_an_empty_value(entries: list[str]) -> None:
    """An ordinary variable whose value is a key, as the next item or on the next line, is a
    variable of its own, so below an empty ``MEFOR_VALUE_*`` value the empty entry is named, and
    the remedy does not say to remove the item below it (Lander holds on PR 3142: the first's
    finding 3, the item form, and the second's H1, the line form)."""
    posture = _read(entries)
    assert posture.empty_value_names == ("MEFOR_VALUE_A",)
    assert not posture.value_runs_on
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert "An empty or blank MEFOR_VALUE_* entry is refused too: delete it" in refusal
    assert "remove those strings with it" not in refusal


_DIRECTORY_KEY = f"MEFOR_SECRETS_DIRECTORY={_KEY_B64}"

#: What the refusal says of a directory string joined to a refused value, whatever it holds, and
#: how it says to pass the list back, so that string is not passed back with it.
_REWRITE = (
    "Remove each such string, whatever it holds, since it may hold that value, and do not keep it "
    "as the directory's entry. Where the service has a secrets directory, or a step below puts a "
    "setting in one, the lists must then hold exactly one MEFOR_SECRETS_DIRECTORY entry, written "
    "as MEFOR_SECRETS_DIRECTORY=<path> on its own"
)
_PASS_BACK = (
    "pass back every entry but those refused above and the strings this step and any step above "
    "say to remove"
)
_CREATE = (
    'Where no secrets directory exists yet, the bullet "The other secrets: a secrets directory" '
    'under docs/SERVICE.md, "Protect the store encryption key at rest", says how the directory '
    "is created"
)
_REMOVE_ALL = "so remove those strings with it, or the value stays in the registry key"


def _assert_written_again(refusal: str) -> None:
    """One directory step, which never says to keep or spare the joined string."""
    assert refusal.count(_REWRITE) == 1, refusal
    assert _PASS_BACK in refusal[refusal.index(_REWRITE) :]
    assert "Keep one MEFOR_SECRETS_DIRECTORY entry" not in refusal
    assert "but for any that sets MEFOR_SECRETS_DIRECTORY" not in refusal
    assert "The service's lists set no MEFOR_SECRETS_DIRECTORY" not in refusal


@pytest.mark.parametrize(
    "entries",
    [
        pytest.param([f"{_KEY}=", _DIRECTORY_KEY], id="item"),
        pytest.param(
            [f"MEFOR_AI_ENVIRONMENT=prod\n{_KEY}=", _DIRECTORY_KEY], id="item-below-a-later-line"
        ),
        pytest.param([_KEY, _DIRECTORY_KEY], id="item-below-the-name"),
        pytest.param([f"{_KEY}=", f"mefor_secrets_directory= ={_KEY_B64}"], id="item-blank-led"),
        pytest.param([f"{_KEY}=", f"MEFOR_SECRETS_DIRECTORY==\n{_KEY_B64}"], id="item-key-below"),
        pytest.param(
            [f"{_KEY}=", f"mefor_secrets_directory=C:\\d\nx={_KEY_B64}"], id="item-path-and-key"
        ),
        pytest.param(
            [f"{_KEY}=", f"mefor_secrets_directory=C:\\d;{_KEY_B64}"], id="item-key-beside-a-path"
        ),
        pytest.param([f"{_KEY}=", "mefor_secrets_directory=C:\\d"], id="item-path-only"),
        pytest.param(
            [f"{_KEY}=", "MEFOR_VALUE_A", "mefor_secrets_directory=C:\\d"],
            id="item-past-a-name-alone",
        ),
        pytest.param([f"{_KEY}=", _KEY, _DIRECTORY_KEY], id="item-past-the-key-alone"),
        pytest.param(
            [f"{_KEY}=", "MEFOR_STORE_PASSWORD", "mefor_secrets_directory=C:\\d"],
            id="item-past-a-secret-alone",
        ),
    ],
)
def test_a_joined_directory_string_is_removed_and_written_again(entries: list[str]) -> None:
    """A ``MEFOR_SECRETS_DIRECTORY`` string joined below an empty store key may hold the key, so
    whatever it holds, the remedy says to remove it with the value and write the directory's entry
    again on its own, and never to keep it (Lander's second hold on PR 3142, H3)."""
    posture = _read(entries)
    assert posture.listed_keys == (_KEY,), posture.listed
    assert posture.value_runs_on and posture.directory_joined
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert _REMOVE_ALL in refusal
    _assert_written_again(refusal)


def test_a_joined_directory_string_keeps_the_create_or_add_back_guidance() -> None:
    """Beside a secret the directory takes, the refusal still says how to name an existing
    secrets directory again, or create one, as 9c54e7e9fd80 did."""
    posture = _read([f"{_KEY}=", _DIRECTORY_KEY, "MEFOR_AUTH_AD_BIND_PASSWORD=synthetic"])
    refusal = service_env_refusal(posture)
    assert refusal is not None and posture.directory_joined
    _assert_written_again(refusal)
    assert (
        "where the strings removed leave none, write it again in AppEnvironmentExtra, beside its "
        "other entries" in refusal
    )
    assert "where they leave more than one, remove the rest" in refusal
    assert _CREATE in refusal


def test_a_directory_string_joined_past_a_name_alone_beside_a_secret_is_not_set_none() -> None:
    """A name written alone between the empty value and the directory string carries the join
    on, so beside a secret the directory takes the refusal still must not say the lists set
    none (H3)."""
    posture = _read(
        [
            f"{_KEY}=",
            "MEFOR_VALUE_A",
            "mefor_secrets_directory=C:\\d",
            "MEFOR_AUTH_AD_BIND_PASSWORD=x",
        ]
    )
    refusal = service_env_refusal(posture)
    assert refusal is not None and posture.directory_joined
    _assert_written_again(refusal)


def test_a_directory_set_first_in_a_joined_groups_first_string_is_not_joined() -> None:
    """Only a string after the first of a joined group is joined into a value above it. A
    directory set on the first line of the group's own first string is the service's entry,
    and the refusal must not say to remove it (H3)."""
    posture = _read(["MEFOR_SECRETS_DIRECTORY=C:\\d\nMEFOR_STORE_PASSWORD=", "abc"])
    assert posture.value_runs_on and not posture.directory_joined
    assert "MEFOR_SECRETS_DIRECTORY" in posture.listed
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert _REWRITE not in refusal


@pytest.mark.parametrize("prefix", ["", "MEFOR_AI_ENVIRONMENT=prod\n"], ids=["line", "later-line"])
def test_a_directory_line_in_the_key_string_refuses_as_the_key_alone(prefix: str) -> None:
    """A key-valued directory line inside the empty key's own string is read as the key's
    value: it refuses as the key, runs on into nothing, and adds no directory step. The rule
    for joined strings does not reach this form, which is left as it stands (H3, item (c))."""
    posture = _read([f"{prefix}{_KEY}=\n{_DIRECTORY_KEY}"])
    assert posture.listed_keys == (_KEY,), posture.listed
    assert not posture.value_runs_on and not posture.directory_joined
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert _REWRITE not in refusal


def test_two_joined_directory_strings_get_one_directory_step() -> None:
    """With a path-only and a key-bearing directory string both joined, one step covers both."""
    posture = _read(
        [
            f"{_KEY}=",
            _DIRECTORY_KEY,
            "MEFOR_STORE_PASSWORD=",
            "mefor_secrets_directory=C:\\d",
            "MEFOR_AUTH_AD_BIND_PASSWORD=synthetic",
        ]
    )
    assert posture.directory_joined
    refusal = service_env_refusal(posture)
    assert refusal is not None
    _assert_written_again(refusal)


def test_a_nameless_key_item_joins_an_empty_value_item() -> None:
    """An item with no name before its equals sign, ``=<key>``, is read as the empty
    ``MEFOR_VALUE_*`` item's value split from it, so the remedy says to remove it too. This
    pins the ``_is_key_value(rest)`` clause of ``serviceenv._continues_string`` (BACKLOG #5394
    items 6 and 12); main at 895925f2d3a named the empty entry instead."""
    posture = _read(["MEFOR_VALUE_A=", f"={_KEY_B64}"])
    assert posture.value_runs_on
    assert posture.empty_value_names == ()
    refusal = service_env_refusal(posture)
    assert refusal is not None and "remove those strings with it" in refusal


@pytest.mark.parametrize(
    "line",
    [
        "Path=C:\\Windows\\system32;C:\\Windows",
        "MEFOR_SECRETS_DIRECTORY=D:/MessageFoundrySecrets/ProductionEngineSecretsDirectory",
        # Mixed case alone does not make these secrets.
        "PSModulePath=C:/Program Files/WindowsPowerShell/Modules/MessageFoundryProduction",
        "ProgramData=D:/MessageFoundryProductionData/ServiceEnvironmentProgramData",
    ],
)
def test_an_ordinary_line_still_ends_the_empty_key(line: str) -> None:
    """Control: a line with no key material, under one of the few names that may end an empty
    secret-class value (``serviceenv._ends_blank_class``), still ends the empty key, on a later
    line and in the next item alike, so the secret reads as unset. Every other name refuses there
    since BACKLOG #5394 wave 3 (``tests/test_b532w3_serviceenv_split_shapes.py``). Each form the
    positive tests above use is here."""
    for entries in (
        [f"MEFOR_AI_ENVIRONMENT=prod\n{_KEY}=\n{line}"],
        [f"{_KEY}=", line],
        [f"MEFOR_AI_ENVIRONMENT=prod\n{_KEY}=", line],
        [f"{_KEY}\n{line}"],
        [_KEY, line],
    ):
        assert _read(entries).listed_keys == (), (entries, _read(entries).listed)
