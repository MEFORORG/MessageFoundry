# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Key material below an empty secret is that secret's value (vault BACKLOG #5394, added items 6
and 12).

Synthetic values only: each stand-in is ASCII text, never a real key. On the code before, each
shape below was read as a variable that ends the empty secret above it, so the secret read as
unset and the start was not refused.
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


#: Each as the line or the item below an empty store key.
_SHAPES = (
    pytest.param(f"x={_KEY_B64}", id="ordinary-name-set-to-a-key"),
    pytest.param(_URL_ONE_PAD, id="base64url-one-pad"),
    pytest.param(f"={_KEY_B64}", id="equals-led"),
    pytest.param(f"={_URL_ONE_PAD}", id="equals-led-base64url"),
    # Review round 2: a retired-keys list and a quoted key as an ordinary variable's value.
    pytest.param(f"x={_KEY_B64},{_KEY_B64}", id="ordinary-name-set-to-a-key-list"),
    pytest.param(f'x="{_KEY_B64}"', id="ordinary-name-set-to-a-quoted-key"),
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


@pytest.mark.parametrize(
    "line",
    [
        "PATH=C:\\Windows\\system32;C:\\Windows",
        "MEFOR_SECURITY_REQUIRE_MEMORY_ENCRYPTION_DECLARATION=1",
        # Review round 1: each of these was read as key material by a looser rule.
        "mefor_security_require_memory_encryption_declaration=1",
        "PYTHONPYCACHEPREFIX=C:/ProgramData/MessageFoundry/pycache/cachedir",
        "OTEL_SERVICE_NAME=messagefoundry-integration-engine-production-east",
        "MEFOR_SECRETS_DIRECTORY=D:/MessageFoundrySecrets/ProductionEngineSecretsDirectory",
        # Review round 2: mixed case alone does not make these secrets.
        "HOME_DIR=/opt/MessageFoundry/ConfigDirectory/ProductionEnvironment",
        "OTEL_SERVICE_NAME=MessageFoundry-Integration-Engine-Production-East",
        "Mefor_Security_Require_Memory_Encryption_Declaration=1",
    ],
)
def test_an_ordinary_line_still_ends_the_empty_key(line: str) -> None:
    """Control: a line with no key material still ends the empty key, on a later line and in the
    next item alike, so the secret reads as unset. An engine name longer than a key's run is
    upper case, so it is not read as one."""
    for entries in ([f"MEFOR_AI_ENVIRONMENT=prod\n{_KEY}=\n{line}"], [f"{_KEY}=", line]):
        assert _read(entries).listed_keys == (), (entries, _read(entries).listed)


@pytest.mark.parametrize("item", ["=C:=C:\\x", "ab-c_dE="])
def test_an_item_with_no_key_material_still_ends_the_empty_key(item: str) -> None:
    """Control for the next-item rule: Windows' own empty-named entry, and a short base64url
    text, hold no run of a secret's length, so each still ends the empty key above it."""
    assert _read([f"{_KEY}=", item]).listed_keys == ()
