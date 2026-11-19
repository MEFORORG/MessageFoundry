# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The service-environment reader reads a string that follows an empty refused value by the same
line rule it applies to a later line of one string (vault BACKLOG #5394).

Each test drives :func:`messagefoundry.serviceenv.read_service_env_posture` through a probe, so
every one runs on every platform. Synthetic values only: each base64 stand-in below decodes to
plain ASCII text, never a real key or secret.
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
_KEY = KEY_CLASS_NAMES[0]
#: A secret whose base64 carries exactly one ``=`` of padding: 17 bytes make 24 characters.
_ONE_PAD = base64.b64encode(b"synthetic-tok-017").decode()
_KEY_RUN = "A" * 43
_RUNS_ON = "runs on into the strings after it in the same registry value"


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


def test_the_stand_in_has_one_padding_character() -> None:
    assert _ONE_PAD.endswith("=") and not _ONE_PAD.endswith("==")
    assert not serviceenv._holds_key_run(_ONE_PAD)


# --- the MUST finding: a secret with one ``=`` of padding split into the next item -------------


@pytest.mark.parametrize("name", ["MEFOR_STORE_PASSWORD", "MEFOR_AUTH_OIDC_CLIENT_SECRET"])
def test_a_one_padded_secret_split_into_the_next_item_refuses(name: str) -> None:
    """Its text reads as ``NAME=`` with an empty value. Below the name in one string that line
    already continued the value; as the next item it now does too."""
    one_string = _read([f"MEFOR_AI_ENVIRONMENT=prod\n{name}=\n{_ONE_PAD}"])
    assert one_string.listed_directory_names == (name,)
    split = _read([f"{name}=", _ONE_PAD])
    assert split.listed_directory_names == (name,)
    assert service_env_refusal(split) is not None


# --- finding 8: one line rule for a later line and for the next item -----------------------------

#: Items, each read as the next item below an empty store key and as the lines below it in one
#: string. None has an empty name, the one shape the two readings differ on.
_FOLLOWERS = (
    _ONE_PAD,
    base64.b64encode(b"synthetic-tok-16").decode(),  # two ``=`` of padding
    "HTTP_PROXY=",
    "MEFOR_SECRETS_DIRECTORY=",
    "X= =",
    f"{_KEY_RUN}=x",
    f"{_KEY_RUN},x\nPATH=C:\\x",
    "foo",
    "foo\nPATH=C:\\x",
    "-----BEGIN " + "PRIVATE KEY-----",
    "PATH=C:\\x",
    "ProgramFiles(x86)=C:\\x",
    "MEFOR_AI_ENVIRONMENT=prod",
    "A" * 42 + "_B=1",
    "MEFOR_VALUE_B=1",
)


@pytest.mark.parametrize("follower", _FOLLOWERS)
def test_the_next_item_is_read_as_the_same_lines_below_the_key_in_one_string(
    follower: str,
) -> None:
    """The prefix line keeps the whole-string reading of the one string off the key, so only the
    line rule decides there, as it does for the joined items."""
    one_string = _read([f"MEFOR_AI_ENVIRONMENT=prod\n{_KEY}=\n{follower}"])
    split = _read([f"{_KEY}=", follower])
    assert split.listed_keys == one_string.listed_keys, follower
    first = follower.splitlines()[0]
    continues = serviceenv._line_start(first) is None
    assert serviceenv._continues_string(follower) is continues, follower


def test_an_empty_named_item_is_the_one_shape_the_readings_differ_on() -> None:
    """Below the key in one string an empty-named line belongs to the key's value, so it refuses;
    as the next item it is Windows' own ``=C:`` shape and ends the value above."""
    assert _read([f"MEFOR_AI_ENVIRONMENT=prod\n{_KEY}=\n=C:=C:\\x"]).listed_keys == (_KEY,)
    assert _read([f"{_KEY}=", "=C:=C:\\x"]).listed_keys == ()
    assert serviceenv._line_start("=C:=C:\\x") is None
    assert not serviceenv._continues_string("=C:=C:\\x")


# --- finding 2: a key-shaped first line above an ordinary later line ------------------------------


def test_a_key_shaped_item_with_an_ordinary_later_line_continues_the_empty_key() -> None:
    posture = _read([f"{_KEY}=", f"{_KEY_RUN},x\nPATH=C:\\x"])
    assert posture.listed_keys == (_KEY,)
    assert service_env_refusal(posture) is not None


# --- findings 4 and 5: the remedy step for strings a value runs on into ----------------------------


def test_no_runs_on_step_when_the_variable_that_ran_on_is_not_refused() -> None:
    """The path-form OIDC key runs on into a path, which is not a secret, so only the
    ``MEFOR_VALUE_A`` above it refuses, and its value did not run on."""
    posture = _read(["MEFOR_VALUE_A=x\nMEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY=", "C:\\k.pem"])
    assert posture.listed == ("MEFOR_VALUE_A",)
    assert not posture.value_runs_on
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert _RUNS_ON not in refusal


def test_a_broken_value_name_whose_value_is_the_next_item_says_to_remove_it() -> None:
    """``MEFOR_VALUE_A<LF>X=`` is one variable under the whole-string reading, empty in its own
    string, so the next item is its value and the step says to remove that item too."""
    posture = _read(["MEFOR_VALUE_A\nX=", "synthetic"])
    assert posture.listed_value_names == ("MEFOR_VALUE_A",)
    assert posture.empty_value_names == ()
    assert posture.value_runs_on
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert _RUNS_ON in refusal
