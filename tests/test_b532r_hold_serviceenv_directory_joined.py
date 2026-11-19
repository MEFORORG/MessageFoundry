# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The refusal's remedy when ``MEFOR_SECRETS_DIRECTORY==`` is joined into an empty refused name
(vault BACKLOG #5394).

The join stays: the string still continues the empty value, so the refusal still fires. What
changes is the remedy, which must neither tell the operator to remove the directory's entry with
the refused one, nor say the lists set no secrets directory. Synthetic values only.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field

import pytest

from messagefoundry.serviceenv import (
    KEY_CLASS_NAMES,
    ServiceEnvPosture,
    read_service_env_posture,
    service_env_refusal,
)

_EXTRA = "Parameters\\AppEnvironmentExtra"
_PLAIN = "Parameters\\AppEnvironment"


@dataclass
class _Probe:
    entries: list[tuple[str, str]] = field(default_factory=list)

    def ancestor_images(self) -> Iterator[tuple[int, str]]:
        return iter([(200, "python.exe"), (100, "nssm.exe")])

    def service_at(self, pid: int) -> str | None:
        return "MessageFoundry" if pid == 100 else None

    def environment_entries(self, service_name: str) -> list[tuple[str, str]]:
        return list(self.entries)


def _read_pairs(pairs: list[tuple[str, str]]) -> ServiceEnvPosture:
    return read_service_env_posture(probe=_Probe(pairs), environ={})


def _read(entries: list[str]) -> ServiceEnvPosture:
    return _read_pairs([(_EXTRA, e) for e in entries])


_KEEP = (
    "At least one string read here as part of such a value sets MEFOR_SECRETS_DIRECTORY, which "
    "NSSM may instead read as a variable of its own, so this reading does not take it as naming "
    "the secrets directory. Keep one MEFOR_SECRETS_DIRECTORY entry in the service's lists, "
    "written as MEFOR_SECRETS_DIRECTORY=<path> naming the secrets directory by its path, and "
    "remove the other strings"
)


@pytest.mark.parametrize("directory", ["MEFOR_SECRETS_DIRECTORY==", "mefor_secrets_directory =="])
@pytest.mark.parametrize("refused", [f"{KEY_CLASS_NAMES[0]}=", "MEFOR_VALUE_A="])
def test_a_joined_directory_entry_is_kept_by_the_remedy(refused: str, directory: str) -> None:
    posture = _read([refused, directory])
    refusal = service_env_refusal(posture)
    assert refusal is not None  # the join is not narrowed: this still refuses
    assert posture.value_runs_on and posture.directory_joined
    assert _KEEP in refusal
    assert refusal.count("Keep one MEFOR_SECRETS_DIRECTORY entry") == 1
    assert "The service's lists set no MEFOR_SECRETS_DIRECTORY" not in refusal
    assert "add MEFOR_SECRETS_DIRECTORY naming that existing path back" not in refusal


def test_a_directory_set_elsewhere_too_is_kept_once() -> None:
    posture = _read_pairs(
        [
            (_PLAIN, "MEFOR_SECRETS_DIRECTORY=C:\\synthetic-secrets"),
            (_EXTRA, "MEFOR_VALUE_A="),
            (_EXTRA, "MEFOR_SECRETS_DIRECTORY=="),
        ]
    )
    refusal = service_env_refusal(posture)
    assert refusal is not None and posture.directory_joined
    assert _KEEP in refusal


def test_a_directory_under_a_value_that_is_not_refused_is_not_reported_as_joined() -> None:
    """A path-form OIDC key is not refused, so a directory string joined to it is not read as
    part of a refused value, and the remedy must not say it is."""
    posture = _read_pairs(
        [
            (_EXTRA, "MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY="),
            (_EXTRA, "MEFOR_SECRETS_DIRECTORY=="),
            (_PLAIN, "MEFOR_VALUE_B=1"),
        ]
    )
    assert not posture.directory_joined
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert "sets MEFOR_SECRETS_DIRECTORY, which NSSM may instead read" not in refusal


def test_with_no_directory_joined_the_old_remedies_stand() -> None:
    """Control: a value name with no directory entry still gets the "add it back" route, and a
    run-on into key material still says to remove those strings."""
    value_only = service_env_refusal(_read(["MEFOR_VALUE_A="]))
    assert value_only is not None
    assert "The service's lists set no MEFOR_SECRETS_DIRECTORY" in value_only
    run_on = _read([f"{KEY_CLASS_NAMES[0]}=", "abc=="])
    assert run_on.value_runs_on and not run_on.directory_joined
    refusal = service_env_refusal(run_on)
    assert refusal is not None
    assert "so remove those strings with it" in refusal
    assert "Keep one MEFOR_SECRETS_DIRECTORY entry" not in refusal
