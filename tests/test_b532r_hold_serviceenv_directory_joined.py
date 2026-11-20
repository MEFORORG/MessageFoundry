# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The refusal's remedy when ``MEFOR_SECRETS_DIRECTORY==`` is joined into an empty value
(vault BACKLOG #5394), whether or not the variable it is joined to is refused.

The join stays: the string still continues the empty value, and every input that refused before
still refuses. What changes is the remedy, which must neither tell the operator to remove the
directory's entry with a run-on value, nor say the lists set no secrets directory. The variable
the directory string is joined to need not be refused or kept by ``_names``: a path-form OIDC key
is neither, and the directory string is still an item NSSM may read. Synthetic values only.
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
    "At least one string in the service's lists sets MEFOR_SECRETS_DIRECTORY on its first "
    "non-blank line and is read here as part of the empty value of the variable in the string "
    "above it. NSSM may instead read it as a variable of its own, so this reading does not take "
    "it as naming "
    "the secrets directory. Keep one MEFOR_SECRETS_DIRECTORY entry in the service's lists, "
    "written as MEFOR_SECRETS_DIRECTORY=<path> naming the secrets directory by its path, and "
    "remove any other entry that sets MEFOR_SECRETS_DIRECTORY, before any re-run of the "
    "installer"
)
_PASS_BACK = (
    "and pass back every entry but those refused above and the strings this step and any step "
    "above say to remove"
)
_NO_DIRECTORY = "The service's lists set no MEFOR_SECRETS_DIRECTORY"
_ADD_BACK = "add MEFOR_SECRETS_DIRECTORY naming that existing path back"
_REMOVE_ALL = "so remove those strings with it, or the value stays"
_KEEPS_ONE = (
    "The value stays in the registry key until those strings are removed, so remove each of "
    "them, but for any that sets MEFOR_SECRETS_DIRECTORY, which the next step covers"
)


def _assert_kept_once(refusal: str) -> None:
    assert _KEEP in refusal
    assert refusal.count("Keep one MEFOR_SECRETS_DIRECTORY entry") == 1
    keep_at = refusal.index(_KEEP)
    assert _PASS_BACK in refusal[keep_at:]
    assert _NO_DIRECTORY not in refusal
    assert _ADD_BACK not in refusal
    assert _REMOVE_ALL not in refusal


@pytest.mark.parametrize("directory", ["MEFOR_SECRETS_DIRECTORY==", "mefor_secrets_directory =="])
@pytest.mark.parametrize("refused", [f"{KEY_CLASS_NAMES[0]}=", "MEFOR_VALUE_A="])
def test_a_joined_directory_entry_is_kept_by_the_remedy(refused: str, directory: str) -> None:
    posture = _read([refused, directory])
    refusal = service_env_refusal(posture)
    assert refusal is not None  # the join is not narrowed: this still refuses
    assert posture.value_runs_on and posture.directory_joined
    _assert_kept_once(refusal)
    # The run-on step names its exception in the same sentence, ahead of the step that keeps it.
    assert _KEEPS_ONE in refusal
    assert refusal.index(_KEEPS_ONE) < refusal.index(_KEEP)


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
    assert "MEFOR_SECRETS_DIRECTORY" in posture.listed
    _assert_kept_once(refusal)


def test_a_directory_joined_to_a_dropped_variable_still_counts_as_set() -> None:
    """The Lander's input on 88a9f83: a path-form OIDC key is not kept by ``_names``, but the
    directory string joined to it is still an item NSSM may read as the directory. So the lists
    do set it, and the remedy must not say they set none or to add it back."""
    posture = _read_pairs(
        [
            (_EXTRA, "MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY="),
            (_EXTRA, "MEFOR_SECRETS_DIRECTORY=="),
            (_PLAIN, "MEFOR_VALUE_B=1"),
        ]
    )
    assert posture.listed == ("MEFOR_VALUE_B",)
    assert posture.directory_joined and not posture.value_runs_on
    refusal = service_env_refusal(posture)
    assert refusal is not None  # still refuses, on the MEFOR_VALUE_* name
    _assert_kept_once(refusal)
    # Nothing refused runs on here, so there is no run-on step to carry an exception.
    assert "its value runs on into" not in refusal


def test_a_run_on_and_a_join_from_different_variables_do_not_claim_the_strings_hold_it() -> None:
    """The run-on comes from a store key whose next string is key material, and the join from a
    dropped path-form OIDC key. The run-on step must not say its strings hold the directory."""
    posture = _read(
        [
            f"{KEY_CLASS_NAMES[0]}=",
            "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGk=",
            "MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY=",
            "MEFOR_SECRETS_DIRECTORY==",
        ]
    )
    assert posture.value_runs_on and posture.directory_joined
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert "but for any that sets MEFOR_SECRETS_DIRECTORY" in refusal
    assert "but for one MEFOR_SECRETS_DIRECTORY entry" not in refusal
    _assert_kept_once(refusal)


def test_a_join_beside_a_store_key_alone_adds_no_directory_step() -> None:
    """A refusal about a store key alone, with nothing running on, sends the operator to a key
    file. The joined directory string does not need touching for that, so no step names it."""
    posture = _read_pairs(
        [
            (_EXTRA, "MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY="),
            (_EXTRA, "MEFOR_SECRETS_DIRECTORY=="),
            (_PLAIN, f"{KEY_CLASS_NAMES[0]}=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGk="),
        ]
    )
    assert posture.directory_joined and not posture.value_runs_on
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert "DPAPI-protected key file" in refusal
    assert "Keep one MEFOR_SECRETS_DIRECTORY entry" not in refusal
    assert _NO_DIRECTORY not in refusal


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
