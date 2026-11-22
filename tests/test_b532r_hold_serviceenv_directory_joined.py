# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The refusal's remedy when ``MEFOR_SECRETS_DIRECTORY==`` is joined into an empty value
(vault BACKLOG #5394), whether or not the variable it is joined to is refused.

The join stays: the string still continues the empty value, and every input that refused before
still refuses. What changes is the remedy, which must not say the lists set no secrets directory.
Since the Lander's second hold on PR 3142 (H3) it says to remove the joined string, whatever it
holds, since it may hold the value, and to write the directory's entry again on its own. An OIDC key
empty on its own line was once dropped by ``_names`` as a path when it ran on; it is now kept
(round-2 finding 1), and the remedy pins that relied on the drop build the posture directly.
Synthetic values only.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field

import pytest

from messagefoundry.serviceenv import (
    KEY_CLASS_NAMES,
    ServiceEnvPosture,
    ServiceEnvStatus,
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


_REWRITE = (
    "At least one string in the service's lists sets MEFOR_SECRETS_DIRECTORY on its first "
    "non-blank line and is read here as part of the empty value of the variable in the string "
    "above it. NSSM may instead read it as a variable of its own, so this reading does not take "
    "it as naming the secrets directory. Remove each such string, whatever it holds, since it "
    "may hold that value, and do not keep it as the directory's entry. Where the service has a "
    "secrets directory, or a step below puts a setting in one, the lists must then hold exactly "
    "one MEFOR_SECRETS_DIRECTORY entry, written as MEFOR_SECRETS_DIRECTORY=<path> on its own, "
    "naming the secrets directory by its path: where the strings removed leave none, write it "
    "again among the entries you pass back, and where they leave more than one, remove the rest, "
    "before any re-run of the installer"
)
_PASS_BACK = (
    "and pass back every entry but those refused above and the strings this step and any step "
    "above say to remove"
)
_NO_DIRECTORY = "The service's lists set no MEFOR_SECRETS_DIRECTORY"
_ADD_BACK = "add MEFOR_SECRETS_DIRECTORY naming that existing path back"
_REMOVE_ALL = "so remove those strings with it, or the value stays"
_KEPT = "Keep one MEFOR_SECRETS_DIRECTORY entry"
_SPARED = "but for any that sets MEFOR_SECRETS_DIRECTORY"


def _assert_rewritten_once(refusal: str) -> None:
    """One directory step, which never says to keep or spare the joined string."""
    assert refusal.count(_REWRITE) == 1
    rewrite_at = refusal.index(_REWRITE)
    assert _PASS_BACK in refusal[rewrite_at:]
    assert _NO_DIRECTORY not in refusal
    assert _ADD_BACK not in refusal
    assert _KEPT not in refusal and _SPARED not in refusal


@pytest.mark.parametrize("directory", ["MEFOR_SECRETS_DIRECTORY==", "mefor_secrets_directory =="])
@pytest.mark.parametrize("refused", [f"{KEY_CLASS_NAMES[0]}=", "MEFOR_VALUE_A="])
def test_a_joined_directory_entry_is_written_again(refused: str, directory: str) -> None:
    posture = _read([refused, directory])
    refusal = service_env_refusal(posture)
    assert refusal is not None  # the join is not narrowed: this still refuses
    assert posture.value_runs_on and posture.directory_joined
    _assert_rewritten_once(refusal)
    # The run-on step removes every string it runs on into, directory strings among them.
    assert _REMOVE_ALL in refusal
    assert refusal.index(_REMOVE_ALL) < refusal.index(_REWRITE)


def test_a_directory_set_elsewhere_too_is_written_once() -> None:
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
    _assert_rewritten_once(refusal)


def test_a_directory_joined_to_an_empty_pem_key_still_counts_as_set() -> None:
    """The Lander's input on 88a9f83: the directory string joined to an OIDC key is still an item
    NSSM may read as the directory. So the lists do set it, and the remedy must not say they set
    none or to add it back. The key, empty on its own line, now refuses and runs on (round-2
    finding 1), so the run-on step removes the directory string with it."""
    posture = _read_pairs(
        [
            (_EXTRA, "MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY="),
            (_EXTRA, "MEFOR_SECRETS_DIRECTORY=="),
            (_PLAIN, "MEFOR_VALUE_B=1"),
        ]
    )
    assert posture.listed == ("MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY", "MEFOR_VALUE_B")
    assert posture.directory_joined and posture.value_runs_on
    refusal = service_env_refusal(posture)
    assert refusal is not None
    _assert_rewritten_once(refusal)
    assert _REMOVE_ALL in refusal


def _joined_beside(*listed: str) -> ServiceEnvPosture:
    """A posture with a directory string joined to a variable ``_names`` dropped and nothing
    refused running on, built directly: the reading no longer drops an OIDC key that runs on."""
    return ServiceEnvPosture(
        ServiceEnvStatus.OBSERVED,
        service_name="MessageFoundry",
        listed=listed,
        sources=tuple((name, _PLAIN) for name in listed),
        directory_joined=True,
    )


def test_a_directory_joined_to_a_dropped_variable_still_counts_as_set() -> None:
    """The remedy half of the pin above, for a joined directory with nothing refused running on:
    the lists do set it, and there is no run-on step."""
    refusal = service_env_refusal(_joined_beside("MEFOR_VALUE_B"))
    assert refusal is not None
    _assert_rewritten_once(refusal)
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
    assert _REMOVE_ALL in refusal
    assert "but for one MEFOR_SECRETS_DIRECTORY entry" not in refusal
    _assert_rewritten_once(refusal)


def test_a_join_beside_a_store_key_alone_adds_no_directory_step() -> None:
    """A refusal about a store key alone, with nothing running on, sends the operator to a key
    file. The joined directory string does not need touching for that, so no step names it."""
    posture = _joined_beside(KEY_CLASS_NAMES[0])
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert "DPAPI-protected key file" in refusal
    assert _REWRITE not in refusal
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
    assert _REWRITE not in refusal
