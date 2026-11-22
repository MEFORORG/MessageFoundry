# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The refusal's remedy when ``MEFOR_SECRETS_DIRECTORY==`` is joined into an empty value
(vault BACKLOG #5394), whether or not the variable it is joined to is refused.

The join stays: the string still continues the empty value, and every input that refused before
still refuses. Since the Lander's third hold on PR 3142 the remedy names no list, registry string
or command: it says to remove each refused variable and what a value runs on
into, and points at docs/SERVICE.md. An OIDC key empty on its own line runs on and refuses
(round-2 finding 1).
Synthetic values only.
"""

from __future__ import annotations

import base64
from collections.abc import Iterator
from dataclasses import dataclass, field

import pytest

from messagefoundry.serviceenv import (
    KEY_CLASS_NAMES,
    ServiceEnvPosture,
    read_service_env_posture,
    service_env_refusal,
)
from tests._serviceenv_remedy import CREATE, KEEP, REMOVE, RUNS_ON

_EXTRA = "Parameters\\AppEnvironmentExtra"
_PLAIN = "Parameters\\AppEnvironment"
#: A synthetic stand-in for a store key: its ``=`` padding makes it look like ``NAME=``.
_KEY_B64 = base64.b64encode(b"synthetic-store-key-0123456789ab").decode()


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


@pytest.mark.parametrize("directory", ["MEFOR_SECRETS_DIRECTORY==", "mefor_secrets_directory =="])
@pytest.mark.parametrize("refused", [f"{KEY_CLASS_NAMES[0]}=", "MEFOR_VALUE_A="])
def test_a_joined_directory_entry_is_removed_with_the_value(refused: str, directory: str) -> None:
    posture = _read([refused, directory])
    refusal = service_env_refusal(posture)
    assert refusal is not None  # the join is not narrowed: this still refuses
    assert posture.value_runs_on
    assert REMOVE in refusal and RUNS_ON in refusal
    assert refusal.index(REMOVE) < refusal.index(RUNS_ON)
    # The reader reads ``mefor_secrets_directory ==`` as no variable of its own (_line_start), so
    # joined to an empty MEFOR_VALUE_A it is A's content, and A is moved. Otherwise nothing here
    # has a value to move (the fifth hold on PR 3142, H3; the seventh hold; its eighth round).
    moved = refused.startswith("MEFOR_VALUE_") and " " in directory
    assert (CREATE in refusal) is moved and ("Put " in refusal) is moved
    assert ("An empty or blank MEFOR_VALUE_* entry is refused too: delete it" in refusal) is (
        refused.startswith("MEFOR_VALUE_") and " " not in directory
    )


def test_the_bare_prefix_joined_to_the_directory_is_only_deleted() -> None:
    """The bare prefix names no env() key, so even with nothing but a directory entry joined to it
    the refusal says only to delete it, never to write an empty override in the value file."""
    refusal = service_env_refusal(_read(["MEFOR_VALUE_=", "MEFOR_SECRETS_DIRECTORY=="]))
    assert refusal is not None
    assert "The bare name MEFOR_VALUE_ sets no env() key, so delete that entry" in refusal
    assert "An empty or blank MEFOR_VALUE_* entry" not in refusal
    assert CREATE not in refusal and "Put " not in refusal


@pytest.mark.parametrize(
    "pairs",
    [
        pytest.param(
            [(_PLAIN, "MEFOR_VALUE_A="), (_EXTRA, "MEFOR_VALUE_A=synthetic-a-value")],
            id="two-values",
        ),
        pytest.param(
            [(_EXTRA, "MEFOR_VALUE_A=\nmefor_value_a=synthetic-a-value")], id="one-string"
        ),
    ],
)
def test_a_name_set_empty_in_one_entry_and_with_content_in_another_is_moved(
    pairs: list[tuple[str, str]],
) -> None:
    """The Lander's sixth hold on PR 3142, H2: Put is decided by name. A name with content in
    any entry is told to go to the secrets directory, even where another entry sets it empty;
    the empty entry is still told to go."""
    refusal = service_env_refusal(_read_pairs(pairs))
    assert refusal is not None
    assert "Put each MEFOR_VALUE_* variable in the secrets directory" in refusal
    assert "An empty or blank MEFOR_VALUE_* entry is refused too: delete it" in refusal
    assert "synthetic-a-value" not in refusal


@pytest.mark.parametrize(
    "entry",
    [
        "MEFOR_VALUE_A=\nOTHER=1",
        "MEFOR_VALUE_A=\nMEFOR_SECRETS_DIRECTORY=C:\\d",
        "MEFOR_VALUE_A=\n   ",
        f"MEFOR_VALUE_A=\nOTHER={_KEY_B64}",
        "MEFOR_VALUE_A=\nProgramFiles(x86)=C:\\x",
        "MEFOR_VALUE_A=\nOTHER=1\nsynthetic-other-line",
        "MEFOR_VALUE_A=\nMEFOR_VALUE_B",
        "MEFOR_VALUE_A=\nMEFOR_SECRETS_DIRECTORY==",
    ],
    ids=[
        "assignment",
        "directory-assignment",
        "blank-line",
        "assignment-to-a-key",
        "assignment-with-parentheses",
        "lines-after-an-assignment",
        "name-alone",
        "blank-directory-line",
    ],
)
def test_a_name_with_no_content_of_its_own_is_only_deleted(entry: str) -> None:
    """The Lander's seventh hold on PR 3142, as corrected in its eighth round: a later line
    the reader reads as a variable of its own takes the lines after it, and a blank one adds
    nothing, nor does a blank directory entry, so the name has no content and the refusal
    says only to delete it."""
    refusal = service_env_refusal(_read([entry]))
    assert refusal is not None
    assert "An empty or blank MEFOR_VALUE_* entry is refused too: delete it" in refusal
    assert "Put " not in refusal and CREATE not in refusal and KEEP not in refusal
    assert _KEY_B64[:43] not in refusal


def test_a_refused_name_alone_after_an_empty_value_takes_the_key_after_it() -> None:
    """A refused name written alone starts a variable of its own, so the key joined after it
    is that name's, not the empty value's: nothing says to move a MEFOR_VALUE_* variable."""
    refusal = service_env_refusal(
        _read_pairs(
            [(_EXTRA, "MEFOR_VALUE_A="), (_EXTRA, KEY_CLASS_NAMES[0]), (_EXTRA, "=" + _KEY_B64)]
        )
    )
    assert refusal is not None
    assert "An empty or blank MEFOR_VALUE_* entry is refused too: delete it" in refusal
    assert "Put each MEFOR_VALUE_* variable" not in refusal
    assert _KEY_B64[:43] not in refusal


@pytest.mark.parametrize(
    "pairs",
    [
        [(_EXTRA, "MEFOR_VALUE_A=\nhunter2")],
        [(_EXTRA, "MEFOR_VALUE_A=\n-----BEGIN X-----\nAAAA\n-----END X-----")],
        [(_EXTRA, "MEFOR_VALUE_A="), (_EXTRA, "hunter2")],
        [(_EXTRA, "MEFOR_VALUE_A=\n#x")],
        [(_EXTRA, f"MEFOR_VALUE_A=\n{_KEY_B64}")],
        [(_EXTRA, "MEFOR_VALUE_A=\nhunter2=")],
        [(_EXTRA, "MEFOR_VALUE_A=\n==")],
        [(_EXTRA, "MEFOR_VALUE_A=\nOTHER=")],
        [(_EXTRA, "MEFOR_VALUE_A"), (_EXTRA, "="), (_EXTRA, "Winter=2026!")],
        [(_EXTRA, "X=1\nMEFOR_VALUE_A\nWinter=2026!")],
    ],
    ids=[
        "next-line",
        "pem-from-line-2",
        "next-item",
        "comment-only-line",
        "key-with-padding",
        "text-then-an-equals-sign",
        "equals-only-line",
        "name-with-nothing-after-it",
        "name-alone-split-value",
        "name-alone-in-one-string",
    ],
)
def test_a_value_that_starts_on_a_later_line_is_moved(pairs: list[tuple[str, str]]) -> None:
    """The Lander's eighth round on PR 3142: a later line, or the item joined after an empty
    value, is the name's content unless the reader reads it as a variable of its own, so Put
    prints. ``#`` is nothing special, so ``#x`` is content too."""
    refusal = service_env_refusal(_read_pairs(pairs))
    assert refusal is not None
    assert "Put each MEFOR_VALUE_* variable in the secrets directory" in refusal
    assert "An empty or blank MEFOR_VALUE_* entry" not in refusal
    assert "hunter2" not in refusal and "AAAA" not in refusal and "Winter" not in refusal
    assert _KEY_B64[:43] not in refusal


def test_a_name_empty_in_one_entry_and_joined_to_a_directory_in_another_moves_nothing() -> None:
    """The control for the test above: neither entry gives the name content of its own, so
    nothing says to put it in the directory, and the empty entry is told to go."""
    refusal = service_env_refusal(
        _read_pairs(
            [
                (_PLAIN, "MEFOR_VALUE_A="),
                (_EXTRA, "MEFOR_VALUE_A="),
                (_EXTRA, "MEFOR_SECRETS_DIRECTORY=="),
            ]
        )
    )
    assert refusal is not None
    assert "Put " not in refusal and CREATE not in refusal
    assert "An empty or blank MEFOR_VALUE_* entry is refused too: delete it" in refusal


def test_a_directory_set_elsewhere_too_gets_no_create_guidance() -> None:
    posture = _read_pairs(
        [
            (_PLAIN, "MEFOR_SECRETS_DIRECTORY=C:\\synthetic-secrets"),
            (_EXTRA, "MEFOR_VALUE_A="),
            (_EXTRA, "MEFOR_SECRETS_DIRECTORY=="),
        ]
    )
    assert "MEFOR_SECRETS_DIRECTORY" in posture.listed
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert REMOVE in refusal and RUNS_ON in refusal and CREATE not in refusal


def test_a_directory_joined_to_an_empty_pem_key_is_removed_with_it() -> None:
    """The key, empty on its own line, refuses and runs on (round-2 finding 1), so the run-on
    sentence covers the directory string joined to it."""
    posture = _read_pairs(
        [
            (_EXTRA, "MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY="),
            (_EXTRA, "MEFOR_SECRETS_DIRECTORY=="),
            (_PLAIN, "MEFOR_VALUE_B=1"),
        ]
    )
    assert posture.listed == ("MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY", "MEFOR_VALUE_B")
    assert posture.value_runs_on
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert REMOVE in refusal and RUNS_ON in refusal and CREATE in refusal


def test_with_nothing_joined_the_run_on_sentence_follows_the_run_on() -> None:
    """Control: a value alone gets the removal and the create guidance and no run-on
    sentence, and a run-on into key material gets the run-on sentence."""
    value_only = service_env_refusal(_read(["MEFOR_VALUE_A=1"]))
    assert value_only is not None
    assert REMOVE in value_only and CREATE in value_only and RUNS_ON not in value_only
    run_on = _read([f"{KEY_CLASS_NAMES[0]}=", "abc=="])
    assert run_on.value_runs_on
    refusal = service_env_refusal(run_on)
    assert refusal is not None
    assert RUNS_ON in refusal and CREATE not in refusal


def test_two_joined_groups_in_one_registry_value_both_refuse_and_run_on() -> None:
    """A store key running on into key material, then an OIDC key running on into a directory
    string: both keys are listed and the value runs on. This pins the reader, not the remedy."""
    posture = _read(
        [
            f"{KEY_CLASS_NAMES[0]}=",
            "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGk=",
            "MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY=",
            "MEFOR_SECRETS_DIRECTORY==",
        ]
    )
    assert posture.listed == (KEY_CLASS_NAMES[0], "MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY")
    assert posture.value_runs_on
    refusal = service_env_refusal(posture)
    assert refusal is not None and RUNS_ON in refusal
