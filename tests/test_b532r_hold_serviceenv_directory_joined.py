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
    # A MEFOR_VALUE_* name always gets the one Put sentence and the create step (the Lander's
    # decision d20261122T181059560-3bac03). A key whose only value is the directory entry has
    # nothing to move (the fifth hold on PR 3142, H3).
    moved = refused.startswith("MEFOR_VALUE_")
    assert (CREATE in refusal) is moved and ("Put " in refusal) is moved
    assert ("An empty or blank MEFOR_VALUE_* entry is refused too: delete it" in refusal) is (
        moved and " " not in directory
    )


def test_the_bare_prefix_joined_to_the_directory_is_deleted() -> None:
    """The bare prefix names no env() key, so the refusal says to delete that entry, and never
    to write an empty override in the value file."""
    refusal = service_env_refusal(_read(["MEFOR_VALUE_=", "MEFOR_SECRETS_DIRECTORY=="]))
    assert refusal is not None
    assert "The bare name MEFOR_VALUE_ sets no env() key, so delete that entry" in refusal
    assert "An empty or blank MEFOR_VALUE_* entry" not in refusal


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
    """The Lander's sixth hold on PR 3142, H2: the empty entry is told to go, and the name is
    still told to go to the secrets directory."""
    refusal = service_env_refusal(_read_pairs(pairs))
    assert refusal is not None
    assert "Put each MEFOR_VALUE_* variable in the secrets directory" in refusal
    assert "An empty or blank MEFOR_VALUE_* entry is refused too: delete it" in refusal
    assert "synthetic-a-value" not in refusal


#: Text in the shapes below that is a value, or could be: the refusal must echo none of it.
_VALUE_TEXT = ("hunter2", "AAAA", "Winter", "synthetic-other-line", _KEY_B64[:43])

_SHAPES = [
    pytest.param([(_EXTRA, "MEFOR_VALUE_A=\nOTHER=1")], id="assignment"),
    pytest.param([(_EXTRA, "MEFOR_VALUE_A=\nMEFOR_SECRETS_DIRECTORY=C:\\d")], id="dir-line"),
    pytest.param([(_EXTRA, "MEFOR_VALUE_A=\n   ")], id="blank-line"),
    pytest.param([(_EXTRA, f"MEFOR_VALUE_A=\nOTHER={_KEY_B64}")], id="assignment-to-a-key"),
    pytest.param([(_EXTRA, "MEFOR_VALUE_A=\nOTHER=1\nsynthetic-other-line")], id="after-it"),
    pytest.param([(_EXTRA, "MEFOR_VALUE_A=\nMEFOR_VALUE_B")], id="name-alone"),
    pytest.param([(_EXTRA, "MEFOR_VALUE_A=\nMEFOR_SECRETS_DIRECTORY==")], id="blank-dir-line"),
    pytest.param(
        [(_EXTRA, "MEFOR_VALUE_A="), (_EXTRA, KEY_CLASS_NAMES[0]), (_EXTRA, "=" + _KEY_B64)],
        id="key-name-alone",
    ),
    pytest.param([(_EXTRA, "MEFOR_VALUE_A=\nhunter2")], id="next-line"),
    pytest.param(
        [(_EXTRA, "MEFOR_VALUE_A=\n-----BEGIN X-----\nAAAA\n-----END X-----")],
        id="pem-from-line-2",
    ),
    pytest.param([(_EXTRA, "MEFOR_VALUE_A="), (_EXTRA, "hunter2")], id="next-item"),
    pytest.param([(_EXTRA, "MEFOR_VALUE_A=\n#x")], id="comment-only-line"),
    pytest.param([(_EXTRA, f"MEFOR_VALUE_A=\n{_KEY_B64}")], id="key-with-padding"),
    pytest.param(
        [
            (_PLAIN, "MEFOR_VALUE_A="),
            (_EXTRA, "MEFOR_VALUE_A="),
            (_EXTRA, "MEFOR_SECRETS_DIRECTORY=="),
        ],
        id="empty-twice-and-a-directory",
    ),
]


@pytest.mark.parametrize("pairs", _SHAPES)
def test_every_value_name_gets_one_generic_put_sentence(pairs: list[tuple[str, str]]) -> None:
    """The Lander's decision d20261122T181059560-3bac03 on PR 3142: no reading of which line is
    content gates the steps. Every MEFOR_VALUE_* refusal prints the one Put sentence, naming no
    variable, with the value-file alternative and the ``provider = "env"`` sentence. An empty
    entry adds the delete clause, and a name the secrets directory refuses adds the rename."""
    posture = _read_pairs(pairs)
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert refusal.count("Put each MEFOR_VALUE_* variable in the secrets directory") == 1
    assert "environments/<env>.toml" in refusal
    assert '[secrets].provider = "env"' in refusal and "leaves the secret in the registry key" in (
        refusal
    )
    empty = bool(posture.empty_value_names) or any(
        name.startswith("MEFOR_VALUE_") and name != "MEFOR_VALUE_"
        for name in posture.directory_only_names
    )
    assert ("An empty or blank MEFOR_VALUE_* entry is refused too: delete it" in refusal) is empty
    assert ("rename that env() key" in refusal) is bool(posture.unplain_value_names)
    assert KEEP not in refusal  # no shape here joins a path into a refused value
    assert "MEFOR_VALUE_A" not in refusal and "MEFOR_VALUE_B" not in refusal
    assert not any(text in refusal for text in _VALUE_TEXT)


@pytest.mark.parametrize(
    "pairs",
    [
        pytest.param([(_EXTRA, "MEFOR_VALUE_A\n=")], id="O1-separator-line"),
        pytest.param([(_EXTRA, "MEFOR_VALUE_A"), (_EXTRA, "=")], id="O1-separator-item"),
        pytest.param([(_EXTRA, "MEFOR_VALUE_A\nX=1")], id="O2-assignment-line"),
        pytest.param([(_EXTRA, "MEFOR_VALUE_A\nWinter=2026!")], id="O2-split-secret-line"),
        pytest.param([(_EXTRA, "MEFOR_VALUE_A"), (_EXTRA, "Winter=2026!")], id="O3-split-item"),
    ],
)
def test_the_round_three_shapes_print_put(pairs: list[tuple[str, str]]) -> None:
    """Review round 3's O1 to O3 shapes on PR 3142, which a content reading misjudged: each
    prints the one Put sentence, and the rename where the name is one the directory refuses."""
    posture = _read_pairs(pairs)
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert refusal.count("Put each MEFOR_VALUE_* variable in the secrets directory") == 1
    assert CREATE in refusal
    assert ("rename that env() key" in refusal) is bool(posture.unplain_value_names)
    assert "MEFOR_VALUE_A" not in refusal
    assert "Winter" not in refusal and "2026!" not in refusal


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
