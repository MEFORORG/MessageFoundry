# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An entry that names a secret-class variable with nothing in it refuses on its own (vault
BACKLOG #5394, the deferred scope of engine PR 3134: "refuse any empty secret-class entry
outright").

A secret can be written apart from its name, into the entry after it, as ``nssm set ... NAME =
value`` writes one. Where that entry ends the empty value (``serviceenv._ends_blank_class``), the
reader does not read it as the secret, so the empty entry was the one sign of it left, and it
refused nothing. Each refusal test below passes no refusal on the code before this change: its
first assertion, on the refusal or on ``listed``, fails there. The negative controls are empty
entries for names that are no secret, which still refuse nothing. Synthetic values only.
"""

from __future__ import annotations

import pytest

from messagefoundry.serviceenv import (
    KEY_CLASS_NAMES,
    service_env_enforced_refusal,
    service_env_refusal,
)
from tests.test_b2595_service_env_secret_elsewhere import _machine
from tests.test_service_env_secrets import _service

_KEY = KEY_CLASS_NAMES[0]
_PASSWORD = "MEFOR_STORE_PASSWORD"
_EMPTY_SENTENCE = "is named in the service's lists with nothing set in it"

#: Empty secret-class entries, each shape the reader reads as naming the variable with nothing
#: in it, beside an item that ends the empty value, so no value is joined to it.
_EMPTY_SHAPES = {
    "empty item": [f"{_PASSWORD}=", "Path=C:\\x"],
    "blank item": [f"{_PASSWORD}=   ", "Path=C:\\x"],
    "empty item alone": [f"{_PASSWORD}="],
    "name alone": [_PASSWORD, "Path=C:\\x"],
    "empty later line": [f"MEFOR_AI_ENVIRONMENT=prod\n{_PASSWORD}=\nPath=C:\\x"],
    "empty last line": [f"MEFOR_AI_ENVIRONMENT=prod\n{_PASSWORD}="],
    "lower-case empty item": ["mefor_store_password=", "TEMP=C:\\t"],
    "empty pem-or-path key": ["MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY=", "Path=C:\\x"],
}


@pytest.mark.parametrize("shape", sorted(_EMPTY_SHAPES))
def test_an_empty_secret_class_entry_refuses(shape: str) -> None:
    posture = _service(_EMPTY_SHAPES[shape])
    refusal = service_env_refusal(posture)
    assert refusal is not None, shape
    assert len(posture.empty_class_names) == 1, shape
    assert posture.empty_class_names == posture.listed, shape
    assert _EMPTY_SENTENCE in refusal, shape
    # Read as empty, not as set to the item after it, so no step says its value runs on.
    assert not posture.value_runs_on, shape
    assert "runs on past its own entry" not in refusal, shape


@pytest.mark.parametrize(
    "entries",
    [
        pytest.param(["HTTP_PROXY=", "Path=C:\\x"], id="empty ordinary item"),
        pytest.param(["MEFOR_SECRETS_DIRECTORY=", "Path=C:\\x"], id="empty directory item"),
        pytest.param(["HTTP_PROXY", "Path=C:\\x"], id="ordinary name alone"),
        pytest.param(["MEFOR_AI_ENVIRONMENT=", "TZ="], id="empty non-secret engine name"),
        pytest.param(
            ["MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY=C:\\k.pem"], id="path-form pem-or-path key"
        ),
        pytest.param(["MEFOR_STORE_PASSWORD_HINT="], id="name that only starts like one"),
    ],
)
def test_an_empty_entry_for_a_name_that_is_no_secret_refuses_nothing(entries: list[str]) -> None:
    """The negative control: only a secret-class name refuses empty. Each of these refused
    nothing before this change and still refuses nothing, so this test passes on both."""
    posture = _service(entries)
    assert service_env_refusal(posture) is None, entries
    assert not any(name.startswith("MEFOR_STORE") for name in posture.listed), entries


def test_a_name_set_in_one_entry_and_empty_in_another_is_set() -> None:
    """A name some entry sets to something is read as set, with that entry as its source, so
    the remedy still says to move it; only a name no entry sets is an empty one."""
    posture = _service([f"{_PASSWORD}=", "Path=C:\\x", f"{_PASSWORD}=synthetic-pw"])
    assert posture.listed == (_PASSWORD,)
    refusal = service_env_refusal(posture)
    assert refusal is not None and _EMPTY_SENTENCE not in refusal
    assert f"Put {_PASSWORD} in" in refusal
    assert posture.empty_class_names == ()


def test_an_empty_key_has_nothing_to_move_unless_the_process_holds_one() -> None:
    """An empty store key has no key to protect, so the protect-key step does not print; a
    store key that still reaches this process keeps it, as for any listed key."""
    empty = service_env_refusal(_service([f"{_KEY}=", "Path=C:\\x"]))
    assert empty is not None and _EMPTY_SENTENCE in empty
    assert "messagefoundry protect-key" not in empty
    held = service_env_refusal(
        _service([f"{_KEY}=", "Path=C:\\x"], **{_KEY: "synthetic-store-key"})
    )
    assert held is not None and "messagefoundry protect-key" in held


def test_an_empty_entry_still_leaves_a_machine_wide_secret_named() -> None:
    """An empty entry sets nothing, so a value of the same name in this process came from
    elsewhere: it is still looked for in the machine-wide environment, and refused there under
    enforce, as it was before the empty entry refused. The empty entry now refuses too: that
    last assertion is the one that fails on the code before this change."""
    posture = _machine(
        [f"{_PASSWORD}="], (_PASSWORD,), **{_PASSWORD: "synthetic-machine-wide-password"}
    )
    assert posture.others_from_elsewhere == (_PASSWORD,)
    assert posture.others_machine_wide == (_PASSWORD,)
    enforced = service_env_enforced_refusal(posture)
    assert enforced is not None and "machine-wide environment" in enforced
    assert service_env_refusal(posture) is not None
