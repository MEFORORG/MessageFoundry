# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An entry that names a secret-class variable with nothing in it refuses on its own (vault
BACKLOG #5394, the deferred scope of engine PR 3134: "refuse any empty secret-class entry
outright").

A secret can be written apart from its name, into an entry or line after it, as ``nssm set ...
NAME = value`` writes one. Where that one ends the empty value (``serviceenv._ends_blank_class``),
the reader does not read it as the secret, so the empty entry was the one sign of it left, and it
refused nothing. ``test_an_empty_secret_class_entry_refuses``, the path-form test and the
protect-key test fail on the code before this change on their refusal assertion; the
machine-wide test fails there on its last assertion only. The negative controls are empty
entries for names that are no secret, which refuse nothing on both. The tests that cite code
review round 3 repair that round's four findings and fail on a0b245d3d6d, each as its docstring
says. Synthetic values only.
"""

from __future__ import annotations

import pytest

from messagefoundry.serviceenv import (
    KEY_CLASS_NAMES,
    service_env_enforced_refusal,
    service_env_refusal,
)
from tests._serviceenv_remedy import EMPTY_CLASS_STEP, EMPTY_PATH_FORM_STEP, NAMED_EMPTY
from tests.test_b2595_service_env_secret_elsewhere import _machine
from tests.test_service_env_secrets import _service

_KEY = KEY_CLASS_NAMES[0]
_PASSWORD = "MEFOR_STORE_PASSWORD"
_PEM_OR_PATH = "MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY"
_EXTRA = "Parameters\\AppEnvironmentExtra"

#: Empty secret-class entries, each shape the reader reads as naming the variable with nothing
#: in it, beside an item that ends the empty value, so no value is joined to it, and the line
#: of its string that names it where that is not the first.
_EMPTY_SHAPES: dict[str, tuple[list[str], int | None]] = {
    "empty item": ([f"{_PASSWORD}=", "Path=C:\\x"], None),
    "blank item": ([f"{_PASSWORD}=   ", "Path=C:\\x"], None),
    "empty item alone": ([f"{_PASSWORD}="], None),
    "name alone": ([_PASSWORD, "Path=C:\\x"], None),
    "empty later line": ([f"MEFOR_AI_ENVIRONMENT=prod\n{_PASSWORD}=\nPath=C:\\x"], 2),
    "empty last line": ([f"MEFOR_AI_ENVIRONMENT=prod\n{_PASSWORD}="], 2),
    "lower-case empty item": (["mefor_store_password=", "TEMP=C:\\t"], None),
    "empty pem-or-path key": ([f"{_PEM_OR_PATH}=", "Path=C:\\x"], None),
}


def _located(name: str, line: int | None, verb: str = "names it") -> str:
    """How the refusal locates ``name`` (``ServiceEnvPosture.named_with_source``): an empty
    entry as the string that names it, a set one, with ``verb``, as the string that sets it."""
    if line is None:
        return f"{name} (in {_EXTRA})"
    return f"{name} (in {_EXTRA}, line {line} of the registry string that {verb})"


@pytest.mark.parametrize("shape", sorted(_EMPTY_SHAPES))
def test_an_empty_secret_class_entry_refuses(shape: str) -> None:
    entries, line = _EMPTY_SHAPES[shape]
    posture = _service(entries)
    refusal = service_env_refusal(posture)
    assert refusal is not None, shape
    assert len(posture.empty_class_names) == 1, shape
    # Named, not set: ``listed`` holds only names set to something.
    assert posture.listed == (), shape
    assert f"{_located(posture.empty_class_names[0], line)} {NAMED_EMPTY}" in refusal, shape
    assert EMPTY_CLASS_STEP in refusal, shape
    # Nothing moves to a secrets directory, so no step says to add one back with `nssm set`.
    assert "`nssm set`" not in refusal, shape
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
        pytest.param([f"{_PEM_OR_PATH}=C:\\k.pem"], id="path-form pem-or-path key"),
        pytest.param(["MEFOR_STORE_PASSWORD_HINT="], id="name that only starts like one"),
    ],
)
def test_an_empty_entry_for_a_name_that_is_no_secret_refuses_nothing(entries: list[str]) -> None:
    """The negative control: only a secret-class name refuses empty. Each of these refused
    nothing before this change and still refuses nothing, so this test passes on both."""
    posture = _service(entries)
    assert service_env_refusal(posture) is None, entries
    assert not set(posture.listed) - {"MEFOR_SECRETS_DIRECTORY"}, entries
    assert getattr(posture, "empty_class_names", ()) == (), entries


def test_an_empty_entry_beside_a_path_form_entry_of_its_name_refuses() -> None:
    """A path-form OIDC key is no secret, so it leaves its name unlisted, and an empty entry of
    that name beside it is still read as one with nothing set in it, which refuses: NSSM may
    apply either, and the empty one may be the sign of a split key (code review round 2 on this
    change). The path alone is the control above."""
    posture = _service([f"{_PEM_OR_PATH}=C:\\k.pem", "Path=C:\\x", f"{_PEM_OR_PATH}="])
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert posture.empty_class_names == (_PEM_OR_PATH,)
    assert NAMED_EMPTY in refusal


def test_a_name_set_in_one_entry_and_empty_in_another_is_both() -> None:
    """A name some entry sets to a secret is read as set, with that entry as its source, so the
    remedy still says to move it. An entry that names it empty is named too, with its own
    source, and the empty-entry step prints: the item after that entry may be the secret split
    from its name, and without the step no step covers it (code review round 3 on this change,
    finding 2). This fails on a0b245d3d6d, which hid the empty entry behind the set one."""
    posture = _service(
        [f"MEFOR_AI_ENVIRONMENT=prod\n{_PASSWORD}=", "Path=C:\\x", f"{_PASSWORD}=synthetic-pw"]
    )
    assert posture.listed == (_PASSWORD,)
    assert posture.empty_class_names == (_PASSWORD,)
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert f"{_located(_PASSWORD, None)} is set and " in refusal
    assert f"{_located(_PASSWORD, 2)} {NAMED_EMPTY}" in refusal
    assert f"Put {_PASSWORD} in" in refusal
    assert EMPTY_CLASS_STEP in refusal


#: The split ``nssm set <service> AppEnvironmentExtra NAME = value`` writes: the name, an item of
#: equals signs, and the value, here one the reader cannot tell from an ordinary variable that
#: ends the empty value (``serviceenv._ends_blank_class``). With whether the pass-back step
#: prints: only a secret the secrets directory takes brings it, never a store key alone.
_CANONICAL_SPLITS: dict[str, tuple[list[str], bool]] = {
    "password, = item": ([_PASSWORD, "=", "Path=C:\\synthetic-split"], True),
    "store key, = item": ([_KEY, "=", "Path=C:\\synthetic-split"], False),
    "password=, = item": ([f"{_PASSWORD}=", "=", "Path=C:\\synthetic-split"], True),
}


@pytest.mark.parametrize("shape", sorted(_CANONICAL_SPLITS))
def test_the_canonical_split_is_read_as_named_empty(shape: str) -> None:
    """``NAME``, ``=``, ``<secret>`` reads ``NAME`` as set to ``=``, which still refuses as set;
    it is named empty too, and the empty-entry step prints before the step that passes entries
    back with ``nssm set``, which then leaves out the item that may hold the secret (code review
    round 3 on this change, finding 1). This fails on a0b245d3d6d, where the step never printed
    and the pass-back step kept that item."""
    entries, passes_back = _CANONICAL_SPLITS[shape]
    posture = _service(entries)
    name = entries[0].rstrip("=")
    refusal = service_env_refusal(posture)
    assert refusal is not None, shape
    # Still refused as set, as it was: the refusal only gets stricter.
    assert name in posture.listed, shape
    assert posture.empty_class_names == (name,), shape
    assert f"{_located(name, None)} {NAMED_EMPTY}" in refusal, shape
    assert EMPTY_CLASS_STEP in refusal, shape
    pass_back = refusal.find("`nssm set` replaces that whole list")
    assert (pass_back != -1) is passes_back, shape
    if passes_back:
        assert refusal.index(EMPTY_CLASS_STEP) < pass_back, shape


def test_the_step_keeps_a_path_form_entry() -> None:
    """An empty OIDC client key beside an entry that sets it to its path: the step says to
    remove each entry that names it empty, and to keep the path, never to remove the name from
    every list, which would take the path out (code review round 3 on this change, finding 3).
    This fails on a0b245d3d6d, whose step said "remove it from each"."""
    refusal = service_env_refusal(
        _service([f"{_PEM_OR_PATH}=C:\\k.pem", "Path=C:\\x", f"{_PEM_OR_PATH}="])
    )
    assert refusal is not None
    assert "remove it from each" not in refusal
    assert EMPTY_PATH_FORM_STEP in refusal
    assert refusal.index(EMPTY_CLASS_STEP) < refusal.index(EMPTY_PATH_FORM_STEP)


def test_the_path_form_line_prints_only_for_the_oidc_key() -> None:
    refusal = service_env_refusal(_service([f"{_PASSWORD}=", "Path=C:\\x"]))
    assert refusal is not None and EMPTY_PATH_FORM_STEP not in refusal


def test_the_path_form_line_does_not_print_where_the_key_is_listed() -> None:
    """Empty and path lines of the OIDC client key in one string read the key as set, so the
    steps say to take that entry out, and a "keep it" would contradict them (code review round
    1 on the repair of round 3)."""
    posture = _service([f"{_PEM_OR_PATH}=\n{_PEM_OR_PATH}=C:\\k.pem"])
    assert _PEM_OR_PATH in posture.listed
    assert posture.empty_class_names == (_PEM_OR_PATH,)
    refusal = service_env_refusal(posture)
    assert refusal is not None and EMPTY_PATH_FORM_STEP not in refusal


def test_an_empty_retired_key_is_sent_to_rotate_key() -> None:
    """An empty retired-key entry: the step says a retired key belongs only in the shell that
    runs `messagefoundry rotate-key`, not in a DPAPI key file (code review round 3 on this
    change, finding 4). This fails on a0b245d3d6d, whose step named a DPAPI key file only."""
    retired = "MEFOR_STORE_ENCRYPTION_KEYS_RETIRED"
    assert retired in KEY_CLASS_NAMES
    posture = _service([f"{retired}=", "Path=C:\\x"])
    assert posture.empty_class_names == (retired,)
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert "a retired key only in the shell that runs `messagefoundry rotate-key`" in refusal


def test_an_empty_key_has_nothing_to_move_unless_the_process_holds_one() -> None:
    """An empty store key has no key to protect, so the protect-key step does not print; a
    store key that still reaches this process keeps it, as for any listed key."""
    empty = service_env_refusal(_service([f"{_KEY}=", "Path=C:\\x"]))
    assert empty is not None and f"{_located(_KEY, None)} {NAMED_EMPTY}" in empty
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
