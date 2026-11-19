# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The service-environment reader's added items under vault BACKLOG #5394.

Each test drives :func:`messagefoundry.serviceenv.read_service_env_posture` through a probe, so
every one runs on every platform. Synthetic values only: the base64 stand-in below decodes to 32
bytes of plain ASCII text, never a real key.
"""

from __future__ import annotations

import base64
import inspect
import re
import tracemalloc
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

#: A store-key-shaped stand-in: 32 bytes of ASCII, so 44 base64 characters ending in one ``=``.
_KEY_B64 = base64.b64encode(b"synthetic-store-key-0123456789ab").decode()
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


def _read(entries: Sequence[str | tuple[str, str]]) -> ServiceEnvPosture:
    pairs = [e if isinstance(e, tuple) else (_EXTRA, e) for e in entries]
    return read_service_env_posture(probe=_Probe(pairs), environ={})


def test_the_stand_in_has_a_store_keys_shape() -> None:
    assert len(_KEY_B64) == 44 and _KEY_B64.endswith("=") and not _KEY_B64.endswith("==")


# --- item 1: an empty store key continued on the next line or the next item ----------------------


@pytest.mark.parametrize("key", KEY_CLASS_NAMES)
def test_an_empty_store_key_item_whose_key_is_the_next_item_refuses(key: str) -> None:
    """``nssm set`` makes one ``REG_MULTI_SZ`` item per argument, so a key split from its name
    lands in the next item. That item starts no variable, so it is the key's value."""
    posture = _read([f"{key}=", _KEY_B64])
    assert posture.listed_keys == (key,)
    assert service_env_refusal(posture) is not None


@pytest.mark.parametrize("key", KEY_CLASS_NAMES)
def test_a_retired_keys_list_on_the_line_below_an_empty_name_refuses(key: str) -> None:
    """``<key>,<key>`` reads as ``NAME=value`` with the first key as the name. A name of 43
    base64 characters is a key, not an ordinary variable, so it does not end the value above."""
    listing = f"{_KEY_B64},{_KEY_B64}"
    later = _read([f"MEFOR_AI_ENVIRONMENT=prod\n{key}=\n{listing}"])
    assert later.listed_keys == (key,)
    items = _read(["MEFOR_AI_ENVIRONMENT=prod", f"{key}=", listing])
    assert items.listed_keys == (key,)


@pytest.mark.parametrize("key", KEY_CLASS_NAMES)
def test_an_empty_store_key_item_above_an_ordinary_item_does_not_refuse(key: str) -> None:
    """The control: an empty key is harmless when the next item sets an ordinary variable, or is
    empty-named like Windows' own ``=C:`` entries."""
    for follower in ("MEFOR_AI_ENVIRONMENT=prod", "ProgramFiles(x86)=C:\\x", "=C:=C:\\x"):
        posture = _read([f"{key}=", follower])
        assert posture.listed_keys == (), follower
        assert service_env_refusal(posture) is None, follower


def test_an_item_continues_only_the_value_its_own_registry_value_ends_on() -> None:
    key = KEY_CLASS_NAMES[0]
    posture = _read([(_PLAIN, f"{key}="), (_EXTRA, _KEY_B64)])
    assert posture.listed_keys == ()


def test_a_long_run_of_continuing_items_is_read_in_linear_memory() -> None:
    """A key split one line per item: each item adds to one gathered value, not to a copy."""
    items = [f"{KEY_CLASS_NAMES[0]}="] + [f"{n:064d}" for n in range(4000)]
    started_here = not tracemalloc.is_tracing()
    if started_here:
        tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        before, _peak = tracemalloc.get_traced_memory()
        posture = _read(items)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        if started_here:
            tracemalloc.stop()
    assert posture.listed_keys == (KEY_CLASS_NAMES[0],)
    assert peak - before < 16 * 1024 * 1024, f"peak {peak - before} bytes"


def test_a_blank_item_between_does_not_end_the_value() -> None:
    key = KEY_CLASS_NAMES[0]
    assert _read([f"{key}=", "", _KEY_B64]).listed_keys == (key,)


# --- item 2: key material never reaches ``listed`` -------------------------------------------------


def test_a_line_of_key_material_that_starts_an_item_is_not_listed() -> None:
    """A PEM key split one line per item: the padded base64 item reads as ``NAME=value``."""
    pem = "-----BEGIN " + "PRIVATE KEY-----"
    posture = _read(
        [f"MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY={pem}", "MIIBsyntheticBody==", "-----END x"]
    )
    assert posture.listed == ("MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY",)
    assert not any("MIIB" in name for name, _where in posture.sources)


def test_only_a_name_the_refusal_reads_is_listed() -> None:
    posture = _read(["PATH=C:\\x", "MEFOR_AI_ENVIRONMENT=prod", "MEFOR_SECRETS_DIRECTORY=C:\\s"])
    assert posture.listed == ("MEFOR_SECRETS_DIRECTORY",)


# --- item 4: a broken MEFOR_VALUE_* name keeps its rename step -------------------------------------


def test_a_broken_value_name_counted_under_a_later_line_still_asks_for_a_rename() -> None:
    """Under the whole-string reading the engine loads ``MEFOR_VALUE_A<LF>MEFOR_VALUE_B``, a name
    the secrets directory refuses, so the remedy keeps the rename step while counting one."""
    posture = _read(["MEFOR_VALUE_A\nMEFOR_VALUE_B=1"])
    assert posture.listed_value_names == ("MEFOR_VALUE_B",)
    assert posture.unplain_value_names == ("MEFOR_VALUE_A",)
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert "1 MEFOR_VALUE_* variable(s)" in refusal
    assert "rename that env() key" in refusal


# --- item 5: the refusal does not grow with the line count -----------------------------------------


def test_the_value_count_is_grouped_by_registry_value_not_by_line() -> None:
    entry = "\n".join(f"MEFOR_VALUE_K{n}=synthetic-{n}" for n in range(500))
    refusal = service_env_refusal(_read([entry]))
    assert refusal is not None
    assert f"500 MEFOR_VALUE_* variable(s) (in {_EXTRA})" in refusal
    assert "line 2" not in refusal


# --- item 7: no value in a repr --------------------------------------------------------------------


def test_a_variable_repr_holds_no_value() -> None:
    variable = serviceenv._Variable(_EXTRA, "MEFOR_STORE_PASSWORD", "synthetic-repr-value")
    assert "synthetic-repr-value" not in repr(variable)


def test_a_posture_repr_holds_no_registry_name() -> None:
    """A ``MEFOR_VALUE_*`` name may be a value typed where the name goes."""
    posture = _read(["MEFOR_VALUE_synthetictypedvalue=x"])
    assert posture.listed_value_names == ("MEFOR_VALUE_SYNTHETICTYPEDVALUE",)
    assert "SYNTHETICTYPEDVALUE" not in repr(posture).upper()


# --- item 8: the line label is accurate for every shape --------------------------------------------


@pytest.mark.parametrize(
    ("entry", "line"),
    [
        ("MEFOR_AI_ENVIRONMENT=prod\n{key}=v", 2),
        ("MEFOR_VALUE_A\n{key}=v", 2),  # the first line is not an entry
        ("\n\nMEFOR_AI_ENVIRONMENT=prod\n{key}=v", 4),  # blank lines above count
        ("\n{key}=v", 2),  # the key is the first non-blank line
    ],
)
def test_the_refusal_names_the_line_of_the_string_that_sets_the_key(entry: str, line: int) -> None:
    key = KEY_CLASS_NAMES[0]
    refusal = service_env_refusal(_read([entry.format(key=key)]))
    assert refusal is not None
    assert f"{key} (in {_EXTRA}, line {line} of the registry string that sets it)" in refusal
    assert "whose first line is another entry" not in refusal


def test_a_key_on_its_strings_first_line_names_no_line() -> None:
    key = KEY_CLASS_NAMES[0]
    refusal = service_env_refusal(_read([f"{key}=v\nMEFOR_AI_ENVIRONMENT=prod"]))
    assert refusal is not None
    assert f"{key} (in {_EXTRA})" in refusal


# --- item 10: the ordinary-line pattern says what its comment says ---------------------------------


@pytest.mark.parametrize("tail", ["X= =", "X= ", "X=\t=\t"])
def test_a_line_whose_value_is_only_equals_signs_and_blanks_continues_the_value(tail: str) -> None:
    key = KEY_CLASS_NAMES[0]
    posture = _read([f"MEFOR_AI_ENVIRONMENT=prod\n{key}=\n{tail}"])
    assert posture.listed_keys == (key,)


# --- item 11: no wording that goes stale on merge --------------------------------------------------


def test_the_module_names_no_branch_or_head_as_its_baseline() -> None:
    source = inspect.getsource(serviceenv)
    assert not re.search(r"``main``|\bthe head\b", source)
