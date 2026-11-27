# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The ``ha`` engines log in to Postgres with the password Postgres reads (BACKLOG #5400).

The postgres service read ``POSTGRES_PASSWORD`` by compose substitution of ``MEFOR_STORE_PASSWORD``,
while the ``ha`` engines took ``MEFOR_STORE_PASSWORD`` only from ``env_file: ./secrets.env``. The two
came from different places, so they could differ, and the engines would then fail at store login.
Now every Postgres store user sets the variable in ``environment:``, which beats ``env_file:``, to
the same required substitution postgres reads, aliased from one anchor.
"""

from __future__ import annotations

import copy
import re
from typing import Any

import pytest

from tests.test_compose_revocation_attestation import _compose_doc

_VAR = "MEFOR_STORE_PASSWORD"
#: The required, no-default form: a `:-` fallback would ship its literal the moment the variable
#: is unset (BACKLOG #1091). The same shape test_compose_revocation_attestation's _REQUIRED pins.
_REQUIRED = re.compile(r"\$\{" + _VAR + r":\?[^}]+\}")
#: The services the shipped file must cover, a floor for the derived set below.
_KNOWN_STORE_USERS = {"schema-provision", "engine-ha", "engine-standby"}


def _env(svc: dict[str, Any]) -> dict[str, Any]:
    env = svc.get("environment") or {}
    return env if isinstance(env, dict) else {}


def _store_users(doc: dict[str, Any]) -> set[str]:
    """Every service that logs in to the Postgres store, so a new one is checked too."""
    return {
        name
        for name, svc in doc["services"].items()
        if _env(svc).get("MEFOR_STORE_BACKEND") == "postgres"
    }


def _split(doc: dict[str, Any]) -> list[str]:
    """Why a Postgres store user and postgres could read different passwords; empty when none."""
    services = doc["services"]
    source = _env(services["postgres"]).get("POSTGRES_PASSWORD")
    problems: list[str] = []
    if not (isinstance(source, str) and _REQUIRED.fullmatch(source)):
        problems.append(f"postgres: POSTGRES_PASSWORD is not one required {_VAR} substitution")
    for name in sorted(_store_users(doc)):
        if _env(services[name]).get(_VAR) != source:
            problems.append(f"{name}: {_VAR} is not postgres's POSTGRES_PASSWORD")
    return problems


def test_the_store_users_are_found() -> None:
    # Positive control for the derived set: an empty one would pass every check below.
    assert _store_users(_compose_doc()) >= _KNOWN_STORE_USERS


def test_every_ha_store_user_reads_the_password_postgres_reads() -> None:
    assert _split(_compose_doc()) == []


def _drop_from(doc: dict[str, Any], name: str) -> None:
    del doc["services"][name]["environment"][_VAR]


def _differ_in(doc: dict[str, Any], name: str) -> None:
    doc["services"][name]["environment"][_VAR] = "${MEFOR_OTHER_PASSWORD:?required}"


@pytest.mark.parametrize("name", sorted(_KNOWN_STORE_USERS))
@pytest.mark.parametrize("mutate", [_drop_from, _differ_in], ids=["dropped", "differs"])
def test_the_check_sees_a_split_password(mutate: Any, name: str) -> None:
    # Negative control: the check must fail when one store user leaves the shared value.
    doc = copy.deepcopy(_compose_doc())
    mutate(doc, name)
    assert any(p.startswith(f"{name}:") for p in _split(doc))


def test_the_check_sees_a_new_store_user_without_the_password() -> None:
    doc = copy.deepcopy(_compose_doc())
    added = copy.deepcopy(doc["services"]["engine-standby"])
    del added["environment"][_VAR]
    doc["services"]["engine-ha2"] = added
    assert any(p.startswith("engine-ha2:") for p in _split(doc))


@pytest.mark.parametrize(
    "value",
    ["${" + _VAR + ":-changeme}", "${" + _VAR + ":?}", "${" + _VAR + "}", "fixed"],
    ids=["defaulted", "empty-message", "optional", "literal"],
)
def test_the_check_sees_a_postgres_password_that_is_not_required(value: str) -> None:
    doc = copy.deepcopy(_compose_doc())
    doc["services"]["postgres"]["environment"]["POSTGRES_PASSWORD"] = value
    assert any(p.startswith("postgres:") for p in _split(doc))
