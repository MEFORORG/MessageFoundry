# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The ``ha`` engines log in to Postgres with the password Postgres was given (BACKLOG #5400).

The postgres service read ``POSTGRES_PASSWORD`` by compose substitution of ``MEFOR_STORE_PASSWORD``,
while the ``ha`` engines took ``MEFOR_STORE_PASSWORD`` only from ``env_file: ./secrets.env``. The two
came from different places, so they could differ, and the engines would then fail at store login.
Now every ``ha`` store user sets the variable in ``environment:``, which beats ``env_file:``, to the
same required substitution postgres reads, aliased from one anchor.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

from tests.test_compose_revocation_attestation import _compose_doc

_HA_STORE_USERS = ("schema-provision", "engine-ha", "engine-standby")
_VAR = "MEFOR_STORE_PASSWORD"


def _split(doc: dict[str, Any]) -> list[str]:
    """Why the ``ha`` store users and postgres could read different passwords; empty when none."""
    services = doc["services"]
    source = (services["postgres"].get("environment") or {}).get("POSTGRES_PASSWORD")
    problems: list[str] = []
    # A `:-` fallback would ship its literal the moment the variable is unset (BACKLOG #1091), so
    # only the required, no-default form counts, as one whole substitution.
    if not (
        isinstance(source, str)
        and source.startswith("${" + _VAR + ":?")
        and source.endswith("}")
        and source.count("${") == 1
    ):
        problems.append(f"postgres: POSTGRES_PASSWORD is not one required {_VAR} substitution")
    for name in _HA_STORE_USERS:
        env = services[name].get("environment") or {}
        if not isinstance(env, dict):
            problems.append(f"{name}: environment is not a mapping")
        elif env.get(_VAR) != source:
            problems.append(f"{name}: {_VAR} is not postgres's POSTGRES_PASSWORD")
    return problems


def test_every_ha_store_user_reads_the_password_postgres_reads() -> None:
    assert _split(_compose_doc()) == []


def _drop_from(doc: dict[str, Any], name: str) -> None:
    del doc["services"][name]["environment"][_VAR]


def _differ_in(doc: dict[str, Any], name: str) -> None:
    doc["services"][name]["environment"][_VAR] = "${MEFOR_OTHER_PASSWORD:?required}"


def _default_postgres(doc: dict[str, Any]) -> None:
    doc["services"]["postgres"]["environment"]["POSTGRES_PASSWORD"] = "${" + _VAR + ":-changeme}"


@pytest.mark.parametrize("name", _HA_STORE_USERS)
@pytest.mark.parametrize("mutate", [_drop_from, _differ_in], ids=["dropped", "differs"])
def test_the_check_sees_a_split_password(mutate: Any, name: str) -> None:
    # Negative control: the check must fail when one store user leaves the shared value.
    doc = copy.deepcopy(_compose_doc())
    mutate(doc, name)
    assert any(p.startswith(f"{name}:") for p in _split(doc))


def test_the_check_sees_a_defaulted_postgres_password() -> None:
    doc = copy.deepcopy(_compose_doc())
    _default_postgres(doc)
    assert any(p.startswith("postgres:") for p in _split(doc))
