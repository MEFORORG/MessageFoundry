# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The ``[vault]`` extra declares the requests floor its send-time checks need (vault BACKLOG #2548).

``transports/strict_requests.py`` runs most of its send-time Vault hop checks (BACKLOG #300,
#2317, and the strict-head and narrowed-pool checks) in
``HTTPAdapter.get_connection_with_tls_context``. requests made that hook public in 2.32.2.
2.32.0 and 2.32.1 call a private ``_get_connection`` instead, and older releases call neither, so
on any of them the checks would silently not run. The extra used to declare
only ``hvac``, so requests arrived as hvac's dependency with no such floor. The lock pinned a newer
requests, so CI was safe; an install resolving without the lock would not have been.

Two halves. The floor is read from ``pyproject.toml`` and must admit no version below the hook's.
The hook is then shown to be the one the adapter overrides, so the floor's reason cannot quietly
go away while the pin stays, or the reverse.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.version import Version

from tests._extras_probe import OPTIONAL_EXTRAS, extra_is_installed

_PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"

#: The first requests release that calls ``HTTPAdapter.get_connection_with_tls_context``. The
#: installed requests says so in the deprecation text of ``get_connection``: custom adapters "will
#: need to migrate for Requests>=2.32.2".
_HOOK_SINCE = Version("2.32.2")

#: The hook, by name. The send-time checks live in the adapter's override of it.
_HOOK = "get_connection_with_tls_context"


def _vault_requests_requirement() -> Requirement:
    data = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    extra: list[str] = data["project"]["optional-dependencies"]["vault"]
    found = [Requirement(spec) for spec in extra if Requirement(spec).name.lower() == "requests"]
    assert len(found) == 1, (
        "the [vault] extra must declare requests exactly once; it carries the send-time hook "
        f"floor (vault BACKLOG #2548). Found: {extra}"
    )
    return found[0]


def test_the_vault_extra_declares_a_requests_floor_at_the_hook_version() -> None:
    """RED before the change: the extra held only hvac. Mutation: lower the floor to
    ``requests>=2.32``; red, 2.32.0 is admitted and never calls the hook."""
    requirement = _vault_requests_requirement()
    floors = [
        Version(spec.version) for spec in requirement.specifier if spec.operator in (">=", ">")
    ]
    assert floors, f"{requirement} has no lower bound"
    assert max(floors) >= _HOOK_SINCE, f"{requirement} admits a requests below {_HOOK_SINCE}"
    # The set as a whole, so another operator in it cannot reopen the gap below the floor.
    for below in ("2.32.1", "2.32.0", "2.31.0", "2.0.0"):
        assert not requirement.specifier.contains(below), f"{requirement} admits {below}"


@pytest.mark.skipif(
    not extra_is_installed(OPTIONAL_EXTRAS["vault"]),
    reason="the [vault] extra (hvac + requests + urllib3) is not installed in this interpreter",
)
def test_the_floor_is_for_the_hook_the_adapter_overrides() -> None:
    """The adapter defines the hook itself, and the installed requests calls it. If the checks
    ever move to another hook, this goes red, so the floor gets re-derived rather than kept by
    habit."""
    from importlib.metadata import version

    import requests.adapters

    from messagefoundry.transports.strict_requests import StrictReplyAdapter

    assert _HOOK in vars(StrictReplyAdapter), "the send-time checks no longer override the hook"
    assert hasattr(requests.adapters.HTTPAdapter, _HOOK)
    assert Version(version("requests")) >= _HOOK_SINCE
