# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A synthetic Vault address and token for the tests that drive a Vault provider through a fake.

Since BACKLOG #2851 each provider refuses when its ``MEFOR_*_VAULT_ADDR`` or ``MEFOR_*_VAULT_TOKEN``
is unset, rather than let hvac read ``VAULT_ADDR``, ``VAULT_TOKEN`` or ``~/.vault-token``. A test
that replaces ``_build_client`` with a fake still reaches that refusal first, so it names both.

Synthetic values only: the host is under the reserved ``.test`` name and the token is made up.
"""

from __future__ import annotations

import pytest

SYNTHETIC_VAULT_ADDR = "https://vault.synthetic.test:8200"
SYNTHETIC_VAULT_TOKEN = "hvs.synthetic-engine-token"  # nosec B105 - a made-up test value

#: The two hops, by the prefix of their variables.
STORE = "MEFOR_STORE"
SECRETS = "MEFOR_SECRETS"


def supply_vault_hop(monkeypatch: pytest.MonkeyPatch, *hops: str) -> None:
    """Set ``<hop>_VAULT_ADDR`` and ``<hop>_VAULT_TOKEN`` for each hop in ``hops``."""
    for hop in hops:
        monkeypatch.setenv(f"{hop}_VAULT_ADDR", SYNTHETIC_VAULT_ADDR)
        monkeypatch.setenv(f"{hop}_VAULT_TOKEN", SYNTHETIC_VAULT_TOKEN)
