# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend contract for ``reencrypt_to_active``'s side result, ``reseal_outcome`` (vault
BACKLOG #5635).

Extra-free, as ``tests/_role_seal_contract.py`` is, so the live Postgres and SQL Server suites
import it inside their test functions. The caller passes a store opened with a store key, and
``raw``: one SQL statement run outside the store's helpers, written with ``?`` placeholders.

A seal naming a key the run does not hold is planted on a user, a role and a directory map, so
each re-seal pass leaves it as it is and the outcome must count it ``unheld``. A malformed seal on
another role is the control: the pass refuses it too, and it must count ``refused`` instead.
"""

from __future__ import annotations

from typing import Any

from messagefoundry.auth.permissions import Role
from messagefoundry.store.row_seal import SEAL_PREFIX, ResealOutcome
from messagefoundry.store.store import AD_ROLE_MAP
from tests._session_seal_contract import RawSql
from tests._user_seal_contract import _Harness

#: A well-formed seal that names a key no store here holds, as a row a retired key sealed reads
#: to a run that was not given that key.
UNHELD_SEAL = f"{SEAL_PREFIX}0123456789abcdef:{'0' * 64}"
#: A seal no key could have written: no key id and MAC separator.
MALFORMED_SEAL = f"{SEAL_PREFIX}not-a-seal"

_GROUP = "cn=reseal-outcome,dc=example,dc=test"


async def assert_reseal_outcome_contract(store: Any, raw: RawSql) -> None:
    """Drive ``reseal_outcome`` through a run that leaves nothing and a run that leaves both kinds."""
    assert store.row_sealer() is not None, "the contract needs a store opened with a store key"
    h = _Harness(store, raw)
    await h.service.initialize()
    assert store.reseal_outcome() == ResealOutcome()  # before any run

    unheld_role = (
        await h.service.create_custom_role(
            display_name="unheld", description=None, permissions=["messages:replay"], actor="t"
        )
    ).id
    forged_role = (
        await h.service.create_custom_role(
            display_name="forged", description=None, permissions=["messages:replay"], actor="t"
        )
    ).id
    user = await h.account("unheld")
    await store.set_ad_group_role_map([(_GROUP, Role.VIEWER.value)])

    # Control: every row the store wrote is under the active key, so a run leaves nothing.
    await store.reencrypt_to_active()
    assert store.reseal_outcome() == ResealOutcome()

    await raw("UPDATE roles SET seal=? WHERE id=?", (UNHELD_SEAL, unheld_role))
    await raw("UPDATE users SET authz_seal=? WHERE id=?", (UNHELD_SEAL, user))
    await raw("UPDATE authority_set_seal SET seal=? WHERE name=?", (UNHELD_SEAL, AD_ROLE_MAP))
    await raw("UPDATE roles SET seal=? WHERE id=?", (MALFORMED_SEAL, forged_role))

    await store.reencrypt_to_active()
    assert store.reseal_outcome() == ResealOutcome(unheld=3, refused=1)
