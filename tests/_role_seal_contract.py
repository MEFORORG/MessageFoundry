# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend contract for sealed role definitions and the sealed AD group-to-role map
(BACKLOG #2592).

Deliberately **extra-free**, as ``tests/_user_seal_contract.py`` is: it imports nothing optional,
so the live Postgres and SQL Server suites import it inside their test functions and run the same
assertions on legs that install only their own driver extra.

The caller passes a store opened with a store key, and ``raw``: a way to run one SQL statement
against the same database without going through the store's helpers, written with ``?``
placeholders. Every refusal below has a control beside it: the same role or map grants before the
change, or the same change made through the store or the service takes effect.
"""

from __future__ import annotations

import json
from typing import Any

from messagefoundry.auth.permissions import Permission, Role
from messagefoundry.store.row_seal import SEAL_PREFIX
from messagefoundry.store.store import RoleRow, ad_role_map_seal_ok, role_seal_ok
from tests._session_seal_contract import RawSql
from tests._user_seal_contract import _Harness

#: Each sealed ``roles`` column, and a value that differs from what the service writes.
_ROLE_SEALED_CHANGES: tuple[tuple[str, Any], ...] = (
    ("display_name", "Someone Else's Role"),
    ("description", "changed outside the store"),
    ("builtin", True),
    ("permissions", json.dumps(["messages:replay", "audit:read"])),
)

#: The AD group every map arm below maps; stored lower-cased, as the store keeps group names.
_GROUP = "cn=contract-ops,dc=example,dc=test"
_OTHER_GROUP = "cn=contract-other,dc=example,dc=test"


async def _role(h: _Harness, name: str, permissions: list[str]) -> str:
    created = await h.service.create_custom_role(
        display_name=name, description=None, permissions=permissions, actor="contract"
    )
    return created.id


async def _role_row(store: Any, role_id: str) -> RoleRow:
    found = await store.get_role(role_id)
    assert found is not None, role_id
    return RoleRow.from_mapping(found)


async def _listed_permissions(h: _Harness, role_id: str) -> frozenset[Permission]:
    for listed in await h.service.list_custom_roles():
        if listed.id == role_id:
            return listed.permissions
    raise AssertionError(f"{role_id} is not listed")


async def assert_role_seal_contract(store: Any, raw: RawSql) -> None:
    """Drive the sealed role definition and the sealed AD role map through their contract."""
    sealer = store.row_sealer()
    assert sealer is not None, "the contract needs a store opened with a store key"
    h = _Harness(store, raw)
    await h.service.initialize()

    # --- a role the service wrote carries a seal and grants what it says -----------------------
    replay = await _role(h, "contract-replay", ["messages:replay"])
    assert (await _role_row(store, replay)).seal.startswith(SEAL_PREFIX)
    assert role_seal_ok(sealer, await _role_row(store, replay))
    holder = await h.account("role-holder", roles=(Role.VIEWER.value, replay))
    token = await h.token(holder)
    before = await h.service.identity_for_token(token)
    assert before is not None and before.has(Permission.MESSAGES_REPLAY)
    assert not before.has(Permission.AUDIT_READ)
    assert h.alerts == []  # control: a sealed role raises nothing
    # The built-in rows are sealed too, by the role seed; they resolve from code either way.
    assert role_seal_ok(sealer, await _role_row(store, Role.ADMINISTRATOR.value))

    # --- a permission set widened outside the store grants nothing, and is reported ------------
    await raw(
        "UPDATE roles SET permissions=? WHERE id=?",
        (json.dumps(["messages:replay", "audit:read"]), replay),
    )
    widened = await h.service.identity_for_token(token)
    # The account still resolves on its other roles; the failing role adds nothing at all.
    assert widened is not None and Role.VIEWER in widened.roles
    assert not widened.has(Permission.AUDIT_READ)
    assert not widened.has(Permission.MESSAGES_REPLAY)
    assert len(h.alerts) == 1 and replay in h.alerts[0]
    assert await h.seal_failures() == 1
    # An administrator reading the role sees what it grants, which is nothing.
    assert await _listed_permissions(h, replay) == frozenset()
    # Repair, and the control: the same widening through the service takes effect, sealed.
    await h.service.update_custom_role(
        replay,
        display_name="contract-replay",
        description=None,
        permissions=["messages:replay", "audit:read"],
        actor="contract",
    )
    assert role_seal_ok(sealer, await _role_row(store, replay))
    repaired = await h.service.identity_for_token(await h.token(holder))
    assert repaired is not None and repaired.has(Permission.AUDIT_READ)
    assert await _listed_permissions(h, replay) == frozenset(
        {Permission.MESSAGES_REPLAY, Permission.AUDIT_READ}
    )

    # --- every sealed column changed outside the store makes the role grant nothing -----------
    for column, value in _ROLE_SEALED_CHANGES:
        changed = await _role(h, f"contract-{column}", ["messages:replay"])
        assert await h.service._load_role(changed) is not None, column  # control
        await raw(f"UPDATE roles SET {column}=? WHERE id=?", (value, changed))
        assert await h.service._load_role(changed) is None, column

    # --- a role row inserted outside the store grants nothing; one the service made does ------
    planted = "custom:contract-planted"
    await raw(
        "INSERT INTO roles (id, display_name, description, builtin, permissions) VALUES (?,?,?,?,?)",
        (planted, "Planted", None, False, json.dumps(["audit:read"])),
    )
    planted_holder = await h.account("planted", roles=(Role.VIEWER.value, planted))
    planted_identity = await h.service.identity_for_token(await h.token(planted_holder))
    assert planted_identity is not None and not planted_identity.has(Permission.AUDIT_READ)
    audit_role = await _role(h, "contract-audit", ["audit:read"])
    granted_holder = await h.account("granted", roles=(Role.VIEWER.value, audit_role))
    granted_identity = await h.service.identity_for_token(await h.token(granted_holder))
    assert granted_identity is not None and granted_identity.has(Permission.AUDIT_READ)

    # --- a seal copied from another role does not carry over ----------------------------------
    donor = await _role_row(store, audit_role)
    taker = await _role(h, "contract-taker", ["audit:read"])
    await raw("UPDATE roles SET seal=? WHERE id=?", (donor.seal, taker))
    assert await h.service._load_role(taker) is None

    # --- a role with no seal is counted at open and repaired by saving it again ----------------
    blank = await _role(h, "contract-blank", ["messages:replay"])
    unsealed_before = await store.count_unsealed_role_records()
    await raw("UPDATE roles SET seal='' WHERE id=?", (blank,))
    assert await store.count_unsealed_role_records() == unsealed_before + 1
    assert await h.service._load_role(blank) is None
    await h.service.update_custom_role(
        blank,
        display_name="contract-blank",
        description=None,
        permissions=["messages:replay"],
        actor="contract",
    )
    assert await h.service._load_role(blank) is not None
    assert await store.count_unsealed_role_records() == unsealed_before

    # --- the AD group-to-role map: the store's own write seals it and it grants ---------------
    await store.set_ad_group_role_map([(_GROUP.upper(), Role.VIEWER.value)])
    current = await store.get_ad_group_role_map()
    assert current.seal.startswith(SEAL_PREFIX) and ad_role_map_seal_ok(sealer, current)
    assert await h.service._ad_roles_for_groups([_GROUP]) == {Role.VIEWER.value}
    alerts_before_map = len(h.alerts)

    # --- a pair inserted outside the store makes the whole map grant nothing -----------------
    await raw(
        "INSERT INTO ad_group_role_map (ad_group, role_id) VALUES (?,?)",
        (_GROUP, Role.ADMINISTRATOR.value),
    )
    assert await h.service._ad_roles_for_groups([_GROUP]) == set()
    assert len(h.alerts) == alerts_before_map + 1
    # An administrator reading the map sees none of it, so a re-save copies nothing in.
    assert await h.service.list_ad_group_role_map() == []
    # Repair, and the control: the same pair through the store takes effect, sealed.
    await store.set_ad_group_role_map(
        [(_GROUP, Role.VIEWER.value), (_GROUP, Role.ADMINISTRATOR.value)]
    )
    assert await h.service._ad_roles_for_groups([_GROUP]) == {
        Role.VIEWER.value,
        Role.ADMINISTRATOR.value,
    }

    # --- a pair re-pointed, or the seal deleted, outside the store also grants nothing -------
    await store.set_ad_group_role_map([(_GROUP, Role.VIEWER.value)])
    await raw(
        "UPDATE ad_group_role_map SET role_id=? WHERE ad_group=?",
        (Role.ADMINISTRATOR.value, _GROUP),
    )
    assert await h.service._ad_roles_for_groups([_GROUP]) == set()
    await store.set_ad_group_role_map([(_GROUP, Role.VIEWER.value)])
    assert await h.service._ad_roles_for_groups([_GROUP]) == {Role.VIEWER.value}  # control
    await raw("DELETE FROM authority_set_seal WHERE name=?", ("ad_group_role_map",))
    assert await h.service._ad_roles_for_groups([_GROUP]) == set()
    assert await store.count_unsealed_role_records() == unsealed_before + 1

    # --- a role seal does not verify as the map's -------------------------------------------
    await store.set_ad_group_role_map([(_GROUP, Role.VIEWER.value)])
    await raw(
        "UPDATE authority_set_seal SET seal=? WHERE name=?",
        ((await _role_row(store, audit_role)).seal, "ad_group_role_map"),
    )
    assert await h.service._ad_roles_for_groups([_GROUP]) == set()

    # --- a role delete keeps a sealed map sealed, and does not re-seal a failing one -----------
    mapped = await _role(h, "contract-mapped", ["messages:replay"])
    await store.set_ad_group_role_map(
        [(_GROUP, Role.VIEWER.value), (_OTHER_GROUP, mapped), (_OTHER_GROUP, Role.OPERATOR.value)]
    )
    await h.service.delete_custom_role(mapped, actor="contract")
    kept = await store.get_ad_group_role_map()
    assert ad_role_map_seal_ok(sealer, kept)  # control: re-sealed without the deleted role
    assert kept.pairs == ((_GROUP, Role.VIEWER.value), (_OTHER_GROUP, Role.OPERATOR.value))
    assert await h.service._ad_roles_for_groups([_OTHER_GROUP]) == {Role.OPERATOR.value}
    doomed = await _role(h, "contract-doomed", ["messages:replay"])
    await store.set_ad_group_role_map([(_GROUP, Role.VIEWER.value), (_OTHER_GROUP, doomed)])
    await raw(
        "INSERT INTO ad_group_role_map (ad_group, role_id) VALUES (?,?)",
        (_OTHER_GROUP, Role.ADMINISTRATOR.value),
    )
    await h.service.delete_custom_role(doomed, actor="contract")
    left = await store.get_ad_group_role_map()
    assert doomed not in {r for _, r in left.pairs}  # the role's own pairs are gone
    assert not ad_role_map_seal_ok(sealer, left)  # and the planted pair was not sealed in
    assert await h.service._ad_roles_for_groups([_OTHER_GROUP]) == set()
