# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend store contract for the AD group maps' key widths (BACKLOG #3187).

The API takes a canonical group DN of up to 512 characters, a role id of up to 64 and a channel of
up to 256. Every store must hold all three at those widths, in both maps. SQL Server is the one
that sizes them: its ``ad_group`` column, and its composite primary keys, which must fit an index
key. ``tests/test_ad_group_dn_only.py`` runs this against SQLite; ``tests/test_postgres_store.py``
and ``tests/test_sqlserver_store.py`` run it against the server backends, which only the
live-server CI legs do. Synthetic DNs only.
"""

from __future__ import annotations

from typing import Any

#: An ASCII group DN already in canonical form, exactly the 512 characters the API allows.
AT_WIDTH = "cn=" + "a" * 477 + ",ou=groups,dc=example,dc=invalid"

#: A channel at the API's 256: a connection name, so one character is one UTF-16 unit.
CHANNEL_AT_WIDTH = "C" * 256


async def assert_group_map_keys_at_width_store(store: Any) -> None:
    """Both maps store and read back a DN at 512 beside a role id and a channel at their widths.
    One call, both tables, so the two composite keys are sized together."""
    assert len(AT_WIDTH) == 512
    # The PostgreSQL map has a foreign key to roles, and its suite's fixture empties roles.
    await store.upsert_role(role_id="operator", display_name="Operator", description=None)
    await store.set_ad_group_role_map([(AT_WIDTH, "operator")])
    assert await store.roles_for_ad_groups([AT_WIDTH]) == {"operator"}
    await store.set_ad_group_scope_map([(AT_WIDTH, CHANNEL_AT_WIDTH)])
    assert await store.channels_for_ad_groups([AT_WIDTH]) == {CHANNEL_AT_WIDTH}
    rows = [dict(r) for r in await store.list_ad_group_scope_map()]
    assert rows == [{"ad_group": AT_WIDTH, "channel": CHANNEL_AT_WIDTH}]
