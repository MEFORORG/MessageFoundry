- **A self-service revoke of one session that ends nothing is now audited.** `DELETE
  /me/sessions/{session_id}` and the console's revoke button answer as before when the id names no
  session or another account's. Each such miss now writes one `auth.session_revoke_missed` row. It
  names the actor, the caller's address and the first 12 characters of the id, and nothing else, so
  the row does not tell an unknown id from another account's any more than the answer does. Before,
  the miss left no row of its own on either plane. The `auth.session_revoked` row now carries the
  caller's address too. See [SECURITY.md](../docs/SECURITY.md). (`vault BACKLOG #3260`)
