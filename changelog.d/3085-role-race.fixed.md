- **Two directory reconcilers that apply one role change report it once.** Each pass read the
  account's roles, then wrote its planned roles unconditionally, so two that both read the old
  roles both counted a change, and both alerted and told the user; and a write landing between
  that read and the pass's write was overwritten. The role write is now a compare-and-set on the roles the pass read, on all
  three stores (`set_user_roles_if_held`): only the first of two writes, and a write that finds
  the roles moved writes nothing. A pass that wrote no role and ended no session is quiet, and
  still writes its `auth.ad_session_revoked` row with `sessions: 0`; the next pass plans from what
  is stored. The second of two reconcilers still reports when it ends a session the first had not
  yet ended, and a sign-in that wrote between the pass's plan and its apply is still
  overwritten. See [SECURITY.md](../docs/SECURITY.md). (`vault BACKLOG #3085`)
