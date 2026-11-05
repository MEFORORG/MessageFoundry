- **Two directory reconcilers that apply one role change report it once.** Each read the account's
  roles, then wrote its planned roles unconditionally, so two that both read the old roles both
  counted a change, and both alerted and told the user. The role write is now a compare-and-set on
  the roles it writes, on all three stores (`set_user_roles_unless_held`): only the first writes and
  reports, and the second, ending no session, is quiet and still writes its
  `auth.ad_session_revoked` row with `sessions: 0`. The second still reports when it ends a session
  the first had not yet ended. The Administrator loss and grant alerts now judge the roles the
  write itself replaced. See [SECURITY.md](../docs/SECURITY.md). (`vault BACKLOG #3085`)
