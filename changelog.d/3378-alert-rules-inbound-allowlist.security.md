- **`GET /alerts/rules` no longer shows a channel-scoped caller the rules of an outbound its scope
  lists.** The filter tested only whether each name was in the scope, never which side of the
  graph it was on, so a scope naming an outbound read that outbound's rules, while the flag route
  refuses every outbound to such a caller. On a first deployment that would have shown them. The
  route now shows such a caller a rule only when each name it carries is an in-scope inbound of
  the loaded graph, and never a `restart_outbound` rule. With no graph loaded it shows such a
  caller no rule that names a connection. The alert-instance routes are unchanged.
  [SECURITY.md](../docs/SECURITY.md), in the `GET /alerts/rules` paragraph, says what such a
  caller reads and who decided it. (`BACKLOG #3378`)
