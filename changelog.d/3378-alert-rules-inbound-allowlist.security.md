- **`GET /alerts/rules` shows a channel-scoped caller only rules on its in-scope inbounds.** The
  filter used to test only whether each name was in the scope. It never asked which side of the
  graph a name was on. So a scope naming an outbound read that outbound's rules, while the flag
  route refuses every outbound to such a caller. On a first deployment that would have shown
  them. The route now shows such a caller a rule only when each name it carries is in its scope
  and in the config's inbound names, and is not also an outbound the runner knows, a draining one
  included. It never shows it a `restart_outbound` rule, or a rule whose event type only an
  outbound raises, such as `message_stall`, a `"*"` rule included, nor a `"*"` rule of a type
  both sides raise, or of `any`. An event type or action with no recorded side is withheld too. With no graph loaded it shows it no rule that names a
  connection. The alert-instance routes are unchanged. [SECURITY.md](../docs/SECURITY.md), in
  the `GET /alerts/rules` paragraph, says what such a caller reads and who decided it.
  (`BACKLOG #3378`)
