- **The firewall guide gains four outbound rows.**
  [ANTIVIRUS-FIREWALL.md](../docs/ANTIVIRUS-FIREWALL.md) now has rows for `Email()`, `Direct()`, a
  forward proxy and the syslog forwarder, and its REMOTEFILE row names `[egress].allowed_remote`.
  Its opening says at least, points at the table's gate column, and links to
  [CONFIGURATION.md](../docs/CONFIGURATION.md#egress). (vault `BACKLOG #2621`)
- **The text on a generic-ODBC hop's credential now matches the code.** `odbc_params` takes a fixed
  keyword list, and the only credential that list can carry is a client certificate. What
  `messagefoundry check` and `GET /security/posture` report does not change.
  (vault `BACKLOG #2621`)
