- **The generic ODBC dialect sends its checked values without braces, so psqlODBC honours
  `SSLmode`.** Measured against real drivers, psqlODBC did not honour a braced `SSLmode`:
  `SSLmode={verify-full}` and `SSLmode={require}` connected with no TLS at all. It also kept the
  braces as part of `UID` and `DATABASE`, and psqlODBC and MySQL Connector/ODBC both refused a
  braced port. `database`, `username` and every `odbc_params` value are now sent plain; the
  `odbc_driver` name stays braced. Those values refuse at least `;`, `{`, `}` and `=`, an empty or
  blank value and a leading or trailing space, when the connection is built, and an
  `odbc_params` value or `server` of `None` is refused rather than sent as the text `None`. The
  password is still always braced, with the `}}` escape, when `odbc_driver` names psqlODBC or
  MySQL, both measured to read that escape, or `ODBC Driver <n> for SQL Server`, whose escape the
  SQL Server preset already relies on: psqlODBC URL-decodes an unbraced password. For any other
  driver it is sent plain when it holds none of `;`, `{` or `}` and no leading or trailing space,
  and refused otherwise; the legacy `SQL Server` name, often a FreeTDS alias on Linux, is one such
  driver. See [CONNECTIONS.md](../docs/CONNECTIONS.md). (`BACKLOG #2705`)
- **A generic ODBC connection's login is bounded by `connect_timeout`.** The setting reached the
  driver as pyodbc's `timeout=` on the SQL Server preset only. It now does on the generic dialect
  too, with the same 15 s default; measured, it bounded a psqlODBC and a MySQL connect to an
  unreachable host at about 5 s with `timeout=5`, against about 21 s without it.
  (`BACKLOG #2705`)
