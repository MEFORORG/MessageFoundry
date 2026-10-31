- **The generic ODBC dialect sends its checked values without braces, and refuses the `SSLmode`
  spellings psqlODBC would misread.** Measured against real drivers, psqlODBC did not honour a
  braced `SSLmode`: `SSLmode={verify-full}` and `SSLmode={require}` connected with no TLS at all.
  It also kept the braces as part of `UID` and `DATABASE`, and psqlODBC and MySQL Connector/ODBC
  both refused a braced port. `database`, `username` and every `odbc_params` value are now sent
  plain; the `odbc_driver` name stays braced. Those values, and `server`, refuse at least `;`,
  `{`, `}`, `=` and both quote characters, and an empty, blank or padded value, `None` and a
  boolean are refused rather than sent as text. For every driver but MySQL Connector/ODBC, an
  `SSLmode` value must be one of libpq's six modes in lower case, since psqlODBC's source reads
  `Require` or `True` as `disable`. The password is still always braced, with the `}}` escape,
  when `odbc_driver` names psqlODBC (the bare `PostgreSQL` included) or MySQL, both measured to
  read that escape, or `ODBC Driver <n> for SQL Server`; psqlODBC URL-decodes an unbraced
  password. For any other driver it is sent plain when it can be and refused otherwise. The rules
  are in [CONNECTIONS.md, *Values on the generic dialect*](../docs/CONNECTIONS.md#values-on-the-generic-dialect).
  (`BACKLOG #2705`)
- **A generic ODBC connection's login is bounded by `connect_timeout`.** The setting reached the
  driver as pyodbc's `timeout=` on the SQL Server preset only. It now does on the generic dialect
  too, with the same 15 s default; measured, it bounded a psqlODBC and a MySQL connect to an
  unreachable host at about 5 s with `timeout=5`, against about 21 s without it.
  (`BACKLOG #2705`)
