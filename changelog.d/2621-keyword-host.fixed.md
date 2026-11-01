- **CONNECTIONS.md states what the generic ODBC keyword list covers.** It said no `odbc_params`
  keyword can give the driver another host, with no condition. It now says no listed keyword is one
  the engine knows to name a host, and the list covers keywords only and relies on at least the driver
  reading the `}}` escape in a braced password and reading `SERVER` as its target. Behaviour is
  unchanged. See [CONNECTIONS.md](../docs/CONNECTIONS.md). (`BACKLOG #2621`)
