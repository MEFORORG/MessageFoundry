- **CONNECTIONS.md states what the generic ODBC keyword list covers.** It said no `odbc_params`
  keyword can give the driver another host, with no condition. It now says the list covers
  keywords only, and a braced password relies on the driver reading the `}}` escape. Behaviour is
  unchanged. See [CONNECTIONS.md](../docs/CONNECTIONS.md). (`BACKLOG #2621`)
