- **An asyncpg error's message is no longer printed as a SQLSTATE.** An asyncpg error keeps its
  message in `args[0]`. When its `sqlstate` attribute was absent, None or not a SQLSTATE, a
  message of five SQLSTATE characters, such as an identifier, was named as the state. That
  happened in the DATABASE connector's connect and send errors, their `code`, the stored
  `last_error`, its log lines and the traceback line. Those now read `[SQLSTATE withheld]` or
  `<type> [message withheld]`. The error is still classified and dead-lettered as before. The
  store's own SQLSTATE readers are unchanged. (vault `BACKLOG #1661`)
