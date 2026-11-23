- **An asyncpg error's message is no longer named as a SQLSTATE by the DATABASE connector or the
  traceback line.** An asyncpg error keeps its message in `args[0]`. When that message had five
  SQLSTATE characters, such as an identifier, and the error's `sqlstate` attribute did not name
  that state, the connector named the message as the state. That happened on at least its connect
  and send errors, their `code`, the stored `last_error` and its log lines. They now name no
  state: for example the send error reads `[SQLSTATE withheld]` with the code `db`, and a log
  line reads `<type> [message withheld]`. The traceback line did the same when the
  attribute was absent or None, and now prints `[driver message withheld]`. The error is still
  classified by that shape, as before, so its disposition is unchanged. The store's own SQLSTATE
  readers are unchanged. (vault `BACKLOG #1661`)
