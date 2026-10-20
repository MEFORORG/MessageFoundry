- **A protocol header floor self-test that fails with an exception now says where.** When a drive
  raised, the refusal named the exception's type and only the file and line where it was raised. It
  now names the Python and the module and line of each frame the exception passed through,
  outermost first, and still never the exception's message. A recursion's repeated frame is listed
  once with its count. So a fault in uvicorn, in asyncio or in the self-test itself reads apart.
  That matters for one case in particular: the self-test runs on a private event loop built on
  CPython internals. A later Python that moves `_selector` or `_process_events` still stops the
  start with exit code 2, and the refusal now names that Python, the `asyncio` frame that raised,
  and the Python as a possible cause. A Python that moved only `_write_to_self`, which no drive
  reaches today, would not show here. (`BACKLOG #3308`)
