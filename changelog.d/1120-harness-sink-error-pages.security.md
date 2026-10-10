- **The harness HTTP sinks answer Python's own error pages in plain text, not HTML.** Python's
  HTTP server writes some answers before the sink's code runs. At least these: a `400` for a
  malformed request line, `414`, `431`, `501` and `505`. It writes them through `send_error`,
  which defaults to an HTML page. The sink now sends them as `text/plain; charset=utf-8`. The
  body is the status and Python's explanation. It leaves out the reason phrase, which can echo
  the request line. The status line still carries that phrase, as Python writes it. The
  baseline headers on those answers are unchanged. (`BACKLOG #1120`)
