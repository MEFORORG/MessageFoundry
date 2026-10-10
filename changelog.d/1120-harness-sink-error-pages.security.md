- **The harness HTTP sinks answer Python's own error pages in plain text, not HTML.** Python's
  HTTP server writes some answers before the sink's code runs, such as its `400` for a malformed
  request line, `414` for an over-long one, `431`, `501` for an unknown method and `505`. It
  writes each through `send_error`, which defaults to an HTML page. The sink now sets that page's
  content type to `text/plain; charset=utf-8` and its body to the status, reason and explanation
  on two lines, so a browser has nothing to render. The baseline headers on those answers are
  unchanged. (`BACKLOG #1120`)
