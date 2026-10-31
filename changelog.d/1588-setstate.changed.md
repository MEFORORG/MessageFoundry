- **`SetState` refuses a namespace or key that ends in a space, on every store backend.** SQL
  Server ignores trailing spaces when it compares keys, under every collation, so `k` and `k `
  would be one row there and two everywhere else. The error names the field and never its value. A
  Handler that sets such a key now fails at the `SetState(...)` call, so strip padding from a
  fixed-width field before keying on it. (`BACKLOG #1588`)
