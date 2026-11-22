- The MLLP, raw-TCP and X12 listeners write a `reply_replaced` connection event for each reply in
  which characters the inbound's charset cannot encode were replaced before it was sent. The
  WARNING log line for a replacement is still written once per connection per process.
  [PHI.md](../docs/PHI.md) section 7 says what the event carries. (`BACKLOG #5799`)
