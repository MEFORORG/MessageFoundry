- The MLLP, raw-TCP and X12 listeners send a `reply_replaced` connection event for each reply in
  which characters the inbound's charset cannot encode were replaced. The WARNING log line for a
  replacement is still written once per connection per process.
  [PHI.md](../docs/PHI.md) section 7 says what the event carries. (`BACKLOG #5799`)
