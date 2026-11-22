- When connection events are captured, the MLLP, raw-TCP and X12 listeners send a
  `reply_replaced` connection event when characters the inbound's charset cannot encode were
  replaced in a reply: the first at once, then at most one a minute per listener, carrying the
  count of replaced replies since the last one. The WARNING log line for a replacement is still
  written once per connection per process.
  [PHI.md](../docs/PHI.md) section 7 says what the event carries. (`BACKLOG #5799`)
