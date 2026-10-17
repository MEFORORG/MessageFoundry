- **`[inbound].ack_after = "delivered"` is refused when the settings load.** That ACK timing is
  planned, not built. A connection's own `ack_after = "delivered"` was already refused at wiring,
  but the service-wide default was refused only as each listener started. So
  `messagefoundry check` said OK, and `serve` came up with every listener that inherited it
  isolated. Now `serve` will not start on it, and the `check` settings legs fail. (`BACKLOG #3063`)
- **The build check gates the same listeners a reload binds, from one copy of the skips.** Start,
  reload, the reload's CA check and the predicate the build check runs the inbound exposure gates
  under now read one helper. An operator-started `auto_start = false` listener with a schedule,
  reloaded after its window closes, is no longer gated: the reload leaves it unbound, and the
  scheduler never starts it. An `auto_start` listener outside its window is still gated, because
  the scheduler binds it when the window opens. The build-check refusal no longer says a later
  start meets the same refusal. It says what each setting does: an operator start of an
  `auto_start = false` listener meets the refusal, and a `deployed = false` listener cannot be
  started, so the reload that deploys it, or its first start, does. A dry run and a flag toggle
  read the listening set outside the reload lock; the code says why that window is accepted.
  (`BACKLOG #3063`)
