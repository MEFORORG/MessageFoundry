- **A DR activation's trust-anchor preflights are now bounded, and its abort rows say more.** The
  settings and registry preflights a `POST /dr/activate` runs before it re-applies the graph now
  share one bound, `[dr].takeover_timeout_seconds`. They run under the coordinator's lock, so an
  anchor on a share that stopped answering used to hold every later activate and release too.
  While a timed-out preflight's read is still blocked, the next activation is refused and starts no
  thread. The re-apply itself is still not bounded, so at least the outbound and FTPS poller CA
  reads it makes can still hold an activation. Every `dr_activation_aborted` row of an activation
  now records the `seed_segment` of the marker that attempt wrote, and `vip_hook_ran`. That field
  says whether the takeover hook's process started. An abort after a hook that started says the VIP may
  have moved to this box. An error no abort path caught is now an audited abort of kind `error`
  that answers `503`. One example is an error from the seed marker's digest provider. It used to
  escape as a bare `500`. (`vault BACKLOG #3094`)
