- **A DR activation's trust-anchor preflights are now bounded, and its abort rows say more.** The
  settings and registry preflights a `POST /dr/activate` runs before it re-applies the graph now
  share one bound, `[dr].takeover_timeout_seconds`. They run under the coordinator's lock, so an
  anchor on a share that stopped answering used to hold every later activate and release too. A
  timeout cancels the preflight, but a read blocked on the share may leave its thread stuck, and
  retries against a dead share can strand more of them. The re-apply itself is still not bounded, so
  at least the outbound and FTPS poller CA reads it makes can still hold an activation. Every
  `dr_activation_aborted` row of an activation now records the `seed_segment` of the marker that
  attempt wrote, and `vip_hook_ran`. The `[dr].takeover_hook` row of `docs/CONFIGURATION.md` says
  what each hook outcome records. An error no abort path caught is now an audited abort of kind
  `error` that answers `503`. One example is an error from the seed marker's digest provider. It
  used to escape as a bare `500`. (`vault BACKLOG #3094`)
