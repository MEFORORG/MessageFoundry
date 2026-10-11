- **A DR activation's trust-anchor preflights are now bounded, and its abort rows say more.** The
  settings and registry preflights a `POST /dr/activate` runs before it re-applies the graph now
  share one bound, `[dr].takeover_timeout_seconds`. They run under the coordinator's lock, so an
  anchor on a share that stopped answering used to hold every later activate and release too. The
  re-apply itself is still not bounded, so at least the outbound and FTPS poller CA reads it makes
  can still hold an activation. Every `dr_activation_aborted` row of an activation now records the
  `seed_segment` of the marker that attempt wrote and `vip_hook_ran`. A step 4 abort after the
  takeover hook says the VIP may have moved to this box. An error no abort path caught, such as one
  from the seed marker's digest provider, is now an audited abort of kind `error` that answers
  `503`, where it used to escape as a bare `500`. (`vault BACKLOG #3094`)
