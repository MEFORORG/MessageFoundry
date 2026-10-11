- **A DR activation no longer waits for good on a trust anchor that does not answer, and its
  abort rows say more.** The trust-anchor preflights a `POST /dr/activate` runs before it
  re-applies the graph are now bounded by `[dr].takeover_timeout_seconds`. They run under the
  coordinator's lock, so an anchor on a share that stopped answering used to hold every later
  activate and release too. A step 4 abort's `dr_activation_aborted` row now records
  `vip_hook_ran` and the `seed_segment` of the marker that attempt wrote, and its reason says the
  VIP may have moved to this box when the takeover hook ran. An error no abort path caught, such as
  a `dr_seed` marker the store refuses, is now an audited abort of kind `state`, where it used to
  escape as a bare 500. The re-apply itself is still not bounded. (`vault BACKLOG #3094`)
