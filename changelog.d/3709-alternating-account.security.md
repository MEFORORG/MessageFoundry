- **An account whose directory probes alternate between answering and failing now pages.** The
  page for one account the directory keeps failing to answer for counted its probes running, and
  any answer ended the count, so an account served by one domain controller that answers and one
  that does not, behind at least DNS round-robin or a VIP, never paged. It now pages once
  `[auth].ad_reconcile_outage_passes` (K) of the account's last `2K - 1` probes fail, three of the
  last five at the default, in a row or not: a failing probe pages once the window holds K or more
  failures, the account is not already paged, and no outage page covers it. A lone flake pages
  only when the window already holds K - 1 earlier failures, an outage's or any other. Once
  paged, the account re-arms only when its window holds no failure. A value above the default
  does not only delay this page: some patterns that page at 3 never page at 4. The page and the
  WARNING now say "K of up to the last 2K - 1", since a window can hold fewer probes, and the
  `auth.ad_reconcile_unreached` row carries that bound as `window_up_to`. No new setting; the
  knob's meaning for the per-account page changes.
  CONFIGURATION.md, the `ad_reconcile_outage_passes` row, has the full rule (vault BACKLOG #3709).
