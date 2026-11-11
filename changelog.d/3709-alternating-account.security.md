- **An account whose directory probes alternate between answering and failing now pages.** The
  page for one account the directory keeps failing to answer for counted its probes running, and
  any answer ended the count, so an account served by one domain controller that answers and one
  that does not, behind DNS round-robin, a VIP or a referral, never paged. It now pages once
  `[auth].ad_reconcile_outage_passes` (K) of the account's last `2K - 1` probes fail, three of the
  last five at the default, in a row or not, on the failing probe that makes it K. A lone flake
  does not page, except just after a lasting outage, whose failures stay in the window. Once
  paged, the account re-arms only when its window holds no failure. A value above the default
  does not only delay this page: some patterns that page at 3 never page at 4. The page,
  the WARNING and the `auth.ad_reconcile_unreached` row now say "K of the last 2K - 1", and the row
  carries the window size. No new setting; the knob's meaning for the per-account page changes.
  CONFIGURATION.md, the `ad_reconcile_outage_passes` row, has the full rule (vault BACKLOG #3709).
