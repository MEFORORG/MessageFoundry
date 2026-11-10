- **The directory session reconciler now pages for one account the directory keeps failing to
  answer for.** A probe that fails with an LDAP error is fail-open: it neither strikes nor revokes.
  Where the directory answered for the other accounts, nothing bounded that before, so such an
  account's sessions could run to the absolute session cap with nobody told. Once
  `[auth].ad_reconcile_outage_passes` of that account's probes running fail this way, the pass
  raises one `ad_reconcile_aborted` alert with reason `account_unreachable`, under the source
  `directory-reconciler-unreached:<username>`, and writes an `auth.ad_reconcile_unreached` audit
  row. On a rolled-up pass, those entering page as one alert under the bare
  `directory-reconciler-unreached` source. A whole-directory outage keeps its own alert.
  CONFIGURATION.md, the `ad_reconcile_outage_passes` row, has the full rule (vault BACKLOG #3100).
