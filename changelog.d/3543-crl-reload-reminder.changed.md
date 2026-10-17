- **A refused CRL reload is reminded about while the refusal stands.** The `crl_reload_refused`
  alert was raised once per version of the file, so a page that was throttled, muted or resolved
  by hand was never sent again. The engine now raises it again every five to six minutes while
  the refusal stands, as `intake_paused` reminds, with the same fields, and stops once the alert
  resolves. A reminder is sent even while the engine cannot read the file. The notifier's
  cooldown still spaces the pages. See [CONFIGURATION.md](../docs/CONFIGURATION.md), under "CRL
  files". (`vault BACKLOG #3543`)
