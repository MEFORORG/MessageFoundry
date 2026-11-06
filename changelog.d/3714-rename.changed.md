- **`Engine.create`, `Engine.__init__` and `create_managed_app` take `settings_monitored_files`
  in place of `settings_crls`.** The rows passed there include the SQL Server store pin, a
  certificate, as well as the settings-level CRL files, so the old name said CRLs for a list that
  is not only CRLs. `serve` and `cert inventory` now build that list with one helper,
  `monitored_files_from_settings`, and the `cert inventory` help names the pin files too. The same
  rows reach the same expiry monitor. (`BACKLOG #3714` item 5)
