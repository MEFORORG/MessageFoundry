- `check-privileges` quotes each Vault policy name in its `token policies [...]` line, so one
  server-chosen name holding `, ` or `]` cannot read as several names or as a verdict of its own;
  it prints a control character in the store principal or database name escaped once, not twice
  (the summary's `repr` escape was escaped again by the terminal rule); and `messagefoundry-toolkit
  adr-analyze` writes its stderr `error:` line through the shared terminal escape (BACKLOG #2891).
