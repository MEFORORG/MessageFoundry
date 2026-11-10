- `check-privileges` quotes each Vault policy name in its `token policies [...]` line, so one
  server-chosen name holding `, ` or `]` cannot read as several names in that list; it prints a
  control character in the store principal or database name escaped once, not twice (the
  summary's `repr` escape was escaped again by the terminal rule); and `messagefoundry-toolkit
  adr-analyze` escapes the controls in its stderr `error:` line through the shared terminal
  escape, printing a non-ASCII letter as itself. The shared terminal escape's
  `keep_printable_unicode` mode now prints a non-ASCII space separator, such as a no-break or
  ideographic space, as a visible escape rather than a blank, on the console and in a Markdown
  report cell (BACKLOG #2891).
