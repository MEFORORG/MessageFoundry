- **The SQL Server cluster heartbeat, config-version refresh and lease release run under the
  renew clamp.** `[cluster].lease_renew_timeout_seconds` now bounds their wait for a pooled
  connection and their statement, as it already bounded the lease claim, so a slow statement
  among them cannot delay the next renew by up to `[store].command_timeout`. Each can still take
  up to about twice the clamp, as the claim can. Whether anything bounds the COMMIT after the
  statement is not known: by a reading of pyodbc's documentation the statement timeout does not,
  and that is not a measurement. Start-up registration still runs under `[store].command_timeout`.
  (vault `BACKLOG #5064`)
