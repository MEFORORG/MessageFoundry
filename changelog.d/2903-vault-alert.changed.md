- **An over-granted or unreadable Vault token now raises a `vault_privilege_warning` alert at
  start.** The Vault privilege preflight already logged and audited each finding. It now also fires
  the alert through the configured notifier, keyed on `vault:store` or `vault:secrets`, before any
  refusal, so a refused start still pages. An alert rule can match the new event type, and a later
  start that reads that hop's token clean resolves the open alert. ADR 0216 Amendment A says what
  the payload holds. (`BACKLOG #2903`)
