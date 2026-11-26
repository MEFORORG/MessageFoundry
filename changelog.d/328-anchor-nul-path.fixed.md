- **Correction to the 0.4.0 entry for `[integrity].audit_anchor_file`.** That entry says a missing,
  unreadable or malformed anchor never blocks startup. The read does not catch every error the
  reader raises: at least a path carrying a NUL character raises, and `serve` does not start. The
  `audit_anchor_file` row in [CONFIGURATION.md](../docs/CONFIGURATION.md) says so. (`BACKLOG #328`)
