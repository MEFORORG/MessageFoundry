- **`messagefoundry cert self-signed` now calls its pair a placeholder, not a dev-only
  certificate.** The engine serves the same kind of self-signed certificate on first run when no
  `[api].tls_cert_file` is set (ADR 0172), so "never front production PHI" no longer matched what
  the engine does. The command's help, its console note and the `note` field of its `--json`
  output now share one text: the pair has no chain of trust, so it is better than cleartext and
  worse than an operator-supplied chain, and it is a placeholder to replace. The VS Code
  walkthrough now gives the `messagefoundry.engineUrl` default as `https://127.0.0.1:8765`,
  matching the setting itself. (`vault BACKLOG #1276`)
