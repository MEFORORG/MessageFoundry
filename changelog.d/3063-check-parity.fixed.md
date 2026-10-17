- **`messagefoundry check` names the settings file it graded when `serve` may read another.**
  Under `--project-root` with no `--service-config`, `check` reads the project root's
  `messagefoundry.toml` (or the config dir's), while `serve` with the same flags reads
  `./messagefoundry.toml` in its own working directory. Run from anywhere but that file's folder,
  each settings line now names the file it read and the difference; the verdict is unchanged.
  Without `--project-root`, a directory named `messagefoundry.toml` in the working directory,
  which stops `serve`, now fails the settings legs when the upward search reaches it, where it got
  an environment-only OK. When `[security].require_encryption_for_remote = false` admits a
  cleartext listener, the `build-check` OK line now says so and names the first one. The `check`
  help now says an explicit `--service-config` is read wherever it points. (`BACKLOG #3063`)
- **An operator start or restart that a listener's start gate refuses with a configuration error
  now answers 409 and is audited.** It answered 500 and wrote no `connection_control` row. The
  answer names only the listener; the refusal text goes to the server log. (`BACKLOG #3063`)
- **`messagefoundry connection upsert` and `remove` name `--service-config` in a cleartext-listener
  refusal**, and say the command reads `[security].require_encryption_for_remote = false` in place
  of `serve --allow-insecure-bind`, besides the per-connection attestation. `check` says the same.
  (`BACKLOG #3063`)
