- **`audit-verify` prints a `FAIL` line when a store key or key-provider error stops the walk
  part way**, such as a Transit outage. It still exits 1, but the error reached the last-resort
  handler with no `FAIL` line, so a job on a first deployment would have seen a broken chain's
  code with nothing to read. The line names the error's class and its cause's class, never its
  text. A store cipher the settings cannot build, a key that is not base64 of 32 bytes among
  them, now exits 2, could not start, from at least `audit-verify`, `audit-anchor`,
  `admin-unlock`, `admin-set-notify-email`, `admin-reset-totp`, `provision-admin` and
  `rotate-key`; it exited 1 at the last-resort handler. `admin-unlock` and
  `admin-set-notify-email` also exit 2 on a key that does not resolve. The admin commands' shared
  host gate exits 2, not 1, for settings it cannot load and for an absent store. A store-open
  error no longer prints the text of a row SQLite could not decode. With a matched
  `--expected-anchor`, the exit-5 warning scopes a rewrite as keyless to before the anchor was
  taken. The exit table is in the *Tamper-evidence* paragraph of
  [SECURITY.md](../docs/SECURITY.md).
