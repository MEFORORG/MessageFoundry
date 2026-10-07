- **`audit-verify` exits 6, not 1, when a store key or key-provider error stops the walk part
  way**, such as a Transit outage. It printed no `FAIL` line, so a job reading only the code took
  it for a broken chain. It now prints a `NOT CHECKED` line naming the error's class and never its
  text. A store key that is not base64 of 32 bytes exits 2, could not start, from `audit-verify`,
  `audit-anchor`, `admin-unlock` and `admin-set-notify-email`, and those two admin commands now
  exit 2 on a key that does not resolve too. The admin commands' shared host gate exits 2, not 1,
  for settings it cannot load and for an absent store. With a matched `--expected-anchor`, the
  exit-5 warning no longer names a rewrite as keyless as a possible cause. The exit table is in
  the *Tamper-evidence* paragraph of [SECURITY.md](../docs/SECURITY.md).
