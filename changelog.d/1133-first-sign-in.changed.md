- **The engine no longer says nobody can sign in when no Administrator exists.** A Windows sign-in
  (Kerberos), where configured, is not refused for want of an Administrator: on a new store it
  creates a directory account with no role. The start-up WARNING for a store with no enabled Administrator, logged when
  the security-notice gate is skipped, now begins `the engine is starting with the notice gate
  skipped:` instead of `the engine is starting with no way to sign in:`. Its detail, also used by
  the refusal at the shipped posture, now says no enabled account holds the role that manages users
  and roles. The `provision-admin --help` text
  now says nobody can manage a new install until it runs, not that an install has no way to sign
  in. This corrects an earlier release's start-without-an-Administrator note, which said nobody
  can sign in until `provision-admin` runs. (`vault BACKLOG #1133`)
