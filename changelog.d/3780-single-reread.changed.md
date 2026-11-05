- **A directory account's TOTP or recovery-code attempt re-reads its session, account and lock once
  after the directory lookup, not twice.** `verify_mfa` no longer re-reads right after the lookup;
  the re-read inside the account's queue, which already ran before any code is checked, is now that
  read. It also rejoins the queue under the account's new name when a directory rename landed after
  the queue was keyed, which the dropped read used to cover for the lookup. (`BACKLOG #3780`)
