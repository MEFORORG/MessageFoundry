- **A directory account's TOTP or recovery-code attempt reads its session, account and lock once
  between the directory lookup and the code check, not twice.** `verify_mfa` no longer re-reads
  right after the lookup. The re-read inside the account's queue, which already ran before any code
  is checked, is now that read. The re-reads after the code check are unchanged. The dropped read
  also supplied the queue's key, so the in-queue read now rejoins the queue once under the
  account's new name when a directory rename landed after the queue was keyed. (`BACKLOG #3780`)
