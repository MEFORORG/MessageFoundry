- **A refused CRL reload now says which signature finding held the file back.** The reload's
  signature check used to give one remedy, `bad_signature`, for a CRL proven badly signed and for
  one it could not confirm, so after a CA renewed its key it told you to fix a file that can be
  right. A proof keeps `bad_signature`: fix the file, which a start that finds the same proof
  refuses at any time, so that refusal no longer carries `start_refuses` or the "at least until"
  caveat for a file not yet in effect. A CRL that names no key of the CA its issuer matches, and
  that CA's key does not verify, now reads `unproven_signature`. One whose signature the engine
  cannot check with that CA's key, such as a signature of another kind than the key, now reads
  `uncheckable_signature`. Both ask you to check the file and then restart, and both carry
  `start_refuses` while the file is not yet in effect. Where a CA file holds the same CRL file, the
  CRL expiry alert orders no second restart after either. (vault BACKLOG #3506)
