- **A re-ingress token whose own payload is a corrupt cell under a key the store holds is no
  longer labelled a failed queue tag.** Such a cell, for example bad base64 or a ciphertext too
  short for a tag, now dead-letters the `Stage.RESPONSE` token with `last_error` "integrity: the
  re-ingress work-row holds a corrupt payload" and a `dead` event saying the same, on SQLite,
  PostgreSQL and SQL Server, and the server backends' fenced-write WARNING names it
  `ingress_handoff(corrupt-token)`. The re-ingress worker's WARNING for any refused token now
  quotes the `last_error` it records, in place of the fixed words "failed its integrity tag". Its
  handling is unchanged: it is still dead-lettered, still audited under
  `integrity.queue_tag_failed` with cause `corrupt`, and still alerted under the corrupt-cell
  subject. Known limits, at least: under Vault Transit a corrupt cell is refused with cause
  `unknown`, not as a corrupt cell, and a blank payload is refused with cause `blank`; both keep
  the failed-queue-tag label, as before. (`BACKLOG #5982`)
