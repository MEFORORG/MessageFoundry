- **A re-ingress token whose own payload is corrupt is no longer labelled a failed queue tag.** A
  corrupt cell under a key the store holds, for example bad base64 or a ciphertext too short for a
  tag, now dead-letters the `Stage.RESPONSE` token with `last_error` "integrity: the re-ingress
  work-row holds a corrupt payload" and a `dead` event saying the same, on SQLite, PostgreSQL and
  SQL Server, at the re-ingress reply read and at the handoff. The re-ingress worker's WARNING
  names the refusal's cause in the queue-tag wording, so a corrupt cell reads "holds a payload that
  is corrupt" rather than "failed its integrity tag". Its handling is unchanged: it is still
  dead-lettered, still audited under `integrity.queue_tag_failed` with cause `corrupt`, and still
  alerted under the corrupt-cell subject. A cell that fails its tag keeps its old wording.
  (`BACKLOG #5982`)
