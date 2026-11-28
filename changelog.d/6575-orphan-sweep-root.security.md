- **The uploads orphan sweep checks its root before it trusts an absent answer.** A listing that
  answers absence, as a lost drive does, now ends the retention pass's orphan sweep with a logged
  error rather than a silent clean pass, unless no save has made the uploads folder yet. A body
  whose sidecar reads as absent is removed only while the uploads root is still the folder the
  sweep listed, so a share remounted under it stops the sweep. A stale client cache or a hidden
  name can still read as absent (BACKLOG #6575).
