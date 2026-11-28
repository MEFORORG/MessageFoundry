- **The uploads orphan sweep checks its root before it trusts an absent answer.** At least a
  drive letter that is no longer mapped, and an uploads folder that is a link to a lost target,
  now end the retention pass's orphan sweep with a logged error rather than a silent clean pass.
  A root deleted after its first save, and one under a POSIX mount point whose share dropped,
  still read as a folder no save has made yet. A body whose sidecar reads as absent is removed
  only while the uploads root still answers as the folder the sweep listed, so a share remounted
  under it as another folder stops the sweep. A body whose sidecar exists can still be removed,
  with no audit row, in at least these cases: a stale client cache, a hidden name, a remount that
  answers with the same identity or that flaps back before the check, a root swapped after the
  check and before the unlink, and a sidecar that lands between its check and the unlink
  (BACKLOG #6575).
