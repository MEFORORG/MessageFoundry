- **The uploads orphan sweep checks its root before it trusts an absent answer.** At least a
  drive letter that is no longer mapped, and an uploads folder that is a link to a lost target,
  now end the retention pass's orphan sweep with a logged error rather than a silent clean pass.
  A root deleted after its first save, and one under a POSIX mount point whose share dropped,
  still read as a folder no save has made yet. Once the root's own read has succeeded, a listing
  that then answers absence is a logged error too. The sweep reads the root's identity before
  its listing. Right before it removes a temp leftover, or a body whose sidecar reads as absent,
  it checks that identity again. A share remounted under the root as another folder therefore
  stops the sweep. The check does not catch a remount with the same identity, one that flaps
  back before the check, or one that lands between the check and the removal. On a file system
  that mints identities on the client, such as a CIFS mount with `noserverino`, the check can
  stop sound passes, so orphans can stay past retention. A body whose sidecar exists can still be
  removed, with no audit row. At least these cases do it: a stale client cache, a hidden name,
  any of the remounts the check does not catch, and a sidecar that lands between its check and
  the unlink (BACKLOG #6575).
