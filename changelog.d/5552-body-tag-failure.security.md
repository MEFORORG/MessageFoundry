- **Uploaded logs: a body that fails its integrity tag is reported too.** A read of an uploaded
  file's body that was sealed under a key the store holds, but fails its integrity tag, is now
  logged with the upload's id and raises the cipher's tag-failure alert while a tag-failure hook
  is armed. The alert names the part, `body` or `sidecar`, and is raised at most about once per
  part per upload per hour. A sidecar is still reported only by the listing, quota check and
  retention prune scan, not by a read of one upload. (`BACKLOG #5552`)
