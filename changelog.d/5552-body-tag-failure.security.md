- **Uploaded logs: a body that fails its integrity tag is reported too.** A read of an uploaded
  file's body that was sealed under a key the store holds, but fails its integrity tag, is now
  logged with the upload's id and raises the cipher's tag-failure alert while a tag-failure hook
  is armed, under its own alert subject, `uploaded_file_body-tag`, apart from a sidecar's
  `uploaded_file-tag`. Each engine process raises it at most about once per part per upload per
  hour, so several engine shards can each raise it. A sidecar is still reported only by the
  listing, quota check and retention prune scan, not by a read of one upload. (`BACKLOG #5552`)
