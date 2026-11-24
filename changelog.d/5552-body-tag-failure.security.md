- **Uploaded logs: a body that fails its integrity tag is reported too.** A read of an uploaded
  file whose body was sealed under a key the store holds, but fails its integrity tag, now raises
  the cipher's tag-failure alert while a tag-failure hook is armed, once per upload per hour, as a
  sidecar that fails its tag already did. The alert names the part, `body` or `sidecar`.
  (`BACKLOG #5552`)
