- **`rotate-key` exits 2 when the Vault client for the store key cannot be built.** Under
  `[store].key_provider = "vault"`, a check in the client build that refuses with a `ValueError`
  passed the command's first key check and exited 1 through the last-resort hook. At least the
  outbound length bound, the TLS suite assertion and the strict-reader mount refuse that way. The
  command now prints the refusal whole and exits 2, as it already did when the store open met the
  same refusal: it could not start, and nothing was changed. (vault BACKLOG #3247)
