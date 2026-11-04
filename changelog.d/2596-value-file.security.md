- **The config digest covers the environment value file wherever `[environments].base_dir` puts
  it.** In the default layout the value file sits outside the config directory, so an edit to it
  left the digest unchanged, and a released reload read it from disk after the check. Each reload
  now reads it into the snapshot it loads, after vetting the file and its folder, folds it into the
  digest, and `serve` parses the values from those bytes. A dual-control release so checks and
  applies the same value bytes, and refuses a value file edited, created or removed since its
  approval. The start's provenance digest folds it too, and the fingerprint scheme is now
  `mefor-cfg-fp:v4`, so a digest recorded before this change reads as not comparable rather than as
  a changed config. (vault `BACKLOG #2596`)
