- **The config digest covers the environment value file wherever `[environments].base_dir` puts
  it.** In the default layout the value file sits outside the config directory, so an edit to it
  left the digest unchanged, and a released reload read it from disk after the check. A reload now
  folds the value file into the digest, and `serve` parses the values from the snapshot's bytes. A
  value file outside the config directory's `environments/` folder is read into that snapshot
  after vetting the file, its folder and the folder of each link along a chain of file links from
  it, and where it
  alone cannot be read the reload is refused, released or not, rather than reading it again from
  disk. Where the config directory cannot be read whole, a value file in its `environments/` folder
  included, a released reload is refused and an ungated one still reads the values from disk. A
  start refuses a value file it cannot stat rather than reading no values. A dual-control release
  so checks and applies the same value bytes, and refuses a value file edited, created or removed
  since its approval. The start's provenance digest folds it too, read after the start resolved
  its values, so it can name later bytes. The fingerprint scheme is now `mefor-cfg-fp:v4`, so a
  digest recorded before this change reads as not comparable rather than as a changed config.
  (vault `BACKLOG #2596`)
