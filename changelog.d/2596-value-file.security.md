- **A released reload checks the environment value file wherever `[environments].base_dir` puts
  it.** In the default layout the value file sits outside the config directory, so a released
  reload read it from disk after the digest check, and an edit to it applied under the approved
  digest. A reload now reads that value file into its snapshot, after vetting the file, its folder
  and the folder of each link along a chain of file links from it, and `serve` parses the values
  from those bytes. Where it alone cannot be read, the reload is refused, released or not, rather
  than reading it again from disk. A dual-control hold binds the file with an HMAC-SHA256 under a
  key derived from the store key, and the release refuses a value file edited, created or removed
  since the request. No published config digest folds that file, since it can hold credentials and
  those digests are unkeyed; the fingerprint scheme stays `mefor-cfg-fp:v3`. A store with no
  in-process key binds nothing, and the release logs a WARNING. A start refuses a value file it
  cannot stat rather than reading no values. (vault `BACKLOG #2596`)
