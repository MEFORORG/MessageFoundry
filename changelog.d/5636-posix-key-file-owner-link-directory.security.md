- **On POSIX the key-file access check now refuses a key file reached through a link, one owned by
  an account other than the engine's own or root, and one held in a directory that such an account
  owns or that a group or other account may write without the sticky bit.** Before, it judged the
  mode bits of the file a link named, so a mode `0600` key another account owned, or one in a
  directory others could replace it in, would have passed. The check is the one `serve` and
  `supervise` apply to the store key file, the generated and the operator's API TLS key, and each
  connection's key file, and the one the secrets directory and its files get. A link is now judged
  as itself, so a dangling link to a key is refused rather than passed as a missing file. Only the
  directory that holds the file is read, not the ones above it. The shipped manifests
  `docker/k8s/statefulset.yaml` and `docker/k8s/ha-postgres.yaml` add a `tls-dir` initContainer
  that makes `/etc/mefor/tls/engine` at `0700` as uid 10001, and `copy-tls` copies the API pair
  there, because the kubelet makes the `emptyDir`'s root and sets its mode. (`BACKLOG #5636`,
  `BACKLOG #5656`)
