- **On POSIX the key-file access check now refuses a key file reached through a link, one owned by
  an account other than the engine's own or root, and one held in a directory that such an account
  owns or that a group or other account may write without the sticky bit.** Before, it judged the
  mode bits of the file a link named, so a mode `0600` key another account owned, or one in a
  directory others could replace it in, would have passed. On POSIX the check applies to at least
  the generated and the operator's API TLS key and each connection's key file, which `serve` and
  `supervise` judge, and to the secrets directory and its files. The engine now mints its own
  TLS key into `api-generated-key.d`, a directory beside the store that it creates at `0700` on
  POSIX, so its key check passes in a store directory a group may write, such as one made under
  umask `002`; that group can still replace the certificate, lock and store beside it. The
  certificate stays beside the store. `cert self-signed` and `cert import` create `--out-dir` at
  `0700` on POSIX. On Windows both directories inherit their parent's access list, as before.
  Only the last part of a path is read without following a link; a link above it is followed. A link is now judged
  as itself, so a dangling link to a key is refused rather than passed as a missing file. Only the
  directory that holds the file is read, not the ones above it. The shipped manifests
  `docker/k8s/statefulset.yaml` and `docker/k8s/ha-postgres.yaml` add a `tls-dir` initContainer
  that makes `/etc/mefor/tls/engine` at `0700` as uid 10001, and `copy-tls` copies the API pair
  there, because the kubelet makes the `emptyDir`'s root and sets its mode. (`BACKLOG #5636`,
  `BACKLOG #5656`)
