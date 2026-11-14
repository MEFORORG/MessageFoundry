- **On POSIX the key-file access check now refuses a key file reached through a link, one owned by
  an account other than the engine's own or root, and one held in a directory that such an account
  owns or that a group or other account may write without the sticky bit.** Before, it judged the
  mode bits of the file a link named, so a mode `0600` key another account owned, or one in a
  directory others could replace it in, would have passed. The check applies at least to the
  generated and the operator's API TLS key and each connection's key file, which `serve` and
  `supervise` judge, and to the secrets directory and its files. A dangling link to a key is now
  refused rather than passed as a missing file. Where no link is on the path, only the directory
  that holds the file has its owner and mode read, not the ones above it. A link above the file is
  judged by `_posix_link_problem` in `messagefoundry/restricted_file.py`.
  When the engine mints its own TLS pair and the store directory does not exist yet, it creates
  that directory on POSIX with no group or other write bit (`0755` at most), and only then; with
  an operator certificate or an upstream terminator it creates none. The `cert self-signed` and
  `cert import` commands create `--out-dir` at `0700` on POSIX, so other local accounts can no
  longer read the public certificate files in a directory those commands create. An existing
  directory keeps its mode; how the engine reports a store directory a group may write, and what
  to do about it, is in [PHI.md](../docs/PHI.md), *Key files*. On Windows these
  directories inherit their parent's access list, as before. The shipped manifests
  `docker/k8s/statefulset.yaml` and `docker/k8s/ha-postgres.yaml` add a `tls-dir` initContainer
  that makes `/etc/mefor/tls/engine` at `0700` as uid 10001, and `copy-tls` copies the API pair
  there, because the kubelet makes the `emptyDir`'s root and sets its mode. (`BACKLOG #5636`,
  `BACKLOG #5656`)
