- **On linux/amd64, the engine image's base moved on 2026-10-26 to a digest inspected not to trust
  "emSign ECC Root CA - G3", the root [GHSA-6q48-6c7w-9gw2](https://github.com/advisories/GHSA-6q48-6c7w-9gw2)
  covers; the digest the base is pinned to now was not inspected.** The digest the base moved
  from, `sha256:48b13b00...`, carried the root in at least three CA bundles the base holds outside
  any lock: Debian's `ca-certificates` in `/etc/ssl/certs`, which OpenSSL's default verify paths
  read, and the certifi pip vendors, in the system pip and in the bundled ensurepip wheel that the
  pip under `/opt/venv` comes from. The digest inspected on 2026-10-26, for linux/amd64 only,
  `sha256:9974e24551f9e7ca172cf284d85b8ab3e031d22d945f7026ede7a8279118c9f1`, ships
  `ca-certificates` 20250419~deb12u2 and pip 26.2.2, and none of those three carries the root; no
  other platform was inspected. That 2026-10-26 move also took the image's Python from 3.14.8 to
  3.14.10. The certifi installed into `/opt/venv` was already the locked 2026.10.19. On 2026-11-04
  Dependabot moved the pin to `sha256:516b51cb...`, whose CA bundles were not inspected on any
  platform; it was only compared with `9974e245`, as recorded in the
  [engine PR 2778 hold comment](https://github.com/MEFORORG/MessageFoundry/pull/2778#issuecomment-6629228552).
  Rebuild an image built from an earlier checkout. See the [`Dockerfile`](../docker/Dockerfile)
  header for the digests and that comparison. (`BACKLOG #3905`)
