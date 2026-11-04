- **On linux/amd64, the engine image's base moves to a digest that no longer trusts "emSign ECC
  Root CA - G3", the root [GHSA-6q48-6c7w-9gw2](https://github.com/advisories/GHSA-6q48-6c7w-9gw2)
  covers.** Only linux/amd64 was inspected; other platforms under the same pin were not. There,
  the previous `python:3.14-slim-bookworm` digest carried it in at least three CA bundles the base
  holds outside any lock: Debian's `ca-certificates` in `/etc/ssl/certs`, which OpenSSL's default
  verify paths read, and the certifi pip vendors, in the system pip and in the bundled ensurepip
  wheel that the pip under `/opt/venv` comes from. The digest inspected on 2026-10-26,
  `sha256:9974e24551f9e7ca172cf284d85b8ab3e031d22d945f7026ede7a8279118c9f1`, ships
  `ca-certificates` 20250419~deb12u2 and pip 26.2.2, and none of those three carries the root.
  The base is now pinned to `sha256:516b51cb9db2ef061e465c803e50f64361b82cefd91e525b889b967b83e83527`,
  whose CA bundles were not inspected; the Lander's review of engine PR 2778 on 2026-11-04 only
  compared it with `9974e245`, finding the same tag, the same docker-library revision, Python
  3.14.10 and the same 69 Debian packages at the same versions on linux/amd64, `ca-certificates`
  20250419~deb12u2 among them. The certifi
  installed into `/opt/venv` was already the locked 2026.10.19. The move also takes the image's
  Python from 3.14.8 to 3.14.10. Rebuild an image built from an earlier checkout. See the
  [`Dockerfile`](../docker/Dockerfile) header. (`BACKLOG #3905`)
