- **The engine image's base moves to a digest that no longer trusts "emSign ECC Root CA - G3",
  the root [GHSA-6q48-6c7w-9gw2](https://github.com/advisories/GHSA-6q48-6c7w-9gw2) covers.**
  On linux/amd64, the platform inspected, the previous `python:3.14-slim-bookworm` digest carried
  it in three CA bundles the base holds outside any lock: Debian's `ca-certificates` in
  `/etc/ssl/certs`, which OpenSSL's default verify paths read, and the certifi pip vendors, in the
  system pip and in the bundled ensurepip wheel that the pip under `/opt/venv` comes from. The new
  digest ships `ca-certificates` 20250419~deb12u2 and pip 26.2.2, and none of the three carries
  the root. The certifi installed into `/opt/venv` was already the locked 2026.10.19. The move
  also takes the image's Python from 3.14.8 to 3.14.10. Rebuild an image built from an earlier
  checkout. See the [`Dockerfile`](../docker/Dockerfile) header. (`BACKLOG #3905`)
