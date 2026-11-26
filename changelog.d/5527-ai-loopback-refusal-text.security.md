- **The AI-broker revocation refusal says which endpoint hosts read as loopback.** Its last remedy
  now asks for an endpoint URL whose host reads as loopback, such as `localhost`, `127.0.0.1` or
  `[::1]`, with its host listed in `[ai].allowed_endpoints`, says such an endpoint is verified
  against the OS trust store alone, and says that at least a spelling
  with a trailing dot or a shortened IPv4 address such as `127.1` reads as remote, so a gateway
  on this machine spelled that way is judged as off-box. See
  [SECURITY-LOOSENING.md](../docs/SECURITY-LOOSENING.md). (`BACKLOG #5527`)
