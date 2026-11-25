- **The AI-broker revocation refusal says which endpoint hosts read as loopback.** Its last remedy
  now asks for an endpoint URL whose host reads as loopback, such as `localhost`, `127.0.0.1` or
  `[::1]`, with its host listed in `[ai].allowed_endpoints`, and says that at least a spelling
  with a trailing dot or a short form such as `127.1` reads as remote. The refusal reads the host
  as spelled, so a gateway on this machine spelled that way is refused too. See
  [SECURITY-LOOSENING.md](../docs/SECURITY-LOOSENING.md). (`BACKLOG #5527`)
