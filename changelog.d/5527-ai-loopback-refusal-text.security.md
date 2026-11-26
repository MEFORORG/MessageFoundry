- **The AI-broker revocation refusal says which endpoint hosts read as loopback.** Its last remedy
  now asks for an endpoint URL whose host reads as loopback, such as `localhost`, `127.0.0.1` or
  `[::1]`, listed in `[ai].allowed_endpoints` as the URL writes it, says such an endpoint is
  verified against the OS trust store alone, with neither `[tls]` file, and says that the host is
  not resolved: at least a spelling with a trailing dot or a shortened IPv4 address
  such as `127.1` reads as remote, so a gateway on this machine spelled that way is judged as any
  non-loopback endpoint is. See
  [SECURITY-LOOSENING.md](../docs/SECURITY-LOOSENING.md). (`BACKLOG #5527`)
