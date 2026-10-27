- **The revocation refusal's unused egress-terminator input is gone.** `revocation_hop_disposition`
  and `RevocationHopGuard` no longer take `proxy_proven`. No call site ever set it True (two passed
  False), so no hop's decision changes. (`BACKLOG #3514`)
