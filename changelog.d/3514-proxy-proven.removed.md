- **The revocation refusal's unused egress-terminator input is gone.** `revocation_hop_disposition`
  and `RevocationHopGuard` no longer take `proxy_proven`. No engine call site ever set it True (at
  least two passed False), so no hop's decision changes. (`BACKLOG #3514`)
