<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 MessageFoundry Organization and contributors -->

# ECH egress sidecar (ASVS 12.1.5, ADR 0139)

Hide the **outbound SNI** on a connection's TLS handshakes so a network observer on the external hop
cannot see *which* partner/EHR the engine is talking to. This is **metadata** protection (which partner,
how often) — the payload is already encrypted by TLS, so **no PHI content is exposed either way**.

> **Demand-gated / inert until a partner supports it.** Encrypted Client Hello (ECH) requires the
> **destination** to publish an `ECHConfig` in DNS. A 2026-07-20 DoH probe found **no** MessageFoundry
> partner endpoint (Epic, Oracle Health/Cerner, athenahealth, Google Cloud Healthcare, SMART) publishes
> one — ECH deployment is effectively Cloudflare-only. Standing this up today hides nothing; wire it when
> a real destination begins publishing an `ECHConfig` (the register re-score trigger). See
> [ADR 0139](../../docs/adr/0139-ech-egress-sidecar-sni-hiding-for-asvs-12-1-5-demand-gated.md).

## What the engine ships (Increment 1) — and what it does NOT

Python's stdlib `ssl` (OpenSSL 3.5.x, what CPython 3.14 links) has **no ECH API** — ECH is an OpenSSL 4.0
feature (a `ctypes` probe of the bundled `libssl` finds zero ECH symbols). So the engine cannot originate
an ECH handshake itself. What it **does** provide, per outbound connection, is the **routing + fail-closed
plumbing**: `ech_egress=true` sends the connection's egress through a designated **loopback sidecar**
instead of dialing the destination directly, and if the sidecar is unreachable the hop **errors** — it
never silently falls back to a direct, SNI-leaking connection.

**The engine does NOT originate ECH, and a plain forward proxy will not add it.** ECH lives in the
*ClientHello*; a generic HTTP proxy **tunnels** an `https://` destination (CONNECT), so the engine's own
non-ECH TLS is what reaches the partner — the SNI still leaks. To actually hide the SNI the sidecar must
**terminate the loopback hop and re-originate a fresh ECH-bearing TLS connection** to the destination.
Building/packaging that terminating sidecar is the **deferred leg** of ADR 0139 (no Go toolchain ships in
the wheel; and it is inert until a partner publishes an `ECHConfig`).

```
 engine connector ──(loopback, cleartext)──▶ ECH sidecar ──(NEW TLS + ECH, over DoH)──▶ partner endpoint
   ech_egress=true                          TERMINATES here          SNI hidden here
   ech_sidecar=127.0.0.1:1080               re-originates
```

## The sidecar contract (what a real sidecar must do)

A conforming sidecar is a **loopback TLS-terminating re-originator**, not a tunnel:

1. Accept the engine's egress on a loopback listener (same-host → the cleartext loopback hop has no wire
   exposure, the ADR 0092 same-host posture).
2. For each destination, open a **new** TLS connection with **ECH enabled**, fetching the `ECHConfig` from
   the destination's DNS **HTTPS record over DoH/DoT** (so the hostname is not leaked in cleartext DNS
   either — solving both halves).
3. Be **fail-closed**: if ECH cannot be negotiated (destination publishes no `ECHConfig`), fail rather than
   silently completing a non-ECH handshake.

Candidate implementations (operator-supplied, downloaded beside the engine like OpenBao for the store
sidecar): **sing-box** (Go `crypto/tls` client ECH since 1.23) configured as a TLS-terminating proxy, or a
purpose-built ~500-line Go re-originator. A generic CONNECT-tunneling proxy is **not** conforming.

## Wire it in MessageFoundry

Per outbound connection (opt-in; off by default → byte-identical):

```toml
[connections.OB_PARTNER_FHIR.settings]
ech_egress  = true                     # route this connection's egress through the ECH sidecar
ech_sidecar = "http://127.0.0.1:1080"  # the sidecar's loopback listener (must be loopback)
```

`ech_sidecar` must be a loopback address and is **mutually exclusive** with `proxy_url` (the sidecar *is*
that connection's egress proxy). It composes with the connection's TLS verify/allowlist/signing posture.

## Verify before trusting a partner

```
# Confirm the sidecar re-originates ECH against the Cloudflare control (an endpoint that publishes ech=):
#   (destination whose DNS HTTPS record carries an ech= SvcParam)
dig +short -t HTTPS crypto.cloudflare.com          # -> shows an ech= param
# Re-probe YOUR real partner endpoints before enabling ech_egress on them — enable only where ech= appears:
dig +short -t HTTPS <partner-host>                 # no ech= param today for the EHR endpoints probed
```
