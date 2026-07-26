# ech-sidecar — terminating, fail-closed ECH re-originator

A small **stdlib-only Go** forward proxy that hides the destination **SNI** on
MessageFoundry's outbound HTTPS by re-originating each request with **Encrypted
Client Hello (ECH)**. It exists to satisfy **ASVS 12.1.5** (protect the server name
from a network observer) for egress that CPython's `ssl` cannot yet do (OpenSSL ECH
is not exposed by the stdlib).

## What it does

For every request it receives on a loopback HTTP port it:

1. Determines the upstream host — from the **absolute-form request URI** (classic
   forward proxy, e.g. `GET http://host/path` through an HTTP proxy) or, failing
   that, the **`Host` header**.
2. Resolves that host's **ECHConfigList** from its DNS **HTTPS record (RR type 65)**
   over **DoH** (`https://cloudflare-dns.com/dns-query`, `accept: application/dns-json`),
   walking the record's SvcParams for **SvcParamKey 5 (`ech`)** — parsed in Go with
   `encoding/hex` + a manual SvcParam walk (`walkSvcParamsForECH`), mirroring the
   working ECH proof.
3. Dials the upstream with `crypto/tls` using
   `EncryptedClientHelloConfigList = <that list>`, so the true `ServerName` is sent
   only inside the encrypted **ClientHelloInner**.
4. **Verifies the upstream certificate normally** — `InsecureSkipVerify` is never set.
5. Re-issues the HTTP request over that connection and streams the response back.

## FAIL-CLOSED (do not weaken)

There are **two** gates and **no** cleartext-SNI fallback:

- If the upstream publishes **no ECHConfig**, the request is **refused with `502`**
  (`resolveECH` returns an error, never a "no ECH but OK").
- If the TLS server does **not accept** ECH (`ConnectionState.ECHAccepted == false`),
  the connection is **refused** even though a config list was found.

`CONNECT` tunnels are rejected (`405`): an end-to-end tunnel would leave TLS
origination — and therefore ECH — with the client, defeating the purpose.

## Build & run (offline)

Requires **Go >= 1.26** (stdlib ECH). No module dependencies; builds with
`GOPROXY=off`.

```sh
go build -o ech-sidecar.exe .
./ech-sidecar.exe -addr 127.0.0.1:8123        # loopback-only; refuses non-loopback binds
```

Flags: `-addr` (default `127.0.0.1:8123`), `-timeout` (per-request upstream timeout,
default `30s`).

## Proof — SNI hidden through the sidecar

```sh
$ curl -s http://127.0.0.1:8123/cdn-cgi/trace -H "Host: crypto.cloudflare.com"
...
sni=encrypted        # <-- the destination SNI was encrypted end to end
...
```

Equivalent true forward-proxy form (the engine's path):

```sh
$ curl -s -x http://127.0.0.1:8123 http://crypto.cloudflare.com/cdn-cgi/trace | grep sni=
sni=encrypted
```

Fail-closed check (a host with no ECHConfig is refused, not downgraded):

```sh
$ curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8123/ -H "Host: example.com"
502
```

## Engine integration (not wired here)

MessageFoundry's REST transport already threads a **forward-proxy handler**
(ADR 0126) into its per-connection opener. Point that proxy at this sidecar
(`http://127.0.0.1:8123`) for connections whose destination publishes ECH. The
sidecar upgrades the scheme to `https` and originates ECH; the engine keeps its own
verifying opener for everything else. `messagefoundry/transports/rest.py` is **not**
modified by this tool — wiring is a follow-up owned by the engine.

## Scope / limitations

- Cloudflare DoH JSON returns type-65 RDATA in RFC 3597 generic form
  (`\# <len> <hex>`); a presentation-form `ech="<base64>"` fallback is also handled.
- No DoH result caching (one HTTPS lookup per request) — add a short TTL cache before
  high-volume use.
- HTTP/1.1 and HTTP/2 upstream via `net/http` defaults; no WebSocket upgrade.
