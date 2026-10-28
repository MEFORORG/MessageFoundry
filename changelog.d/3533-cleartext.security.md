- **No declaration carries an HTTP-family credential across cleartext http.** `Rest`, `Soap`,
  `FHIR`, `DICOMweb` and `FhirLookup` refuse a credential over plain `http` to a host off this
  machine, with no escape. Neither `tls_hop_attested` nor `cleartext_accepted` lifts it; a
  loopback host still does. The rule covers the OAuth2 and SMART token requests, HTTP Digest and
  SOAP WS-Security as well. Its credential test now counts the credentials the
  `verify_tls = false` refusal counts, header names in any case, so a static API-key header or a
  credential-shaped value under a neutral name is refused too. It does not take that refusal's
  header-name allowlist, so a neutral header such as `Prefer` still crosses a declared cleartext
  hop; whether it should is an open owner question. A static `Proxy-Authorization` is left to the
  send-time proxy rule only when the request goes to a proxy. On a hop that goes direct, through
  `proxy_no_proxy`, urllib's own bypass list, or `proxy_url = "default"` with no system proxy, it
  counts as a credential and refuses the hop at build. A header key that holds whitespace or is
  shaped like a credential is withheld from the refusal text. Owner ruling 2026-10-26, recorded as
  a dated amendment to
  [ADR 0153](../docs/adr/0153-collapse-the-posture-gradient-no-data-label-may-allow-a-cleartext-hop.md).
  The forward-proxy login stays under the declarations, by the owner's 2026-10-05 ruling on that
  credential. (`BACKLOG #3533`)
- **A Handler's per-message headers meet the hop's header rule at send.** On a
  `verify_tls = false` hop, a header stamped under `dynamic_headers` must be `Accept`,
  `Content-Type`, `User-Agent` or `X-Request-ID` with no credential in it. Over plain `http` off
  this machine, it must hold no credential. Otherwise that one message is refused permanently and
  dead-lettered, and the lane goes on. The send-time hop check runs first, so a hop that is no
  longer permitted still stops the lane and keeps the row. The refusal names the connection and
  how many headers it refused, never a header's name or value. (`BACKLOG #3533`)
