- **No declaration carries an HTTP-family credential across cleartext http.** `Rest`, `Soap`,
  `FHIR`, `DICOMweb` and `FhirLookup` refuse a credential over plain `http` to a host off this
  machine, with no escape. Neither `tls_hop_attested` nor `cleartext_accepted` lifts it; a
  loopback host still does. The rule covers the OAuth2 and SMART token requests, HTTP Digest and
  SOAP WS-Security as well. Its credential test now counts what the `verify_tls = false` refusal
  counts, header names in any case, so a static API-key header or a neutrally named header is
  refused too. A static `Proxy-Authorization` is left to the send-time proxy rule. Owner ruling 2026-10-26, recorded as a dated amendment to
  [ADR 0153](../docs/adr/0153-collapse-the-posture-gradient-no-data-label-may-allow-a-cleartext-hop.md).
  The forward-proxy login is not covered, and
  [SECURITY-LOOSENING.md](../docs/SECURITY-LOOSENING.md) lists it. (`BACKLOG #3533`)
- **A Handler's per-message headers meet the header allowlist at send.** On a
  `verify_tls = false` hop, or plain `http` off this machine, a header stamped under
  `dynamic_headers` must be `Accept`, `Content-Type`, `User-Agent` or `X-Request-ID` with no
  credential in it, or the message is refused permanently. The refusal names the connection
  and how many headers it refused, never a header's name or value. (`BACKLOG #3533`)
