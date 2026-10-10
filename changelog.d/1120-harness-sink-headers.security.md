- **Every answer the harness HTTP sinks write now carries the baseline security headers (ASVS
  3.4.4 and 3.4.6, and the `base-uri` part of 3.4.3).** `harness/sinks/_http.py` is the loopback
  server behind the REST, SOAP, FHIR and DICOMweb sinks. Its answers carried no `X-Content-Type-Options` and no
  `Content-Security-Policy`. They now carry the same four headers the engine's HTTP listener sends:
  `nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY` and
  `frame-ancestors 'none'; base-uri 'none'`. That covers the answers Python's own HTTP server
  writes before the sink's code runs, such as its `400` for a malformed request and its `501` for
  an unknown method. Python's server would write some answers with no status line and no headers
  at all, in HTTP/0.9 form: at least an HTTP/0.9 request, its own `400` for a request line it
  cannot parse, and its `505` for a version it refuses. The sink now answers those with a status line and headers.
  The interim `100 Continue` carries the four headers too. No answer carries HSTS. The sink still
  sends Python's `Server` line, which the engine listener does not. The status, the sink's own
  bodies and what the sink records are unchanged. (`BACKLOG #1120`)
