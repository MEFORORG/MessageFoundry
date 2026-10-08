- **Every answer the harness HTTP sinks write now carries the baseline security headers (ASVS
  3.4.3, 3.4.4, 3.4.6).** `harness/sinks/_http.py` is the loopback server behind the REST, SOAP,
  FHIR and DICOMweb sinks. Its answers carried no `X-Content-Type-Options` and no
  `Content-Security-Policy`. They now carry the same four headers the engine's HTTP listener sends:
  `nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY` and
  `frame-ancestors 'none'; base-uri 'none'`. That covers the answers Python's own HTTP server
  writes before the sink's code runs, such as its `400` for a malformed request and its `501` for
  an unknown method. Python's server would write some of those with no status line and no headers
  at all, in HTTP/0.9 form: an HTTP/0.9 request, and its own `400` and `505` for a bad request
  version. The sink now answers those in HTTP/1.0 form. No answer carries HSTS. The status, body
  and what the sink records are unchanged. (`BACKLOG #1120`)
