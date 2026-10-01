- **BREAKING: a FHIR `update` or `if-match` no longer puts the resource id in the request URL.**
  A RESTful update is `PUT {base}/{ResourceType}/{id}`, so on a first deployment a message-derived
  id would have reached the receiving server's access logs. The `FHIR()` destination now sends both
  as the one entry of a `transaction` Bundle, POSTed to `{base}`. The entry's `request` carries
  `PUT {ResourceType}/{id}`, and the `If-Match` ETag moves into `request.ifMatch`. The resource is
  spliced in byte for byte. The receiving server must support the `transaction` interaction, and for
  `if-match` it must honor the entry's `ifMatch`. A 2xx reply whose entry status failed is
  classified on that status, and `capture_response_headers` reads `ETag`, `Location` and
  `Last-Modified` from the entry. A resource id made only of dots is now refused. A `fhir_lookup`
  read-by-id still carries the id in its path, which is what a RESTful read is; owner ruling R3
  names the two writes only. See [CONNECTIONS.md](../docs/CONNECTIONS.md), "An update keeps the
  resource id out of the URL". (vault `BACKLOG #1965`, ASVS 14.2.1)
