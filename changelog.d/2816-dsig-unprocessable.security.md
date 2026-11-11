- **XML-DSig `verify()` raises a body-free `XmlError` for a signature it cannot process.**
  Malformed content inside `ds:Signature`, such as a non-base64 or empty `ds:SignatureValue` or
  unreadable key data, used to escape as whatever signxml, lxml or `cryptography` raised, and
  several of those messages quote the document. It now raises `XmlError` naming only the
  exception type, with nothing chained. A document the coverage check cannot canonicalize fails
  with `UnsignedContent`. An unreadable `x509_cert` or `ca_pem_file` anchor is read first and
  still raises its own `ValueError`. (`BACKLOG #2816`, `BACKLOG #5372`)
