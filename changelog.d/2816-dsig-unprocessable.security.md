- **XML-DSig `verify()` raises a body-free `XmlError` for a signature it cannot process.**
  Malformed content inside `ds:Signature`, such as a non-base64 or empty `ds:SignatureValue` or
  unreadable key data, used to escape as whatever signxml, lxml or `cryptography` raised, and
  several of those messages quote the document. It now raises `XmlError` naming only the
  exception type, with nothing chained. A document the coverage check cannot canonicalize fails
  with `UnsignedContent`. The `x509_cert` or `ca_pem_file` anchor is now read before the
  document. An anchor that cannot be read is refused there, at least with `ValueError` (`OSError`
  for a CA file that cannot be opened); `verify()`'s docstring says what that read checks. The CA
  file is read once per call, and signxml's chain check uses that read, so the call does not open
  the file again. (`BACKLOG #2816`, `BACKLOG #5372`)
