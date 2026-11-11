- **XML-DSig `verify()` raises a body-free `XmlError` for a signature it cannot process.**
  Malformed content inside `ds:Signature`, such as a non-base64 or empty `ds:SignatureValue` or
  unreadable key data, used to escape as whatever signxml, lxml or `cryptography` raised, and
  several of those messages quote the document. It now raises `XmlError` naming only the
  exception type, with nothing chained. A document the coverage check cannot canonicalize fails
  with `UnsignedContent`. The anchor `verify()` uses is now read before the document, and one
  that cannot be read is refused there; `verify()`'s docstring states which exceptions that
  raises and what the read checks. The CA file is read at most once per call, before the
  document, and signxml's chain check uses that read, so a CA file changed or deleted during the
  call is not reported as an `XmlError`. (`BACKLOG #2816`, `BACKLOG #5372`)
