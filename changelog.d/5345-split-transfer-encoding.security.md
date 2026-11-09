- **The API's request body limit reads every `Transfer-Encoding` line, not only the first.** A
  request carrying `Transfer-Encoding: gzip` and then a second `Transfer-Encoding: chunked` line is
  framed as chunked by the llhttp parser `serve` pins, but the limit read only the first line, saw
  `gzip`, and admitted the chunked body at any size when no `Content-Length` came with it, before
  any route or authentication ran. With a `Content-Length` it skipped the ambiguous-framing 400 on
  a server other than llhttp. Such a request is now refused **411** without a `Content-Length`,
  and **400** with one, as a single `chunked` line is. [SECURITY.md](../docs/SECURITY.md) also now
  says that under `serve` a chunked body whose framing is malformed gets llhttp's own 400, not the
  app's 411. (vault `BACKLOG #5345`)
