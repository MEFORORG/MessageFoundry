- **The API body limit now counts a body that declares no length.** A request with neither
  `Content-Length` nor `Transfer-Encoding` passed the limit uncounted, so a host framing it another
  way (HTTP/2, an in-process ASGI call) could have buffered a body of any size. Such a body is now
  counted as the route reads it and refused with `413` at the first chunk past the same cap,
  including the upload routes' larger one. A call with no body is still admitted, and `serve`,
  which frames this shape as an empty body, is unaffected. (`BACKLOG #5345`)
