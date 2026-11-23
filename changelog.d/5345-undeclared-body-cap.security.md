- **The API body limit now counts every HTTP request body.** A request with neither
  `Content-Length` nor `Transfer-Encoding` passed the limit uncounted, and a body longer than its
  `Content-Length` was judged by that header alone, so a host that frames a request another way (at
  least HTTP/2, HTTP/3 and an in-process ASGI call) could have buffered a body of any size. Each
  body is now counted as the route reads it and refused with `413` at the first chunk past the same
  cap, including the upload routes' larger one. If the route has already started a response, no
  `413` is sent: its read gets a disconnect, and the log says so. A call with no body is still
  admitted. Under `serve`, which ends a body at its `Content-Length` and frames a request with
  neither header as empty, the count cannot pass the cap. A body-limit refusal over HTTP/2 or
  HTTP/3 no longer carries the `Connection` field those protocols forbid, so only on HTTP/1.x does
  it ask for the connection to close. (`BACKLOG #5345`)
