- **A request the API's HTTP parser refuses now gets the `400` and nothing after it.** On CPython
  3.14.9 on Windows, a chunked body refused after the head also got the app's own `411` behind the
  `400`, two responses to one request, as measured on the test suite's plaintext loopback. A
  pipelined request still running ahead of it could answer there as well. The engine now ends
  every request still in flight on that connection once the `400` is written.
