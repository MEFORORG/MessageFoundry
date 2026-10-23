- **Nothing goes out after the API parser's `400` when the bad body arrives with the head.** A
  chunked request whose body the parser then refused could get two responses: the `400` with
  `connection: close`, then the app's `411`. CPython 3.14.9 made this show on Windows, and the
  selector loop could do it too. The engine now mutes every open request on that connection after
  the `400`. It closes the connection when the server's own `400` writer fails, and the startup
  self-test checks the step. A request read in the same pass as the bad bytes now gets
  `http.disconnect`, and its answer is never written. One case remains: when the head arrives
  before the bad body, the app's `411` goes out first and the `400` follows on the same
  connection. A proxy that sends one `Content-Length` never forwards such a request. See
  [DEPLOYMENT.md](../docs/DEPLOYMENT.md).
