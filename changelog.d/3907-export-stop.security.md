- **A stopped bulk or audit export now reaches the client as a failed download.** When its
  re-check stops `GET`/`POST /messages/export` or `GET /audit/export` after the 200 has started,
  the server now drops the connection with the body unfinished, so the client sees a transfer that
  failed. It used to receive a cleanly ended 200 holding only the rows sent before the stop, a
  short file it could not tell from a complete export. The engine's security-header and
  request-body-limit middleware are now pure ASGI: Starlette's `@app.middleware("http")` layer
  they replace sent the final body message before the stop's raise left it. The registration order
  is unchanged, and the existing header-floor, no-store and body-limit tests pass unchanged.
  Measured for an HTTP/1.1 client over cleartext loopback; see SECURITY.md for what is not.
  (`BACKLOG #3907`)
