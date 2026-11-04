- The 0.5.2 entry said that where the event loop runs a TLS handshake, the peer's address is not
  known. More exactly, the loop's hook does not read it. On the standard asyncio loop on Windows,
  the hook could reach it only through the loop's private state, and uvloop was not measured. The
  records still name no peer there; the module docstring of
  `messagefoundry/tls_handshake_failures.py` says what was measured. (vault `BACKLOG #3302`)
