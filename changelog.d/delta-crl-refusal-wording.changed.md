- **The delta CRL refusal no longer says every OpenSSL reads a delta CRL as complete.** OpenSSL
  3.0.22, 3.4.7, 3.5.8, 3.6.4 and 4.0.2 stopped doing that (openssl/openssl PR 31044); 3.1 to 3.3
  have no fixed release. The message now names the fix. The engine still refuses a delta CRL in a
  CRL file, on every build.
