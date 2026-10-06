- **The delta CRL refusal now names the OpenSSL releases it guards against.** OpenSSL 3.0.22, 3.4.7,
  3.5.8 and 3.6.4 stopped reading a delta CRL as a complete one, so the message no longer says every
  OpenSSL does. The engine still refuses a delta CRL in a CRL file, on every build.
