- **`cert import` now checks a private key inside an encrypted part of a PKCS#12 bundle.** Before,
  the wrap check read only the outside of a bundle. A key bag inside an encrypted part (an
  EncryptedData SafeContents) needed the passphrase to reach, so it went unchecked: a key wrapped
  with PBKDF2 at 2048 iterations, or with a PKCS#12 PBE scheme, loaded from inside an AES-256-CBC
  part at the floor. Now `pki.load_pkcs12` opens each encrypted part with the passphrase once the
  outside passes, and holds its key bags to the same floor before `cryptography` decrypts any key.
  This is design A, a Manager decision (M4, 2026-10-10), not an owner ruling. A bundle with the
  certificate in an AES-256-CBC part, the shape OpenSSL 3's export writes, still loads when its
  parameters meet the floor, as the re-export command's output does. **BREAKING** for at least
  these bundle shapes: a weak key bag inside an encrypted part, and an encrypted part the engine
  does not open to check, such as one under scrypt or a cipher other than AES-CBC. Each is refused
  with the reason. See
  [CONNECTIONS.md](../docs/CONNECTIONS.md#encrypted-private-keys-must-meet-the-wrap-floor).
  (`BACKLOG #1352`)
