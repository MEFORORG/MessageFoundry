- **A store-key rotation no longer resets the age of every other tracked secret.** The secret-rotation
  watcher fingerprints each secret under a key derived from the store key. Rotating the store key
  changed every fingerprint. On first deployment, every other secret would have read as rotated that
  day. That would have lifted each overdue refusal under `[secret_rotation].enforce_secret_expiry_classes`.
  Each fingerprint now names the key that made it. A changed key alone is a re-key: the engine
  re-fingerprints the secret and keeps its last-rotated date. Keep the prior store key in
  `MEFOR_STORE_ENCRYPTION_KEYS_RETIRED` through the engine's first start after `rotate-key`. Then a
  secret changed at the same time still reads as rotated. Without that key the engine cannot tell.
  It keeps the older date and logs a warning.
