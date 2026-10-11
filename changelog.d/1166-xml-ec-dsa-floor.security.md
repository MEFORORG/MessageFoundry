- **BREAKING: XML signature checks now refuse weak EC keys and every DSA key.** The XML-DSig
  `verify()` used to floor only RSA keys. It accepted a P-192 key and a 1024-bit DSA key on both
  the `x509_cert` and the `ca_pem_file` paths. Now an EC key must be on P-256, P-384 or P-521, the
  same curves the Direct transport allows. A DSA key is refused at any size, and so is any key type
  other than RSA, EC, Ed25519 or Ed448. A refused key returns
  `verified=False` with the reason `WeakSigningKey`, even when the signature itself is valid. A
  partner that signs XML with one of these keys must move to an approved EC curve or to RSA of at
  least 2048 bits. (`BACKLOG #1166`, ASVS 11.2.3)
