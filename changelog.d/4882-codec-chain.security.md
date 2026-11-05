- **The store cipher build leaves no byte of a codec error in its refusal, whatever the error's
  class or where the codec error sits on its chain.** A key source error whose own text was built
  from a codec error, one whose codec error was a context beside a cause, and a `RuntimeError`
  such as a `KeyProviderError` or `DpapiError` that chained one each kept the byte the codec error
  quotes. Each is now refused with a fixed text naming its class and the codec error without its
  bytes, and with no chain: a `ValueError` as `StoreCipherConfigError`, any other class as
  `KeyProviderError`, which every command that opens the store reports as a key that could not be
  resolved, exit 2. An error with no codec error on it is unchanged. The PostgreSQL store's TLS
  context wrap reads the same chain. (`BACKLOG #4882`, `BACKLOG #3471`)
- **`check-privileges`' AD bind probe keeps a hop refusal's text only when the LDAPS revocation
  guard raised it.** Any other hop refusal on that probe, at least one from resolving a Vault-held
  bind password, is named by its type, as on the Vault probe. (`BACKLOG #4883`, `BACKLOG #3471`)
