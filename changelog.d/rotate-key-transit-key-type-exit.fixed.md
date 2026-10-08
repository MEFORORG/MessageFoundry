- **`rotate-key` refuses a Vault Transit key of an unsupported type with a clean exit 2.** In
  `vault_transit` mode with a local key set, the Transit key-type check runs while the store opens.
  Its refusal escaped the command's handlers, so the command exited 1 through the last-resort hook.
  It now prints the refusal and exits 2, as the other key-resolution failures do. No command moves
  Transit ciphertext between keys yet; the refusal still says so.
