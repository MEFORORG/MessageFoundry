- **A corrupt queue cell is logged at WARNING without the cipher's refusal text.** A queue row
  whose payload is corrupt under a held key, for example bad base64 or a ciphertext too short for
  a tag, is still dead-lettered, audited and alerted with cause `corrupt`. Its report's WARNING names
  the row, its stage and the cause, and the claim's dead-letter WARNING names the error class in
  place of its text; the cipher's reason is written at DEBUG. (`BACKLOG #5982`)
