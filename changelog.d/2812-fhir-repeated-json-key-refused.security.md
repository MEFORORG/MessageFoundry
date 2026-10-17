- **`FhirPeek.parse` now refuses a FHIR body in which a JSON object repeats a key, and so does
  every path that peeks with it.** A body for a single-resource interaction, such as create, update
  or a conditional one, that repeats a key is dead-lettered with code `bad-body`, and nothing is
  sent. A Router that peeks such a body takes the error path, and a `fhir_lookup` whose reply
  repeats a key fails. A wrapped update's 2xx reply that repeats a key is a permanent refusal, code
  `reply-repeats-a-key`, and is not recorded as delivered. The text of the `bad-body` refusal now
  names which check fired. A `transaction` or `batch` Bundle was already refused for a repeated key
  (vault BACKLOG #2804). Other reads still keep the last of two equal keys, at least
  `FhirResource.parse`, `RawMessage.json()` and the classification of other FHIR replies. See
  [CONNECTIONS.md](../docs/CONNECTIONS.md), "Interactions". (`vault BACKLOG #2812`)
