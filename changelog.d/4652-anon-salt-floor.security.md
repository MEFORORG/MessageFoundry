- **The anonymizer salt's length floor is stated in bytes, and its refusals withhold the salt.**
  The keyer names its 16-character floor as 16 bytes, the length of a 128-bit key, and says that
  length is not entropy. A salt holding a character UTF-8 cannot encode, such as an undecodable
  byte in an environment variable, was refused with the codec's own error, which quoted that
  character of the salt; it is now refused with a message that does not, and with no chained
  codec error. `python -m tee anonymize-captures` names the variable the salt came from in its
  refusal. Both the toolkit keyer and the copy vendored into the tee changed (BACKLOG #4652).
