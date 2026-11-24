- **An anonymizer salt UTF-8 cannot encode is refused without quoting the salt in the message or
  carrying it on the exception chain.** Such a salt, as an undecodable byte (POSIX) or an unpaired
  surrogate (Windows) in an environment variable becomes, was refused with the codec's own error,
  which quoted that character in its message and kept the whole salt on its `object` attribute. It
  is now refused with a `ValueError` that quotes none of it and has no chained exception. The
  refusing frame's locals still hold the salt, so a traceback renderer that captures locals would
  print it. `python -m tee anonymize-captures` names the variable the salt came from when the keyer
  refuses it, and the too-short refusal now names the generator. Both the toolkit keyer and the
  copy vendored into the tee changed (BACKLOG #4652).
