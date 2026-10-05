- **The Email destination refuses a body it cannot encode without naming any of it.** A payload
  the configured `encoding` cannot encode raised a bare `UnicodeEncodeError`. Its text named a
  character of the message, and its `.object` held the whole payload. The delivery worker would
  have recorded that text as an internal error in the stored error column, or stopped the lane
  under the STOP policy. The destination now encodes through the shared `encode_wire_body`, as
  Direct does: an unencodable body is a permanent `encoding` refusal that names the codec and a
  position, carries no exception chain, and dead-letters on the first attempt.
