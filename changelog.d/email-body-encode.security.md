- **The Email destination refuses a body it cannot encode without naming any of it.** Such a body
  raised a bare `UnicodeEncodeError`. Its text named a character of the message, and its `.object`
  held the whole payload. The delivery worker would have stored that text as an internal error, or
  stopped the lane under the STOP policy. The body now goes through the shared `encode_wire_body`,
  as on Direct. The refusal is permanent, names the charset and a position, and carries no
  exception chain. A second check covers the encode inside the email package, which Python 3.15
  does in a different charset for `euc-jp` and `shift_jis`.
