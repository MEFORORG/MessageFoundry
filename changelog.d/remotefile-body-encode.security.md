- **The RemoteFile destination refuses a payload it cannot encode without naming any of it.** Such a
  payload raised a bare `UnicodeEncodeError` on SFTP, FTP and FTPS uploads. Its text named a
  character of the message, and its `.object` held the whole payload. The delivery worker would have
  stored that text as an internal error, or stopped the lane under the STOP policy. The payload now
  goes through the shared `encode_wire_body`, as on Direct. The refusal is permanent, names the
  charset and a position, carries no exception chain, and comes before anything is sent.
