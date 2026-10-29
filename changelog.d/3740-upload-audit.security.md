- **An uploaded-file delete that the shutdown drain cancels now still writes its `upload.delete`
  audit row, and a row it cannot land is logged at ERROR by `file_id`.** The drain's cancel used
  to cut the delete short between its unlink and its row, or inside the row's write, which would
  leave a removed file with no row and no log line. The cancel now waits for both as long as the
  drain's grace allows. A delete refused as missing or unreadable, which removed nothing, logs no
  lost row. (vault BACKLOG #3740 item 1)
- **An upload whose `upload.create` call failed now gets an `upload.delete` row when its file is
  removed.** The failed call cannot tell a row that never landed from one that committed and then
  raised, so before, a committed row could name a file that was removed with no row saying so. The
  row is attributed to `system`; the uploads row of [PHI.md](../docs/PHI.md) says where its
  contents and limits are stated. (vault BACKLOG #3740 item 2)
