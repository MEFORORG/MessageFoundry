- **An operation the shutdown drain cancels under a waiting request now answers 503.** A DR
  activation, DR release, config reload, approval release or uploaded-log write whose outliving
  operation was cancelled while its request still waited raised a bare cancellation into that
  request, past every API exception handler. It now answers 503, saying the outcome is unknown,
  and an approval release cut off that way is recorded `interrupted`. (`BACKLOG #5903`)
