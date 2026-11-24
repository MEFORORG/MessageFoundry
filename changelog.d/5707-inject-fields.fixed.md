- **An injected message records its control id, type and summary.** `Engine.inject_message` stored
  none of the three, so an operator upload or resend read blank in the message list. A control id
  over 256 or a type over 64 UTF-16 units, the narrowest backend's columns, is stored as none on
  every backend, and the inject still succeeds. The summary is not built when a PID, ORC or OBR
  line or the fields it can read run over 16,384 characters, or their escapes could add over 4,096.
  Pass-through connections and operator edit-resubmit are unchanged by this entry. (BACKLOG #5707)
