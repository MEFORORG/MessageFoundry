- **An injected message records its control id, type and summary.** `Engine.inject_message` stored
  none of the three, so an operator upload or resend read blank in the message list. It now reads
  them as a listener does. A value a store column could not hold is stored as none, and the inject
  still succeeds. The summary is not built when the fields it reads total over 16,384 characters or
  their escapes could add over 4,096, which bounds the memory a label can cost. Pass-through
  connections and operator edit-resubmit are unchanged by this entry. (BACKLOG #5707)
