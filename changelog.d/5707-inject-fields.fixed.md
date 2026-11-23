- **An injected message records its control id, type and summary.** `Engine.inject_message` stored
  none of the three, so an operator upload or resend read blank in the message list. It now reads
  them as a listener does. A value a store column could not hold is stored as none, and the inject
  still succeeds. The summary is not built from a body over 256 KiB or one whose escapes could add
  more than 4096 characters, so an escape-heavy body cannot cost memory for a label. Pass-through
  connections and operator edit-resubmit still store none of the three. (BACKLOG #5707)
