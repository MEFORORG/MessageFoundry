The **Test Bench** loads a set of HL7 messages and dry-runs them through your config — no engine,
no sending. For each message it shows the disposition (routed/unrouted/filtered/error), which
Handlers ran, and a before/after diff of the transformed message.

Use it after every Router/Handler edit to see the effect immediately, and to step through a
Handler under the Python debugger.
