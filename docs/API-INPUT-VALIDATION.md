# Operator API input validation

**This page defines what the engine's operator API accepts for each kind of data item you send it.**
It covers the control plane: the ids, connection names, time bounds and search terms an operator or a
client sends to the engine. It does not cover message payloads. Those are the data plane, and they
have their own documents: [HL7-VALIDATION.md](HL7-VALIDATION.md) and [CODESETS.md](CODESETS.md).

The rules live in one module, [`messagefoundry/api/validation.py`](../messagefoundry/api/validation.py).
Everything below is quoted from it, and `tests/test_api_input_validation.py` fails if this page and
that module ever disagree.

A value that breaks one of these rules gets an HTTP 422 with the field named. The engine refuses it
before the value reaches a database query, a filesystem path, a log line or a CSV export.

---

## The rules

| Data item | What it may be | Where you send it |
|---|---|---|
| Resource id | Exactly 32 lowercase hex characters | `message_id`, `file_id`, `approval_id`, `preset_id`, `user_id`, and each entry of an export `ids` list |
| Digest id | Exactly 64 lowercase hex characters | `attachment_id`, `session_id` |
| Custom role id | `custom:` then 32 lowercase hex characters | `role_id` on the `/roles/custom` routes |
| Connection name | A letter, then letters, digits, `_` and `-`, up to 256 characters | `{name}` in a path, and `channel_id`, `destination_name`, `to`, `source`, `connection` |
| Time bound | A finite number from 0 up to 4102444800 (2100-01-01 UTC) | `received_from`, `received_to`, `since`, `until` |
| Free text | Printable text, no control characters, up to 512 characters | `content`, `field_value` |
| Vocabulary token | Letters and underscores, up to 64 characters | `status`, and each `kind` on the event routes |
| Message type | Printable text, no control characters, up to 64 characters | `message_type` |
| Control id | Printable text, no control characters, up to 256 characters | `control_id`, and `actor` on the audit routes |
| HL7 field path | A three-character segment id, a field number, then optional component and subcomponent numbers, such as `PID-3` or `PID-5.1` | `field_path` |
| Email address | One `@`, a local part with no spaces, and a dotted domain, up to 254 characters | `recipient_override` |

"Printable text, no control characters" means every character except the C0 range, DEL, and the C1
range. In practice: no NUL, no tab, no carriage return, no line feed.

Two lists have a length of their own. A message export may name at most 100000 ids explicitly, the
same ceiling as its `limit`. An events request may filter on at most 32 event kinds.

---

## Why the rules are drawn where they are

**An id is minted by the engine, never typed by a person.** Every id above comes back to you in an
earlier response. So the rule can be exact, and being exact is what makes it useful: no `.`, `/`, `\`
or NUL survives it, which is why an id can never be read as a file path. The upload store already
shipped this rule for one id; the module generalizes that rule rather than writing a second one.

**A connection name is wider than the VS Code extension allows, on purpose.** The extension's wizard
rejects a hyphen. Four connection names shipped in this repository contain one, so adopting the
extension's narrower rule would make four connections unreachable through the API. The rule here
admits them. What it still excludes earns its place: path characters, whitespace, control characters,
and the quoting characters a value would need to carry meaning into a URL or a query.

**A time bound must be finite, and that was the gap.** A lower bound of zero does not exclude
infinity. Before this rule, `?received_from=inf` was accepted and reached a database query, and the
audit routes accepted `?since=nan` as well. A NaN bound is the worse of the two, because every
comparison against it is false, so the filter would return nothing rather than fail.

**Free text can only be ruled on by what it must not contain.** A search term is whatever an operator
typed to find a patient, so no alphabet rule fits it. What does fit is the control characters. These
terms reach the search audit record, the application log and, through the audit export, a CSV file. A
carriage return or a line feed in one of them would forge a second record in any of the three.

That rule costs one capability, and this page states it rather than hiding it: a search term can no
longer span an HL7 segment separator, because that separator is a carriage return. The console's
search box is a single-line input, so no shipped client could send one.

**Two items keep a rule that is not a pattern, and the pattern in front of them does not replace it.**

1. A reload `config_dir` is confined by an allow-list, because the loader executes Python from that
   directory. The shape rule adds the NUL a path check can be truncated by. **The allow-list is still
   the control.**
2. A log `level` is checked against the engine's own level names, which is why a wrong one gets a
   400. The shape rule only keeps an arbitrary-length string out of that error message.

**One rule is documented here but enforced elsewhere.** The HL7 field path grammar belongs to
`messagefoundry.parsing.peek.parse_path`, and `messagefoundry.store.content_search.make_spec` applies
it at every point the API accepts a `field_path`. A malformed path is already a 400. Copying that
pattern into the API models would create a second definition of a rule that has one.

---

## What these rules do not cover

**The data plane is untouched.** A message body reaching the engine over MLLP, a file, TCP, HTTP or a
database poll is validated by the parsing and connector rules, not by anything on this page. The
edit-and-resubmit body is the one place a message body arrives over the API, and it deliberately
keeps a size bound and no alphabet rule: an HL7 v2 body is separated by carriage returns.

**The web console declares its own bounds for the same items.** The console's `/ui` routes carry at
least 17 of their own parameter declarations for items this page governs, and they are hand-written
copies rather than references to this module. They can drift. Two of them are a different data item
that happens to share a name: the console's `received_from` and `received_to` are `datetime-local`
strings from a browser form, not the epoch numbers the engine API takes.

**The console reaches some handlers in process, which skips this validation entirely.** The console
is mounted inside the engine and calls a set of handler callables directly rather than over HTTP. A
direct call runs no request validation. Where the console builds an engine request model, these rules
do apply. Where it calls a handler with plain values, they do not.

**Several hundred response fields carry no rule, and they should not.** A response field is something
the engine emits, not something you send. It is not an input, so an unbounded response field is not a
gap. Counting one as a gap manufactures a number that cannot be closed.

**These other input surfaces are not covered here.** The engine's inbound HTTP listener, the command
line, and the `connections.toml` file each accept operator input and each carry their own rules or
their own absence of rules. Establishing what they should be is separate work.

**The engine does not yet enforce the connection-name rule at registration.** A connection registered
in code or in `connections.toml` under a name this page rejects would be created and then would not
be reachable through the API. Nothing in the shipped samples, harness or tests has such a name.

---

## Two questions this page does not answer

**Does the standard ask that rules be written down, or that they exist to be written?** This page and
the module behind it take the harder reading and do both. Whether the softer reading would also have
been acceptable is a method question. It is recorded in BACKLOG #1108 and is not settled here.

**Does the existing HL7 and codeset documentation satisfy the same requirement for the data plane?**
That would make this a control-plane question rather than a whole-product one. It is the second open
question in that item, and this page deliberately does not fold the data plane into its answer.

---

## The generated schema is not this document

The engine can produce an OpenAPI schema, and that schema does carry every pattern above. It is off
by default, and turning it on would not be a documentation change. A schema lists types and
constraints. It does not say why a rule is drawn where it is, what it costs, or what it does not
cover, which is what the three sections above are for. Turning it on widens the network surface, so
leave `[api].expose_docs` at its default unless you have a separate reason.
