# Operator API input validation

**This page defines what the engine's operator API accepts for each kind of data item you send it.**
It covers the control plane: the ids, connection names, time bounds and search terms an operator or a
client sends to the engine. It does not cover message payloads. Those are the data plane, and they
have their own documents: [HL7-VALIDATION.md](HL7-VALIDATION.md) and [CODESETS.md](CODESETS.md).

The rules live in one module, [`messagefoundry/api/validation.py`](../messagefoundry/api/validation.py).
Everything below is quoted from it, and `tests/test_api_input_validation.py` fails if this page and
that module ever disagree. The connection-name pattern is the one exception to where it is written:
it is defined in [`messagefoundry/connection_names.py`](../messagefoundry/connection_names.py) and
imported by that module, because the config loader enforces the same rule.

A value that breaks one of these rules gets an HTTP 422 with the field named. The engine refuses it
before the value reaches a database query, a filesystem path, a log line or a CSV export.

---

## The rules

| Data item | What it may be | Where you send it |
|---|---|---|
| Resource id | Exactly 32 lowercase hex characters | `message_id`, `file_id`, `approval_id`, `preset_id`, `user_id`, and each entry of an export `ids` list |
| Digest id | Exactly 64 lowercase hex characters | `attachment_id`, `session_id` |
| Custom role id | `custom:` then 32 lowercase hex characters | `role_id` on the `/roles/custom` routes |
| Role id | A lowercase word, or a custom role id | Each entry of a `roles` list |
| Permission id | `area:action`, lowercase letters and underscores | Each entry of a `permissions` list |
| Connection name | A letter, then letters, digits, `_` and `-`, up to 256 characters | `{name}` in a path, and `channel_id`, `destination_name`, `to`, `source`, `connection` |
| Channel-scope entry | A connection name, or the all-channels token `*` on its own | Each entry of the `channels` list on `PUT /users/{user_id}/channel-scope` |
| Time bound | A finite number from 0 up to 4102444800 (2100-01-01 UTC) | `received_from`, `received_to`, `since`, `until` |
| Free text | Printable text, no control characters, up to 512 characters | `content`, `field_value` |
| Vocabulary token | Letters and underscores, up to 64 characters | `status`, and each `kind` on the event routes |
| Message type | Printable text, no control characters, up to 64 characters | `message_type` |
| Control id | Printable text, no control characters, up to 256 characters | `control_id`, and `actor` on the audit routes |
| HL7 field path | A three-character segment id, a field number, then optional component and subcomponent numbers, such as `PID-3` or `PID-5.1` | `field_path` |
| Email address | One `@`, a local part with no spaces, and a dotted domain, up to 254 characters | `recipient_override` |
| Idempotency key | Printable text, no control characters, 1 to 256 characters | `idempotency_key` on `POST /messages/{message_id}/resend` and `POST /messages/{message_id}/edit-resend` |
| Audit action filter | Printable text, no control characters, up to 128 characters | `action` on `GET /audit` and `GET /audit/export` |
| Display label | Printable text, no control characters, up to 128 characters | `name` on `POST /search/presets` |
| Filesystem path | Printable text, no control characters, up to 4096 characters | `config_dir` on `POST /config/reload`, and `archive` on `POST /dr/activate` |
| Layered preset ids | Resource ids joined by single commas with no spaces, up to 1024 characters in all | `presets` on `GET /search/layered` |

The email-address row covers `recipient_override` only. The account email fields follow a different
rule, set out under [Items checked a second time](#items-checked-a-second-time-behind-the-route).

"Printable text, no control characters" means every character except the C0 range, DEL, and the C1
range. In practice: no NUL, no tab, no carriage return, no line feed.

Some lists have a length of their own. A message export may name at most 100000 ids explicitly, the
same ceiling as its `limit`. An events request may filter on at most 32 event kinds. A directory
group mapping, and a counter-reset request, may carry at most 1000 entries.

**Which words and codes exist is not decided here.** The role names, the permission catalog and the
status vocabulary belong to the engine. These rules decide only the shape a value may take, so a
value that could not be a member is refused early and one that merely does not exist gets a 404.

---

## Items checked a second time, behind the route

**Some items pass two checks: the request model first, then the service the route calls.** The model
refuses with a 422. The service refuses with a 400, unless a line below gives another code. The
table above gives the first check for five of these items. This section gives the whole rule for
each, and names the code that holds it.

### Idempotency key

The client mints this value, so the client chooses its alphabet. The engine asks only for printable
text of 1 to 256 characters. The field is required on both routes, and the model is the only check.

A key the engine has seen before for the same request is not an error. The engine answers
`duplicate` and queues nothing new. The same key on a different request gets a 409.

### Audit action filter

`action` narrows the audit list to one event name, such as `user.updated`. The rule is printable
text of up to 128 characters. The model is the only check, and a name no event carries returns an
empty list.

### Preset name

`name` on `POST /search/presets` is a label the operator types. The rule is printable text of up to
128 characters. A name the caller already uses replaces that preset. It is not refused.

### DR archive path

`archive` on `POST /dr/activate` names a file on the standby. The model checks the shape: printable
text of up to 4096 characters. **The control is the second check, which confines the path.**

1. The path must lie under the directory `[dr].seed_dir` names.
2. With `[dr].seed_dir` unset, a request may name no archive at all.

A refused path aborts the activation with a 422. Every such refusal carries the same message, which
names the setting and no part of the path. The rule is in `DrCoordinator._confine_request_archive`, in
[`messagefoundry/pipeline/dr.py`](../messagefoundry/pipeline/dr.py).

### Layered preset ids

`presets` on `GET /search/layered` is one value holding several resource ids. The model checks the
shape in the table above. The route then splits the value and applies two more rules.

1. At most 8 ids may be layered. A longer list gets a 400.
2. Each id must name a preset the caller owns. Any other id gets a 404.

### Notification address

The engine sends an account's security notices to its notification address. At least these four
fields can set one:

| Field | Route |
|---|---|
| `email` (required) | `POST /users` |
| `email` | `POST /me/notify-email` |
| `notify_email` | `PATCH /users/{user_id}` |
| `notify_email` | `POST /users/directory` |

The model allows up to 256 characters. The service then strips the spaces around the value and
requires one plain mailbox. That means all of these:

1. The value is not blank.
2. It has exactly one `@`, with text on both sides.
3. Every character is printable, and none is whitespace.
4. It holds none of `,` `;` `<` `>` `"` `(` `)` `[` `]` `:` `\`.
5. The whole address is at most 254 characters, and the part before the `@` is at most 64.
6. The part before the `@` is letters, digits and ``#$&'*+-^_`{}~``, in runs split by single dots.
   It does not start with a hyphen.
7. The domain is shaped like a host name with at least two labels. The exact rule is
   `domain_shape_problem`, in [`messagefoundry/domainshape.py`](../messagefoundry/domainshape.py).
8. Python's `email.utils.parseaddr` reads the address back unchanged.

Rules 1 to 4 are `_require_single_mailbox` and `_is_single_mailbox`, in
[`messagefoundry/auth/service.py`](../messagefoundry/auth/service.py). Rules 5 to 8 are
`envelope_address_problem`, in
[`messagefoundry/transports/email.py`](../messagefoundry/transports/email.py). That function is the
rule the mail sender applies to every recipient, so an address accepted here can be sent to.

Three routes add a rule of their own:

- `PATCH /users/{user_id}` leaves the address alone when `notify_email` is omitted. An explicit
  `null` gets a 400, because the address can be changed but not cleared. A value equal to the stored
  address is accepted without a second check.
- `POST /users/directory` requires `notify_email` when the directory supplies no usable address, and
  refuses it when the directory supplies one.
- `POST /me/notify-email` fills a missing address only. An account that already has a different one
  gets a 409.

### User email

`email` on `PATCH /users/{user_id}` is the profile address. It does not move the notification
address.

**This field has a length rule and no shape rule.** The model allows up to 256 characters. Neither
the model nor the service checks what the characters are, so the engine stores the value as sent.
Omitting the field keeps the stored value, and an explicit `null` clears it.

`email` on `POST /users` is a different case. It seeds the notification address as well, so it takes
the whole notification-address rule above.

### Federated subject

`subject` on `PUT /users/{user_id}/federated-identity` is the `sub` value the identity provider
issues for the account.

1. The model requires 1 to 255 characters.
2. The service requires printable ASCII with no space at the start or the end. A space inside the
   value is allowed.

The engine matches this value exactly against a verified token, so a stray space would make a
binding nobody could present. The second rule is in `AuthService.bind_federated_subject`.

The same route, and `DELETE` on the same path, also take `expected_issuer` and `expected_subject`.
Both keys are required and each may be `null`. They carry a length rule only: up to 256 characters
for the issuer and up to 255 for the subject. They need no shape rule, because the engine only
compares them with the stored pair. A pair that differs gets a 409 and nothing changes.

There is no issuer field to send. The service binds under the issuer `[auth].oidc_issuer` names.

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

**One list holds a value that is not a connection name, and it stops there.** A user's `channels`
scope may carry `*`, the all-channels grant. That grant used to be spelled by sending no list at all;
BACKLOG #1152 made an absent scope deny, so `*` is now the only way to ask for the whole estate, and
a rule that refused it would refuse the field's own purpose. The token is admitted in that one list
and nowhere else. Widening the connection-name rule instead would let `*` through `{name}` on a path
and through every `channel_id` filter, where nothing reads it as a wildcard. It is a whole value with
its own anchors, so `IB_*` and `*ADT` are still refused, and every other member of the list is still
exactly a connection name.

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

**At least three items keep a rule that is not a pattern, and the pattern in front of them does not
replace it.** The first two are below. The third is the DR archive path, under
[Items checked a second time](#items-checked-a-second-time-behind-the-route).

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

**The console reaches its handlers in process, so nothing here runs unless the console runs it.** The
web console is mounted inside the engine and calls the handler callables directly rather than over
HTTP. A direct call runs no request validation at all. Where the console builds an engine request
model, these rules apply because the model carries them. Where it hands a handler plain values, the
console applies the rule itself, route by route.

That is a choice, not a law, and the alternative was considered. Each handler the console calls *is*
a route function, and its signature already carries these rules, so a wrapper at the seam could read
each signature and validate the console's arguments before every call — closing every handler at
once, including the ones no one has worked through yet. Two costs decided against it for now. The
wrapper has to skip the parameters that are not data (`engine`, `request`, `identity`), and whatever
rule does the skipping will one day skip a real parameter without saying so — the same silent-skip
failure the seam already documents for permission checks. And it cannot produce the 400 re-render
below, because it never sees the form. Revisit it when the remaining console parameters are closed.

**The console applies these rules on its message, dead-letter, event and connection-control routes.**
It reuses the annotated types this module defines rather than restating their patterns, so narrowing
a rule's pattern here narrows both surfaces at once. Which parameter carries which rule is pinned as
a table in `packaging/messagefoundry-webconsole/tests/golden/ui_input_rules.txt`, generated from the
live routes, and behavioural tests in `test_ui_input_rules.py` check that each route still refuses.
The table cannot see the second thing and the tests cannot see the first, so both are needed.

A refusal takes one of two shapes, and which one depends on who produced the value:

| Where the value comes from | Shape |
|---|---|
| A filter form an operator types into (the message log, content search, the event log) | 400, and the page re-renders with the reason and what they typed |
| A path segment or link the console itself minted (the dead-letter filters, the five per-name connection routes) | 422, the same answer the engine API gives |
| A name list in a bulk POST body (bulk control, bulk purge) | The batch continues and the refused selection gets its own outcome row |

**Two console values share a name with a rule here and are not that rule.** The console's
`received_from` and `received_to` are `datetime-local` strings from a browser form, not the epoch
numbers the engine API takes. The console parses each one and then applies this page's time-bound
rule to the result, so the two surfaces refuse the same instants by different routes.

**Two console parameters carry no rule on purpose, and it is an audit control that decides it.** The
bulk purge confirm page's `dest`, and the name in each of the two bulk POST bodies. FastAPI checks a
parameter before the handler runs, so a refusal there would return before the handler writes the row
that records a channel-scoped operator reaching for a connection outside their scope — measured, a
well-formed out-of-scope name writes that row and a malformed one wrote none, which means sending a
bad name would delete your own security event. Nothing is lost: the confirm page already narrows
`dest` to the live, quiesced outbound connections, and the two bulk bodies apply the rule for
operators whose attempt would not have been audited anyway.

**Other console parameters carry a length bound, or nothing, and no rule.** The golden table lists
every one of them, marked `-`. They include at least the uploaded-log filters and resend target, the
dead-letter replay path segments, the layered-search preset ids, and the engine-minted ids on `/ui`
paths. Closing those is separate work, and the table is what makes each one visible: read it rather
than this paragraph for the current set.

**Several hundred response fields carry no rule, and they should not.** A response field is something
the engine emits, not something you send. It is not an input, so an unbounded response field is not a
gap. Counting one as a gap manufactures a number that cannot be closed.

**These other input surfaces are not covered here.** The engine's inbound HTTP listener, the command
line, and the `connections.toml` file each accept operator input and each carry their own rules or
their own absence of rules. Establishing what they should be is separate work.

**The config loader enforces the connection-name rule too (BACKLOG #1107).** A connection declared in
code or in `connections.toml` under a name this page rejects now fails the load with a `WiringError`
that names it. Before, it loaded, and the API could not reach it. Why the loader must hold the API's rule is
stated once, in [`messagefoundry/connection_names.py`](../messagefoundry/connection_names.py). Both
layers read that one pattern, and `tests/test_connection_name_rule.py` fails if they diverge.
Nothing in the shipped samples or harness has such a name; only that test file declares one, to
prove the refusal.

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
