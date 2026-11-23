# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The pynetdicom and pydicom log lines an operator may read (vault BACKLOG #6637 item 10).

Everything else those libraries log is withheld by :mod:`messagefoundry.transports.dicom`, so this
file is an allowlist: a line missing from it costs an operator a line of diagnosis, and a line wrongly
in it is a leak. Read from pynetdicom 3.0.4 and pydicom 3.0.2. ``tests/_dicom_log_census.py`` pins what
those libraries can log, so an upgrade that adds or rewords a line fails a test.

:data:`VALUE_FREE_LINES` holds whole lines with nothing interpolated. :data:`TEMPLATES` holds lines
with fields, written with ``{kind}`` slots. A slot's kind decides what happens to its text:

* ``uid``, ``quoted_uid``, ``instance``, ``title``, ``version``, ``move``: the value a peer sent. It
  stays only where the engine's check on that kind of value passes, and otherwise reads
  ``[redacted]``.
* ``name``, ``keyword``, ``codecs``: a word the library supplies, which stays only if it is in a
  closed list: :data:`ELEMENT_NAMES`, pydicom's keyword dictionary, or Python's codec names. Anything
  else reads ``[redacted]``.
* ``value``, ``hex_dump``: a value the library is refusing or flagging, or bytes it dumps. It always
  reads ``[redacted]``.
* Every other kind matches only a number or a word from the library's own fixed vocabulary, so what
  it matches stays. A field outside its pattern makes the line match no template, and so withholds it.

Matching stays linear on a peer's text: a template has at most one unbounded run that can overlap
what follows it. ``quoted_uid`` stops at a quote, and ``{indent}{hex_dump}`` is two runs over
characters neither shares.
"""

from __future__ import annotations

import functools
import re
from typing import NamedTuple

#: An unbounded run. It stops at a line break, so a value holding one matches no template and its
#: line is withheld.
_TO_LINE_END = r"[^\r\n]*"

#: The text each kind of slot may match.
_SLOT_PATTERNS = {
    "uid": _TO_LINE_END,
    "instance": _TO_LINE_END,
    "title": _TO_LINE_END,
    "version": _TO_LINE_END,
    "move": _TO_LINE_END,
    "value": _TO_LINE_END,
    "quoted_uid": r"[^'\r\n]*",
    "int": r"\d{1,10}",
    "number": r"\d{1,10}|None",
    "hex": r"[0-9A-Fa-f]{1,8}",
    "vr": r"[A-Z]{2}",
    "tag": r"[0-9A-F]{4},[0-9A-F]{4}",
    "name": r"[A-Za-z][A-Za-z /-]{0,63}",
    "keyword": r"[A-Za-z0-9]{1,64}",
    "message_type": r"[CN][-_][A-Z_-]{2,24}",
    "role": r"SCU|SCP",
    "roles": r"SCP/SCU|SCP|SCU|Default|",
    "codecs": r"[A-Za-z0-9_, -]{1,64}",
    "struct_format": r"[<>=!@]?[A-Za-z0-9]{1,8}",
    "see_url": r"https://dicom\.nema\.org/[A-Za-z0-9/._#-]{0,120}",
    "indent": r" +",
    "hex_dump": r"[0-9a-f]{2}(?:  [0-9a-f]{2})*",
    "status_word": r"Success|Failure|Warning|Cancel|Pending|Unknown",
    "presence": r"Present|None",
    "yes_none": r"Yes|None",
    "priority": r"Low|Medium|High",
    "standalone_charset": r"ISO_IR 192|GBK|GB18030",
    "refusal_reason": (
        r"must be str|must not exceed 16 characters|must only contain ASCII characters"
        r"|must not contain control characters or backslashes|must be pydicom\.uid\.UID"
        r"|UID is non-conformant|must not be an empty str|must not exceed 64 characters"
    ),
    "assoc_result": (
        r"Accepted|Rejected Permanent|Rejected Transient|Rejected \(Permanent\)"
        r"|Rejected \(Transient\)|\(no value available\)"
    ),
    "assoc_source": (
        r"Service User|Service Provider \(ACSE\)|Service Provider \(Presentation\)"
        r"|DUL service-user|DUL service-provider \(ACSE related\)"
        r"|DUL service-provider \(presentation related\)|DUL service-provider|Reserved"
        r"|\(no value available\)"
    ),
    "assoc_reason": (
        r"No reason given|Application context name not supported"
        r"|Calling AE title not recognised|Called AE title not recognised"
        r"|Protocol version not supported|Temporary congestion|Local limit exceeded|Reserved"
        r"|Unrecognised PDU|Unexpected PDU|Unrecognised PDU parameter|Unexpected PDU parameter"
        r"|Invalid PDU parameter value|\(no value available\)"
    ),
    "context_result": (
        r"Accepted|User Rejection|Provider Rejection|Rejected - Abstract Syntax Not Supported"
        r"|Rejected - Transfer Syntax Not Supported|\(no value available\)"
    ),
    "identity_type": r"Username/Password|Username|Kerberos|SAML|JSON Web Token",
    "dataset_encoding": r"(?:Deflated )?(?:Little|Big) Endian (?:Implicit|Explicit)",
}

#: The slots whose text is never kept.
ALWAYS_REDACTED_KINDS = frozenset({"value", "hex_dump"})
#: The slots whose text is a peer's value: each is checked, or never kept.
PEER_VALUE_KINDS = ALWAYS_REDACTED_KINDS | {
    "uid",
    "quoted_uid",
    "instance",
    "title",
    "version",
    "move",
    "name",
    "keyword",
    "codecs",
}

#: The element names pynetdicom passes to ``set_uid`` and ``set_ae``, and the two it names in its own
#: non-conformant lines. A test pins them against the library.
ELEMENT_NAMES = frozenset(
    {
        "Abstract Syntax Name",
        "Affected SOP Class UID",
        "Affected SOP Instance UID",
        "Application Context Name",
        "Called AE Title",
        "Calling AE Title",
        "Implementation Class UID",
        "Implementation Version Name",
        "Move Destination",
        "Move Originator AE Title",
        "Related General SOP Class UID",
        "Requested SOP Instance UID",
        "SOP Class UID",
        "Service Class UID",
        "Transfer Syntax Name",
        "abstract_syntax",
        "ae_title",
        "implementation_class_uid",
        "implementation_version_name",
        "require_calling_aet",
    }
)

_SLOT = re.compile(r"\{([a-z_]+)\}")

#: Lines with fields, tried in order, so a line's longer form comes before the one with its tail cut.
TEMPLATES: tuple[str, ...] = (
    # --- Association and message progress, the lines an operator reads first ---
    "Sending Store Request: MsgID {int}",
    "Sending Store Request: MsgID {int}, (CT)",
    "Sending Store Request: MsgID {int}, (MR)",
    "Sending Echo Request: MsgID {int}",
    "Received Echo Request (MsgID {int})",
    "Received Echo Response (Status: 0x{hex} - {status_word})",
    "Received Store Response (Status: 0x{hex} - {status_word})",
    "Received DIMSE message with invalid or rejected context ID: {int}",
    "Result: {assoc_result}, Source: {assoc_source}",
    "Reason: {assoc_reason}",
    # --- Protocol errors, each naming a number or a fixed word ---
    "Received an invalid {message_type} response from the peer",
    "Received an unexpected {message_type} message from the peer",
    "Received unexpected {message_type} service message",
    "{message_type} message received during association release, ignoring",
    "Unknown status value returned by the EVT_C_STORE handler: 0x{hex}",
    "The received PDU is shorter than expected ({int} of {int} bytes received)",
    "Unknown PDU type received '0x{hex}'",
    "A-ASSOCIATE-RQ: Unsupported protocol version '0x{hex}'",
    "Invalid A-ABORT-RQ 'Source' {int}",
    "Invalid A-ABORT-RQ 'Reason/Diagnostic' {int}",
    "Invalid A-ASSOCIATE 'Result' {int}",
    "Invalid A-ASSOCIATE 'Result Source' {int}",
    "Invalid Presentation Context Item 'Result' {int}",
    "Invalid 'User Identity Type' {int}",
    "Non-conformant VM {int} for '{keyword}', taking the first value",
    "maximum_pdu_size set to {int}",
    'pydicom.read_dataset() TransferSyntax="{dataset_encoding}"',
    # --- A SOP class or transfer syntax the peer named ---
    "No presentation context for '{quoted_uid}' has been accepted by the peer for the {role} role",
    "No presentation context for '{quoted_uid}' has been accepted by the peer with "
    "'{quoted_uid}' transfer syntax for the {role} role",
    "No presentation context for '{value}",
    "No supported service class available for the SOP Class UID '{quoted_uid}', please see the "
    "pynetdicom.sop_class.register_uid() function if you need to add support for a private, "
    "retired or otherwise unknown SOP Class UID",
    "No supported service class available for the SOP Class UID '{value}",
    # --- What pynetdicom says as it refuses or flags a value ---
    "Invalid '{name}' value - must not consist entirely of spaces",
    "Invalid '{name}' value - must not be an empty str",
    "Invalid '{name}' value '{value}' - {refusal_reason}",
    "Invalid '{name}' value '{value}",
    "Non-conformant '{name}' value '{value}'",
    "Non-conformant '{name}' value '{value}",
    "The {name} '{value}' is non-conformant",
    "A UID has been added to 'transfer_syntax' that is not a transfer syntax: '{value}'",
    "A UID has been added to 'transfer_syntax' that is not a transfer syntax: '{value}",
    "Unable to decode '{value}' using the {codecs} codec(s)",
    "Unable to decode '{value}",
    # --- What pydicom says as it refuses or flags a value ---
    "The value length ({int}) exceeds the maximum length of {int} allowed for VR {vr}.",
    "The value length ({int}) exceeds the maximum length of {int} allowed for VR {vr}. Invalid "
    "value for VR {vr}: {value}. Please see <{see_url}> for allowed values for each VR.",
    "The value length ({int}) exceeds the maximum length of {int} allowed for VR {vr}. Invalid "
    "value for VR {vr}: {value}",
    "Invalid value for VR {vr}: {value}. Please see <{see_url}> for allowed values for each VR.",
    "Invalid value for VR {vr}: {value}",
    "Incorrect value for Specific Character Set '{value}",
    "Unknown encoding '{value}' - using default encoding instead",
    "Unknown encoding '{value}",
    "Value '{standalone_charset}' for Specific Character Set does not allow code extensions, "
    "ignoring: {value}",
    'Value "{value}" is not valid for elements with a VR of {vr}\n'
    "Set reading_validation_mode to WARN or IGNORE to bypass",
    'Value "{value}" is not valid for elements with a VR of {vr}',
    "Expected total bytes to be an even multiple of bytes per value. Instead received {value} "
    "with length {int} and struct format '{struct_format}' which corresponds to bytes per value "
    "of {int}.",
    "could not convert string to float: {value}",
    "invalid literal for int() with base {int}: {value}",
    "({tag}) '{value}' is not a valid private creator",
    "\"({tag}) \\'{value}' is not a valid private creator\"",
    "\"({tag}) '{value}' is not a valid private creator\"",
    # --- pynetdicom's DEBUG dumps, by label ---
    "{indent}{hex_dump}",
    "Their Implementation Class UID:      {uid}",
    "Their Implementation Class UID:    {uid}",
    "Our Implementation Class UID:      {uid}",
    "Their Implementation Version Name:   {version}",
    "Their Implementation Version Name: {version}",
    "Our Implementation Version Name:   {version}",
    "Application Context Name:    {uid}",
    "Calling Application Name:    {title}",
    "Called Application Name:     {title}",
    "Responding Application Name: {title}",
    "Their Max PDU Receive Size:  {int}",
    "Our Max PDU Receive Size:    {int}",
    "  Context ID:        {int} (Proposed)",
    "  Context ID:        {int} ({context_result})",
    "  Context ID:        {int}",
    "  Abstract Syntax:   ={uid}",
    "    Abstract Syntax: ={uid}",
    "    Accepted Transfer Syntax: ={uid}",
    "      ={uid}",
    "    Service Class: ={uid}",
    "  SOP Class: ={uid}",
    "    Accepted SCP/SCU Role: {roles}",
    "    Proposed SCP/SCU Role: {roles}",
    "  Maximum Invoked Operations:     {int}",
    "  Maximum Performed Operations:   {int}",
    "  Authentication Mode: {int} - {identity_type}",
    "  Username: {value}",
    "  Password: {value}",
    "  Kerberos Service Ticket (not dumped) length: {int}",
    "  SAML Assertion (not dumped) length: {int}",
    "  JSON Web Token (not dumped) length: {int}",
    "User Identity Negotiation Response: {yes_none}",
    "Abort Source: {assoc_source}",
    "Abort Reason: {assoc_reason}",
    "Result:    {assoc_result}",
    "Source:    {assoc_source}",
    "Reason:    {assoc_reason}",
    "Message ID                    : {int}",
    "Message ID Being Responded To : {int}",
    "Presentation Context ID       : {int}",
    "Affected SOP Class UID        : {uid}",
    "Affected SOP Class UID     : {uid}",
    "Requested SOP Class UID       : {uid}",
    "Affected SOP Instance UID     : {instance}",
    "Requested SOP Instance UID    : {instance}",
    "Move Originator               : {move}",
    "Move Destination              : {title}",
    "Priority                      : {priority}",
    "Data Set                      : {presence}",
    "Identifier                    : {presence}",
    "Attribute List                : {presence}",
    "Attribute Identifier List     : {presence}",
    "Modification List             : {presence}",
    "Action Information            : {presence}",
    "Action Reply                  : {presence}",
    "Event Information             : {presence}",
    "Event Reply                   : {presence}",
    "Action Type ID                : {number}",
    "Event Type ID                 : {number}",
    "Remaining Sub-operations      : {number}",
    "Completed Sub-operations      : {number}",
    "Failed Sub-operations         : {number}",
    "Warning Sub-operations        : {number}",
    "Status                        : 0x{hex}",
    "Status                        : 0x{hex} - {status_word}",
)


class Template(NamedTuple):
    """One entry of :data:`TEMPLATES`, compiled. Group ``n + 1`` is the text of ``kinds[n]``."""

    pattern: re.Pattern[str]
    kinds: tuple[str, ...]


def compile_template(text: str) -> Template:
    """``text`` with each ``{kind}`` slot turned into a capturing group and all else literal."""
    parts: list[str] = []
    kinds: list[str] = []
    position = 0
    for slot in _SLOT.finditer(text):
        parts.append(re.escape(text[position : slot.start()]))
        kind = slot.group(1)
        kinds.append(kind)
        parts.append(f"({_SLOT_PATTERNS[kind]})")
        position = slot.end()
    parts.append(re.escape(text[position:]))
    return Template(re.compile("".join(parts)), tuple(kinds))


@functools.cache
def compiled_templates() -> tuple[Template, ...]:
    """:data:`TEMPLATES`, compiled once, on the first line a library logs."""
    return tuple(compile_template(text) for text in TEMPLATES)


#: Whole lines with nothing interpolated, from the census. Generated: see tests/_dicom_log_census.py.
VALUE_FREE_LINES: frozenset[str] = frozenset(
    {
        # BEGIN GENERATED
        "",
        "    Proposed Transfer Syntax:",
        "    Proposed Transfer Syntaxes:",
        "    Related General SOP Class(es):",
        "    Related General SOP Classes: None",
        "  Positive Response Requested: No",
        "  Positive Response Requested: None",
        "  Positive Response Requested: Yes",
        "# DICOM Dataset",
        "# Request Identifier",
        "# Response Identifier",
        "'A_ASSOCIATE.called_presentation_address' must be an AddressInformation instance or None",
        "'datetime.datetime' doesn't allow a value of '60' for the seconds component, changing to '59'",
        "'datetime.time' doesn't allow a value of '60' for the seconds component, changing to '59'",
        "'dtype_corrected_for_endianness' is deprecated and will be removed in v4.0",
        "'pydicom.dataelem.DataElement_from_raw' is deprecated and will be removed in v4.0, please use 'pydicom.dataelem.convert_raw_data_element' instead",
        "'sop_class_uid' must be set prior to Association",
        "'transfer_syntax' contains an invalid UID",
        "'write_like_original' is deprecated and will be removed in v4.0, please use 'enforce_file_format' instead",
        "======================= INCOMING A-ASSOCIATE-AC PDU ========================",
        "======================= INCOMING A-ASSOCIATE-RJ PDU ========================",
        "======================= INCOMING A-ASSOCIATE-RQ PDU ========================",
        "======================= OUTGOING A-ASSOCIATE-AC PDU ========================",
        "======================= OUTGOING A-ASSOCIATE-RJ PDU ========================",
        "======================= OUTGOING A-ASSOCIATE-RQ PDU ========================",
        "========================== END A-ASSOCIATE-AC PDU ==========================",
        "========================== END A-ASSOCIATE-RJ PDU ==========================",
        "========================== END A-ASSOCIATE-RQ PDU ==========================",
        "========================== INCOMING DIMSE MESSAGE ==========================",
        "========================== OUTGOING DIMSE MESSAGE ==========================",
        "=========================== DEBUG - ENCODED PDU ============================",
        "=========================== DEBUG - PDU SUMMARY ============================",
        "=========================== INCOMING A-ABORT PDU ===========================",
        "=========================== OUTGOING A-ABORT PDU ===========================",
        "============================ END DIMSE MESSAGE =============================",
        "============================= END A-ABORT PDU ==============================",
        "============================= END ENCODED PDU ==============================",
        "============================= END PDU SUMMARY ==============================",
        "A non-conformant UID has been added to 'transfer_syntax'",
        "A-ABORT or A-RELEASE-RQ received during Q/R sub-operations",
        "ACSE timeout reached while waiting for response to association request",
        "ACSE timeout set to 30 seconds",
        "A_ABORT.abort_source value not set",
        "A_ABORT.provider_reason parameter not set",
        "A_ASSOCIATE.diagnostic set to an unknown value",
        "A_ASSOCIATE.presentation_context_definition_list must be a list",
        "A_ASSOCIATE.presentation_context_definition_results_list must be a list",
        "A_ASSOCIATE.result set to an unknown value",
        "A_ASSOCIATE.result_source set to an unknown value",
        "A_ASSOCIATE.user_information must be a list",
        "A_RELEASE.result must be None or 'affirmative'",
        "Abort Parameters:",
        "Aborting Association",
        "Accept Parameters:",
        "Accepted Asynchronous Operations Window Negotiation:",
        "Accepted Asynchronous Operations Window Negotiation: None",
        "Accepted Extended Negotiation:",
        "Accepted Extended Negotiation: None",
        "Accepting Association",
        "An A-RELEASE collision has occurred",
        "Applying a VOI LUT on a float input array may give incorrect results",
        "Association Aborted",
        "Association Aborted (A-P-ABORT)",
        "Association Accepted",
        "Association Rejected",
        "Association Released",
        "Association request failed: unable to connect to remote",
        "AssociationSocket instantiated with both a 'client_socket' and bind 'address'. The original socket will not be rebound",
        "Attempted to add an invalid transfer syntax",
        "Attempted to send data over closed connection",
        "Attempted to set A_ASSOCIATE.presentation_context_definition_list to a list which includes an invalid items",
        "Attempted to set A_ASSOCIATE.presentation_context_definition_results_list to a list which includes one or more invalid items",
        "Attempted to set A_ASSOCIATE.user_information to a list which includes an unsupported item",
        "Attempted to set A_P_ABORT.provider_reason to an invalid value",
        "Attempted to set Priority parameter to an invalid value",
        "C-STORE sub-operation failed.",
        "Call to dcmread()",
        "Caller passed file name",
        "Caller passed file object",
        "Connection closed before the entire PDU was received",
        "Connection closed while waiting for DIMSE message",
        "DIMSE timeout reached while waiting for message response",
        "Data Set                      : None",
        "Deferred read warning -- file modification time has changed",
        "Exception in DUL.run(), aborting association",
        "Exception in handler bound to 'evt.EVT_C_FIND'",
        "Exception in handler bound to 'evt.EVT_C_GET'",
        "Exception in handler bound to 'evt.EVT_C_MOVE'",
        "Exception in handler bound to 'evt.EVT_USER_ID'",
        "Exception in the handler bound to 'evt.EVT_C_ECHO', responding with a default 'Status' value of 0x0000 (Success)",
        "Exception in the handler bound to 'evt.EVT_C_STORE'",
        "Exception raised by pixel data handler",
        "Exception raised in handler bound to 'evt.EVT_ASYNC_OPS'",
        "Exception raised in handler bound to 'evt.EVT_SOP_COMMON'",
        "Exception raised in handler bound to 'evt.EVT_SOP_EXTENDED'",
        "Failed encoding the response 'Action Reply' dataset",
        "Failed encoding the response 'Attribute List' dataset",
        "Failed encoding the response 'Event Reply' dataset",
        "Failed encoding the response 'Identifier' dataset",
        "Failed to decode the received Identifier dataset",
        "Failed to encode the supplied 'Action Information' dataset",
        "Failed to encode the supplied 'Attribute List' dataset",
        "Failed to encode the supplied 'Modification List' dataset",
        "Failed to encode the supplied Dataset",
        "Failed to encode the supplied Identifier dataset",
        "Failed to encode the supplied dataset",
        "File is not conformant with the DICOM File Format: 'DICM' prefix is missing from the File Meta Information header or the header itself is missing. Assuming no header and continuing.",
        "Find SCP Request Identifier:",
        "Find SCP Response Identifier:",
        "Find SCP Response: 0x0000 (Success)",
        "Get SCP Request Identifier:",
        "Handler bound to 'evt.EVT_C_MOVE' yielded further (status, dataset) results but these will be ignored as the sub-operations are complete",
        "Hash not found in hashes.json. File will be updated.",
        "Implementation Class UID has not been set",
        "Invalid 'Move Originator AE Title' in C-STORE request",
        "Invalid element tag value used with the 'in' operator: tags have a maximum value of (0xFFFF, 0xFFFF)",
        "Invalid status returned by callback",
        "Invalid status returned by the EVT_C_STORE handler",
        "Invalid type returned by handler bound to 'evt.EVT_SOP_COMMON'",
        "Invalid type returned by handler bound to 'evt.EVT_SOP_EXTENDED'",
        "Invalid value in Reason field in A-ASSOCIATE-RJ PDU",
        "Invalid value in Result field in A-ASSOCIATE-RJ PDU",
        "Invalid value in Source field in A-ASSOCIATE-RJ PDU",
        "Maximum Length Received must be greater than 0",
        "Maximum Length Received must be numerical",
        "Maximum Number Operations Invoked must be an int",
        "Maximum Number Operations Performed must be an int",
        "Message Type                  : C-CANCEL RQ",
        "Message Type                  : C-ECHO RQ",
        "Message Type                  : C-FIND RQ",
        "Message Type                  : C-FIND RSP",
        "Message Type                  : C-GET RQ",
        "Message Type                  : C-GET RSP",
        "Message Type                  : C-MOVE RQ",
        "Message Type                  : C-MOVE RSP",
        "Message Type                  : C-STORE RQ",
        "Message Type                  : C-STORE RSP",
        "Message Type                  : N-ACTION RQ",
        "Message Type                  : N-ACTION RSP",
        "Message Type                  : N-CREATE RQ",
        "Message Type                  : N-CREATE RSP",
        "Message Type                  : N-DELETE RQ",
        "Message Type                  : N-DELETE RSP",
        "Message Type                  : N-EVENT-REPORT RQ",
        "Message Type                  : N-EVENT-REPORT RSP",
        "Message Type                  : N-GET RQ",
        "Message Type                  : N-GET RSP",
        "Message Type                  : N-SET RQ",
        "Message Type                  : N-SET RSP",
        "Move SCP Request Identifier:",
        "Move SCP: Unable to associate with destination AE",
        "Network timeout reached",
        "No accepted presentation contexts",
        "No exact matching context found for 'Unified Procedure Step - Push SOP Class', checking accepted contexts for other UPS SOP classes",
        "No supported Presentation Contexts have been defined",
        "None of the records in the DICOMDIR dataset contain all the query elements, consider using the 'load' parameter to expand the search to the corresponding SOP instances",
        "One or more download failures occurred, the list of matching file paths may be incomplete",
        "One or more requested presentation contexts must be set prior to association negotiation",
        "Positive Response Requested must be boolean",
        "Presentation Context:",
        "Presentation Contexts:",
        "Presentation Contexts: None",
        "Primary Field must be bytes if requesting Association, None otherwise",
        "Reading File Meta Information preamble...",
        "Reading File Meta Information prefix...",
        "Received C-CANCEL-FIND RQ from peer",
        "Received C-CANCEL-GET RQ from peer",
        "Received C-CANCEL-MOVE RQ from peer",
        "Received Get Response",
        "Received Store Request",
        "Received an invalid A-ASSOCIATE response from the peer",
        "Received an invalid C-FIND response from the peer",
        "Received an invalid DIMSE message",
        "Received invalid dataset from callback",
        "Reject Parameters:",
        "Rejecting Association",
        "Related General SOP Class Identification contains an invalid UID",
        "Related General SOP Class Identification must be a list of pydicom.uid.UID, str or bytes",
        "Releasing Association",
        "Request Parameters:",
        "Requested Asynchronous Operations Window Negotiation:",
        "Requested Asynchronous Operations Window Negotiation: None",
        "Requested Common Extended Negotiation:",
        "Requested Common Extended Negotiation: None",
        "Requested Extended Negotiation:",
        "Requested Extended Negotiation: None",
        "Requested User Identity Negotiation:",
        "Requested User Identity Negotiation: None",
        "Requesting Association",
        "SCP Role must be boolean",
        "SCU Role must be boolean",
        "SOP Class UID and Service Class Application Information must be set prior to Association negotiation",
        "SOP Class UID and Service Class UID must be set prior to Association negotiation",
        "Secondary Field must be bytes if requesting Association with User Identity Type equal to 2, None otherwise",
        "Secondary Field must be set when User Identity is 2",
        "Sending C-CANCEL request",
        "Server Response must be bytes or None",
        "Service Class Application Information should be a bytes object",
        "The C-GET request handler yielded more than 65535 matches",
        "The C-MOVE request handler yielded more than 65535 matches",
        "The EVT_C_STORE handler returned a Dataset without a 'Status' element",
        "The Implementation Class UID must be set prior to requesting Association",
        "The N-CREATE-RQ has no 'Affected SOP Instance UID' value and the 'evt.EVT_N_CREATE' handler doesn't include one in the 'Attribute List' dataset",
        "The end of the encapsulated pixel data has been reached but fewer frames than expected have been found",
        "The end of the encapsulated pixel data has been reached but fewer frames than expected have been found. Please confirm that the generated frame data is correct",
        "The end of the encapsulated pixel data has been reached but no JPEG EOI/EOC marker was found, the final frame may be be invalid",
        "The end of the encapsulated pixel data has been reached but no JPEG EOI/EOC marker was found, the returned frame data may be invalid",
        "The following presentation contexts have inconsistent scu_role/scp_role values (if one is None, both must be):\n  ",
        "The number of bytes of compressed pixel data matches the expected number for uncompressed data - check that the transfer syntax has been set correctly",
        "The number of items in (7FE0,0001) 'Extended Offset Table' and (7FE0,0002) 'Extended Offset Table Lengths' don't match - the extended offset table will be ignored",
        "The odd length pixel data is missing a trailing padding byte",
        "The overlay data length is odd and misses a padding byte.",
        "Unable to decode the received 'Action Reply' dataset",
        "Unable to decode the received 'Attribute List' dataset",
        "Unable to decode the received 'Event Reply' dataset",
        "Unable to decode the received PDU data",
        "Unable to encode the supplied 'Event Information' dataset",
        "Unable to return an ndarray that's a view on the original buffer for 8-bit pixel data encoded as OW with 'Explicit VR Big Endian'",
        "Unable to return an ndarray that's a view on the original buffer for bit-packed pixel data",
        "Unable to return an ndarray that's a view on the original buffer for uncompressed pixel data with a photometric interpretation of 'YBR_FULL_422'",
        "Unable to return an ndarray that's a view on the original buffer if applying a color space conversion",
        "Unable to return an ndarray that's a view on the original buffer when (0028,0101) 'Bits Stored' doesn't equal (0028,0100) 'Bits Allocated' and 'correct_unused_bits=True'. In most cases you can pass 'correct_unused_bits=False' instead to get a view if the uncorrected array is equivalent to the corrected one.",
        "Unable to set the User Identity Negotiation's 'server_response'",
        "User Identity Type and Primary Field must be set prior to Association negotiation",
        "User Identity Type must be 1, 2, 3, 4 or 5 if requesting Association, None otherwise",
        "User Identity Type must be an int or None",
        "User callback returned a `Dataset` without a Status element",
        "User identity failed verification",
        "User's C-GET generator yielded further (status, dataset) results but these will be ignored as the sub-operations are complete",
        "Using Presentation Context:",
        "Values for elements with a VR of 'DS' values must be <= 16 characters long. Use a smaller string, set 'config.settings.reading_validation_mode' to 'WARN' to override the length check, use 'Decimal.quantize()' and initialize with a 'Decimal' instance, or explicitly construct a DS instance with 'auto_format' set to True",
        "connection_timeout set to None",
        "dimse_timeout set to 30 s",
        "maximum_associations set to 1",
        "network_timeout set to 60 s",
        "pydicom.write_dataset() failed:",
        # END GENERATED
    }
)
