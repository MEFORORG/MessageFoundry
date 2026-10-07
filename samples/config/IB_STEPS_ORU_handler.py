# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""IB_STEPS_ORU — Handler for the typed-Steps worked example (ADR 0076, ADR 0106).

Every statement in the handler body is a typed row: a vocabulary action, a code-set lookup, a
diagnostic, a recognized ``if`` / ``for`` control row, or a send. Comments are note rows. Keep it that
way: a line of hand-written Python here shows as a locked ``code`` row in the analyst editor, and
``tests/test_samples_typed_steps.py`` fails.
"""

from messagefoundry import (
    Send,
    code_lookup,
    code_set,
    convert_case,
    copy_field,
    format_date,
    handler,
    log_note,
    set_field,
    trim_field,
)

# Sending-facility code (MSH-4) -> downstream mnemonic, edited as data in codesets/.
FACILITY_MNEMONICS = code_set("facility_mnemonics")


@handler("steps_oru_handler")
def steps_oru_handler(msg):
    # A result with no patient identifier cannot be filed: fail it to the error path.
    if msg.field("PID-3.1") is None:
        raise ValueError("PID-3 patient identifier is missing")
    # A cancelled order (OBR-25 = X) carries no result to deliver: filter it.
    if msg.field("OBR-25") == "X":
        return []
    # Field mapping: address the message to the receiving system.
    set_field(msg, "MSH-5", "EMR")
    set_field(msg, "MSH-6", "MAINHOSP")
    code_lookup(msg, "MSH-4", FACILITY_MNEMONICS)
    trim_field(msg, "PID-5.1")
    convert_case(msg, "PID-5.1", "upper")
    copy_field(msg, "OBR-7", "OBR-22")
    format_date(msg, "OBR-22", "%Y%m%d%H%M")
    # A patient with no administrative sex is sent as unknown (HL7 table 0001).
    if msg.field("PID-8") is None:
        set_field(msg, "PID-8", "U")
    # Each OBX with no result status (OBX-11) is sent as final (HL7 table 0085).
    for i in range(1, msg.count_segments("OBX") + 1):
        if msg.field("OBX-11", occurrence=i) is None:
            msg.set("OBX-11", "F", occurrence=i)
    # Log each patient identifier repetition. log_note redacts every value by default.
    for ident in msg.repetitions("PID-3"):
        log_note("PID-3 repetition {}", ident)
    # Fan out: the EMR gets the result, and the archive keeps a copy.
    return [Send("OB_STEPS_ORU_EMR", msg), Send("OB_STEPS_ORU_ARCHIVE", msg)]
