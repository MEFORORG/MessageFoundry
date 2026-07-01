# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""messagefoundry — an open-source integration engine for healthcare.

The engine is an importable library. The PySide6 console (and any other client)
drives it over a localhost HTTP + WebSocket API, so the same code path serves
in-process, local-daemon, and remote deployments.

Config modules define the message graph against this surface::

    from messagefoundry import inbound, outbound, router, handler, Send, MLLP, File, Message
"""

from messagefoundry.config.models import (
    AckMode,
    BuildupThreshold,
    ContentType,
    InternalErrorPolicy,
    OrderingMode,
    RetryPolicy,
    StallThreshold,
)
from messagefoundry.config.active_environment import current_environment
from messagefoundry.config.db_lookup import DbLookupError, db_lookup
from messagefoundry.config.fhir_lookup import FhirLookupError, fhir_lookup
from messagefoundry.config.ingest_time import current_ingest_time
from messagefoundry.config.reference import reference
from messagefoundry.config.response import response_get
from messagefoundry.config.state import state_get
from messagefoundry.config.wiring import (
    CodeSet,
    Database,
    DatabaseLookup,
    DatabasePoll,
    DatabaseRef,
    Email,
    FhirLookup,
    File,
    FileRef,
    Ftp,
    FHIR,
    Http,
    DICOM,
    DICOMweb,
    Loopback,
    MLLP,
    PassThrough,
    Reference,
    Rest,
    SMTP,
    Sftp,
    Soap,
    Tcp,
    Timer,
    X12,
    Send,
    SetState,
    code_set,
    env,
    handler,
    inbound,
    outbound,
    router,
)
from messagefoundry.parsing.groups import SegmentGroup
from messagefoundry.parsing.message import Message, RawMessage
from messagefoundry.parsing.split import split_by_obr
from messagefoundry.timezone import (
    age_from_dob,
    convert_hl7_timestamp,
    hl7_now,
    length_of_stay,
    parse_hl7_timestamp,
    to_zone,
)

__version__ = "0.2.12"

__all__ = [
    "Message",
    "RawMessage",
    "SegmentGroup",
    "split_by_obr",
    "Send",
    "SetState",
    "state_get",
    "response_get",
    "MLLP",
    "Tcp",
    "X12",
    "Http",
    "File",
    "Timer",
    "Loopback",
    "PassThrough",
    "Rest",
    "Email",
    "SMTP",
    "FHIR",
    "DICOM",
    "DICOMweb",
    "Database",
    "DatabaseLookup",
    "DatabasePoll",
    "Soap",
    "Sftp",
    "Ftp",
    "env",
    "code_set",
    "CodeSet",
    "reference",
    "Reference",
    "FileRef",
    "DatabaseRef",
    "db_lookup",
    "DbLookupError",
    "FhirLookup",
    "fhir_lookup",
    "FhirLookupError",
    "current_ingest_time",
    "current_environment",
    "AckMode",
    "RetryPolicy",
    "OrderingMode",
    "InternalErrorPolicy",
    "BuildupThreshold",
    "StallThreshold",
    "ContentType",
    "inbound",
    "outbound",
    "router",
    "handler",
    "convert_hl7_timestamp",
    "to_zone",
    "parse_hl7_timestamp",
    "hl7_now",
    "age_from_dob",
    "length_of_stay",
    "__version__",
]
