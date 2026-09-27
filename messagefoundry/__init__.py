# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""messagefoundry — an open-source integration engine for healthcare.

The engine is an importable library. Clients such as the VS Code extension and the test
harness drive it over a localhost HTTP + WebSocket API, and the engine serves the browser web
console at ``/ui`` from its own app, so the same code path serves in-process, local-daemon,
and remote deployments.

Config modules define the message graph against this surface::

    from messagefoundry import inbound, outbound, router, handler, Send, MLLP, File, Message
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # Static-only. mypy (strict) resolves the whole authoring surface from here, so a config
    # author's `from messagefoundry import Send, handler` is typed exactly as before; at runtime
    # nothing here executes and `__getattr__` below imports the owning module on first touch.
    from messagefoundry.actions import (
        append_to_field,
        arith_field,
        code_lookup,
        convert_case,
        copy_field,
        copy_segment,
        date_diff_field,
        delete_segment,
        format_date,
        pad_field,
        replace_literal,
        set_field,
        split_field,
        substring_field,
        trim_field,
    )
    from messagefoundry.config.active_environment import current_environment
    from messagefoundry.config.db_lookup import DbLookupError, db_lookup
    from messagefoundry.config.fhir_lookup import FhirLookupError, fhir_lookup
    from messagefoundry.config.ingest_time import current_ingest_time
    from messagefoundry.config.models import (
        BatchConfig,
        BuildupThreshold,
        ContentType,
        InternalErrorPolicy,
        OrderingMode,
        RetryPolicy,
        SaturationThreshold,
        StallThreshold,
    )
    from messagefoundry.config.reference import reference
    from messagefoundry.config.response import response_get
    from messagefoundry.config.state import state_get
    from messagefoundry.config.wiring import (
        DICOM,
        FHIR,
        MLLP,
        SMTP,
        X12,
        CodeSet,
        Database,
        DatabaseLookup,
        DatabasePoll,
        DatabaseRef,
        DICOMweb,
        Direct,
        Email,
        FhirLookup,
        File,
        FileRef,
        Ftp,
        Http,
        Loopback,
        MessageTypeError,
        PassThrough,
        Reference,
        Rest,
        Send,
        SetMeta,
        SetState,
        Sftp,
        Soap,
        Tcp,
        Timer,
        code_set,
        env,
        handler,
        inbound,
        message_type_of,
        outbound,
        router,
    )
    from messagefoundry.diagnostics import checkpoint, log_note
    from messagefoundry.fhirsearch import FhirRaw, FhirToken
    from messagefoundry.mllpcodec import AckMode
    from messagefoundry.parsing.compression import (
        CompressionError,
        deflate_compress,
        deflate_decompress,
        deflate_decompress_with_tail,
        gzip_compress,
        gzip_decompress,
        zip_compress,
        zip_decompress,
    )
    from messagefoundry.parsing.groups import SegmentGroup
    from messagefoundry.parsing.message import Message, RawMessage
    from messagefoundry.parsing.split import split_by_obr
    from messagefoundry.timezone import (
        AmbiguousLocalTimeError,
        DstEdgePolicy,
        DstTransitionError,
        NonExistentLocalTimeError,
        age_from_dob,
        convert_hl7_timestamp,
        hl7_now,
        length_of_stay,
        parse_hl7_timestamp,
        to_zone,
    )


__version__ = "0.4.0"

#: Every name in ``__all__`` except ``__version__``, mapped to the module that defines it.
#: Grouped and ordered to mirror the ``TYPE_CHECKING`` block above, so the two are reviewable
#: side by side; ``test_lazy_package_root.py`` proves they agree and that every entry resolves.
_LAZY_EXPORTS: dict[str, str] = {
    "append_to_field": "messagefoundry.actions",
    "arith_field": "messagefoundry.actions",
    "code_lookup": "messagefoundry.actions",
    "convert_case": "messagefoundry.actions",
    "copy_field": "messagefoundry.actions",
    "copy_segment": "messagefoundry.actions",
    "date_diff_field": "messagefoundry.actions",
    "delete_segment": "messagefoundry.actions",
    "format_date": "messagefoundry.actions",
    "pad_field": "messagefoundry.actions",
    "replace_literal": "messagefoundry.actions",
    "set_field": "messagefoundry.actions",
    "split_field": "messagefoundry.actions",
    "substring_field": "messagefoundry.actions",
    "trim_field": "messagefoundry.actions",
    "current_environment": "messagefoundry.config.active_environment",
    "DbLookupError": "messagefoundry.config.db_lookup",
    "db_lookup": "messagefoundry.config.db_lookup",
    "FhirLookupError": "messagefoundry.config.fhir_lookup",
    "fhir_lookup": "messagefoundry.config.fhir_lookup",
    "current_ingest_time": "messagefoundry.config.ingest_time",
    "BatchConfig": "messagefoundry.config.models",
    "BuildupThreshold": "messagefoundry.config.models",
    "ContentType": "messagefoundry.config.models",
    "InternalErrorPolicy": "messagefoundry.config.models",
    "OrderingMode": "messagefoundry.config.models",
    "RetryPolicy": "messagefoundry.config.models",
    "SaturationThreshold": "messagefoundry.config.models",
    "StallThreshold": "messagefoundry.config.models",
    "reference": "messagefoundry.config.reference",
    "response_get": "messagefoundry.config.response",
    "state_get": "messagefoundry.config.state",
    "DICOM": "messagefoundry.config.wiring",
    "FHIR": "messagefoundry.config.wiring",
    "MLLP": "messagefoundry.config.wiring",
    "SMTP": "messagefoundry.config.wiring",
    "X12": "messagefoundry.config.wiring",
    "CodeSet": "messagefoundry.config.wiring",
    "Database": "messagefoundry.config.wiring",
    "DatabaseLookup": "messagefoundry.config.wiring",
    "DatabasePoll": "messagefoundry.config.wiring",
    "DatabaseRef": "messagefoundry.config.wiring",
    "DICOMweb": "messagefoundry.config.wiring",
    "Direct": "messagefoundry.config.wiring",
    "Email": "messagefoundry.config.wiring",
    "FhirLookup": "messagefoundry.config.wiring",
    "File": "messagefoundry.config.wiring",
    "FileRef": "messagefoundry.config.wiring",
    "Ftp": "messagefoundry.config.wiring",
    "Http": "messagefoundry.config.wiring",
    "Loopback": "messagefoundry.config.wiring",
    "MessageTypeError": "messagefoundry.config.wiring",
    "PassThrough": "messagefoundry.config.wiring",
    "Reference": "messagefoundry.config.wiring",
    "Rest": "messagefoundry.config.wiring",
    "Send": "messagefoundry.config.wiring",
    "SetMeta": "messagefoundry.config.wiring",
    "SetState": "messagefoundry.config.wiring",
    "Sftp": "messagefoundry.config.wiring",
    "Soap": "messagefoundry.config.wiring",
    "Tcp": "messagefoundry.config.wiring",
    "Timer": "messagefoundry.config.wiring",
    "code_set": "messagefoundry.config.wiring",
    "env": "messagefoundry.config.wiring",
    "handler": "messagefoundry.config.wiring",
    "inbound": "messagefoundry.config.wiring",
    "message_type_of": "messagefoundry.config.wiring",
    "outbound": "messagefoundry.config.wiring",
    "router": "messagefoundry.config.wiring",
    "checkpoint": "messagefoundry.diagnostics",
    "log_note": "messagefoundry.diagnostics",
    "FhirRaw": "messagefoundry.fhirsearch",
    "FhirToken": "messagefoundry.fhirsearch",
    "AckMode": "messagefoundry.mllpcodec",
    "CompressionError": "messagefoundry.parsing.compression",
    "deflate_compress": "messagefoundry.parsing.compression",
    "deflate_decompress": "messagefoundry.parsing.compression",
    "deflate_decompress_with_tail": "messagefoundry.parsing.compression",
    "gzip_compress": "messagefoundry.parsing.compression",
    "gzip_decompress": "messagefoundry.parsing.compression",
    "zip_compress": "messagefoundry.parsing.compression",
    "zip_decompress": "messagefoundry.parsing.compression",
    "SegmentGroup": "messagefoundry.parsing.groups",
    "Message": "messagefoundry.parsing.message",
    "RawMessage": "messagefoundry.parsing.message",
    "split_by_obr": "messagefoundry.parsing.split",
    "AmbiguousLocalTimeError": "messagefoundry.timezone",
    "DstEdgePolicy": "messagefoundry.timezone",
    "DstTransitionError": "messagefoundry.timezone",
    "NonExistentLocalTimeError": "messagefoundry.timezone",
    "age_from_dob": "messagefoundry.timezone",
    "convert_hl7_timestamp": "messagefoundry.timezone",
    "hl7_now": "messagefoundry.timezone",
    "length_of_stay": "messagefoundry.timezone",
    "parse_hl7_timestamp": "messagefoundry.timezone",
    "to_zone": "messagefoundry.timezone",
}


def __getattr__(name: str) -> object:
    """PEP 562 lazy export (BACKLOG #1675).

    Importing the root used to pull `config.wiring` and the whole authoring surface -- 65
    engine modules -- on any `import messagefoundry`, including the many that only wanted
    `__version__` or a single submodule. Each export now costs only the module that defines it.

    Raising AttributeError for an unknown name is load-bearing, not politeness: `from
    messagefoundry import pki` (and `actions`, `diagnostics`, `service`, `logging_setup`,
    `store`, ...) reaches the submodule ONLY because the import machinery falls back to
    importing it after getattr raises. Return None or raise anything else and those break.
    """
    module_name = _LAZY_EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    # Deferred on purpose, not by accident: `importlib` is absent from a fresh interpreter's
    # sys.modules and costs 3 modules to import, which the `__version__`-only callers would
    # otherwise pay for a surface they never touch.
    import importlib

    value = getattr(importlib.import_module(module_name), name)
    globals()[name] = value  # bind it, so the next lookup never reaches __getattr__
    return value


def __dir__() -> list[str]:
    """Keep the lazy names visible to `dir()`, tab-completion and `help()`."""
    return sorted(set(__all__) | set(globals()))


__all__ = [
    "Message",
    "RawMessage",
    "SegmentGroup",
    "split_by_obr",
    "Send",
    "SetState",
    "SetMeta",
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
    "Direct",
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
    "FhirToken",
    "FhirRaw",
    "current_ingest_time",
    "current_environment",
    "AckMode",
    "RetryPolicy",
    "OrderingMode",
    "InternalErrorPolicy",
    "BuildupThreshold",
    "StallThreshold",
    "SaturationThreshold",
    "BatchConfig",
    "ContentType",
    "inbound",
    "outbound",
    "router",
    "handler",
    "message_type_of",
    "MessageTypeError",
    "copy_field",
    "set_field",
    "append_to_field",
    "trim_field",
    "substring_field",
    "pad_field",
    "replace_literal",
    "convert_case",
    "arith_field",
    "format_date",
    "date_diff_field",
    "split_field",
    "code_lookup",
    "copy_segment",
    "delete_segment",
    "log_note",
    "checkpoint",
    "convert_hl7_timestamp",
    "to_zone",
    "parse_hl7_timestamp",
    "hl7_now",
    "age_from_dob",
    "length_of_stay",
    # Raised when a named source zone does not map an HL7 wall time to exactly one instant, plus the
    # alias naming the resolution policies so a Handler can annotate its own wrapper.
    "DstEdgePolicy",
    "DstTransitionError",
    "AmbiguousLocalTimeError",
    "NonExistentLocalTimeError",
    # Compression codec (ADR 0123) — pure gzip/zlib-deflate/zip for on-demand Handler use.
    "CompressionError",
    "gzip_compress",
    "gzip_decompress",
    "deflate_compress",
    "deflate_decompress",
    "deflate_decompress_with_tail",
    "zip_compress",
    "zip_decompress",
    "__version__",
]
