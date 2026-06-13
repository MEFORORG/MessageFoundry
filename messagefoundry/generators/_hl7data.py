"""HL7 v2.5.1 datatype encoders + synthetic data pools for the ADT generator.

This module is deliberately small and dependency-free: it knows how to render a handful
of HL7 *datatypes* (CX, XPN, XAD, XCN, PL, CWE, TS) as delimited strings, and it carries
pools of **fabricated** demographic/clinical values to draw from. Everything here is
synthetic test data — **no real PHI** (see CLAUDE.md §9).

The encoders take a *component* separator of ``^`` and never emit the field separator
``|``; segment assembly (joining fields with ``|``) is the caller's job in ``adt.py``.
Table-coded values use codes that are valid for their HL7 table so the corpus is genuinely
conformant, not merely accepted by the validator.
"""

from __future__ import annotations

from datetime import datetime

__all__ = [
    "ts",
    "date8",
    "cx",
    "xpn",
    "xad",
    "xcn",
    "pl",
    "cwe",
    "ei",
    "ORDER_CONTROLS",
    "ORDER_STATUSES",
    "TRANSACTION_TYPES",
    "SERVICES",
    "PROCEDURES",
    "APPT_REASONS",
    "SPECIMEN_TYPES",
    "DOCUMENT_TYPES",
    "DOC_STATUSES",
    "VACCINES",
    "ROUTES",
    "INSURANCE_PLANS",
    "INSURANCE_COMPANIES",
    "MEDICATIONS",
    "FAMILY_NAMES",
    "GIVEN_NAMES",
    "MIDDLE_INITIALS",
    "STREETS",
    "CITIES",
    "SEXES",
    "PATIENT_CLASSES",
    "ADMIT_TYPES",
    "HOSPITAL_SERVICES",
    "POINTS_OF_CARE",
    "ROOMS",
    "BEDS",
    "FACILITIES",
    "SENDING_APPS",
    "RECEIVING_APPS",
    "CLINICIANS",
    "RELATIONSHIPS",
    "ALLERGENS",
    "ALLERGY_SEVERITIES",
    "DIAGNOSES",
    "DIAGNOSIS_TYPES",
    "OBSERVATIONS",
    "BED_STATUSES",
    "EVENT_REASONS",
]


# --- datatype encoders -------------------------------------------------------


def ts(when: datetime) -> str:
    """TS / DTM timestamp: ``YYYYMMDDHHMMSS``."""
    return when.strftime("%Y%m%d%H%M%S")


def date8(when: datetime) -> str:
    """DT date: ``YYYYMMDD`` (e.g. a birth date)."""
    return when.strftime("%Y%m%d")


def cx(id_number: str, *, authority: str = "HOSP", id_type: str = "MR") -> str:
    """CX identifier: ``ID^^^AssigningAuthority^IdentifierTypeCode`` (PID-3, MRG-1, …)."""
    return f"{id_number}^^^{authority}^{id_type}"


def xpn(family: str, given: str, middle: str = "") -> str:
    """XPN person name: ``Family^Given^Middle`` (PID-5, NK1-2)."""
    return f"{family}^{given}^{middle}" if middle else f"{family}^{given}"


def xad(street: str, city: str, state: str, zip_code: str, country: str = "USA") -> str:
    """XAD address: ``Street^^City^State^Zip^Country`` (PID-11)."""
    return f"{street}^^{city}^{state}^{zip_code}^{country}"


def xcn(id_number: str, family: str, given: str) -> str:
    """XCN provider: ``ID^Family^Given`` (PV1-7/8/17, attending/referring/admitting)."""
    return f"{id_number}^{family}^{given}"


def pl(point_of_care: str, room: str, bed: str, facility: str = "MAIN") -> str:
    """PL location: ``PointOfCare^Room^Bed^Facility`` (PV1-3, NPU-1)."""
    return f"{point_of_care}^{room}^{bed}^{facility}"


def cwe(code: str, text: str, system: str) -> str:
    """CWE coded element: ``Code^Text^CodingSystem`` (diagnoses, allergens, reasons)."""
    return f"{code}^{text}^{system}"


def ei(entity_id: str, namespace: str = "HOSP") -> str:
    """EI entity identifier: ``EntityID^NamespaceID`` (ORC/OBR placer & filler numbers)."""
    return f"{entity_id}^{namespace}"


# --- synthetic pools (fabricated; no real PHI) -------------------------------

FAMILY_NAMES: tuple[str, ...] = (
    "SMITH",
    "JOHNSON",
    "WILLIAMS",
    "BROWN",
    "JONES",
    "GARCIA",
    "MILLER",
    "DAVIS",
    "RODRIGUEZ",
    "MARTINEZ",
    "HERNANDEZ",
    "LOPEZ",
    "GONZALEZ",
    "WILSON",
    "ANDERSON",
    "THOMAS",
    "TAYLOR",
    "MOORE",
    "JACKSON",
    "MARTIN",
    "LEE",
    "PEREZ",
    "THOMPSON",
    "WHITE",
    "HARRIS",
    "SANCHEZ",
    "CLARK",
    "RAMIREZ",
    "LEWIS",
    "ROBINSON",
    "WALKER",
    "NGUYEN",
    "PATEL",
    "KIM",
    "OKAFOR",
    "ROSSI",
)

GIVEN_NAMES: tuple[str, ...] = (
    "JAMES",
    "MARY",
    "JOHN",
    "PATRICIA",
    "ROBERT",
    "JENNIFER",
    "MICHAEL",
    "LINDA",
    "WILLIAM",
    "ELIZABETH",
    "DAVID",
    "BARBARA",
    "RICHARD",
    "SUSAN",
    "JOSEPH",
    "JESSICA",
    "THOMAS",
    "SARAH",
    "CHARLES",
    "KAREN",
    "MARIA",
    "DANIEL",
    "NANCY",
    "ANTHONY",
    "LISA",
    "MARK",
    "BETTY",
    "CARLOS",
    "AISHA",
    "WEI",
    "PRIYA",
    "OMAR",
    "FATIMA",
    "HIROSHI",
    "INGRID",
    "DMITRI",
)

MIDDLE_INITIALS: tuple[str, ...] = ("A", "B", "C", "D", "E", "J", "L", "M", "Q", "R", "T", "")

# street, city, state, zip
STREETS: tuple[str, ...] = (
    "123 MAIN ST",
    "456 OAK AVE",
    "789 PINE RD",
    "1010 MAPLE DR",
    "222 CEDAR LN",
    "55 BIRCH CT",
    "9000 ELM BLVD",
    "31 SPRUCE WAY",
    "78 WILLOW TER",
    "640 ASH PL",
    "1200 LAKESHORE DR",
    "88 SUNSET BLVD",
    "417 RIVERSIDE DR",
    "26 HILLCREST AVE",
)

# city, state, zip — kept consistent as a unit
CITIES: tuple[tuple[str, str, str], ...] = (
    ("METROPOLIS", "IL", "60601"),
    ("SPRINGFIELD", "IL", "62701"),
    ("RIVERTON", "OH", "45011"),
    ("FAIRVIEW", "TX", "75069"),
    ("LAKEVILLE", "MN", "55044"),
    ("GREENVILLE", "SC", "29601"),
    ("CLAYTON", "MO", "63105"),
    ("AURORA", "CO", "80010"),
    ("BRISTOL", "CT", "06010"),
    ("SALEM", "OR", "97301"),
)

SEXES: tuple[str, ...] = ("F", "M", "O", "U")  # HL7 table 0001
PATIENT_CLASSES: tuple[str, ...] = ("I", "O", "E", "P", "R", "B")  # table 0004
ADMIT_TYPES: tuple[str, ...] = ("A", "E", "L", "R", "N", "U", "C")  # table 0007
HOSPITAL_SERVICES: tuple[str, ...] = ("MED", "SUR", "CAR", "PUL", "URO", "OBS", "PED", "ONC")
POINTS_OF_CARE: tuple[str, ...] = ("WARD", "ICU", "ER", "2W", "3E", "OR", "MATERNITY")
ROOMS: tuple[str, ...] = ("101", "102", "210", "305", "412", "A11", "B22", "C30")
BEDS: tuple[str, ...] = ("A", "B", "1", "2", "W")
FACILITIES: tuple[str, ...] = ("MAIN", "NORTH", "SOUTH", "WESTCAMPUS")
SENDING_APPS: tuple[tuple[str, str], ...] = (
    ("ADT", "MAINHOSP"),
    ("REGISTRATION", "NORTHCLINIC"),
    ("EHR", "SOUTHHOSP"),
    ("HIS", "WESTMED"),
)
RECEIVING_APPS: tuple[tuple[str, str], ...] = (
    ("MESSAGEFOUNDRY", "INTEGRATION"),
    ("LAB", "MAINHOSP"),
    ("PHARMACY", "MAINHOSP"),
)

# id, family, given
CLINICIANS: tuple[tuple[str, str, str], ...] = (
    ("1001", "SMITH", "JOHN"),
    ("1002", "PATEL", "ANJALI"),
    ("1003", "NGUYEN", "TRAN"),
    ("1004", "OKAFOR", "CHIDI"),
    ("1005", "ROSSI", "GIULIA"),
    ("1006", "KIM", "SOOJIN"),
    ("1007", "GARCIA", "MIGUEL"),
    ("1008", "WALKER", "DENISE"),
)

# code, text (HL7 table 0063 relationship)
RELATIONSHIPS: tuple[tuple[str, str], ...] = (
    ("SPO", "Spouse"),
    ("CHD", "Child"),
    ("PAR", "Parent"),
    ("SIB", "Sibling"),
    ("FND", "Friend"),
    ("GRD", "Guardian"),
    ("EME", "Employer"),
)

# code, text (allergen mnemonic — AL1-3 / IAM-3)
ALLERGENS: tuple[tuple[str, str], ...] = (
    ("PCN", "Penicillin"),
    ("SULFA", "Sulfa drugs"),
    ("ASA", "Aspirin"),
    ("LATEX", "Latex"),
    ("PEANUT", "Peanuts"),
    ("CODEINE", "Codeine"),
    ("SHELLFISH", "Shellfish"),
    ("IODINE", "Iodine"),
)

# code, text (HL7 table 0128 allergy severity)
ALLERGY_SEVERITIES: tuple[tuple[str, str], ...] = (
    ("SV", "Severe"),
    ("MO", "Moderate"),
    ("MI", "Mild"),
)

# code, text (ICD-10-CM diagnoses — DG1-3)
DIAGNOSES: tuple[tuple[str, str], ...] = (
    ("I10", "Essential hypertension"),
    ("E11.9", "Type 2 diabetes mellitus"),
    ("J45.909", "Unspecified asthma"),
    ("N39.0", "Urinary tract infection"),
    ("M54.5", "Low back pain"),
    ("R07.9", "Chest pain unspecified"),
    ("K21.9", "Gastro-esophageal reflux disease"),
    ("F41.1", "Generalized anxiety disorder"),
    ("S52.501A", "Fracture of right radius"),
    ("A09", "Infectious gastroenteritis"),
)

DIAGNOSIS_TYPES: tuple[str, ...] = ("A", "W", "F")  # admitting / working / final (table 0052)

# code, text, value-type, value, units (OBX vitals)
OBSERVATIONS: tuple[tuple[str, str, str, str, str], ...] = (
    ("8302-2", "Body height", "NM", "170", "cm"),
    ("29463-7", "Body weight", "NM", "72", "kg"),
    ("8480-6", "Systolic blood pressure", "NM", "128", "mm[Hg]"),
    ("8462-4", "Diastolic blood pressure", "NM", "82", "mm[Hg]"),
    ("8867-4", "Heart rate", "NM", "76", "/min"),
    ("8310-5", "Body temperature", "NM", "37.0", "Cel"),
)

# code, text (HL7 table 0116 bed status — NPU-2)
BED_STATUSES: tuple[tuple[str, str], ...] = (
    ("C", "Closed"),
    ("H", "Housekeeping"),
    ("O", "Occupied"),
    ("U", "Unoccupied"),
    ("K", "Contaminated"),
    ("I", "Isolated"),
)

# code, text (event reason — EVN-4, free use of a local table)
EVENT_REASONS: tuple[tuple[str, str], ...] = (
    ("01", "Patient request"),
    ("02", "Physician order"),
    ("03", "Census management"),
    ("", "Routine"),
)

# --- orders / results / financials / scheduling ------------------------------

ORDER_CONTROLS: tuple[str, ...] = ("NW", "OK", "SC", "CA", "XO", "CM")  # table 0119
ORDER_STATUSES: tuple[str, ...] = ("A", "CM", "IP", "SC", "CA")  # table 0038
TRANSACTION_TYPES: tuple[str, ...] = ("CG", "CD", "RA")  # table 0017 (charge/credit/adjust)

# code, text (orderable services / observation identifiers — OBR-4 / AIS-3, LOINC-ish)
SERVICES: tuple[tuple[str, str], ...] = (
    ("24331-1", "Lipid panel"),
    ("57021-8", "CBC with differential"),
    ("2345-7", "Glucose"),
    ("2951-2", "Sodium"),
    ("718-7", "Hemoglobin"),
    ("24362-6", "Renal panel"),
    ("30341-2", "Erythrocyte sedimentation rate"),
)

# code, text (procedure / charge codes — FT1-7, CPT-ish)
PROCEDURES: tuple[tuple[str, str], ...] = (
    ("99213", "Office visit, established"),
    ("36415", "Venipuncture"),
    ("80053", "Comprehensive metabolic panel"),
    ("71046", "Chest X-ray, 2 views"),
    ("93000", "Electrocardiogram"),
    ("85025", "Complete blood count"),
)

# code, text (appointment reason — SCH-6, local table)
APPT_REASONS: tuple[tuple[str, str], ...] = (
    ("ROUTINE", "Routine"),
    ("FOLLOWUP", "Follow-up"),
    ("URGENT", "Urgent"),
    ("CONSULT", "Consultation"),
)

# code, text (specimen type — SPM-4, HL7 table 0487)
SPECIMEN_TYPES: tuple[tuple[str, str], ...] = (
    ("BLD", "Whole blood"),
    ("SER", "Serum"),
    ("UR", "Urine"),
    ("PLAS", "Plasma"),
    ("CSF", "Cerebrospinal fluid"),
)

DOCUMENT_TYPES: tuple[str, ...] = ("DS", "CN", "HP", "OP", "PN", "CD")  # table 0270
DOC_STATUSES: tuple[str, ...] = ("AU", "DO", "IP", "LA")  # table 0271 completion status

# code, text (vaccine — RXA-5, CVX codes)
VACCINES: tuple[tuple[str, str], ...] = (
    ("08", "Hepatitis B"),
    ("20", "DTaP"),
    ("03", "MMR"),
    ("21", "Varicella"),
    ("88", "Influenza"),
    ("207", "COVID-19 mRNA"),
)

# code, text (route of administration — RXR-1, HL7 table 0162)
ROUTES: tuple[tuple[str, str], ...] = (
    ("IM", "Intramuscular"),
    ("SC", "Subcutaneous"),
    ("PO", "Oral"),
    ("IV", "Intravenous"),
    ("IN", "Intranasal"),
)

# code, text (insurance plan — IN1-2, local table)
INSURANCE_PLANS: tuple[tuple[str, str], ...] = (
    ("PPO", "Preferred Provider Organization"),
    ("HMO", "Health Maintenance Organization"),
    ("MCR", "Medicare"),
    ("MCD", "Medicaid"),
)

# id, name (insurance company — IN1-3 / IN1-4)
INSURANCE_COMPANIES: tuple[tuple[str, str], ...] = (
    ("INS001", "BlueCross"),
    ("INS002", "Aetna"),
    ("INS003", "UnitedHealth"),
    ("INS004", "Cigna"),
)

# code, text (medication — RXE-2 give code, RxNorm-ish)
MEDICATIONS: tuple[tuple[str, str], ...] = (
    ("197361", "Amoxicillin 500 mg oral capsule"),
    ("310965", "Ibuprofen 200 mg oral tablet"),
    ("314076", "Lisinopril 10 mg oral tablet"),
    ("198211", "Metformin 500 mg oral tablet"),
    ("313782", "Atorvastatin 20 mg oral tablet"),
)
