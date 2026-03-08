"""owasp_mapper.py – OWASP Top 10 (2021) Coverage Mapper

Maps all OverflowGuard findings to OWASP Top 10 categories and generates
a coverage report showing which categories have been addressed.

OWASP Top 10 2021:
  A01:2021 – Broken Access Control
  A02:2021 – Cryptographic Failures
  A03:2021 – Injection
  A04:2021 – Insecure Design
  A05:2021 – Security Misconfiguration
  A06:2021 – Vulnerable & Outdated Components
  A07:2021 – Identification & Authentication Failures
  A08:2021 – Software & Data Integrity Failures
  A09:2021 – Security Logging & Monitoring Failures
  A10:2021 – Server-Side Request Forgery (SSRF)

Zero external dependencies – uses stdlib only.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple
from collections import defaultdict

# ---------------------------------------------------------------------------
# OWASP Top 10 2021 definitions
# ---------------------------------------------------------------------------

OWASP_TOP_10 = {
    "A01": {
        "id": "A01:2021",
        "name": "Broken Access Control",
        "description": "Failures related to enforcing policies such that users cannot act outside their intended permissions",
        "url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    },
    "A02": {
        "id": "A02:2021",
        "name": "Cryptographic Failures",
        "description": "Failures related to cryptography which often lead to sensitive data exposure",
        "url": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    },
    "A03": {
        "id": "A03:2021",
        "name": "Injection",
        "description": "SQL, NoSQL, OS, LDAP injection where hostile data is sent to an interpreter",
        "url": "https://owasp.org/Top10/A03_2021-Injection/",
    },
    "A04": {
        "id": "A04:2021",
        "name": "Insecure Design",
        "description": "Missing or ineffective control design; flaws in business logic",
        "url": "https://owasp.org/Top10/A04_2021-Insecure_Design/",
    },
    "A05": {
        "id": "A05:2021",
        "name": "Security Misconfiguration",
        "description": "Missing security hardening, unnecessary features, default accounts/passwords",
        "url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    },
    "A06": {
        "id": "A06:2021",
        "name": "Vulnerable and Outdated Components",
        "description": "Using components with known vulnerabilities or without security patches",
        "url": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
    },
    "A07": {
        "id": "A07:2021",
        "name": "Identification and Authentication Failures",
        "description": "Weaknesses in authentication mechanisms allowing credential stuffing, brute force, or session hijacking",
        "url": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    },
    "A08": {
        "id": "A08:2021",
        "name": "Software and Data Integrity Failures",
        "description": "Code and infrastructure that does not protect against integrity violations",
        "url": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
    },
    "A09": {
        "id": "A09:2021",
        "name": "Security Logging and Monitoring Failures",
        "description": "Insufficient logging, detection, monitoring, and active response",
        "url": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
    },
    "A10": {
        "id": "A10:2021",
        "name": "Server-Side Request Forgery",
        "description": "SSRF flaws occur when a web application fetches a remote resource without validating the user-supplied URL",
        "url": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_(SSRF)/",
    },
}

# ---------------------------------------------------------------------------
# CWE → OWASP mapping  (common CWEs mapped to their Top 10 categories)
# ---------------------------------------------------------------------------

_CWE_TO_OWASP: Dict[str, str] = {
    # A01 – Broken Access Control
    "CWE-22":  "A01",   # Path Traversal
    "CWE-23":  "A01",   # Relative Path Traversal
    "CWE-35":  "A01",   # Path Traversal
    "CWE-59":  "A01",   # Link Following
    "CWE-200": "A01",   # Exposure of Sensitive Info
    "CWE-201": "A01",   # Insertion of Sensitive Info into Sent Data
    "CWE-219": "A01",   # Storage of File with Sensitive Data Under Web Root
    "CWE-264": "A01",   # Permissions / Privileges / Access Controls
    "CWE-275": "A01",   # Permission Issues
    "CWE-276": "A01",   # Incorrect Default Permissions
    "CWE-284": "A01",   # Improper Access Control
    "CWE-285": "A01",   # Improper Authorization
    "CWE-352": "A01",   # CSRF
    "CWE-359": "A01",   # Exposure of Private Info
    "CWE-377": "A01",   # Insecure Temp File
    "CWE-402": "A01",   # Transmission of Private Resources into New Sphere
    "CWE-425": "A01",   # Direct Request (Forced Browsing)
    "CWE-441": "A01",   # Unintended Proxy / Intermediary
    "CWE-497": "A01",   # Exposure of System Data
    "CWE-538": "A01",   # File/Dir Info Exposure
    "CWE-540": "A01",   # Inclusion of Sensitive Info in Source Code
    "CWE-548": "A01",   # Exposure of Info Through Directory Listing
    "CWE-552": "A01",   # Files Accessible to External Parties
    "CWE-566": "A01",   # Auth Bypass via SQL Injection
    "CWE-601": "A01",   # URL Redirect
    "CWE-639": "A01",   # Auth Bypass Through User-Controlled Key
    "CWE-651": "A01",   # Info Exposure Through WSDL
    "CWE-668": "A01",   # Exposure of Resource to Wrong Sphere
    "CWE-706": "A01",   # Use of Incorrectly-Resolved Name
    "CWE-862": "A01",   # Missing Authorization
    "CWE-863": "A01",   # Incorrect Authorization
    "CWE-913": "A01",   # Improper Control of Dynamic Code Resources
    "CWE-922": "A01",   # Insecure Storage of Sensitive Info
    "CWE-1275":"A01",   # Sensitive Cookie Without 'Secure' Attribute

    # A02 – Cryptographic Failures
    "CWE-261": "A02",   # Weak Encoding for Password
    "CWE-296": "A02",   # Improper Following of a Certificate's Chain of Trust
    "CWE-310": "A02",   # Cryptographic Issues
    "CWE-319": "A02",   # Cleartext Transmission
    "CWE-321": "A02",   # Use of Hard-coded Cryptographic Key
    "CWE-322": "A02",   # Key Exchange without Entity Authentication
    "CWE-323": "A02",   # Reusing a Nonce
    "CWE-324": "A02",   # Use of a Key Past Expiration Date
    "CWE-325": "A02",   # Missing Required Cryptographic Step
    "CWE-326": "A02",   # Inadequate Encryption Strength
    "CWE-327": "A02",   # Use of Broken Crypto Algorithm
    "CWE-328": "A02",   # Reversible One-Way Hash
    "CWE-329": "A02",   # Not Using Unpredictable IV
    "CWE-330": "A02",   # Use of Insufficiently Random Values
    "CWE-331": "A02",   # Insufficient Entropy
    "CWE-335": "A02",   # Incorrect Usage of Seeds in PRNG
    "CWE-338": "A02",   # Use of Weak PRNG
    "CWE-340": "A02",   # Generation of Predictable Numbers
    "CWE-347": "A02",   # Improper Verification of Cryptographic Signature
    "CWE-523": "A02",   # Unprotected Transport of Credentials
    "CWE-720": "A02",   # OWASP Top Ten 2007 Category A9
    "CWE-757": "A02",   # Selection of Less-Secure Algorithm
    "CWE-759": "A02",   # Use of One-Way Hash Without Salt
    "CWE-760": "A02",   # Use of One-Way Hash with Predictable Salt
    "CWE-780": "A02",   # Use of RSA Without OAEP
    "CWE-818": "A02",   # Insufficient Transport Layer Security
    "CWE-916": "A02",   # Use of Password Hash with Insufficient Effort

    # A03 – Injection
    "CWE-20":  "A03",   # Improper Input Validation
    "CWE-74":  "A03",   # Injection
    "CWE-75":  "A03",   # CRLF Injection
    "CWE-77":  "A03",   # Command Injection
    "CWE-78":  "A03",   # OS Command Injection
    "CWE-79":  "A03",   # Cross-site Scripting
    "CWE-80":  "A03",   # Basic XSS
    "CWE-83":  "A03",   # XSS in Script
    "CWE-87":  "A03",   # Improper Neutralization of Alternate XSS
    "CWE-88":  "A03",   # Improper Neutralization of Argument Delimiters
    "CWE-89":  "A03",   # SQL Injection
    "CWE-90":  "A03",   # LDAP Injection
    "CWE-91":  "A03",   # XML Injection
    "CWE-93":  "A03",   # CRLF Injection
    "CWE-94":  "A03",   # Code Injection
    "CWE-95":  "A03",   # Eval Injection
    "CWE-96":  "A03",   # Static Code Injection
    "CWE-97":  "A03",   # Server-Side Includes
    "CWE-98":  "A03",   # Remote File Inclusion
    "CWE-99":  "A03",   # Resource Injection
    "CWE-100": "A03",   # Deprecated: Technology-Specific Input Validation
    "CWE-113": "A03",   # HTTP Response Splitting
    "CWE-116": "A03",   # Improper Encoding or Escaping of Output
    "CWE-138": "A03",   # Improper Neutralization of Special Elements
    "CWE-184": "A03",   # Incomplete List of Disallowed Inputs
    "CWE-470": "A03",   # Unsafe Reflection
    "CWE-471": "A03",   # Modification of Assumed-Immutable Data
    "CWE-564": "A03",   # SQL Injection: Hibernate
    "CWE-610": "A03",   # Externally Controlled Reference
    "CWE-643": "A03",   # XPath Injection
    "CWE-644": "A03",   # Improper Neutralization of HTTP Headers
    "CWE-652": "A03",   # XQuery Injection
    "CWE-917": "A03",   # Expression Language Injection

    # A04 – Insecure Design
    "CWE-209": "A04",   # Info Exposure via Error Message
    "CWE-256": "A04",   # Plaintext Storage of a Password
    "CWE-501": "A04",   # Trust Boundary Violation
    "CWE-522": "A04",   # Insufficiently Protected Credentials
    "CWE-525": "A04",   # Browser Cache Weakness
    "CWE-539": "A04",   # Persistent Cookies
    "CWE-602": "A04",   # Client-Side Enforcement of Server-Side Security
    "CWE-642": "A04",   # External Control of Critical State Data
    "CWE-656": "A04",   # Reliance on Security Through Obscurity
    "CWE-657": "A04",   # Violation of Secure Design Principles
    "CWE-799": "A04",   # Improper Control of Interaction Frequency
    "CWE-840": "A04",   # Business Logic Errors
    "CWE-841": "A04",   # Improper Enforcement of Behavioral Workflow

    # A05 – Security Misconfiguration
    "CWE-2":   "A05",   # Environmental
    "CWE-11":  "A05",   # ASP.NET Misconfiguration
    "CWE-13":  "A05",   # ASP.NET Misconfiguration
    "CWE-15":  "A05",   # External Control of System Settings
    "CWE-16":  "A05",   # Configuration
    "CWE-260": "A05",   # Password in Configuration File
    "CWE-315": "A05",   # Plaintext Storage in Cookie
    "CWE-520": "A05",   # .NET Misconfiguration
    "CWE-526": "A05",   # Exposure of Sensitive Info Through Environment Variables
    "CWE-537": "A05",   # Runtime Error Message
    "CWE-541": "A05",   # Inclusion of Sensitive Info in Include File
    "CWE-547": "A05",   # Use of Hard-coded, Security-relevant Constants
    "CWE-611": "A05",   # XXE
    "CWE-614": "A05",   # Sensitive Cookie Without 'Secure' Flag
    "CWE-732": "A05",   # Incorrect Permission
    "CWE-756": "A05",   # Missing Custom Error Page
    "CWE-776": "A05",   # Improper Restriction of XML Entity Expansion
    "CWE-942": "A05",   # Permissive CORS

    # A06 – Vulnerable and Outdated Components
    "CWE-937": "A06",   # Using Components with Known Vulnerabilities
    "CWE-1035":"A06",   # 2017 Top 10 A9
    "CWE-1104":"A06",   # Use of Unmaintained Third-Party Components

    # A07 – Identification and Authentication Failures
    "CWE-255": "A07",   # Credentials Management
    "CWE-259": "A07",   # Use of Hard-coded Password
    "CWE-287": "A07",   # Improper Authentication
    "CWE-288": "A07",   # Auth Bypass Using an Alternate Path
    "CWE-290": "A07",   # Auth Bypass by Spoofing
    "CWE-294": "A07",   # Auth Bypass by Capture-Replay
    "CWE-295": "A07",   # Improper Certificate Validation
    "CWE-297": "A07",   # Improper Validation of Host-specific Certificate Data
    "CWE-300": "A07",   # Channel Accessible by Non-Endpoint
    "CWE-302": "A07",   # Auth Bypass by Assumed-Immutable Data
    "CWE-304": "A07",   # Missing Critical Step in Authentication
    "CWE-306": "A07",   # Missing Authentication for Critical Function
    "CWE-307": "A07",   # Improper Restriction of Excessive Authentication Attempts
    "CWE-346": "A07",   # Origin Validation Error
    "CWE-384": "A07",   # Session Fixation
    "CWE-521": "A07",   # Weak Password Requirements
    "CWE-613": "A07",   # Insufficient Session Expiration
    "CWE-620": "A07",   # Unverified Password Change
    "CWE-640": "A07",   # Weak Password Recovery Mechanism
    "CWE-798": "A07",   # Use of Hard-coded Credentials

    # A08 – Software and Data Integrity Failures
    "CWE-345": "A08",   # Insufficient Verification of Data Authenticity
    "CWE-353": "A08",   # Missing Support for Integrity Check
    "CWE-426": "A08",   # Untrusted Search Path
    "CWE-494": "A08",   # Download Without Integrity Check
    "CWE-502": "A08",   # Deserialization of Untrusted Data
    "CWE-565": "A08",   # Reliance on Cookies Without Validation
    "CWE-784": "A08",   # Reliance on Cookies in Security Decision
    "CWE-829": "A08",   # Inclusion of Functionality from Untrusted Control Sphere
    "CWE-830": "A08",   # Inclusion of Web Functionality from Untrusted Source
    "CWE-915": "A08",   # Improperly Controlled Modification of Dynamically-Determined Object Attributes

    # A09 – Security Logging & Monitoring Failures
    "CWE-117": "A09",   # Improper Output Neutralization for Logs
    "CWE-223": "A09",   # Omission of Security-relevant Info
    "CWE-532": "A09",   # Insertion of Sensitive Info into Log File
    "CWE-778": "A09",   # Insufficient Logging

    # A10 – Server-Side Request Forgery
    "CWE-918": "A10",   # SSRF

    # Memory safety (maps to A03 in general, but also A04 for design flaws)
    "CWE-119": "A03",   # Improper Restriction of Operations within the Bounds of a Memory Buffer
    "CWE-120": "A03",   # Buffer Copy without Checking Size
    "CWE-121": "A03",   # Stack-based Buffer Overflow
    "CWE-122": "A03",   # Heap-based Buffer Overflow
    "CWE-125": "A03",   # Out-of-bounds Read
    "CWE-126": "A03",   # Buffer Over-read
    "CWE-127": "A03",   # Buffer Under-read
    "CWE-128": "A03",   # Wrap-around Error
    "CWE-129": "A03",   # Improper Validation of Array Index
    "CWE-131": "A03",   # Incorrect Calculation of Buffer Size
    "CWE-134": "A03",   # Use of Externally-Controlled Format String
    "CWE-170": "A03",   # Improper Null Termination
    "CWE-190": "A03",   # Integer Overflow or Wraparound
    "CWE-191": "A03",   # Integer Underflow
    "CWE-193": "A03",   # Off-by-one Error
    "CWE-194": "A03",   # Unexpected Sign Extension
    "CWE-195": "A03",   # Signed to Unsigned Conversion Error
    "CWE-196": "A03",   # Unsigned to Signed Conversion Error
    "CWE-197": "A03",   # Numeric Truncation Error
    "CWE-242": "A03",   # Use of Inherently Dangerous Function
    "CWE-243": "A03",   # Creation of chroot Jail Without Changing Working Directory
    "CWE-250": "A01",   # Execution with Unnecessary Privileges
    "CWE-362": "A04",   # Race Condition (TOCTOU)
    "CWE-367": "A04",   # TOCTOU
    "CWE-369": "A03",   # Divide By Zero
    "CWE-374": "A04",   # Passing Mutable Objects to an Untrusted Method
    "CWE-375": "A04",   # Passing Mutable Objects by Reference
    "CWE-400": "A05",   # Uncontrolled Resource Consumption
    "CWE-401": "A04",   # Memory Leak
    "CWE-415": "A03",   # Double Free
    "CWE-416": "A03",   # Use After Free
    "CWE-457": "A03",   # Use of Uninitialized Variable
    "CWE-467": "A03",   # sizeof() on a Pointer Type
    "CWE-476": "A03",   # NULL Pointer Dereference
    "CWE-590": "A03",   # Free of Memory not on the Heap
    "CWE-676": "A03",   # Use of Potentially Dangerous Function
    "CWE-681": "A03",   # Incorrect Conversion between Numeric Types
    "CWE-682": "A03",   # Incorrect Calculation
    "CWE-704": "A03",   # Incorrect Type Conversion
    "CWE-761": "A03",   # Free of Pointer not at Start of Buffer
    "CWE-762": "A03",   # Mismatched Memory Management Routines
    "CWE-763": "A03",   # Release of Invalid Pointer or Reference
    "CWE-787": "A03",   # Out-of-bounds Write
    "CWE-788": "A03",   # Access of Memory Location After End of Buffer
    "CWE-805": "A03",   # Buffer Access with Incorrect Length
    "CWE-806": "A03",   # Buffer Access Using Size of Source Buffer
    "CWE-822": "A03",   # Untrusted Pointer Dereference
    "CWE-823": "A03",   # Use of Out-of-range Pointer Offset
    "CWE-824": "A03",   # Access of Uninitialized Pointer
    "CWE-825": "A03",   # Expired Pointer Dereference
    "CWE-908": "A03",   # Use of Uninitialized Resource

    # Concurrency / Race conditions
    "CWE-364": "A04",   # Signal Handler Race Condition
    "CWE-366": "A04",   # Race Condition within a Thread
    "CWE-667": "A04",   # Improper Locking
    "CWE-820": "A04",   # Missing Synchronization
    "CWE-833": "A04",   # Deadlock
}

# ---------------------------------------------------------------------------
# Keyword-based fallback mapping (when CWE is not available)
# ---------------------------------------------------------------------------

_KEYWORD_TO_OWASP: List[Tuple[str, str]] = [
    # A01
    ("path traversal",           "A01"),
    ("directory traversal",      "A01"),
    ("access control",           "A01"),
    ("authorization",            "A01"),
    ("privilege",                "A01"),
    ("permission",               "A01"),
    ("csrf",                     "A01"),
    # A02
    ("cryptograph",              "A02"),
    ("encryption",               "A02"),
    ("weak hash",                "A02"),
    ("weak crypto",              "A02"),
    ("md5",                      "A02"),
    ("sha1",                     "A02"),
    ("des ",                     "A02"),
    ("random",                   "A02"),
    ("prng",                     "A02"),
    ("cleartext",                "A02"),
    ("plaintext password",       "A02"),
    # A03
    ("injection",                "A03"),
    ("sql injection",            "A03"),
    ("command injection",        "A03"),
    ("xss",                      "A03"),
    ("cross-site scripting",     "A03"),
    ("buffer overflow",          "A03"),
    ("stack overflow",           "A03"),
    ("heap overflow",            "A03"),
    ("format string",            "A03"),
    ("use.after.free",           "A03"),
    ("double free",              "A03"),
    ("null pointer",             "A03"),
    ("out.of.bounds",            "A03"),
    ("integer overflow",         "A03"),
    ("memory corruption",        "A03"),
    ("unsafe function",          "A03"),
    ("dangerous function",       "A03"),
    ("gets(",                    "A03"),
    ("strcpy",                   "A03"),
    ("sprintf",                  "A03"),
    ("eval(",                    "A03"),
    ("exec(",                    "A03"),
    ("os.system",                "A03"),
    ("taint",                    "A03"),
    # A04
    ("race condition",           "A04"),
    ("toctou",                   "A04"),
    ("deadlock",                 "A04"),
    ("logic flaw",               "A04"),
    ("business logic",           "A04"),
    ("insecure design",          "A04"),
    ("memory leak",              "A04"),
    # A05
    ("misconfiguration",         "A05"),
    ("debug mode",               "A05"),
    ("default password",         "A05"),
    ("exposed port",             "A05"),
    ("xxe",                      "A05"),
    ("cors",                     "A05"),
    ("docker",                   "A05"),
    ("terraform",                "A05"),
    ("kubernetes",               "A05"),
    ("iac ",                     "A05"),
    # A06
    ("outdated",                 "A06"),
    ("vulnerable component",     "A06"),
    ("known vulnerabilit",       "A06"),
    ("cve-",                     "A06"),
    ("end.of.life",              "A06"),
    ("eol",                      "A06"),
    ("dependency",               "A06"),
    # A07
    ("authentication",           "A07"),
    ("hardcoded password",       "A07"),
    ("hardcoded credential",     "A07"),
    ("hard-coded password",      "A07"),
    ("hard-coded credential",    "A07"),
    ("hardcoded secret",         "A07"),
    ("weak password",            "A07"),
    ("brute force",              "A07"),
    ("session fixation",         "A07"),
    ("api.key",                  "A07"),
    ("secret.key",               "A07"),
    # A08
    ("deserialization",          "A08"),
    ("pickle",                   "A08"),
    ("integrity",                "A08"),
    ("supply.chain",             "A08"),
    ("unsigned",                 "A08"),
    ("untrusted source",         "A08"),
    # A09
    ("logging",                  "A09"),
    ("monitoring",               "A09"),
    ("audit trail",              "A09"),
    ("log injection",            "A09"),
    # A10
    ("ssrf",                     "A10"),
    ("server.side request",      "A10"),
]

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class OWASPMapping:
    """Mapping of a single finding to an OWASP category."""
    owasp_id: str              # e.g. "A03"
    owasp_name: str            # e.g. "Injection"
    finding_type: str          # original issue_type
    finding_severity: str      # original severity
    finding_description: str   # brief description
    source: str                # "cwe" or "keyword"

@dataclass
class OWASPReport:
    """Full OWASP Top 10 coverage report."""
    mappings: List[OWASPMapping] = field(default_factory=list)
    coverage: Dict[str, Dict] = field(default_factory=dict)
    total_findings: int = 0
    mapped_findings: int = 0
    unmapped_findings: int = 0
    coverage_pct: float = 0.0

    def to_dict(self) -> Dict:
        return {
            "owasp_version": "2021",
            "total_findings": self.total_findings,
            "mapped_findings": self.mapped_findings,
            "unmapped_findings": self.unmapped_findings,
            "coverage_percentage": round(self.coverage_pct, 1),
            "categories": self.coverage,
        }


# ---------------------------------------------------------------------------
# Mapper
# ---------------------------------------------------------------------------

def _map_finding_to_owasp(cwe: str, issue_type: str, description: str) -> Optional[str]:
    """Map a finding to an OWASP Top 10 category.

    Strategy: CWE mapping first, then keyword fallback.
    """
    # Try CWE first
    if cwe:
        cwe_norm = cwe.upper().strip()
        if not cwe_norm.startswith("CWE-"):
            cwe_norm = f"CWE-{cwe_norm}"
        if cwe_norm in _CWE_TO_OWASP:
            return _CWE_TO_OWASP[cwe_norm]

    # Keyword fallback
    text = f"{issue_type} {description}".lower()
    import re as _re
    for keyword, owasp_id in _KEYWORD_TO_OWASP:
        if _re.search(_re.escape(keyword), text) if ("." in keyword or "(" in keyword) else keyword in text:
            return owasp_id

    return None


def generate_owasp_report(
    findings: List[Dict],
    sca_findings: Optional[List[Dict]] = None,
    iac_findings: Optional[List[Dict]] = None,
    cross_file_findings: Optional[List[Dict]] = None,
    container_findings: Optional[List[Dict]] = None,
) -> OWASPReport:
    """Generate OWASP Top 10 mapping from all finding types.

    Args:
        findings: Main scan findings (list of dicts with 'issue_type', 'severity', 'description', optional 'cwe')
        sca_findings: SCA findings
        iac_findings: IaC findings
        cross_file_findings: Cross-file taint findings
        container_findings: Container scan findings

    Returns:
        OWASPReport with coverage data.
    """
    report = OWASPReport()

    # Initialize coverage dict
    for key, info in OWASP_TOP_10.items():
        report.coverage[key] = {
            "id": info["id"],
            "name": info["name"],
            "finding_count": 0,
            "severities": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "sample_findings": [],
        }

    all_items = []

    # Main findings
    for f in (findings or []):
        all_items.append({
            "cwe": f.get("cwe", ""),
            "type": f.get("issue_type", f.get("type", "")),
            "severity": f.get("severity", "medium"),
            "description": f.get("description", f.get("message", "")),
            "source_type": "static-analysis",
        })

    # SCA findings → A06
    for f in (sca_findings or []):
        all_items.append({
            "cwe": f.get("cwe", "CWE-1104"),
            "type": f.get("issue_type", "vulnerable-component"),
            "severity": f.get("severity", "medium"),
            "description": f.get("description", f.get("vulnerability", "")),
            "source_type": "sca",
        })

    # IaC findings → A05
    for f in (iac_findings or []):
        all_items.append({
            "cwe": f.get("cwe", ""),
            "type": f.get("issue_type", f.get("rule_id", "")),
            "severity": f.get("severity", "medium"),
            "description": f.get("description", ""),
            "source_type": "iac",
        })

    # Cross-file findings
    for f in (cross_file_findings or []):
        all_items.append({
            "cwe": f.get("cwe", ""),
            "type": f.get("issue_type", ""),
            "severity": f.get("severity", "medium"),
            "description": f.get("description", ""),
            "source_type": "cross-file-taint",
        })

    # Container findings
    for f in (container_findings or []):
        all_items.append({
            "cwe": f.get("cwe", ""),
            "type": f.get("rule_id", f.get("issue_type", "")),
            "severity": f.get("severity", "medium"),
            "description": f.get("description", ""),
            "source_type": "container",
        })

    report.total_findings = len(all_items)

    for item in all_items:
        owasp_id = _map_finding_to_owasp(
            item["cwe"], item["type"], item["description"]
        )
        if owasp_id and owasp_id in report.coverage:
            report.mapped_findings += 1
            cat = report.coverage[owasp_id]
            cat["finding_count"] += 1
            sev = item["severity"].lower()
            if sev in cat["severities"]:
                cat["severities"][sev] += 1
            # Keep up to 3 sample findings
            if len(cat["sample_findings"]) < 3:
                cat["sample_findings"].append({
                    "type": item["type"],
                    "severity": item["severity"],
                    "description": item["description"][:120],
                })
            report.mappings.append(OWASPMapping(
                owasp_id=owasp_id,
                owasp_name=OWASP_TOP_10[owasp_id]["name"],
                finding_type=item["type"],
                finding_severity=item["severity"],
                finding_description=item["description"][:120],
                source="cwe" if item["cwe"] else "keyword",
            ))
        else:
            report.unmapped_findings += 1

    # Coverage percentage: how many of the 10 categories have at least 1 finding
    covered = sum(1 for v in report.coverage.values() if v["finding_count"] > 0)
    report.coverage_pct = (covered / 10) * 100

    return report


def format_owasp_cli(report: OWASPReport) -> str:
    """Format OWASP Top 10 coverage as a CLI table."""
    lines = [
        "OWASP Top 10 (2021) Coverage Report",
        "=" * 70,
    ]

    for key in sorted(OWASP_TOP_10.keys()):
        info = OWASP_TOP_10[key]
        cat = report.coverage.get(key, {})
        count = cat.get("finding_count", 0)
        status = "✓ COVERED" if count > 0 else "✗ No findings"
        sev = cat.get("severities", {})
        sev_str = ""
        if count > 0:
            parts = []
            for s in ("critical", "high", "medium", "low"):
                if sev.get(s, 0):
                    parts.append(f"{sev[s]} {s}")
            sev_str = f" ({', '.join(parts)})"

        lines.append(f"  {info['id']:14s} {info['name'][:40]:<40s} {count:3d} findings  {status}{sev_str}")

    lines.append("=" * 70)
    lines.append(f"  Coverage: {report.coverage_pct:.0f}% ({report.mapped_findings}/{report.total_findings} findings mapped)")
    if report.unmapped_findings:
        lines.append(f"  Unmapped: {report.unmapped_findings} findings could not be mapped to OWASP Top 10")

    return "\n".join(lines)


def format_owasp_html(report: OWASPReport) -> str:
    """Generate an HTML fragment for the OWASP Top 10 coverage report."""
    rows = []
    for key in sorted(OWASP_TOP_10.keys()):
        info = OWASP_TOP_10[key]
        cat = report.coverage.get(key, {})
        count = cat.get("finding_count", 0)
        color = "#e74c3c" if count == 0 else "#27ae60"
        icon = "&#10003;" if count > 0 else "&#10007;"

        sev = cat.get("severities", {})
        sev_html = ""
        for s, c in sev.items():
            if c > 0:
                cls = {"critical": "#d63031", "high": "#e17055", "medium": "#fdcb6e", "low": "#74b9ff", "info": "#b2bec3"}.get(s, "#b2bec3")
                sev_html += f'<span style="color:{cls};font-weight:bold;">{c} {s}</span> '

        rows.append(
            f'<tr>'
            f'<td style="color:{color};font-weight:bold;">{icon}</td>'
            f'<td><strong>{info["id"]}</strong></td>'
            f'<td>{info["name"]}</td>'
            f'<td style="text-align:center;">{count}</td>'
            f'<td>{sev_html}</td>'
            f'</tr>'
        )

    html = f"""
<div class="owasp-report" style="margin:20px 0;">
  <h3>OWASP Top 10 (2021) Coverage</h3>
  <p>Coverage: <strong>{report.coverage_pct:.0f}%</strong> &mdash;
     {report.mapped_findings}/{report.total_findings} findings mapped</p>
  <table style="width:100%;border-collapse:collapse;font-size:14px;">
    <thead>
      <tr style="background:#2d3436;color:#fff;">
        <th style="padding:8px;width:30px;"></th>
        <th style="padding:8px;">ID</th>
        <th style="padding:8px;">Category</th>
        <th style="padding:8px;text-align:center;">Findings</th>
        <th style="padding:8px;">Severity Breakdown</th>
      </tr>
    </thead>
    <tbody>
      {''.join(rows)}
    </tbody>
  </table>
</div>
"""
    return html


if __name__ == "__main__":
    # Demo with sample findings
    sample_findings = [
        {"issue_type": "buffer-overflow", "severity": "critical", "description": "Stack buffer overflow via gets()", "cwe": "CWE-121"},
        {"issue_type": "sql-injection", "severity": "high", "description": "SQL injection in query builder", "cwe": "CWE-89"},
        {"issue_type": "use-after-free", "severity": "critical", "description": "Use after free in parser", "cwe": "CWE-416"},
        {"issue_type": "hardcoded-password", "severity": "high", "description": "Hard-coded password in config", "cwe": "CWE-798"},
        {"issue_type": "weak-crypto", "severity": "medium", "description": "Use of MD5 for password hashing", "cwe": "CWE-327"},
        {"issue_type": "format-string", "severity": "high", "description": "Format string vulnerability", "cwe": "CWE-134"},
    ]
    report = generate_owasp_report(sample_findings)
    print(format_owasp_cli(report))
