"""
remediation_db.py — Secure-alternative snippets for OverflowGuard v10.0

For every dangerous function / pattern the scanner can detect, this module
provides:

1. A **short explanation** of why the function is dangerous.
2. A **secure alternative** code snippet showing the correct replacement.
3. **References** (CWE, CERT, man-page, language docs).

The data is consumed by:
    • The HTML report generator — renders a collapsible "Secure Alternative"
      card below each finding.
    • The CLI summary — prints a one-liner fix hint.

Exported API
------------
    get_remediation(issue_type, lang=None)  → RemediationEntry | None
    RemediationEntry                        — dataclass
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class RemediationEntry:
    """A single remediation record."""
    dangerous_call: str            # e.g. "gets()"
    why_dangerous: str             # short explanation
    secure_alternative: str        # replacement function / pattern
    secure_snippet: str            # multi-line code snippet (in the target lang)
    references: List[str] = field(default_factory=list)
    languages: List[str] = field(default_factory=list)  # ["c", "cpp"] etc.


# ---------------------------------------------------------------------------
# Database — keyed by (issue_type, optional lang_hint)
# ---------------------------------------------------------------------------

_REMEDIATION_DB: Dict[str, RemediationEntry] = {}


def _add(issue_types: list, entry: RemediationEntry) -> None:
    for it in issue_types:
        _REMEDIATION_DB[it] = entry


# ── C / C++ buffer overflows ────────────────────────────────────────────────

_add(["stack-buffer-overflow", "buffer-overflow", "heap-buffer-overflow"], RemediationEntry(
    dangerous_call="strcpy() / strcat() / sprintf() / gets()",
    why_dangerous=(
        "These functions perform unbounded copies — they do not check the "
        "destination buffer size, leading to stack or heap buffer overflows."
    ),
    secure_alternative="strncpy() + NUL / strncat() / snprintf() / fgets()",
    secure_snippet="""\
// DANGEROUS — unbounded copy
char buf[64];
strcpy(buf, user_input);          // ← overflow if strlen(user_input) >= 64
gets(buf);                         // ← NEVER use gets()

// ──── SECURE ALTERNATIVE ────
char buf[64];

// Instead of strcpy():
strncpy(buf, user_input, sizeof(buf) - 1);
buf[sizeof(buf) - 1] = '\\0';     // always NUL-terminate

// Instead of gets():
if (fgets(buf, sizeof(buf), stdin) != NULL) {
    buf[strcspn(buf, "\\n")] = '\\0';  // strip trailing newline
}

// Instead of sprintf():
snprintf(buf, sizeof(buf), "Hello %s", user_input);

// Instead of strcat():
strncat(buf, suffix, sizeof(buf) - strlen(buf) - 1);""",
    references=[
        "CWE-120: Buffer Copy without Checking Size",
        "CWE-121: Stack-based Buffer Overflow",
        "CWE-122: Heap-based Buffer Overflow",
        "CERT C: STR31-C — Guarantee sufficient storage for strings",
        "man 3 strncpy, man 3 snprintf, man 3 fgets",
    ],
    languages=["c", "cpp"],
))

# ── Format string ──────────────────────────────────────────────────────────

_add(["format-string"], RemediationEntry(
    dangerous_call="printf(user_input) / fprintf(fp, user_input)",
    why_dangerous=(
        "When the format string is attacker-controlled, %n writes to memory "
        "and %x / %s leak stack data.  This can lead to arbitrary code "
        "execution via format-string attacks."
    ),
    secure_alternative="printf(\"%s\", user_input)",
    secure_snippet="""\
// DANGEROUS — user controls the format string
printf(user_input);             // ← attacker can use %n, %x, %s

// ──── SECURE ALTERNATIVE ────
printf("%s", user_input);       // treat input as a plain string
// Or use fputs() which has no format interpretation:
fputs(user_input, stdout);""",
    references=[
        "CWE-134: Use of Externally-Controlled Format String",
        "CERT C: FIO30-C — Exclude user input from format strings",
    ],
    languages=["c", "cpp"],
))

# ── Double free ────────────────────────────────────────────────────────────

_add(["double-free"], RemediationEntry(
    dangerous_call="free(ptr) called multiple times",
    why_dangerous=(
        "Freeing the same pointer twice corrupts the heap allocator metadata. "
        "An attacker can manipulate the free-list to achieve arbitrary write "
        "and code execution."
    ),
    secure_alternative="Set pointer to NULL after free()",
    secure_snippet="""\
// DANGEROUS — double free
free(ptr);
// ... more code ...
free(ptr);       // ← second free → heap corruption

// ──── SECURE ALTERNATIVE ────
free(ptr);
ptr = NULL;       // prevents accidental double-free
// ... more code ...
free(ptr);        // free(NULL) is a harmless no-op""",
    references=[
        "CWE-415: Double Free",
        "CERT C: MEM30-C — Do not access freed memory",
    ],
    languages=["c", "cpp"],
))

# ── Use after free ─────────────────────────────────────────────────────────

_add(["use-after-free"], RemediationEntry(
    dangerous_call="Accessing memory after free()",
    why_dangerous=(
        "After free(), the memory may be reallocated to a different object. "
        "Dereferencing the dangling pointer reads/writes unrelated data, "
        "enabling info-leak or code execution."
    ),
    secure_alternative="Nullify pointer after free; use RAII / smart pointers in C++",
    secure_snippet="""\
// DANGEROUS
free(obj);
obj->field = 42;   // ← use-after-free

// ──── SECURE ALTERNATIVE (C) ────
free(obj);
obj = NULL;         // any subsequent access will segfault deterministically

// ──── SECURE ALTERNATIVE (C++) ────
// Use std::unique_ptr / std::shared_ptr — automatic lifetime management
auto obj = std::make_unique<Widget>();
obj->field = 42;    // safe — pointer is valid
// memory is freed automatically when obj goes out of scope""",
    references=[
        "CWE-416: Use After Free",
        "CERT C: MEM30-C — Do not access freed memory",
    ],
    languages=["c", "cpp"],
))

# ── Integer overflow ──────────────────────────────────────────────────────

_add(["integer-overflow", "integer-truncation"], RemediationEntry(
    dangerous_call="Unchecked arithmetic / narrow cast in size computation",
    why_dangerous=(
        "If an integer multiplication or addition wraps around, the resulting "
        "value is much smaller than expected.  When used as an allocation "
        "size, this creates a tiny buffer that subsequent writes overflow."
    ),
    secure_alternative="Check for overflow before the operation",
    secure_snippet="""\
// DANGEROUS
size_t total = count * element_size;  // ← wraps if count is large
void *buf = malloc(total);

// ──── SECURE ALTERNATIVE (C) ────
if (count > 0 && element_size > SIZE_MAX / count) {
    // Overflow detected — reject the request
    return NULL;
}
size_t total = count * element_size;
void *buf = malloc(total);

// ──── SECURE ALTERNATIVE (C11+) ────
// Use calloc() which performs the overflow check internally:
void *buf = calloc(count, element_size);  // returns NULL on overflow""",
    references=[
        "CWE-190: Integer Overflow or Wraparound",
        "CWE-681: Incorrect Conversion between Numeric Types",
        "CERT C: INT30-C — Ensure unsigned operations do not wrap",
    ],
    languages=["c", "cpp"],
))

# ── Off-by-one ────────────────────────────────────────────────────────────

_add(["off-by-one"], RemediationEntry(
    dangerous_call="for (i = 0; i <= count; i++)  with array[i]",
    why_dangerous=(
        "Using <= instead of < as the loop termination condition causes the "
        "loop to execute one extra iteration, accessing array[count] which "
        "is one past the last valid index."
    ),
    secure_alternative="Use strict < comparison",
    secure_snippet="""\
// DANGEROUS — off-by-one
for (int i = 0; i <= count; i++) {   // ← accesses array[count]
    process(array[i]);
}

// ──── SECURE ALTERNATIVE ────
for (int i = 0; i < count; i++) {    // ← stops at array[count-1]
    process(array[i]);
}

// In C++, prefer range-based for:
for (auto& item : array) {
    process(item);
}""",
    references=[
        "CWE-193: Off-by-one Error",
        "CERT C: ARR30-C — Guarantee array indices are within valid range",
    ],
    languages=["c", "cpp"],
))

# ── OS command injection ─────────────────────────────────────────────────

_add(["os-command-injection", "os-injection"], RemediationEntry(
    dangerous_call="system() / popen() / os.system() / subprocess(shell=True)",
    why_dangerous=(
        "Passing user-controlled data to a shell command allows arbitrary "
        "command execution.  Metacharacters like ; | & ` $() enable "
        "chaining additional commands."
    ),
    secure_alternative="Use exec*() family / subprocess with shell=False / parameterised APIs",
    secure_snippet="""\
/* DANGEROUS — C */
char cmd[256];
sprintf(cmd, "ls %s", user_input);
system(cmd);                       // ← shell injection

/* ──── SECURE ALTERNATIVE (C) ──── */
// Use execve() which does NOT invoke a shell:
char *argv[] = {"/bin/ls", user_input, NULL};
execve("/bin/ls", argv, environ);

# DANGEROUS — Python
import os, subprocess
os.system("ls " + user_input)                     # ← injection
subprocess.run("ls " + user_input, shell=True)    # ← injection

# ──── SECURE ALTERNATIVE (Python) ────
import subprocess, shlex
subprocess.run(["ls", user_input])           # shell=False (default)
# Or if you must build a command string:
subprocess.run(shlex.split(f"ls {shlex.quote(user_input)}"))""",
    references=[
        "CWE-78: OS Command Injection",
        "CERT C: ENV33-C — Do not call system()",
        "OWASP: OS Command Injection",
    ],
    languages=["c", "cpp", "python", "java", "go"],
))

# ── SQL injection ────────────────────────────────────────────────────────

_add(["sql-injection"], RemediationEntry(
    dangerous_call="String concatenation / f-string in SQL query",
    why_dangerous=(
        "Injecting user input directly into SQL allows attackers to modify "
        "the query logic — extracting data, bypassing auth, or dropping tables."
    ),
    secure_alternative="Parameterised / prepared statements",
    secure_snippet="""\
# DANGEROUS — Python
cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")

# ──── SECURE ALTERNATIVE (Python) ────
cursor.execute("SELECT * FROM users WHERE name = %s", (name,))

// DANGEROUS — Java
stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");

// ──── SECURE ALTERNATIVE (Java) ────
PreparedStatement ps = conn.prepareStatement(
    "SELECT * FROM users WHERE name = ?");
ps.setString(1, name);
ResultSet rs = ps.executeQuery();

// DANGEROUS — Go
db.Query("SELECT * FROM users WHERE name = '" + name + "'")

// ──── SECURE ALTERNATIVE (Go) ────
db.Query("SELECT * FROM users WHERE name = $1", name)""",
    references=[
        "CWE-89: SQL Injection",
        "OWASP: SQL Injection Prevention Cheat Sheet",
    ],
    languages=["python", "java", "go", "c", "cpp"],
))

# ── Insecure deserialization ──────────────────────────────────────────────

_add(["insecure-deserialization"], RemediationEntry(
    dangerous_call="pickle.load() / ObjectInputStream / yaml.load()",
    why_dangerous=(
        "Deserializing untrusted data can instantiate arbitrary objects, "
        "leading to remote code execution.  Python pickle, Java's "
        "ObjectInputStream, and YAML's !!python/exec are all exploitable."
    ),
    secure_alternative="Use safe loaders / JSON / schema validation",
    secure_snippet="""\
# DANGEROUS — Python
import pickle, yaml
obj = pickle.loads(untrusted_data)   # ← RCE
obj = yaml.load(data)                # ← RCE via !!python/exec

# ──── SECURE ALTERNATIVE (Python) ────
import json, yaml
obj = json.loads(untrusted_data)             # JSON is inert
obj = yaml.safe_load(data)                   # safe_load blocks code execution

// DANGEROUS — Java
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject();               // ← RCE via gadget chains

// ──── SECURE ALTERNATIVE (Java) ────
// Use Jackson / Gson for JSON deserialization:
ObjectMapper mapper = new ObjectMapper();
MyClass obj = mapper.readValue(jsonString, MyClass.class);""",
    references=[
        "CWE-502: Deserialization of Untrusted Data",
        "OWASP: Deserialization Cheat Sheet",
    ],
    languages=["python", "java"],
))

# ── eval / exec ──────────────────────────────────────────────────────────

_add(["insecure-eval"], RemediationEntry(
    dangerous_call="eval() / exec()",
    why_dangerous=(
        "eval()/exec() execute arbitrary code.  If the input is "
        "attacker-controlled, this is a direct remote code execution vector."
    ),
    secure_alternative="ast.literal_eval() / dedicated parsers",
    secure_snippet="""\
# DANGEROUS
result = eval(user_input)         # ← arbitrary code execution

# ──── SECURE ALTERNATIVE ────
import ast
result = ast.literal_eval(user_input)   # only evaluates literals

# For math expressions, use a safe evaluator:
# pip install simpleeval
from simpleeval import simple_eval
result = simple_eval(user_input)""",
    references=[
        "CWE-95: Eval Injection",
        "CWE-94: Code Injection",
    ],
    languages=["python"],
))

# ── Weak crypto ──────────────────────────────────────────────────────────

_add(["weak-crypto"], RemediationEntry(
    dangerous_call="MD5 / SHA-1 / DES / RC4",
    why_dangerous=(
        "MD5 and SHA-1 are broken — practical collision attacks exist. "
        "DES has a 56-bit key (brute-forceable).  RC4 has known biases."
    ),
    secure_alternative="SHA-256+ / AES-256-GCM / ChaCha20-Poly1305",
    secure_snippet="""\
# DANGEROUS — Python
import hashlib
h = hashlib.md5(data).hexdigest()

# ──── SECURE ALTERNATIVE ────
import hashlib
h = hashlib.sha256(data).hexdigest()

// DANGEROUS — Java
MessageDigest md = MessageDigest.getInstance("MD5");

// ──── SECURE ALTERNATIVE ────
MessageDigest md = MessageDigest.getInstance("SHA-256");

// For encryption, use AES-256-GCM:
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");""",
    references=[
        "CWE-327: Use of a Broken Crypto Algorithm",
        "NIST SP 800-131A: Transitioning Crypto Algorithms",
    ],
    languages=["python", "java", "c", "cpp", "go"],
))

# ── Weak RNG ──────────────────────────────────────────────────────────────

_add(["weak-rng"], RemediationEntry(
    dangerous_call="rand() / srand() / java.util.Random / random.random()",
    why_dangerous=(
        "These PRNGs are predictable.  An attacker who observes enough "
        "outputs can predict future values, breaking session tokens, "
        "CSRF tokens, or password-reset links."
    ),
    secure_alternative="CSPRNG: /dev/urandom / secrets / SecureRandom",
    secure_snippet="""\
/* DANGEROUS — C */
int token = rand();

/* ──── SECURE ALTERNATIVE (C / Linux) ──── */
#include <sys/random.h>
unsigned char token[32];
getrandom(token, sizeof(token), 0);

# DANGEROUS — Python
import random
token = random.randint(0, 2**128)

# ──── SECURE ALTERNATIVE (Python) ────
import secrets
token = secrets.token_hex(32)

// DANGEROUS — Java
int token = new Random().nextInt();

// ──── SECURE ALTERNATIVE (Java) ────
SecureRandom sr = new SecureRandom();
byte[] token = new byte[32];
sr.nextBytes(token);""",
    references=[
        "CWE-330: Use of Insufficiently Random Values",
        "CERT C: MSC30-C — Do not use rand() for generating pseudorandom numbers",
    ],
    languages=["c", "cpp", "python", "java"],
))

# ── Hardcoded passwords / secrets ────────────────────────────────────────

_add(["hardcoded-password", "secret-in-code"], RemediationEntry(
    dangerous_call="password = \"s3cret\" / API_KEY = \"...\"",
    why_dangerous=(
        "Credentials in source code are extracted by anyone with read access "
        "to the repo.  They persist in git history even after deletion."
    ),
    secure_alternative="Environment variables / secrets manager",
    secure_snippet="""\
# DANGEROUS
DB_PASSWORD = "super_secret_123"

# ──── SECURE ALTERNATIVE (Python) ────
import os
DB_PASSWORD = os.environ["DB_PASSWORD"]

# Or use a secrets manager:
# from aws_secretsmanager import get_secret
# DB_PASSWORD = get_secret("prod/db/password")

// DANGEROUS — Java
String apiKey = "AKIAIOSFODNN7EXAMPLE";

// ──── SECURE ALTERNATIVE (Java) ────
String apiKey = System.getenv("API_KEY");""",
    references=[
        "CWE-798: Use of Hard-coded Credentials",
        "CWE-312: Cleartext Storage of Sensitive Information",
        "OWASP: Secrets Management Cheat Sheet",
    ],
    languages=["python", "java", "go", "c", "cpp", "rust"],
))

# ── Path traversal ──────────────────────────────────────────────────────

_add(["path-traversal"], RemediationEntry(
    dangerous_call="open(user_path) / fopen(user_path) / File(user_path)",
    why_dangerous=(
        "If the path contains '../' sequences or absolute paths, an attacker "
        "can read/write arbitrary files on the filesystem."
    ),
    secure_alternative="Canonicalize + validate against a base directory",
    secure_snippet="""\
/* DANGEROUS — C */
FILE *f = fopen(user_path, "r");

/* ──── SECURE ALTERNATIVE (C) ──── */
#include <stdlib.h>
char resolved[PATH_MAX];
if (realpath(user_path, resolved) == NULL) abort();
if (strncmp(resolved, "/safe/base/", 11) != 0) {
    fprintf(stderr, "Path traversal blocked\\n");
    abort();
}
FILE *f = fopen(resolved, "r");

# DANGEROUS — Python
with open(user_path) as f: ...

# ──── SECURE ALTERNATIVE (Python) ────
import os
base = "/safe/uploads"
real = os.path.realpath(os.path.join(base, user_path))
if not real.startswith(base + os.sep):
    raise ValueError("Path traversal attempt")
with open(real) as f: ...""",
    references=[
        "CWE-22: Path Traversal",
        "OWASP: Path Traversal",
    ],
    languages=["c", "cpp", "python", "java", "go"],
))

# ── SSRF ──────────────────────────────────────────────────────────────────

_add(["ssrf"], RemediationEntry(
    dangerous_call="requests.get(user_url) / http.Get(user_url)",
    why_dangerous=(
        "If the URL is attacker-controlled, they can make the server fetch "
        "internal resources (cloud metadata, internal APIs) or scan internal "
        "networks."
    ),
    secure_alternative="URL allowlist validation",
    secure_snippet="""\
# DANGEROUS — Python
resp = requests.get(user_url)

# ──── SECURE ALTERNATIVE ────
from urllib.parse import urlparse
ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}
parsed = urlparse(user_url)
if parsed.hostname not in ALLOWED_HOSTS:
    raise ValueError("SSRF blocked: host not in allowlist")
if parsed.scheme not in ("https",):
    raise ValueError("SSRF blocked: only HTTPS allowed")
resp = requests.get(user_url)""",
    references=[
        "CWE-918: Server-Side Request Forgery (SSRF)",
        "OWASP: SSRF Prevention Cheat Sheet",
    ],
    languages=["python", "java", "go"],
))

# ── XXE injection ────────────────────────────────────────────────────────

_add(["xxe-injection"], RemediationEntry(
    dangerous_call="XML parser without disabling external entities",
    why_dangerous=(
        "If external entity processing is enabled, an attacker can read "
        "local files, perform SSRF, or cause denial-of-service (billion "
        "laughs attack)."
    ),
    secure_alternative="Disable DTD / external entities; use defusedxml",
    secure_snippet="""\
# DANGEROUS — Python
from xml.etree.ElementTree import parse
tree = parse(user_xml)

# ──── SECURE ALTERNATIVE (Python) ────
import defusedxml.ElementTree as ET
tree = ET.parse(user_xml)    # external entities disabled by default

// DANGEROUS — Java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

// ──── SECURE ALTERNATIVE (Java) ────
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);""",
    references=[
        "CWE-611: Improper Restriction of XML External Entity Reference",
        "OWASP: XXE Prevention Cheat Sheet",
    ],
    languages=["python", "java"],
))

# ── Insecure TLS ────────────────────────────────────────────────────────

_add(["insecure-tls"], RemediationEntry(
    dangerous_call="InsecureSkipVerify / verify=False / SSL context with no cert check",
    why_dangerous=(
        "Disabling TLS certificate verification makes the connection "
        "vulnerable to man-in-the-middle attacks.  Any attacker on the "
        "network path can intercept and modify traffic."
    ),
    secure_alternative="Always verify certificates; pin if possible",
    secure_snippet="""\
# DANGEROUS — Python
requests.get(url, verify=False)

# ──── SECURE ALTERNATIVE ────
requests.get(url, verify=True)       # default — uses system CA bundle
# Or pin to a specific CA:
requests.get(url, verify="/path/to/custom-ca-bundle.pem")

// DANGEROUS — Go
&tls.Config{InsecureSkipVerify: true}

// ──── SECURE ALTERNATIVE (Go) ────
&tls.Config{
    InsecureSkipVerify: false,  // default
    MinVersion:         tls.VersionTLS13,
}""",
    references=[
        "CWE-295: Improper Certificate Validation",
        "OWASP: TLS Cheat Sheet",
    ],
    languages=["python", "go", "java"],
))

# ── Unsafe Rust blocks ──────────────────────────────────────────────────

_add(["unsafe-block"], RemediationEntry(
    dangerous_call="unsafe { } / mem::transmute / raw pointer dereference",
    why_dangerous=(
        "Code inside unsafe blocks bypasses Rust's borrow checker and "
        "safety guarantees.  Incorrect usage can cause buffer overflows, "
        "data races, and use-after-free — the same bugs Rust was designed "
        "to prevent."
    ),
    secure_alternative="Safe abstractions / crate APIs",
    secure_snippet="""\
// DANGEROUS
unsafe {
    let ptr = data.as_ptr();
    *ptr.add(index) = value;    // ← no bounds check
}

// ──── SECURE ALTERNATIVE ────
// Use safe indexing with bounds check:
data[index] = value;

// For FFI, wrap unsafe in a safe abstraction:
pub fn safe_wrapper(data: &mut [u8], index: usize, value: u8) -> Result<(), &str> {
    data.get_mut(index)
        .map(|cell| *cell = value)
        .ok_or("index out of bounds")
}""",
    references=[
        "Rust Book: Unsafe Rust",
        "CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer",
    ],
    languages=["rust"],
))

# ── Race condition ──────────────────────────────────────────────────────

_add(["race-condition"], RemediationEntry(
    dangerous_call="Shared mutable state without synchronization",
    why_dangerous=(
        "Concurrent access to shared memory without proper synchronization "
        "leads to data races.  The effects are non-deterministic and can "
        "include data corruption, crashes, or security bypasses."
    ),
    secure_alternative="Mutex / RWLock / channels / atomic operations",
    secure_snippet="""\
// DANGEROUS — Go
var counter int
go func() { counter++ }()    // ← data race

// ──── SECURE ALTERNATIVE (Go) ────
import "sync/atomic"
var counter int64
go func() { atomic.AddInt64(&counter, 1) }()

// Or use sync.Mutex:
var mu sync.Mutex
go func() {
    mu.Lock()
    counter++
    mu.Unlock()
}()""",
    references=[
        "CWE-362: Race Condition",
        "CWE-366: Race Condition within a Thread",
    ],
    languages=["go", "c", "cpp", "java"],
))

# ── Template injection (SSTI) ──────────────────────────────────────────

_add(["template-injection"], RemediationEntry(
    dangerous_call="render_template_string(user_input) / SpEL expression",
    why_dangerous=(
        "If the template string is attacker-controlled, Server-Side Template "
        "Injection allows arbitrary code execution on the server."
    ),
    secure_alternative="Never pass user input as the template itself",
    secure_snippet="""\
# DANGEROUS — Flask/Jinja2
from flask import render_template_string
return render_template_string(user_input)    # ← SSTI → RCE

# ──── SECURE ALTERNATIVE ────
from flask import render_template
# Put the template in a file, pass user data as a variable:
return render_template("greeting.html", name=user_input)""",
    references=[
        "CWE-1336: Server-Side Template Injection",
        "OWASP: Server-Side Template Injection",
    ],
    languages=["python", "java"],
))

# ── Null pointer / unchecked alloc ──────────────────────────────────────

_add(["null-pointer"], RemediationEntry(
    dangerous_call="malloc() without NULL check",
    why_dangerous=(
        "malloc() returns NULL when the system is out of memory. "
        "Dereferencing NULL is undefined behavior and typically crashes "
        "the process.  In certain environments, it can be exploitable."
    ),
    secure_alternative="Always check the return value",
    secure_snippet="""\
// DANGEROUS
char *buf = malloc(size);
memcpy(buf, src, size);          // ← crash if buf == NULL

// ──── SECURE ALTERNATIVE ────
char *buf = malloc(size);
if (buf == NULL) {
    perror("malloc failed");
    return -1;                   // or handle gracefully
}
memcpy(buf, src, size);""",
    references=[
        "CWE-476: NULL Pointer Dereference",
        "CERT C: MEM32-C — Detect and handle memory allocation errors",
    ],
    languages=["c", "cpp"],
))

# ── Insecure temp file ──────────────────────────────────────────────────

_add(["insecure-temp-file"], RemediationEntry(
    dangerous_call="tmpnam() / tempnam() / mktemp()",
    why_dangerous=(
        "These functions create predictable temporary file names, enabling "
        "symlink attacks (TOCTOU race).  An attacker can pre-create a "
        "symlink at the predicted path."
    ),
    secure_alternative="mkstemp() / tmpfile() / tempfile.NamedTemporaryFile",
    secure_snippet="""\
/* DANGEROUS — C */
char *name = tmpnam(NULL);
FILE *f = fopen(name, "w");

/* ──── SECURE ALTERNATIVE (C) ──── */
char template[] = "/tmp/myapp-XXXXXX";
int fd = mkstemp(template);      // creates unique file atomically
FILE *f = fdopen(fd, "w");

# DANGEROUS — Python
import tempfile, os
path = tempfile.mktemp()         # ← race condition
open(path, 'w').write(data)

# ──── SECURE ALTERNATIVE (Python) ────
import tempfile
with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
    f.write(data)
    safe_path = f.name""",
    references=[
        "CWE-377: Insecure Temporary File",
        "CERT C: FIO21-C — Do not create temporary files in shared directories",
    ],
    languages=["c", "cpp", "python"],
))

# ── JWT none algorithm ──────────────────────────────────────────────────

_add(["jwt-none-alg"], RemediationEntry(
    dangerous_call="algorithms=['none'] in JWT verification",
    why_dangerous=(
        "The 'none' algorithm means the JWT signature is not checked. "
        "An attacker can forge tokens with arbitrary claims."
    ),
    secure_alternative="Explicitly specify the expected algorithm",
    secure_snippet="""\
# DANGEROUS
import jwt
payload = jwt.decode(token, options={"verify_signature": False})

# ──── SECURE ALTERNATIVE ────
import jwt
payload = jwt.decode(
    token,
    key=SECRET_KEY,
    algorithms=["HS256"],         # only accept HMAC-SHA256
)""",
    references=[
        "CWE-345: Insufficient Verification of Data Authenticity",
        "RFC 7519: JSON Web Token (JWT)",
    ],
    languages=["python"],
))

# ── Open redirect ────────────────────────────────────────────────────────

_add(["open-redirect"], RemediationEntry(
    dangerous_call="redirect(request.args['url'])",
    why_dangerous=(
        "An open redirect allows phishing attacks.  The attacker crafts a "
        "URL on your trusted domain that redirects to their malicious site."
    ),
    secure_alternative="Validate redirect target against an allowlist",
    secure_snippet="""\
# DANGEROUS — Flask
return redirect(request.args.get("next"))

# ──── SECURE ALTERNATIVE ────
from urllib.parse import urlparse
SAFE_HOSTS = {"example.com", "www.example.com"}
target = request.args.get("next", "/")
parsed = urlparse(target)
if parsed.netloc and parsed.netloc not in SAFE_HOSTS:
    target = "/"                  # fallback to home page
return redirect(target)""",
    references=[
        "CWE-601: Open Redirect",
        "OWASP: Unvalidated Redirects and Forwards",
    ],
    languages=["python", "java", "go"],
))

# ── Ring buffer overflow ────────────────────────────────────────────────

_add(["ring-buffer-overflow", "uncapped-loop-bound"], RemediationEntry(
    dangerous_call="Direct array indexing with ring-buffer head/tail",
    why_dangerous=(
        "Ring-buffer head/tail indices must be wrapped with modulo (%). "
        "Without it, the index grows beyond the buffer capacity, causing "
        "an out-of-bounds write."
    ),
    secure_alternative="Always mask or modulo the index",
    secure_snippet="""\
// DANGEROUS
buf[head++] = value;           // ← head grows past capacity

// ──── SECURE ALTERNATIVE ────
buf[head % CAPACITY] = value;
head++;

// Or use a power-of-two capacity with bitwise AND:
#define CAP 256  // must be power of 2
buf[head & (CAP - 1)] = value;
head++;""",
    references=[
        "CWE-787: Out-of-bounds Write",
        "CWE-119: Buffer Overflow",
    ],
    languages=["c", "cpp"],
))

# ── Resource leak ────────────────────────────────────────────────────────

_add(["resource-leak"], RemediationEntry(
    dangerous_call="Unclosed file / socket / goroutine leak",
    why_dangerous=(
        "Leaked resources exhaust system limits (file descriptors, memory, "
        "goroutines).  This leads to denial-of-service under load."
    ),
    secure_alternative="RAII / defer / try-with-resources / context managers",
    secure_snippet="""\
// DANGEROUS — Go
ch := make(chan int)
go func() { ch <- 1 }()       // nobody reads → goroutine blocks forever

// ──── SECURE ALTERNATIVE (Go) ────
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
ch := make(chan int, 1)        // buffered — won't block if consumer dies
go func() {
    select {
    case ch <- 1:
    case <-ctx.Done():
    }
}()

# DANGEROUS — Python
f = open("data.txt")
data = f.read()
# f is never closed if an exception occurs

# ──── SECURE ALTERNATIVE (Python) ────
with open("data.txt") as f:   # auto-closed on exit
    data = f.read()""",
    references=[
        "CWE-404: Improper Resource Shutdown or Release",
        "CWE-775: Missing Release of File Descriptor or Handle",
    ],
    languages=["go", "python", "java", "c", "cpp"],
))

# ── Input validation ────────────────────────────────────────────────────

_add(["input-validation", "insecure-config"], RemediationEntry(
    dangerous_call="Unvalidated user input / insecure configuration",
    why_dangerous=(
        "Missing input validation allows malformed or malicious data to "
        "propagate through the application, triggering downstream bugs."
    ),
    secure_alternative="Validate, sanitize, and constrain all inputs",
    secure_snippet="""\
# ──── SECURE PATTERN ────
# 1. Validate type and format
# 2. Constrain to expected range
# 3. Reject or sanitize unexpected values

# Python example:
def safe_get_age(raw: str) -> int:
    try:
        age = int(raw)
    except ValueError:
        raise ValueError("Age must be an integer")
    if not (0 <= age <= 150):
        raise ValueError("Age out of valid range")
    return age""",
    references=[
        "CWE-20: Improper Input Validation",
        "OWASP: Input Validation Cheat Sheet",
    ],
    languages=["python", "java", "go", "c", "cpp"],
))

# ── Panic unwrap (Rust) ────────────────────────────────────────────────

_add(["panic-unwrap"], RemediationEntry(
    dangerous_call=".unwrap() / .expect()",
    why_dangerous=(
        "unwrap()/expect() will panic and crash the program if the Result "
        "is Err or the Option is None.  In a server context, this causes "
        "a denial-of-service."
    ),
    secure_alternative="Use the ? operator or pattern matching",
    secure_snippet="""\
// DANGEROUS
let val = some_function().unwrap();    // panics on Err

// ──── SECURE ALTERNATIVE ────
let val = some_function()?;            // propagates error to caller

// Or handle explicitly:
let val = match some_function() {
    Ok(v) => v,
    Err(e) => {
        eprintln!("Error: {e}");
        return Err(e.into());
    }
};""",
    references=[
        "Rust Book: Error Handling",
        "Clippy: unwrap_used",
    ],
    languages=["rust"],
))

# ── LDAP injection ──────────────────────────────────────────────────────

_add(["ldap-injection"], RemediationEntry(
    dangerous_call="LDAP search with unescaped user input in filter",
    why_dangerous=(
        "LDAP metacharacters (*, (, ), \\, NUL) in the filter can modify "
        "the query to bypass authentication or leak directory data."
    ),
    secure_alternative="Escape input per RFC 4515",
    secure_snippet="""\
// DANGEROUS — Java
String filter = "(uid=" + username + ")";
ctx.search("ou=users", filter, ...);

// ──── SECURE ALTERNATIVE (Java) ────
import javax.naming.ldap.LdapName;
// Escape special characters per RFC 4515:
String safe = username
    .replace("\\\\", "\\\\5c")
    .replace("*", "\\\\2a")
    .replace("(", "\\\\28")
    .replace(")", "\\\\29")
    .replace("\\0", "\\\\00");
String filter = "(uid=" + safe + ")";""",
    references=[
        "CWE-90: LDAP Injection",
        "OWASP: LDAP Injection Prevention",
    ],
    languages=["java"],
))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_remediation(issue_type: str, lang: Optional[str] = None) -> Optional[RemediationEntry]:
    """
    Look up the remediation entry for *issue_type*.

    Parameters
    ----------
    issue_type : str
        The vulnerability type key (e.g. ``"stack-buffer-overflow"``).
    lang : str, optional
        If supplied, only return the entry when it matches the language.

    Returns
    -------
    RemediationEntry or None
    """
    entry = _REMEDIATION_DB.get(issue_type)
    if entry is None:
        return None
    if lang and entry.languages and lang not in entry.languages:
        return None
    return entry


def get_cli_hint(issue_type: str) -> str:
    """
    Return a one-line CLI remediation hint for *issue_type*.

    Example::

        "Fix: Replace strcpy() with strncpy(buf, src, sizeof(buf)-1)"
    """
    entry = get_remediation(issue_type)
    if entry is None:
        return ""
    return f"Fix: Replace {entry.dangerous_call} → {entry.secure_alternative}"


def get_html_snippet(issue_type: str) -> str:
    """
    Return an HTML block containing the secure-alternative code snippet
    suitable for embedding in the HTML report.
    """
    import html as html_mod
    entry = get_remediation(issue_type)
    if entry is None:
        return ""

    escaped_why = html_mod.escape(entry.why_dangerous)
    escaped_alt = html_mod.escape(entry.secure_alternative)
    escaped_code = html_mod.escape(entry.secure_snippet)
    refs_html = "".join(
        f"<li>{html_mod.escape(r)}</li>" for r in entry.references
    )

    return f"""
<details style="margin-top:10px;background:#111;border:1px solid #2a2a2a;
                border-radius:6px;padding:0;">
  <summary style="cursor:pointer;padding:10px 14px;font-weight:700;
                  color:#69f0ae;font-size:.9em;">
    🔧 Secure Alternative: {escaped_alt}
  </summary>
  <div style="padding:12px 16px;">
    <p style="color:#ff9100;font-size:.85em;margin-bottom:8px;">
      <b>Why dangerous:</b> {escaped_why}
    </p>
    <pre style="background:#000;color:#00ff00;padding:14px;
                border-radius:6px;overflow-x:auto;font-size:.85em;
                line-height:1.5;border:1px solid #333;
                white-space:pre-wrap;">{escaped_code}</pre>
    <div style="margin-top:8px;font-size:.8em;color:#888;">
      <b>References:</b>
      <ul style="margin:4px 0 0 16px;padding:0;">
        {refs_html}
      </ul>
    </div>
  </div>
</details>"""
