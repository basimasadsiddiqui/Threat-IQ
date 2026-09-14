"""ThreatIQ's security knowledge base.

This is the corpus that backs RAG and the compliance mapper. It is shipped in
code rather than fetched at runtime so that framework mappings are reproducible
and work offline, a mapping that changes silently between runs is useless for
compliance evidence.

Each entry carries `keywords`, which lets the compliance mapper do a
deterministic first pass before falling back to semantic retrieval.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class KnowledgeDoc:
    id: str
    framework: str          # OWASP | OWASP-API | CWE | MITRE | NIST-CSF | ASVS
    code: str               # A03:2021, CWE-89, T1566.002, PR.AC-1
    title: str
    text: str
    keywords: list[str] = field(default_factory=list)
    url: str = ""

    @property
    def label(self) -> str:
        return f"{self.code}, {self.title}"

    def to_document(self) -> str:
        return (f"[{self.framework}] {self.code}: {self.title}\n{self.text}\n"
                f"Keywords: {', '.join(self.keywords)}")


OWASP_TOP_10: list[KnowledgeDoc] = [
    KnowledgeDoc(
        "owasp-a01", "OWASP", "A01:2021", "Broken Access Control",
        "Access control enforces that users act only within their intended "
        "permissions. Failures let attackers access other users' accounts, view "
        "sensitive files, modify data, or change access rights. Includes IDOR, "
        "path traversal, privilege escalation, missing function-level access "
        "control, and CORS misconfiguration. Control: deny by default, enforce "
        "access control server-side, log failures and alert on repeats.",
        ["access control", "idor", "authorization", "privilege escalation",
         "path traversal", "forced browsing", "cors", "insecure direct object"],
        "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    ),
    KnowledgeDoc(
        "owasp-a02", "OWASP", "A02:2021", "Cryptographic Failures",
        "Failures related to cryptography that expose sensitive data. Includes "
        "cleartext transmission, weak or deprecated algorithms (MD5, SHA1, DES), "
        "hardcoded or default keys, missing HSTS, and improper certificate "
        "validation. Control: encrypt data in transit with TLS 1.2+, enforce "
        "HSTS, use strong adaptive hashing for passwords, rotate keys.",
        ["encryption", "tls", "ssl", "cleartext", "plaintext", "weak cipher",
         "md5", "sha1", "hsts", "certificate", "https downgrade", "hardcoded key"],
        "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    ),
    KnowledgeDoc(
        "owasp-a03", "OWASP", "A03:2021", "Injection",
        "User-supplied data is not validated, filtered or sanitised, and is "
        "interpreted as a command or query. Covers SQL, NoSQL, OS command, LDAP, "
        "XPath and expression-language injection, and cross-site scripting. "
        "Control: use parameterised queries and prepared statements, validate "
        "input server-side against an allowlist, escape output contextually, and "
        "apply LIMIT clauses to constrain mass disclosure.",
        ["sql injection", "sqli", "nosql injection", "command injection", "xss",
         "cross-site scripting", "ldap injection", "xpath", "template injection",
         "parameterized query", "sanitization"],
        "https://owasp.org/Top10/A03_2021-Injection/",
    ),
    KnowledgeDoc(
        "owasp-a04", "OWASP", "A04:2021", "Insecure Design",
        "Missing or ineffective control design, flaws that cannot be fixed by a "
        "perfect implementation. Includes absent threat modelling, missing rate "
        "limiting on sensitive flows, and business-logic abuse. Control: threat "
        "model per feature, write abuse cases alongside user stories, apply "
        "secure design patterns and reference architectures.",
        ["insecure design", "threat model", "business logic", "rate limiting",
         "abuse case", "design flaw", "missing control"],
        "https://owasp.org/Top10/A04_2021-Insecure_Design/",
    ),
    KnowledgeDoc(
        "owasp-a05", "OWASP", "A05:2021", "Security Misconfiguration",
        "Insecure default configurations, incomplete configurations, open cloud "
        "storage, verbose error messages revealing stack traces, unnecessary "
        "features enabled, and missing security headers such as CSP, HSTS, "
        "X-Content-Type-Options and X-Frame-Options. Control: hardened baseline "
        "images, automated configuration verification, minimal platform surface.",
        ["misconfiguration", "security headers", "csp", "x-frame-options",
         "hsts missing", "default credentials", "directory listing", "verbose error",
         "stack trace", "open bucket", "permissions-policy", "x-content-type-options"],
        "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    ),
    KnowledgeDoc(
        "owasp-a06", "OWASP", "A06:2021",
        "Vulnerable and Outdated Components",
        "Using components with known vulnerabilities, or running unsupported/"
        "out-of-date software. Applies to OS, web server, DBMS, APIs, libraries "
        "and runtime environments. Control: maintain an inventory/SBOM, monitor "
        "CVE feeds and CISA KEV, patch on a risk-based schedule, remove unused "
        "dependencies.",
        ["outdated component", "vulnerable dependency", "cve", "unpatched",
         "end of life", "sbom", "known vulnerability", "library version",
         "third-party component", "kev"],
        "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
    ),
    KnowledgeDoc(
        "owasp-a07", "OWASP", "A07:2021",
        "Identification and Authentication Failures",
        "Weaknesses that let attackers assume other users' identities: credential "
        "stuffing, brute force, weak or default passwords, weak credential "
        "recovery, missing or ineffective MFA, exposed session IDs, and sessions "
        "that are not invalidated on logout. Control: enforce MFA, block known "
        "breached passwords, rate-limit and log failed logins, rotate session IDs "
        "on authentication.",
        ["authentication", "broken authentication", "credential stuffing",
         "brute force", "weak password", "mfa", "session fixation",
         "session management", "password reset", "default credentials",
         "credential harvesting"],
        "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    ),
    KnowledgeDoc(
        "owasp-a08", "OWASP", "A08:2021",
        "Software and Data Integrity Failures",
        "Code and infrastructure that does not protect against integrity "
        "violations: insecure deserialisation, unsigned updates, CI/CD pipelines "
        "without integrity checks, and dependence on plugins or modules from "
        "untrusted sources. Control: verify signatures, pin and verify "
        "dependencies, review CI/CD access, use SLSA-style provenance.",
        ["deserialization", "supply chain", "unsigned update", "ci/cd",
         "integrity", "pipeline", "dependency confusion", "code signing"],
        "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
    ),
    KnowledgeDoc(
        "owasp-a09", "OWASP", "A09:2021",
        "Security Logging and Monitoring Failures",
        "Insufficient logging, detection, monitoring and active response. "
        "Auditable events such as logins, failed logins and high-value "
        "transactions are not logged; logs are only stored locally; alerting "
        "thresholds are absent. Control: log security-relevant events with "
        "sufficient context, ship logs centrally, define detection rules and an "
        "incident response plan.",
        ["logging", "monitoring", "audit log", "detection", "alerting",
         "incident response", "siem", "no logs"],
        "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
    ),
    KnowledgeDoc(
        "owasp-a10", "OWASP", "A10:2021", "Server-Side Request Forgery (SSRF)",
        "The application fetches a remote resource without validating the "
        "user-supplied URL, letting an attacker coerce requests to internal "
        "services, cloud metadata endpoints, or the loopback interface. Control: "
        "validate and allowlist destinations, block private/link-local ranges, "
        "disable redirects or re-validate every hop, segment egress.",
        ["ssrf", "server-side request forgery", "internal network", "metadata "
         "endpoint", "169.254.169.254", "url fetch", "redirect validation"],
        "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
    ),
]

OWASP_API_TOP_10: list[KnowledgeDoc] = [
    KnowledgeDoc(
        "owasp-api1", "OWASP-API", "API1:2023",
        "Broken Object Level Authorization",
        "APIs expose endpoints handling object identifiers, creating a wide "
        "attack surface. Every function that accesses a data source using an ID "
        "from the client must validate that the caller may access that object. "
        "Control: enforce object-level checks in every handler, use random "
        "unpredictable IDs, and test with a second low-privilege account.",
        ["bola", "object level authorization", "idor", "api authorization",
         "object id", "horizontal privilege"],
        "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
    ),
    KnowledgeDoc(
        "owasp-api2", "OWASP-API", "API2:2023", "Broken Authentication",
        "Authentication mechanisms in APIs are implemented incorrectly, letting "
        "attackers compromise tokens or exploit flaws to assume identities. "
        "Includes missing rate limiting on login, weak JWT validation (accepting "
        "alg=none), long-lived tokens and credentials in URLs. Control: validate "
        "token signature and claims, short token lifetimes, rate limit auth.",
        ["api authentication", "jwt", "token", "alg none", "api key in url",
         "credential stuffing", "broken authentication"],
        "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
    ),
    KnowledgeDoc(
        "owasp-api3", "OWASP-API", "API3:2023",
        "Broken Object Property Level Authorization",
        "Combines mass assignment and excessive data exposure: the API returns or "
        "accepts object properties the caller should not read or write. Control: "
        "define explicit request and response schemas, never bind client input "
        "straight to a model, and filter responses server-side.",
        ["mass assignment", "excessive data exposure", "property authorization",
         "over-posting", "response filtering"],
        "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
    ),
    KnowledgeDoc(
        "owasp-api4", "OWASP-API", "API4:2023",
        "Unrestricted Resource Consumption",
        "API requests consume network, CPU, memory or paid third-party calls. "
        "Without limits, attackers cause denial of service or run up costs. "
        "Control: enforce rate limits and quotas per client, cap payload sizes "
        "and pagination limits, add timeouts, and monitor spend on outbound APIs.",
        ["rate limiting", "resource consumption", "denial of service", "quota",
         "pagination limit", "payload size", "throttling"],
        "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
    ),
    KnowledgeDoc(
        "owasp-api5", "OWASP-API", "API5:2023",
        "Broken Function Level Authorization",
        "Complex access control policies with unclear separation between "
        "administrative and regular functions let attackers reach privileged "
        "endpoints. Control: deny by default, enforce role checks in a shared "
        "middleware rather than per-handler, and review admin route exposure.",
        ["function level authorization", "admin endpoint", "vertical privilege",
         "role check", "privilege escalation", "bfla"],
        "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
    ),
    KnowledgeDoc(
        "owasp-api7", "OWASP-API", "API7:2023", "Server Side Request Forgery",
        "APIs that fetch a remote resource from a client-supplied URI without "
        "validation allow SSRF, often bypassing firewalls or VPNs. Control: "
        "allowlist schemes and destinations, resolve and validate the IP before "
        "connecting, and disable automatic redirect following.",
        ["ssrf", "api ssrf", "url parameter", "webhook", "remote fetch"],
        "https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/",
    ),
    KnowledgeDoc(
        "owasp-api8", "OWASP-API", "API8:2023", "Security Misconfiguration",
        "Missing hardening, unnecessary HTTP methods enabled, missing TLS, absent "
        "CORS policy, missing security headers, and verbose error messages that "
        "leak stack traces. Control: repeatable hardened configuration, restrict "
        "methods and origins, return generic errors.",
        ["api misconfiguration", "cors", "http methods", "security headers",
         "verbose errors", "tls missing"],
        "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
    ),
    KnowledgeDoc(
        "owasp-api9", "OWASP-API", "API9:2023", "Improper Inventory Management",
        "Outdated API versions, undocumented endpoints, and forgotten staging or "
        "debug hosts remain exposed. Control: maintain an API inventory including "
        "environment and version, retire old versions on a schedule, and scan for "
        "undocumented endpoints.",
        ["shadow api", "api inventory", "deprecated version", "staging exposed",
         "undocumented endpoint", "zombie api"],
        "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
    ),
]

CWE_ENTRIES: list[KnowledgeDoc] = [
    KnowledgeDoc("cwe-89", "CWE", "CWE-89",
                 "Improper Neutralization of Special Elements used in an SQL Command",
                 "SQL injection. The product constructs an SQL command from "
                 "externally-influenced input without neutralising special "
                 "elements. Mitigation: parameterised queries / prepared statements.",
                 ["sql injection", "sqli", "database query"],
                 "https://cwe.mitre.org/data/definitions/89.html"),
    KnowledgeDoc("cwe-79", "CWE", "CWE-79",
                 "Improper Neutralization of Input During Web Page Generation",
                 "Cross-site scripting (XSS). Untrusted input is placed into web "
                 "output without encoding. Mitigation: contextual output encoding "
                 "and Content-Security-Policy.",
                 ["xss", "cross-site scripting", "reflected", "stored xss", "dom xss"],
                 "https://cwe.mitre.org/data/definitions/79.html"),
    KnowledgeDoc("cwe-78", "CWE", "CWE-78",
                 "Improper Neutralization of Special Elements used in an OS Command",
                 "OS command injection. Mitigation: avoid shell invocation, pass "
                 "arguments as a list, validate against an allowlist.",
                 ["command injection", "os command", "shell injection", "rce"],
                 "https://cwe.mitre.org/data/definitions/78.html"),
    KnowledgeDoc("cwe-22", "CWE", "CWE-22",
                 "Improper Limitation of a Pathname to a Restricted Directory",
                 "Path traversal. External input constructs a pathname that "
                 "escapes the intended directory. Mitigation: canonicalise and "
                 "verify the resolved path stays inside the base directory.",
                 ["path traversal", "directory traversal", "../", "lfi"],
                 "https://cwe.mitre.org/data/definitions/22.html"),
    KnowledgeDoc("cwe-918", "CWE", "CWE-918", "Server-Side Request Forgery (SSRF)",
                 "The web server receives a URL from an upstream component and "
                 "retrieves it without sufficient validation. Mitigation: "
                 "allowlist destinations and block internal address ranges.",
                 ["ssrf", "request forgery", "internal service", "metadata"],
                 "https://cwe.mitre.org/data/definitions/918.html"),
    KnowledgeDoc("cwe-287", "CWE", "CWE-287", "Improper Authentication",
                 "The product does not prove, or insufficiently proves, that a "
                 "claim of identity is correct. Mitigation: standard auth "
                 "framework, MFA, strong session management.",
                 ["authentication bypass", "improper authentication", "login"],
                 "https://cwe.mitre.org/data/definitions/287.html"),
    KnowledgeDoc("cwe-639", "CWE", "CWE-639",
                 "Authorization Bypass Through User-Controlled Key",
                 "Insecure direct object reference (IDOR). The system authorises "
                 "based on a key the user controls. Mitigation: server-side "
                 "ownership checks on every object access.",
                 ["idor", "bola", "object reference", "authorization bypass"],
                 "https://cwe.mitre.org/data/definitions/639.html"),
    KnowledgeDoc("cwe-1021", "CWE", "CWE-1021",
                 "Improper Restriction of Rendered UI Layers or Frames",
                 "Clickjacking. Mitigation: X-Frame-Options: DENY or "
                 "Content-Security-Policy frame-ancestors.",
                 ["clickjacking", "x-frame-options", "frame-ancestors", "ui redress",
                  "iframe", "framed", "embedded in iframe", "overlay"],
                 "https://cwe.mitre.org/data/definitions/1021.html"),
    KnowledgeDoc("cwe-319", "CWE", "CWE-319",
                 "Cleartext Transmission of Sensitive Information",
                 "Sensitive data is transmitted in an unencrypted channel where "
                 "it can be sniffed. Mitigation: TLS everywhere plus HSTS.",
                 ["cleartext", "http", "unencrypted", "https downgrade", "sniffing"],
                 "https://cwe.mitre.org/data/definitions/319.html"),
    KnowledgeDoc("cwe-1395", "CWE", "CWE-1395",
                 "Dependency on Vulnerable Third-Party Component",
                 "The product depends on a third-party component with known "
                 "vulnerabilities. Mitigation: SBOM, dependency scanning, "
                 "risk-based patching prioritised by KEV and exposure.",
                 ["vulnerable dependency", "outdated library", "cve", "third-party"],
                 "https://cwe.mitre.org/data/definitions/1395.html"),
    KnowledgeDoc("cwe-1021b", "CWE", "CWE-693", "Protection Mechanism Failure",
                 "The product does not use, or incorrectly uses, a protection "
                 "mechanism such as a security header. Mitigation: deploy and "
                 "verify the full header set (CSP, HSTS, XCTO, XFO).",
                 ["missing security header", "protection mechanism", "csp missing",
                  "hsts missing"],
                 "https://cwe.mitre.org/data/definitions/693.html"),
    KnowledgeDoc("cwe-290", "CWE", "CWE-290",
                 "Authentication Bypass by Spoofing",
                 "An attacker spoofs an identity to bypass authentication, the "
                 "mechanism underlying sender spoofing and lookalike domains. "
                 "Mitigation: SPF, DKIM and DMARC enforcement; domain monitoring.",
                 ["spoofing", "sender spoofing", "lookalike domain", "impersonation",
                  "dmarc", "spf", "dkim"],
                 "https://cwe.mitre.org/data/definitions/290.html"),
]

MITRE_TECHNIQUES: list[KnowledgeDoc] = [
    KnowledgeDoc("mitre-t1566", "MITRE", "T1566", "Phishing",
                 "Adversaries send phishing messages to gain access to victim "
                 "systems. Phishing may be targeted (spearphishing) and can "
                 "deliver attachments, links, or request credentials directly. "
                 "Tactic: Initial Access. Detection: mail gateway analysis, URL "
                 "detonation, user reporting.",
                 ["phishing", "spearphishing", "malicious email", "lure", "initial access",
                  "pretending to be", "fake email", "impersonating brand",
                  "verify password", "verify account", "suspicious email"],
                 "https://attack.mitre.org/techniques/T1566/"),
    KnowledgeDoc("mitre-t1566-001", "MITRE", "T1566.001",
                 "Phishing: Spearphishing Attachment",
                 "Adversaries send spearphishing emails with a malicious "
                 "attachment to gain execution on a victim system. Tactic: "
                 "Initial Access. Mitigation: attachment sandboxing, macro "
                 "blocking, user training.",
                 ["malicious attachment", "macro", "docm", "xlsm", "iso attachment",
                  "spearphishing attachment"],
                 "https://attack.mitre.org/techniques/T1566/001/"),
    KnowledgeDoc("mitre-t1566-002", "MITRE", "T1566.002",
                 "Phishing: Spearphishing Link",
                 "Adversaries send emails containing a malicious link, typically "
                 "leading to a credential-harvesting page or a drive-by download. "
                 "Tactic: Initial Access. Mitigation: URL rewriting and "
                 "detonation, web filtering, MFA.",
                 ["phishing link", "credential harvesting", "fake login page",
                  "spearphishing link", "url lure", "verify your password",
                  "verify your account", "microsoft login", "steal credentials",
                  "phishing email link"],
                 "https://attack.mitre.org/techniques/T1566/002/"),
    KnowledgeDoc("mitre-t1598", "MITRE", "T1598",
                 "Phishing for Information",
                 "Adversaries send phishing messages to elicit sensitive "
                 "information rather than execute code, including BEC pretexting "
                 "for payment details. Tactic: Reconnaissance.",
                 ["bec", "business email compromise", "pretexting", "wire transfer",
                  "payment redirection", "information elicitation"],
                 "https://attack.mitre.org/techniques/T1598/"),
    KnowledgeDoc("mitre-t1656", "MITRE", "T1656", "Impersonation",
                 "Adversaries impersonate a trusted person or organisation to "
                 "persuade a victim to act. Commonly paired with lookalike "
                 "domains and display-name spoofing. Tactic: Defense Evasion.",
                 ["impersonation", "display name spoof", "brand abuse",
                  "lookalike domain", "typosquat"],
                 "https://attack.mitre.org/techniques/T1656/"),
    KnowledgeDoc("mitre-t1583-001", "MITRE", "T1583.001",
                 "Acquire Infrastructure: Domains",
                 "Adversaries register domains to use during targeting, often "
                 "resembling a legitimate brand and registered shortly before the "
                 "campaign. Tactic: Resource Development. Detection: newly "
                 "registered domain feeds, brand monitoring.",
                 ["newly registered domain", "domain registration", "typosquatting",
                  "infrastructure acquisition", "domain age"],
                 "https://attack.mitre.org/techniques/T1583/001/"),
    KnowledgeDoc("mitre-t1190", "MITRE", "T1190",
                 "Exploit Public-Facing Application",
                 "Adversaries exploit a weakness in an internet-facing host or "
                 "application to gain initial access. Tactic: Initial Access. "
                 "Mitigation: rapid patching prioritised by KEV, WAF, network "
                 "segmentation.",
                 ["exploit", "public facing", "internet exposed", "cve exploitation",
                  "web application attack", "sql injection exploit"],
                 "https://attack.mitre.org/techniques/T1190/"),
    KnowledgeDoc("mitre-t1110", "MITRE", "T1110", "Brute Force",
                 "Adversaries guess passwords or reuse breached credentials. "
                 "Includes password spraying and credential stuffing. Tactic: "
                 "Credential Access. Mitigation: MFA, lockout, breached-password "
                 "screening.",
                 ["brute force", "password spraying", "credential stuffing",
                  "ssh brute force", "login attempts"],
                 "https://attack.mitre.org/techniques/T1110/"),
    KnowledgeDoc("mitre-t1071", "MITRE", "T1071",
                 "Application Layer Protocol",
                 "Adversaries communicate with command and control using "
                 "application layer protocols such as HTTP/S to blend with normal "
                 "traffic. Tactic: Command and Control.",
                 ["c2", "command and control", "beacon", "malicious infrastructure",
                  "http c2"],
                 "https://attack.mitre.org/techniques/T1071/"),
    KnowledgeDoc("mitre-t1204-001", "MITRE", "T1204.001",
                 "User Execution: Malicious Link",
                 "An adversary relies on a user clicking a malicious link to gain "
                 "execution. Tactic: Execution. Mitigation: web filtering, link "
                 "detonation, awareness training.",
                 ["user clicked", "malicious link", "drive-by", "user execution"],
                 "https://attack.mitre.org/techniques/T1204/001/"),
]

NIST_CSF: list[KnowledgeDoc] = [
    KnowledgeDoc("nist-id-ra", "NIST-CSF", "ID.RA",
                 "Identify: Risk Assessment",
                 "The organisation understands the cybersecurity risk to "
                 "operations, assets and individuals. Includes identifying asset "
                 "vulnerabilities, receiving threat intelligence, and using "
                 "threats, vulnerabilities, likelihood and impact to determine "
                 "risk.",
                 ["risk assessment", "threat intelligence", "vulnerability "
                  "identification", "risk determination"],
                 "https://www.nist.gov/cyberframework"),
    KnowledgeDoc("nist-pr-ac", "NIST-CSF", "PR.AA",
                 "Protect: Identity Management, Authentication and Access Control",
                 "Access to assets is limited to authorised users, processes and "
                 "devices, and is managed consistent with assessed risk. Includes "
                 "credential management, MFA and least privilege.",
                 ["access control", "identity management", "mfa", "least privilege",
                  "credential management"],
                 "https://www.nist.gov/cyberframework"),
    KnowledgeDoc("nist-pr-ps", "NIST-CSF", "PR.PS",
                 "Protect: Platform Security",
                 "Hardware, software and services are managed consistent with the "
                 "organisation's risk strategy, including configuration "
                 "hardening, patch management and secure software development.",
                 ["patch management", "hardening", "configuration", "vulnerability "
                  "remediation", "secure configuration"],
                 "https://www.nist.gov/cyberframework"),
    KnowledgeDoc("nist-de-cm", "NIST-CSF", "DE.CM",
                 "Detect: Continuous Monitoring",
                 "Assets are monitored to find anomalies, indicators of "
                 "compromise and other potentially adverse events. Includes "
                 "network, personnel activity and external service provider "
                 "monitoring.",
                 ["monitoring", "detection", "anomaly", "indicator of compromise",
                  "logging", "siem"],
                 "https://www.nist.gov/cyberframework"),
    KnowledgeDoc("nist-rs-mi", "NIST-CSF", "RS.MI",
                 "Respond: Incident Mitigation",
                 "Activities are performed to prevent expansion of an event and "
                 "mitigate its effects, containment, eradication, and blocking "
                 "of newly identified indicators.",
                 ["containment", "block indicator", "quarantine", "eradication",
                  "incident response", "mitigation"],
                 "https://www.nist.gov/cyberframework"),
    KnowledgeDoc("nist-rc-rp", "NIST-CSF", "RC.RP",
                 "Recover: Incident Recovery Plan Execution",
                 "Restoration activities are performed to ensure operational "
                 "availability of systems and services affected by an incident, "
                 "including credential resets and system restoration.",
                 ["recovery", "restore", "credential reset", "remediation plan"],
                 "https://www.nist.gov/cyberframework"),
]

KNOWLEDGE_BASE: list[KnowledgeDoc] = (
    OWASP_TOP_10 + OWASP_API_TOP_10 + CWE_ENTRIES + MITRE_TECHNIQUES + NIST_CSF
)

BY_CODE: dict[str, KnowledgeDoc] = {doc.code: doc for doc in KNOWLEDGE_BASE}
BY_ID: dict[str, KnowledgeDoc] = {doc.id: doc for doc in KNOWLEDGE_BASE}
