# Risk Assessment

Findings mapped to the Secure Controls Framework (SCF), scored on a 5x5 likelihood x impact matrix. HIPAA references are from the SCF crosswalk unless marked otherwise.

| ID | Threat | SCF Controls | L | I | Score | Band | Status | HIPAA Refs | Remediation |
|----|--------|--------------|---|---|-------|------|--------|------------|-------------|
| PRIV-002 | Sensitive data exposed through AI tools used in Privacute's work | AAT-01 | 2 | 3 | 6 | Medium | Open | (no HIPAA mapping) | Document an AI-use policy defining approved tools, permitted data types, redaction requirements, and prohibited uploads (e.g. customer data) |
| PRIV-003 | Prospect and business data is over-retained or improperly disposed of due to no governing standard | DCH-02, DCH-18 | 3 | 2 | 6 | Medium | Open | 164.316(b)(2)(i) | Document a data-handling policy covering classification, retention periods, and disposal for prospect and business data |
| PRIV-001 | Loss or theft of the work device exposes Privacute data stored on it | CRY-05 | 2 | 2 | 4 | Low | Remediated | 164.312(a)(2)(iv) *(analyst)* | Completed - full-disk encryption enabled on the work device (Windows Device Encryption) |
| PRIV-004 | Third-party data exposure goes unmanaged due to no view of which vendors touch what data | TPM-04 | 2 | 2 | 4 | Low | Open | 164.308(b)(1) | Create and maintain a third-party inventory listing each vendor, the data it touches, and its BAA/contract status; establish a periodic vendor review |