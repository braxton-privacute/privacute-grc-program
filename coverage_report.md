# Multi-Framework Coverage Report

Risk findings mapped across HIPAA Security Rule and NIST CSF 2.0 via the Secure Controls Framework (SCF) crosswalk. Coverage is measured against each framework as represented in the SCF crosswalk, not the full published framework.

## Coverage summary

| Framework | Controls covered | Total (in SCF) | Coverage |
|-----------|------------------|----------------|----------|
| HIPAA | 2 | 87 | 2.3% |
| NIST CSF | 5 | 134 | 3.7% |

## Findings and framework mappings

### PRIV-001: Loss or theft of the work device exposes Privacute data stored on it

- **SCF controls:** CRY-05
- **HIPAA:** (none)
- **NIST CSF:** PR.DS-01

### PRIV-002: Sensitive data exposed through AI tools used in Privacute's work

- **SCF controls:** AAT-01
- **HIPAA:** (none)
- **NIST CSF:** (none)

### PRIV-003: Prospect and business data is over-retained or improperly disposed of due to no governing standard

- **SCF controls:** DCH-02, DCH-18
- **HIPAA:** 164.316(b)(2)(i)
- **NIST CSF:** ID.AM-05, PR.DS

### PRIV-004: Third-party data exposure goes unmanaged due to no view of which vendors touch what data

- **SCF controls:** TPM-04
- **HIPAA:** 164.308(b)(1)
- **NIST CSF:** GV.SC-06, GV.SC-07

## NIST CSF coverage by function

| Function | Subcategories covered | Status |
|----------|----------------------|--------|
| Govern | 2 | Covered |
| Identify | 1 | Covered |
| Protect | 2 | Covered |
| Detect | 0 | **No coverage** |
| Respond | 0 | **No coverage** |
| Recover | 0 | **No coverage** |

**Gap callout:** the assessment has no coverage in Detect, Respond, Recover. These functions represent the clearest next areas to assess.
