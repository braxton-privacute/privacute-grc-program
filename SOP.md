# SOP: Adding a New Assessment to the SCF Findings Tool

**Purpose:** Take raw assessment findings and produce a validated, source-cited,
consistently-scored risk matrix using the SCF findings pipeline.

**Who this is for:** A GRC engineer running an assessment through the tool for a
new engagement or scenario.

**Before you start, you need:**
- Python 3 installed
- The `requests` library (`pip install requests`)
- Internet access (the tool fetches SCF data live)
- Your findings gathered: for each risk, you must know the threat, the
  vulnerability, and your likelihood and impact ratings (1-5 each)

---

## Phase 1 — Gather and structure the findings

### Step 1.1 — For each finding, collect the required facts
You cannot map or score what you haven't defined. For every risk, write down:
- **Threat:** what could happen (e.g., "MFA disabled on clinical accounts")
- **Vulnerability:** why it's exposed (e.g., "confirmed-absent MFA on
  internet-facing accounts")
- **Likelihood (1-5):** how probable, given current controls. Reserve 5 for
  confirmed-open/actively-exploitable; 4 for unverified-but-likely.
- **Impact (1-5):** severity if realized. Reserve 5 for multi-framework or
  full-population exposure.

Do NOT fill in the risk score yourself. The tool computes it.

### Step 1.2 — Identify candidate SCF controls
For each finding, decide which SCF control(s) it maps to. Map to the **most
specific** control that captures the failure, not the parent/umbrella control.
Add a second control only if it names a genuinely distinct failure, not a synonym.
You will verify these IDs are real in Phase 2 — a wrong guess here gets caught,
so it's safe to make your best call now.

### Step 1.3 — Write the findings.json file
Create `data/findings.json` as a list of finding objects. Use this exact schema
for every finding:

```json
{
  "id": "PROJ-001",
  "threat": "short description of the threat",
  "vulnerability": "why it is exposed",
  "scf_controls": ["XXX-00", "YYY-00"],
  "likelihood": 5,
  "impact": 4,
  "risk_score": 0,
  "risk_band": "TBD",
  "hipaa_refs": [],
  "hipaa_refs_source": "TBD",
  "remediation": "the required action"
}
```

Rules:
- Every label and text value uses **double quotes**.
- **No comma** after the last item in an object or list.
- Leave `risk_score` as 0, `risk_band` as "TBD", `hipaa_refs` empty, and
  `hipaa_refs_source` as "TBD" — the tool fills these. Do not hand-enter them.
- `likelihood` and `impact` are numbers (no quotes). These are the only scoring
  values you set by hand, because they're judgment.

---

## Phase 2 — Run the pipeline

Run each script from the project's top folder. Each reads `data/findings.json`.

### Step 2.1 — Validate the control IDs
```bash
python validate_findings.py
```
**Expected:** each finding's controls marked `OK` with their official SCF title,
ending in "All control mappings are valid."

**If any control shows `BAD`:** that ID is not a real SCF control. Fix it in
`findings.json` — check for a typo or a wrong prefix (SCF uses PES not PHY,
PRI not PRV, IAC, TPM, CRY, AST, etc.) — and rerun until all pass.
**Do not proceed until validation is clean.**

### Step 2.2 — Enrich with verified HIPAA references
```bash
python write_hipaa.py
```
This writes `data/findings.enriched.json` (a NEW file — your original is
untouched). Each finding gets HIPAA refs pulled from the SCF crosswalk, labeled
`scf-crosswalk`. Controls with no HIPAA mapping fall back to analyst-supplied
refs (defined in the ANALYST_REFS block in the script), labeled `analyst-judgment`.

**Review `findings.enriched.json`:** confirm each finding has `hipaa_refs` and a
`hipaa_refs_source`. Any `analyst-judgment`