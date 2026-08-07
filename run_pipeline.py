import requests
import json
import os
import shutil
import sys
from datetime import datetime

# --- Configuration ---
CONTROLS_URL = "https://grcengclub.github.io/scf-api/api/controls.json"
DETAIL_URL = "https://grcengclub.github.io/scf-api/api/controls/{}.json"
HIPAA_KEY = "usa-federal-law-hipaa-security-rule-2013"

# Accept a findings file as a command-line argument; default to the clinic scenario.
# The report path follows the findings file so a non-default run cannot overwrite
# the default report (same convention as generate_coverage_report.py).
if len(sys.argv) > 1:
    FINDINGS_PATH = sys.argv[1]
    stem = os.path.splitext(os.path.basename(FINDINGS_PATH))[0].replace("-findings", "")
    REPORT_PATH = f"{stem}_risk_assessment.md"
else:
    FINDINGS_PATH = "data/findings.json"
    REPORT_PATH = "risk_assessment.md"

BANDS = [
    (1, 4, "Low"),
    (5, 9, "Medium"),
    (10, 14, "High"),
    (15, 25, "Critical"),
]

# Analyst-supplied HIPAA refs for controls the SCF doesn't crosswalk to HIPAA.
ANALYST_REFS = {
    "IAC-06": ["164.312(d)"],  # authentication standard; no direct SCF crosswalk
    "CRY-05": ["164.312(a)(2)(iv)"],  # HIPAA encryption spec; SCF doesn't crosswalk CRY-05 to HIPAA. Applies once ePHI is handled.
}

detail_cache = {}


def load_scf_catalog():
    """Fetch the SCF catalog and return (set of valid IDs, dict of id->title)."""
    print("Fetching SCF catalog...")
    data = requests.get(CONTROLS_URL).json()
    controls = data["controls"]
    valid_ids = set()
    titles = {}
    for c in controls:
        valid_ids.add(c["control_id"])
        titles[c["control_id"]] = c["title"]
    print(f"  Loaded {len(valid_ids)} controls.\n")
    return valid_ids, titles


def validate(findings, valid_ids, titles):
    """Check every control ID. Returns True if all valid, False otherwise."""
    print("Validating control IDs...")
    all_valid = True
    for f in findings:
        for cid in f["scf_controls"]:
            if cid in valid_ids:
                print(f"  OK   {f['id']}: {cid} -> {titles[cid]}")
            else:
                print(f"  BAD  {f['id']}: {cid} is NOT a real SCF control")
                all_valid = False
    print()
    return all_valid


def get_hipaa_refs(control_id):
    """Fetch one control's HIPAA Security Rule sections from the crosswalk."""
    if control_id not in detail_cache:
        detail_cache[control_id] = requests.get(DETAIL_URL.format(control_id)).json()
    crosswalks = detail_cache[control_id].get("crosswalks", {})
    return crosswalks.get(HIPAA_KEY, [])


def enrich_hipaa(findings):
    """Fill each finding's hipaa_refs and hipaa_refs_source in place."""
    print("Enriching HIPAA references...")
    for finding in findings:
        verified = []
        for cid in finding["scf_controls"]:
            for section in get_hipaa_refs(cid):
                if section not in verified:
                    verified.append(section)

        if verified:
            finding["hipaa_refs"] = verified
            finding["hipaa_refs_source"] = "scf-crosswalk"
        else:
            analyst = []
            for cid in finding["scf_controls"]:
                for section in ANALYST_REFS.get(cid, []):
                    if section not in analyst:
                        analyst.append(section)
            finding["hipaa_refs"] = analyst
            if analyst:
                finding["hipaa_refs_source"] = "analyst-judgment"
            else:
                finding["hipaa_refs_source"] = "no-hipaa-mapping"
    print("  Done.\n")


def score_and_band(likelihood, impact):
    score = likelihood * impact
    for low, high, label in BANDS:
        if low <= score <= high:
            return score, label
    return score, "UNKNOWN"


def apply_scores(findings):
    """Compute risk_score and risk_band for each finding in place."""
    print("Computing risk scores...")
    for f in findings:
        score, band = score_and_band(f["likelihood"], f["impact"])
        f["risk_score"] = score
        f["risk_band"] = band
    print("  Done.\n")


def write_report(findings):
    """Generate the Markdown risk matrix."""
    print("Generating report...")
    ordered = sorted(findings, key=lambda x: x["risk_score"], reverse=True)
    lines = []
    lines.append("# Risk Assessment")
    lines.append("")
    lines.append("Findings mapped to the Secure Controls Framework (SCF), "
                 "scored on a 5x5 likelihood x impact matrix. HIPAA references "
                 "are from the SCF crosswalk unless marked otherwise.")
    lines.append("")
    lines.append("| ID | Threat | SCF Controls | L | I | Score | Band | Status | HIPAA Refs | Remediation |")
    lines.append("|----|--------|--------------|---|---|-------|------|--------|------------|-------------|")
    for f in ordered:
        controls = ", ".join(f["scf_controls"])
        hipaa = ", ".join(f["hipaa_refs"]) if f["hipaa_refs"] else "(none)"
        src = f.get("hipaa_refs_source", "")
        if src == "analyst-judgment":
            hipaa = f"{hipaa} *(analyst)*"
        elif src == "no-hipaa-mapping":
            hipaa = "(no HIPAA mapping)"
        lines.append(
            f"| {f['id']} | {f['threat']} | {controls} | {f['likelihood']} "
            f"| {f['impact']} | {f['risk_score']} | {f['risk_band']} "
            f"| {f.get('status', 'Open')} | {hipaa} | {f['remediation']} |"
        )
    report = "\n".join(lines)
    with open(REPORT_PATH, "w", encoding="utf-8") as out:
        out.write(report)
    print(f"  Wrote {REPORT_PATH}\n")


def main():
    # Read findings once
    with open(FINDINGS_PATH, encoding="utf-8") as f:
        findings = json.load(f)

    # Back up before we change anything
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = f"data/findings.backup-{stamp}.json"
    shutil.copy(FINDINGS_PATH, backup)
    print(f"Backed up current findings to {backup}\n")

    # Fetch catalog and validate FIRST — stop if any control ID is bad
    valid_ids, titles = load_scf_catalog()
    if not validate(findings, valid_ids, titles):
        print("STOPPED: fix the invalid control ID(s) above and rerun.")
        print("No changes were written.")
        return

    # All valid — enrich, score, save, report
    enrich_hipaa(findings)
    apply_scores(findings)

    with open(FINDINGS_PATH, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)
    print(f"Updated {FINDINGS_PATH}\n")

    write_report(findings)
    print("Pipeline complete.")


main()