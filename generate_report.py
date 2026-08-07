import json

with open("data/findings.json", encoding="utf-8") as f:
    findings = json.load(f)

# Sort findings by risk score, highest first, so the worst leads.
findings.sort(key=lambda x: x["risk_score"], reverse=True)

lines = []
lines.append("# Example Family Clinic — Risk Assessment")
lines.append("")
lines.append("Findings mapped to the Secure Controls Framework (SCF), "
             "scored on a 5x5 likelihood x impact matrix. HIPAA references are "
             "pulled from the SCF crosswalk unless marked *(analyst)*.")
lines.append("")

# Table header
lines.append("| ID | Threat | SCF Controls | L | I | Score | Band | Status | HIPAA Refs | Remediation |")
lines.append("|----|--------|--------------|---|---|-------|------|--------|------------|-------------|")

for f in findings:
    controls = ", ".join(f["scf_controls"])
    hipaa = ", ".join(f["hipaa_refs"])
    if f.get("hipaa_refs_source") == "analyst-judgment":
        hipaa = f"{hipaa} *(analyst)*"

    row = (
        f"| {f['id']} "
        f"| {f['threat']} "
        f"| {controls} "
        f"| {f['likelihood']} "
        f"| {f['impact']} "
        f"| {f['risk_score']} "
        f"| {f['risk_band']} "
        f"| {f.get('status', 'Open')} "
        f"| {hipaa} "
        f"| {f['remediation']} |"
    )
    lines.append(row)

# Join all lines into one document and write it out
report = "\n".join(lines)
with open("risk_assessment.md", "w", encoding="utf-8") as out:
    out.write(report)

print("Wrote risk_assessment.md\n")
print(report)