import json

with open("data/findings.json") as f:
    findings = json.load(f)


print(f"Loaded {len(findings)} findings.\n")

for finding in findings:
    print (f"{finding['id']}: {finding['threat']}")

    print (f"    Controls: {finding['scf_controls']}")
           
    print (f"   Risk: {finding['risk_score']} ({finding['risk_band']})\n")