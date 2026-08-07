import json

BANDS = [
    (1, 4, "Low"),
    (5, 9, "Medium"),
    (10, 14, "High"),
    (15, 25, "Critical"),
]

def score_and_band(likelihood, impact):
    score = likelihood * impact
    for low, high, label in BANDS:
        if low <= score <= high:
            return score, label
    return score, "UNKNOWN"

with open("data/findings.json") as f:
    findings = json.load(f)

for finding in findings:
    score, band = score_and_band(finding["likelihood"], finding["impact"])
    finding["risk_score"] = score
    finding["risk_band"] = band

with open("data/findings.scored.json", "w") as f:
    json.dump(findings, f, indent=2)

print("Wrote data/findings.scored.json")
print("Review it, then rename to findings.json if it looks right.\n")

for finding in findings:
    print(f"{finding['id']}: {finding['risk_score']} ({finding['risk_band']})")