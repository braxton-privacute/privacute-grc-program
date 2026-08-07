import json

# Risk bands for a 5x5 matrix. Score = likelihood * impact, range 1-25.
# (low_bound, high_bound, label) — bounds inclusive.
BANDS = [
    (1, 4, "Low"),
    (5, 9, "Medium"),
    (10, 14, "High"),
    (15, 25, "Critical"),
]

def score_and_band(likelihood, impact):
    """Turn likelihood and impact into a score and its risk band."""
    score = likelihood * impact
    for low, high, label in BANDS:
        if low <= score <= high:
            return score, label
    return score, "UNKNOWN"  # only if score falls outside 1-25

with open("data/findings.json") as f:
    findings = json.load(f)

print("Checking hand-entered scores against the formula:\n")

mismatches = 0
for finding in findings:
    L = finding["likelihood"]
    I = finding["impact"]
    computed_score, computed_band = score_and_band(L, I)

    old_score = finding.get("risk_score")
    old_band = finding.get("risk_band")

    flag = ""
    if old_score != computed_score or old_band != computed_band:
        flag = "  <-- MISMATCH"
        mismatches += 1

    print(f"{finding['id']}: L{L} x I{I}")
    print(f"   stored:   {old_score} ({old_band})")
    print(f"   computed: {computed_score} ({computed_band}){flag}\n")

if mismatches == 0:
    print("All stored scores match the formula.")
else:
    print(f"{mismatches} finding(s) have stored scores that disagree with the formula.")