import requests
import json

DETAIL_URL = "https://grcengclub.github.io/scf-api/api/controls/{}.json"
HIPAA_KEY = "usa-federal-law-hipaa-security-rule-2013"

# Analyst-supplied HIPAA refs for controls the SCF doesn't crosswalk to HIPAA.
# Each is a judgment call, recorded here so it's explicit, not hidden.
ANALYST_REFS = {
    "IAC-06": ["164.312(d)"],  # HIPAA authentication standard; no direct SCF crosswalk
}

with open("data/findings.json") as f:
    findings = json.load(f)

detail_cache = {}

def get_hipaa_refs(control_id):
    if control_id not in detail_cache:
        url = DETAIL_URL.format(control_id)
        detail_cache[control_id] = requests.get(url).json()
    crosswalks = detail_cache[control_id].get("crosswalks", {})
    return crosswalks.get(HIPAA_KEY, [])

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
        # SCF had no HIPAA mapping; fall back to analyst judgment if we have one
        analyst = []
        for cid in finding["scf_controls"]:
            for section in ANALYST_REFS.get(cid, []):
                if section not in analyst:
                    analyst.append(section)
        finding["hipaa_refs"] = analyst
        finding["hipaa_refs_source"] = "analyst-judgment"

# Write to a NEW file so the original is never at risk
with open("data/findings.enriched.json", "w") as f:
    json.dump(findings, f, indent=2)

print("Wrote data/findings.enriched.json")
print("Review it, and if it looks right, rename it to findings.json.\n")

for finding in findings:
    print(f"{finding['id']}: {finding['hipaa_refs']}  ({finding['hipaa_refs_source']})")