import requests
import json

DETAIL_URL = "https://grcengclub.github.io/scf-api/api/controls/{}.json"
HIPAA_KEY = "usa-federal-law-hipaa-security-rule-2013"

# Load the findings
with open("data/findings.json", encoding="utf-8") as f:
    findings = json.load(f)

# Small cache so we never fetch the same control twice
detail_cache = {}

def get_hipaa_refs(control_id):
    """Fetch one control's detail and return its HIPAA Security Rule sections."""
    if control_id not in detail_cache:
        url = DETAIL_URL.format(control_id)
        detail_cache[control_id] = requests.get(url).json()
    control = detail_cache[control_id]
    crosswalks = control.get("crosswalks", {})
    return crosswalks.get(HIPAA_KEY, [])

print("Verified HIPAA Security Rule references per finding:\n")

for finding in findings:
    refs = []
    for cid in finding["scf_controls"]:
        for section in get_hipaa_refs(cid):
            if section not in refs:
                refs.append(section)

    print(f"{finding['id']}: {finding['threat']}")
    print(f"   controls: {finding['scf_controls']}")
    if refs:
        print(f"   HIPAA (verified): {refs}")
    else:
        print(f"   HIPAA: no Security Rule mapping found")
    print()