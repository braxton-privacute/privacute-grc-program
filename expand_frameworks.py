import requests
import json

DETAIL_URL = "https://grcengclub.github.io/scf-api/api/controls/{}.json"

# Supported frameworks: friendly name -> SCF crosswalk key.
# Add a framework by adding one line here.
FRAMEWORKS = {
    "HIPAA": "usa-federal-law-hipaa-security-rule-2013",
    "NIST CSF": "general-nist-csf-2-0",
}

detail_cache = {}

def get_control_detail(control_id):
    """Fetch (and cache) one control's full detail."""
    if control_id not in detail_cache:
        detail_cache[control_id] = requests.get(DETAIL_URL.format(control_id)).json()
    return detail_cache[control_id]

def expand_finding(finding):
    """Return {framework_name: [codes]} across all supported frameworks."""
    result = {name: [] for name in FRAMEWORKS}   # start each framework with an empty list
    for cid in finding["scf_controls"]:
        crosswalks = get_control_detail(cid).get("crosswalks", {})
        for name, key in FRAMEWORKS.items():
            for code in crosswalks.get(key, []):
                if code not in result[name]:      # de-duplicate
                    result[name].append(code)
    return result


if __name__ == "__main__":
    with open("data/findings.json") as f:
        findings = json.load(f)

    print("Multi-framework expansion:\n")
    for finding in findings:
        mapping = expand_finding(finding)
        print(f"{finding['id']}: {finding['threat']}")
        print(f"   controls: {finding['scf_controls']}")
        for name in FRAMEWORKS:
            codes = mapping[name]
            shown = ", ".join(codes) if codes else "(none)"
            print(f"   {name}: {shown}")
        print()


