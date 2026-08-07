import requests
import json
from expand_frameworks import expand_finding, FRAMEWORKS

INDEX_URL = "https://grcengclub.github.io/scf-api/api/crosswalks.json"

def get_denominators():
    """Fetch each supported framework's total control count from the index."""
    idx = requests.get(INDEX_URL).json()
    counts = {}
    for fw in idx["frameworks"]:
        counts[fw["framework_id"]] = fw["framework_controls_mapped"]
    return counts

if __name__ == "__main__":
    with open("data/findings.json") as f:
        findings = json.load(f)

    covered = {name: set() for name in FRAMEWORKS}
    for finding in findings:
        mapping = expand_finding(finding)
        for name in FRAMEWORKS:
            for code in mapping[name]:
                covered[name].add(code)

    denominators = get_denominators()

    print("Framework coverage (as represented in the SCF crosswalk):\n")
    for name, key in FRAMEWORKS.items():
        numerator = len(covered[name])
        denominator = denominators.get(key, 0)
        pct = (numerator / denominator * 100) if denominator else 0
        print(f"{name}")
        print(f"   covered: {numerator} of {denominator} controls ({pct:.1f}%)")
        print(f"   codes: {', '.join(sorted(covered[name]))}\n")