import json
from expand_frameworks import expand_finding

# NIST CSF 2.0 has six functions. Prefix -> full name.
CSF_FUNCTIONS = {
    "GV": "Govern",
    "ID": "Identify",
    "PR": "Protect",
    "DE": "Detect",
    "RS": "Respond",
    "RC": "Recover",
}

def function_of(code):
    """Return the CSF function prefix of a subcategory code, e.g. 'GV.OC-02' -> 'GV'."""
    return code.split(".")[0]

def csf_function_coverage(findings):
    """Return (counts dict, covered names, missing names) for CSF functions."""
    csf_codes = set()
    for finding in findings:
        mapping = expand_finding(finding)
        for code in mapping["NIST CSF"]:
            csf_codes.add(code)

    counts = {prefix: 0 for prefix in CSF_FUNCTIONS}
    for code in csf_codes:
        prefix = function_of(code)
        if prefix in counts:
            counts[prefix] += 1

    covered = [CSF_FUNCTIONS[p] for p, n in counts.items() if n > 0]
    missing = [CSF_FUNCTIONS[p] for p, n in counts.items() if n == 0]
    return counts, covered, missing


if __name__ == "__main__":
    with open("data/findings.json") as f:
        findings = json.load(f)

    counts, covered, missing = csf_function_coverage(findings)

    print("NIST CSF coverage by function:\n")
    for prefix, name in CSF_FUNCTIONS.items():
        n = counts[prefix]
        status = "covered" if n > 0 else "NO COVERAGE"
        print(f"  {prefix} ({name}): {n} subcategories — {status}")

    print()
    if missing:
        print(f"Gap callout: no coverage in {', '.join(missing)}.")
    else:
        print("All six CSF functions have at least some coverage.")