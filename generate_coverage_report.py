import json
from expand_frameworks import expand_finding, FRAMEWORKS
from coverage import get_denominators
from gaps import csf_function_coverage, CSF_FUNCTIONS
import os
import sys

# Report name follows the findings file, so a non-default run cannot overwrite
# the default report.
if len(sys.argv) > 1:
    FINDINGS_PATH = sys.argv[1]
    stem = os.path.splitext(os.path.basename(FINDINGS_PATH))[0].replace("-findings", "")
    REPORT_PATH = f"{stem}_coverage_report.md"
else:
    FINDINGS_PATH = "data/findings.json"
    REPORT_PATH = "coverage_report.md"

with open(FINDINGS_PATH, encoding="utf-8") as f:
    findings = json.load(f)

# Coverage math (same as coverage.py)
covered = {name: set() for name in FRAMEWORKS}
per_finding = {}
for finding in findings:
    mapping = expand_finding(finding)
    per_finding[finding["id"]] = mapping
    for name in FRAMEWORKS:
        for code in mapping[name]:
            covered[name].add(code)

denominators = get_denominators()

lines = []
lines.append("# Multi-Framework Coverage Report")
lines.append("")
lines.append("Risk findings mapped across HIPAA Security Rule and NIST CSF 2.0 "
             "via the Secure Controls Framework (SCF) crosswalk. Coverage is "
             "measured against each framework as represented in the SCF "
             "crosswalk, not the full published framework.")
lines.append("")

# Section 1: coverage summary
lines.append("## Coverage summary")
lines.append("")
lines.append("| Framework | Controls covered | Total (in SCF) | Coverage |")
lines.append("|-----------|------------------|----------------|----------|")
for name, key in FRAMEWORKS.items():
    num = len(covered[name])
    den = denominators.get(key, 0)
    pct = (num / den * 100) if den else 0
    lines.append(f"| {name} | {num} | {den} | {pct:.1f}% |")
lines.append("")

# Section 2: per-finding mapping
lines.append("## Findings and framework mappings")
lines.append("")
for finding in findings:
    mapping = per_finding[finding["id"]]
    lines.append(f"### {finding['id']}: {finding['threat']}")
    lines.append("")
    lines.append(f"- **SCF controls:** {', '.join(finding['scf_controls'])}")
    for name in FRAMEWORKS:
        codes = ", ".join(mapping[name]) if mapping[name] else "(none)"
        lines.append(f"- **{name}:** {codes}")
    lines.append("")


# Section 3: NIST CSF function gaps
counts, covered_fns, missing_fns = csf_function_coverage(findings)
lines.append("## NIST CSF coverage by function")
lines.append("")
lines.append("| Function | Subcategories covered | Status |")
lines.append("|----------|----------------------|--------|")
for prefix, name in CSF_FUNCTIONS.items():
    n = counts[prefix]
    status = "Covered" if n > 0 else "**No coverage**"
    lines.append(f"| {name} | {n} | {status} |")
lines.append("")
if missing_fns:
    lines.append(f"**Gap callout:** the assessment has no coverage in "
                 f"{', '.join(missing_fns)}. These functions represent the "
                 f"clearest next areas to assess.")
    lines.append("")
    
report = "\n".join(lines)
with open(REPORT_PATH, "w", encoding="utf-8") as out:
    out.write(report)

print(f"Wrote {REPORT_PATH}")