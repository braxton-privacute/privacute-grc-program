import requests
import json

SCF_URL = "https://grcengclub.github.io/scf-api/api/controls.json"

print("Fetching the SCF control catalog...")
response = requests.get(SCF_URL)
data = response.json()

controls = data["controls"]
print(f"Loaded {len(controls)} controls from the SCF.\n")

#Build two lookups from the control list:
#   valid_ids   -> a set of every real control_id (fast "does it exist?" checks)
#   titles      -> a dict mapping control_id to its official title
valid_ids = set()
titles = {}
for control in controls:
    cid = control["control_id"]
    valid_ids.add(cid)
    titles[cid] = control["title"]

# Load the findings we want to validate
with open("data/findings.json") as f:
    findings = json.load(f)

print("Validating control mappings in findings.json:\n")

problems = 0
for finding in findings:
    print(f"{finding['id']}: {finding['threat']}")
    for cid in finding["scf_controls"]:
        if cid in valid_ids:
            print(f"    OK  {cid}   -> {titles[cid]}")
            problems += 1
    print()

if problems == 0:
    print("ALL control mappings are valid.")
else:
    print(f"Found {problems} invalid control mapping(s).")