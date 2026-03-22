import json
from owasp_mapper import generate_owasp_report

# let's write a script to look at the json output of the previous run
with open("results/samples.json", "r") as f:
    data = json.load(f)

findings = []
for file, file_findings in data.items():
    findings.extend(file_findings)
    
report = generate_owasp_report(findings)
print("Unmapped count:", report.unmapped_findings)
for m in report.mappings:
    pass # we know mapped

all_types = set()
for f in findings:
    if f["issue"] not in [m.finding_type for m in report.mappings]:
        print(f"UNMAPPED: {f}")
