import os, sys, json
from main import AuditManager, analyze_file
from owasp_mapper import generate_owasp_report

audit = AuditManager("samples/")
import glob
for file in os.listdir("samples/"):
    fpath = os.path.join("samples", file)
    if os.path.isfile(fpath):
        analyze_file(fpath, audit)

all_findings = []
for p, flist in audit.report_data.items():
    for f in flist:
        all_findings.append({
            "issue_type": f.get("issue", f.get("type", "")),
            "severity":   f.get("severity", "MEDIUM"),
            "description": f.get("description", ""),
            "cwe":        audit._normalize_cwe(f.get("cwe", "")),
        })

report = generate_owasp_report(all_findings)

print(f"Total: {report.total_findings}, Mapped: {report.mapped_findings}")
print("UNMAPPED FINDINGS:")
for item in all_findings:
    import owasp_mapper
    if not owasp_mapper._map_finding_to_owasp(item["cwe"], item["issue_type"], item["description"]):
        print(f"Unmapped -> CWE: {item.get('cwe')}, TYPE: {item.get('issue_type')}, DESC: {item.get('description')}")
