import re

with open("tests/nist_harness.py", "r") as f:
    text = f.read()

# Instead of regex replace, let's just find the function block
start_idx = text.find('def _load_sarif_findings')
end_idx = text.find('def _normalize_cwe')

if start_idx != -1 and end_idx != -1:
    new_text = text[:start_idx] + """def _load_sarif_findings(path: Path) -> Set[Finding]:
    if not path.exists() or path.stat().st_size == 0:
        return set()
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return set()
        
    results = data.get("runs", [{}])[0].get("results", [])
    findings = set()
    for res in results:
        if res.get("kind") == "pass":
            continue
            
        cwe = ""
        rule_id = res.get("ruleId", "")
        if "CWE" in str(rule_id).upper(): cwe = rule_id
            
        props = res.get("properties", {})
        if not cwe: cwe = props.get("cwe", "")
        if not cwe and props.get("tags"): cwe = props.get("tags")[0]
             
        if not cwe:
            for taxa in res.get("taxa", []):
                if taxa.get("toolComponent", {}).get("name") == "CWE":
                    cwe = "CWE-" + str(taxa.get("id", ""))
                    break
                    
        if not cwe:
            msg = res.get("message", {}).get("text", "")
            m = re.search(r'(CWE-\d+)', msg, re.IGNORECASE)
            if m: cwe = m.group(1).upper()

        cwe_norm = _normalize_cwe(cwe)
        
        locs = res.get("locations", [])
        if not locs and res.get("codeFlows"):
            try: locs = res.get("codeFlows")[0].get("threadFlows")[0].get("locations", [])
            except: pass
                
        for loc in locs:
            phys = loc.get("physicalLocation", {})
            if not phys and loc.get("location"):
                phys = loc.get("location", {}).get("physicalLocation", {})
                
            artifact = phys.get("artifactLocation", {})
            uri = artifact.get("uri", "")
            file_basename = Path(uri).name
            
            line = phys.get("region", {}).get("startLine", 0) or 0
            if file_basename and line > 0 and cwe_norm:
                findings.add(Finding(cwe=cwe_norm, file=file_basename, line=int(line)))
                
    return findings


""" + text[end_idx:]
    with open("tests/nist_harness.py", "w") as f:
        f.write(new_text)
