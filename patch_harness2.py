import re

with open("tests/nist_harness.py", "r") as f:
    text = f.read()

new_load = """def _load_sarif_findings(path: Path) -> Set[Finding]:
    if not path.exists() or path.stat().st_size == 0:
        return set()
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return set()
        
    results = data.get("runs", [{}])[0].get("results", [])
    findings: Set[Finding] = set()
    for res in results:
        # SARD explicitly marks "pass" for test cases that are clean.
        if res.get("kind") == "pass":
            continue
            
        cwe = ""
        # 1. Try ruleId
        rule_id = res.get("ruleId", "")
        if "CWE" in str(rule_id).upper():
            cwe = rule_id
            
        # 2. Try properties or tags
        props = res.get("properties", {})
        if not cwe:
             cwe = props.get("cwe", "")
        if not cwe and props.get("tags"):
             cwe = props.get("tags")[0]
             
        # 3. Try taxa
        if not cwe:
            for taxa in res.get("taxa", []):
                if taxa.get("toolComponent", {}).get("name") == "CWE":
                    cwe = "CWE-" + str(taxa.get("id", ""))
                    break
                    
        # 4. Try message text
        if not cwe:
            msg = res.get("message", {}).get("text", "")
            m = re.search(r'(CWE-\d+)', msg, re.IGNORECASE)
            if m:
                cwe = m.group(1).upper()

        cwe_norm = _normalize_cwe(cwe)
        
        # SARD might have locations or codeFlows
        locs = res.get("locations", [])
        if not locs and res.get("codeFlows"):
            try:
                locs = res.get("codeFlows")[0].get("threadFlows")[0].get("locations", [])
            except (IndexError, KeyError):
                pass
                
        if not locs:
            continue
            
        # extract all locations just in case
        for loc in locs:
            phys = loc.get("physicalLocation", {})
            if not phys and loc.get("location"):
                phys = loc.get("location", {}).get("physicalLocation", {})
                
            artifact = phys.get("artifactLocation", {})
            uri = artifact.get("uri", "")
            # use only basename to avoid absolute vs relative path mismatches
            file_basename = Path(uri).name
            
            line = phys.get("region", {}).get("startLine", 0) or 0
            if file_basename and line > 0 and cwe_norm:
                findings.add(Finding(cwe=cwe_norm, file=file_basename, line=int(line)))
                
    return findings"""

text = re.sub(r'def _load_sarif_findings.*?return findings', new_load, text, flags=re.DOTALL)

with open("tests/nist_harness.py", "w") as f:
    f.write(text)

