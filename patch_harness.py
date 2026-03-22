import re

with open("tests/nist_harness.py", "r") as f:
    content = f.read()

content = content.replace('NIST_ROOT = ROOT / "samples"', 'NIST_ROOT = ROOT / "nist-samples"')

# Add debug mode
# Let's replace _compare function to print matches and mismatches

compare_orig = """def _compare(gt: Set[Finding], pred: Set[Finding]) -> Metrics:
    tp = len(gt & pred)
    fp = len(pred - gt)
    fn = len(gt - pred)
    return Metrics(tp=tp, fp=fp, fn=fn)"""

compare_new = """def _compare(gt: Set[Finding], pred: Set[Finding]) -> Metrics:
    print("\\n--- Matches ---")
    
    tp_set = gt & pred
    fp_set = pred - gt
    fn_set = gt - pred
    
    # Try to match simply by file and line to see what CWE mismatch occurred
    pred_by_loc = {(f.file, f.line): f for f in pred}
    
    for g in gt:
        if g in pred:
            print(f"MATCH (TP): Expected file={g.file} CWE={g.cwe} line={g.line}")
        else:
            match_loc = pred_by_loc.get((g.file, g.line))
            if match_loc:
                print(f"MISS (FN) - CWE Mismatch: Expected CWE={g.cwe}, Got CWE={match_loc.cwe} at file={g.file} line={g.line}")
            else:
                print(f"MISS (FN): Expected file={g.file} CWE={g.cwe} line={g.line}")
                
    for p in fp_set:
        print(f"EXTRA (FP): Found file={p.file} CWE={p.cwe} line={p.line}")

    print("-----------------\\n")

    return Metrics(tp=len(tp_set), fp=len(fp_set), fn=len(fn_set))"""

content = content.replace(compare_orig, compare_new)

with open("tests/nist_harness.py", "w") as f:
    f.write(content)

