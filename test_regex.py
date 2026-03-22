import re
with open("samples/user1.cpp") as f: src = f.read()
src_lines = src.split("\n")
def _lineno(content, idx): return content[:idx].count("\n") + 1
for m in re.finditer(r"\b(?:volatile\s+)?(?:int|long|char|double|float|uint\d+_t)\s+(\w+)\s*=", src):
    ln = _lineno(src, m.start())
    line_text = src_lines[ln - 1]
    print(f"Matched: {m.group(1)} at {ln}: {repr(line_text)}")
