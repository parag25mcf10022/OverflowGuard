import re
with open("samples/user1.cpp") as f: src = f.read()
src_lines = src.splitlines()
def _lineno(content, idx): return content[:idx].count("\n") + 1
for m in re.finditer(r"\b(?:volatile\s+)?(?:int|long|char|double|float|uint\d+_t)\s+(\w+)\s*=", src):
    ln = _lineno(src, m.start())
    line_text = src_lines[ln - 1] if ln <= len(src_lines) else ""
    varname = m.group(1)
    if not line_text.startswith((" ", "\t")) and not line_text.lstrip().startswith(("//", "/*", "#", "*")):
        print(f"Global matched: {varname}")
