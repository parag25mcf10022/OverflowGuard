import re
src_lines = open("samples/user1.cpp", "r").read().splitlines()
src = "\n".join(src_lines)
for m in re.finditer(r"\b(?:volatile\s+)?(?:int|long|char|double|float|uint\d+_t)\s+(\w+)\s*=", src):
    ln = src[:m.start()].count("\n") + 1
    line_text = src_lines[ln - 1]
    if not line_text.startswith((" ", "\t")):
        varname = m.group(1)
        print(f"varname={varname} line_text={repr(line_text)}")
