import re

with open('owasp_mapper.py', 'r') as f:
    content = f.read()

keywords_to_add = """
    ("negative-index",           "A03"),
    ("ring-buffer-overflow",     "A03"),
    ("alloc-loop-mismatch",      "A03"),
    ("uncapped-loop-bound",      "A03"),
    ("le-loop-oob",              "A03"),
    ("narrow-size-cast",         "A03"),
    ("llvm-memcpy-param-size",   "A03"),
    ("data-race",                "A04"),
    ("off-by-one",               "A03"),
    ("integer-truncation",       "A03"),
    ("unsafe-block",             "A04"),
    ("panic-unwrap",             "A04"),
"""

if '"negative-index"' not in content:
    content = content.replace('("use.after.free",           "A03"),', '("use.after.free",           "A03"),' + keywords_to_add)
    with open('owasp_mapper.py', 'w') as f:
        f.write(content)
