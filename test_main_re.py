import re
with open("samples/testunusedvar-048-localvardynamic2.cpp", "r") as f:
    text = f.read()
print(bool(re.search(r'\bmain\s*\(', text)))
