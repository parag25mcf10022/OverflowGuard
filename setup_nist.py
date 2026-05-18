import os, json

# suite 1
os.makedirs("samples/501043", exist_ok=True)
with open("samples/501043/testunusedvar.cpp", "w") as f:
    f.write("""#include <cstdlib>
struct Fred { int i; };
void foo()
{
    Fred* ptr = (Fred*)malloc(sizeof(Fred)); // Variable 'ptr' is allocated memory that is never used.
    free(ptr);
}""")

with open("samples/501043/manifest.sarif", "w") as f:
    json.dump({
      "runs": [{"results": [
        {"properties": {"cwe": "CWE-563"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "testunusedvar.cpp"}, "region": {"startLine": 5}}}]}
      ]}]
    }, f)

# suite 2
os.makedirs("samples/501317", exist_ok=True)
os.system("cp nist-samples/sigcomp-udvm.c samples/501317/sigcomp-udvm.c")

with open("samples/501317/manifest.sarif", "w") as f:
    json.dump({
      "runs": [{"results": [
        {"properties": {"cwe": "CWE-119"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "sigcomp-udvm.c"}, "region": {"startLine": 135}}}]}
      ]}]
    }, f)

