import re

def _check_main():
    content = "int my_func() { return 0; }\n"
    has_main = bool(re.search(r'\bmain\s*\(', content))
    print(has_main)

_check_main()
