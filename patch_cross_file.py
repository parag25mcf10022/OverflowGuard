import re

with open("cross_file_taint.py", "r", encoding="utf-8") as f:
    text = f.read()

old_block = """            # Find calls to imported functions
            import_edges = self._import_graph.get(file_path, [])
            imported_files = {e.to_file for e in import_edges if os.path.isfile(e.to_file)}

            # Check if tainted data flows to functions in other files
            for imp_file in imported_files:
                imp_funcs = self._functions.get(imp_file, [])
                for func in imp_funcs:
                    # Check if this function is called in the current file
                    call_pattern = re.compile(rf'\\b{re.escape(func.name)}\\s*\\(')
"""

new_block = """            # Find calls to imported functions
            import_edges = self._import_graph.get(file_path, [])
            imported_files = {e.to_file for e in import_edges if os.path.isfile(e.to_file)}

            if lang in ("c", "cpp"):
                # GLib & Wireshark callbacks often lack explicit #include and aren't syntactic calls
                for fpath_other, funcs_other in self._functions.items():
                    if fpath_other != file_path:
                        for fn in funcs_other:
                            if fn.name in content:
                                imported_files.add(fpath_other)
                                break

            # Check if tainted data flows to functions in other files
            for imp_file in imported_files:
                imp_funcs = self._functions.get(imp_file, [])
                for func in imp_funcs:
                    # Check if this function is called in the current file (or used as callback)
                    if lang in ("c", "cpp"):
                        call_pattern = re.compile(rf'\\b{re.escape(func.name)}\\b')
                    else:
                        call_pattern = re.compile(rf'\\b{re.escape(func.name)}\\s*\\(')
"""

# Wait, `fn.name in content` is a fast check before adding to imported_files.
text = text.replace(old_block, new_block)
with open("cross_file_taint.py", "w", encoding="utf-8") as f:
    f.write(text)

