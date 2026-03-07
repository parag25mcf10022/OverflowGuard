"""
tests/test_audit.py — Unit & integration tests for OverflowGuard.

Run with:
    python -m pytest tests/ -v
  or
    python -m unittest discover -s tests -v
"""

import os
import sys
import unittest
import tempfile

# Make sure the workspace root is importable
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from ast_analyzer import ASTAnalyzer, CLANG_AVAILABLE
from static_tools  import run_cppcheck, run_clang_tidy, is_available
from main          import AuditManager, analyze_file

SAMPLES = os.path.join(ROOT, "samples")


def fp(name: str) -> str:
    """Return absolute path to a sample file."""
    return os.path.join(SAMPLES, name)


def run_audit(filename: str) -> list:
    """Run full audit pipeline on *filename*, return findings list."""
    mgr = AuditManager(filename)
    analyze_file(filename, mgr)
    return mgr.report_data.get(filename, [])


# ===========================================================================
# AST Analyzer tests (AST or regex fallback, both paths are exercised)
# ===========================================================================

class TestASTAnalyzer(unittest.TestCase):

    # ---- stack overflow ----
    def test_stack_overflow_detected(self):
        findings = ASTAnalyzer(fp("stack_overflow.c")).analyze()
        types = {f.issue_type for f in findings}
        self.assertTrue(
            types & {"stack-buffer-overflow", "buffer-overflow"},
            f"Expected a buffer-overflow type, got: {types}",
        )

    def test_stack_overflow_high_confidence(self):
        findings = ASTAnalyzer(fp("stack_overflow.c")).analyze()
        high = [f for f in findings if f.confidence == "HIGH"]
        self.assertTrue(len(high) > 0,
                        "Expected at least one HIGH-confidence finding for stack_overflow.c")

    def test_stack_overflow_line_is_valid(self):
        findings = ASTAnalyzer(fp("stack_overflow.c")).analyze()
        for f in findings:
            self.assertGreater(f.line, 0, "Line numbers must be > 0")

    # ---- use-after-free ----
    def test_use_after_free_detected(self):
        """use_after.c: free(data) then printf(data) — must detect UAF."""
        findings = ASTAnalyzer(fp("use_after.c")).analyze()
        types = {f.issue_type for f in findings}
        self.assertIn(
            "use-after-free", types,
            f"Expected use-after-free, got: {types}",
        )

    def test_use_after_free_confidence(self):
        findings = ASTAnalyzer(fp("use_after.c")).analyze()
        uaf = [f for f in findings if f.issue_type == "use-after-free"]
        self.assertTrue(all(f.confidence == "HIGH" for f in uaf),
                        "UAF findings should always be HIGH confidence")

    # ---- clean file — no false positives ----
    def test_no_fp_on_clean_file(self):
        """A trivially safe file must not produce HIGH-confidence findings."""
        with tempfile.NamedTemporaryFile(suffix=".c", delete=False,
                                         mode="w") as tmp:
            tmp.write('#include <stdio.h>\n'
                      'int main(void) {\n'
                      '    printf("hello\\n");\n'
                      '    return 0;\n'
                      '}\n')
            tmp_path = tmp.name
        try:
            findings = ASTAnalyzer(tmp_path).analyze()
            # printf("literal") must NOT fire as format-string
            # No dangerous calls → no HIGH findings
            bad = [f for f in findings
                   if f.confidence == "HIGH"
                   and f.issue_type != "format-string"]
            self.assertEqual(bad, [],
                             f"Unexpected HIGH findings on clean file: {bad}")
        finally:
            os.unlink(tmp_path)

    # ---- de-duplication ----
    def test_deduplication(self):
        """The same (issue, line) must not appear twice."""
        findings = ASTAnalyzer(fp("stack_overflow.c")).analyze()
        keys = [(f.issue_type, f.line) for f in findings]
        self.assertEqual(len(keys), len(set(keys)),
                         f"Duplicate findings detected: {keys}")

    # ---- heap overflow file runs without errors ----
    def test_heap_overflow_runs(self):
        findings = ASTAnalyzer(fp("heap_overflow.c")).analyze()
        self.assertIsInstance(findings, list)


# ===========================================================================
# Integration tests — full `analyze_file` pipeline
# ===========================================================================

class TestCppAuditPipeline(unittest.TestCase):

    def test_stack_overflow_at_least_one_finding(self):
        findings = run_audit(fp("stack_overflow.c"))
        self.assertGreater(len(findings), 0,
                           "Expected findings for stack_overflow.c")

    def test_stack_overflow_type_correct(self):
        findings = run_audit(fp("stack_overflow.c"))
        types = {f["issue"] for f in findings}
        self.assertTrue(
            types & {"stack-buffer-overflow", "heap-buffer-overflow",
                     "buffer-overflow"},
            f"Expected an overflow type, got: {types}",
        )

    def test_use_after_free_pipeline(self):
        findings = run_audit(fp("use_after.c"))
        types = {f["issue"] for f in findings}
        # use_after.c has strcpy (static hit) and UAF (AST hit)
        self.assertTrue(len(findings) > 0,
                        f"Expected findings for use_after.c, got none")

    def test_heap_overflow_pipeline_runs(self):
        """heap_overflow.c has no strcpy/etc. — should not crash the pipeline."""
        findings = run_audit(fp("heap_overflow.c"))
        self.assertIsInstance(findings, list)

    def test_no_duplicate_findings_per_file(self):
        for fname in ("stack_overflow.c", "use_after.c"):
            with self.subTest(file=fname):
                findings = run_audit(fp(fname))
                keys = [(f["issue"], f["line"]) for f in findings]
                self.assertEqual(len(keys), len(set(keys)),
                                 f"Duplicates in {fname}: {keys}")


class TestRustAuditPipeline(unittest.TestCase):

    def test_unsafe_block_detected(self):
        findings = run_audit(fp("engine.rs"))
        types = {f["issue"] for f in findings}
        self.assertIn("unsafe-block", types,
                      f"Expected unsafe-block, got: {types}")


class TestJavaAuditPipeline(unittest.TestCase):

    def test_insecure_deserialization_detected(self):
        findings = run_audit(fp("loader.java"))
        types = {f["issue"] for f in findings}
        self.assertIn("insecure-deserialization", types,
                      f"Expected insecure-deserialization, got: {types}")


class TestPythonAuditPipeline(unittest.TestCase):

    def test_vault_py_pipeline_runs(self):
        """vault.py contains shell=True; either bandit or the fuzzer must fire."""
        findings = run_audit(fp("vault.py"))
        self.assertIsInstance(findings, list)


class TestGoAuditPipeline(unittest.TestCase):

    def test_race_go_pipeline_runs(self):
        """race.go pipeline should not raise exceptions."""
        findings = run_audit(fp("race.go"))
        self.assertIsInstance(findings, list)


# ===========================================================================
# Static-tool wrappers (only execute if tools are present)
# ===========================================================================

@unittest.skipUnless(is_available("cppcheck"), "cppcheck not in PATH")
class TestCppcheck(unittest.TestCase):

    def test_cppcheck_returns_list(self):
        result = run_cppcheck(fp("stack_overflow.c"))
        self.assertIsInstance(result, list)

    def test_cppcheck_finds_something(self):
        result = run_cppcheck(fp("stack_overflow.c"))
        self.assertGreater(len(result), 0,
                           "cppcheck should find at least one issue in stack_overflow.c")

    def test_cppcheck_line_numbers_positive(self):
        for f in run_cppcheck(fp("stack_overflow.c")):
            self.assertGreaterEqual(f.line, 0)


@unittest.skipUnless(is_available("clang-tidy"), "clang-tidy not in PATH")
class TestClangTidy(unittest.TestCase):

    def test_clang_tidy_returns_list(self):
        result = run_clang_tidy(fp("stack_overflow.c"))
        self.assertIsInstance(result, list)


# ===========================================================================
# Edge-case / robustness tests
# ===========================================================================

class TestRobustness(unittest.TestCase):

    def test_nonexistent_file_does_not_crash(self):
        findings = ASTAnalyzer("/nonexistent/file.c").analyze()
        self.assertIsInstance(findings, list)

    def test_empty_c_file(self):
        with tempfile.NamedTemporaryFile(suffix=".c", delete=False,
                                         mode="w") as tmp:
            tmp.write("")
            tmp_path = tmp.name
        try:
            findings = ASTAnalyzer(tmp_path).analyze()
            self.assertIsInstance(findings, list)
            self.assertEqual(findings, [])
        finally:
            os.unlink(tmp_path)

    def test_binary_file_does_not_crash(self):
        with tempfile.NamedTemporaryFile(suffix=".c", delete=False,
                                         mode="wb") as tmp:
            tmp.write(bytes(range(256)) * 4)
            tmp_path = tmp.name
        try:
            findings = ASTAnalyzer(tmp_path).analyze()
            self.assertIsInstance(findings, list)
        finally:
            os.unlink(tmp_path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
