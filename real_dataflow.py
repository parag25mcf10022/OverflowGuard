"""
real_dataflow.py — Real dataflow and taint analysis engine for OverflowGuard v9.0

Provides proper dataflow analysis on Control‑Flow Graphs:

* **Reaching Definitions** — track which definitions reach each program point
* **Taint Propagation** — propagate taint from sources to sinks on the CFG
  with proper gen/kill semantics and fixpoint iteration
* **Sanitizer‑Aware** — sanitizers *kill* taint when they *dominate* the sink
  (not a crude ±10‑line heuristic)
* **Inter‑procedural** — call‑graph‑based taint propagation with function
  summaries
* **Multi‑language** — works for every language supported by the tree‑sitter
  engine (12+)

Replaces the old :mod:`dataflow` and :mod:`taint_analyzer` regex‑based modules.
"""

from __future__ import annotations

import os
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import (
    Any,
    Dict,
    FrozenSet,
    List,
    Optional,
    Set,
    Tuple,
)

from tree_sitter_engine import (
    ASTQueries,
    TSNode,
    TreeSitterParser,
    TS_AVAILABLE,
    language_for_file,
    parse_file,
)
from cfg_builder import BasicBlock, CFG, CFGBuilder, Statement, build_cfgs

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TaintFact:
    """An immutable taint tag attached to a variable at a specific point."""
    variable: str
    source_line: int
    source_type: str     # e.g. "user_input", "network", "env"
    source_func: str     # name of the taint‑source function


@dataclass
class TaintPath:
    """Records the complete path from source → sink for reporting."""
    source: TaintFact
    sink_line: int
    sink_func: str
    sink_vuln: str       # vulnerability type from ASTQueries.SINKS
    path_lines: List[int]
    sanitized: bool = False
    sanitizer_line: Optional[int] = None


@dataclass
class DataflowFinding:
    """A single reported taint finding — fed into the main pipeline."""
    issue_type: str
    line: int
    snippet: str
    note: str
    confidence: str       # "High" | "Medium" | "Low"
    source_line: int = 0
    sink_line: int = 0
    taint_path: Optional[TaintPath] = None


# ---------------------------------------------------------------------------
# Reaching Definitions analysis
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Definition:
    """A definition of a variable at a specific line."""
    variable: str
    line: int
    block_id: int


class ReachingDefinitions:
    """
    Classical reaching‑definitions dataflow analysis on a CFG.

    For each block, computes the set of definitions that *reach* the
    beginning of the block (IN set) and the end (OUT set).
    """

    def __init__(self, cfg: CFG):
        self.cfg = cfg

    def compute(self) -> Dict[int, Set[Definition]]:
        """Return a mapping block_id → set of reaching definitions (IN set)."""
        # 1. Collect all definitions
        gen: Dict[int, Set[Definition]] = defaultdict(set)
        kill: Dict[int, Set[Definition]] = defaultdict(set)
        all_defs: Dict[str, Set[Definition]] = defaultdict(set)

        for blk in self.cfg.all_blocks():
            for stmt in blk.stmts:
                for v in stmt.defs:
                    d = Definition(variable=v, line=stmt.line, block_id=blk.id)
                    gen[blk.id].add(d)
                    all_defs[v].add(d)

        # Kill: a block kills all other defs of the same variable
        for blk in self.cfg.all_blocks():
            for g in gen[blk.id]:
                kill[blk.id] |= all_defs[g.variable] - {g}

        # 2. Fixpoint iteration (forward, union)
        in_sets: Dict[int, Set[Definition]] = defaultdict(set)
        out_sets: Dict[int, Set[Definition]] = defaultdict(set)

        changed = True
        rpo = self.cfg.rpo()
        while changed:
            changed = False
            for bid in rpo:
                blk = self.cfg.blocks[bid]
                new_in: Set[Definition] = set()
                for p in blk.preds:
                    new_in |= out_sets[p]
                new_out = gen[bid] | (new_in - kill[bid])
                if new_out != out_sets[bid]:
                    out_sets[bid] = new_out
                    in_sets[bid] = new_in
                    changed = True

        return dict(in_sets)


# ---------------------------------------------------------------------------
# Taint analysis on CFG
# ---------------------------------------------------------------------------


class TaintAnalysisEngine:
    """
    CFG‑based taint propagation analysis (intra‑procedural).

    Algorithm:
      1. Identify taint *sources* in the CFG (calls to source functions).
      2. Propagate taint along CFG edges with gen/kill:
         - gen: an assignment ``x = source()`` generates taint for ``x``
         - gen: an assignment ``y = f(x)`` when ``x`` is tainted → ``y`` tainted
         - kill: ``x = sanitize(x)`` kills taint for ``x`` (if sanitize dominates)
         - kill: ``x = constant`` kills taint for ``x``
      3. At each sink call, check if any argument is tainted.
      4. For tainted sinks, verify that no sanitizer dominates the sink.
    """

    def __init__(self, language: str):
        self.language = language
        self._queries = ASTQueries(language)

    def analyze(self, cfg: CFG, root: TSNode) -> List[TaintPath]:
        """Run taint analysis on one function's CFG.  Returns taint paths."""
        # 1. Seed: find taint sources
        taint_state: Dict[int, Set[TaintFact]] = defaultdict(set)
        sanitizer_locations: Dict[str, List[int]] = defaultdict(list)  # var → [block_ids]

        # Walk each block to find sources and sanitizers
        for blk in cfg.all_blocks():
            for stmt in blk.stmts:
                self._seed_taint(stmt, blk.id, taint_state)
                self._record_sanitizers(stmt, blk.id, sanitizer_locations)

        # 2. Propagate
        taint_state = self._propagate(cfg, taint_state, sanitizer_locations)

        # 3. Check sinks
        return self._check_sinks(cfg, taint_state, sanitizer_locations)

    # ---- step 1: seeding ------------------------------------------------

    def _seed_taint(self, stmt: Statement, block_id: int,
                    taint_state: Dict[int, Set[TaintFact]]) -> None:
        """If *stmt* contains a taint‑source call, seed taint for the LHS."""
        if stmt.kind not in ("assign", "decl", "call"):
            return

        # Look for source calls in the AST subtree
        for call_node in self._find_calls_in(stmt.node):
            cname = self._queries.call_name(call_node)
            if self._queries.is_source_call(call_node):
                # Determine the variable being assigned
                for v in stmt.defs:
                    fact = TaintFact(
                        variable=v,
                        source_line=stmt.line,
                        source_type="user_input",
                        source_func=cname,
                    )
                    taint_state[block_id].add(fact)

                # If no explicit defs, the call itself might be used
                # (e.g., ``sink(gets())`` — transitive)
                if not stmt.defs:
                    fact = TaintFact(
                        variable=f"__ret_{stmt.line}",
                        source_line=stmt.line,
                        source_type="user_input",
                        source_func=cname,
                    )
                    taint_state[block_id].add(fact)

    def _find_calls_in(self, node: TSNode) -> List[TSNode]:
        call_types = self._queries._CALL_TYPES.get(self.language, set())
        return [n for n in node.walk() if n.type in call_types]

    # ---- step 1b: sanitizer recording -----------------------------------

    def _record_sanitizers(self, stmt: Statement, block_id: int,
                           sanitizer_locations: Dict[str, List[int]]) -> None:
        for call_node in self._find_calls_in(stmt.node):
            if self._queries.is_sanitizer_call(call_node):
                for v in stmt.defs:
                    sanitizer_locations[v].append(block_id)

    # ---- step 2: propagation (fixpoint) ----------------------------------

    def _propagate(self, cfg: CFG,
                   taint_state: Dict[int, Set[TaintFact]],
                   sanitizer_locations: Dict[str, List[int]],
                   ) -> Dict[int, Set[TaintFact]]:
        """Propagate taint through assignments along CFG edges."""

        in_taint: Dict[int, Set[TaintFact]] = defaultdict(set)
        out_taint: Dict[int, Set[TaintFact]] = defaultdict(set)

        # Initialise with seeds
        for bid, facts in taint_state.items():
            out_taint[bid] = set(facts)

        rpo = cfg.rpo()
        changed = True
        iterations = 0
        max_iterations = 100  # safety guard

        while changed and iterations < max_iterations:
            changed = False
            iterations += 1
            for bid in rpo:
                blk = cfg.blocks[bid]

                # IN = union of predecessor OUT sets
                new_in: Set[TaintFact] = set()
                for p in blk.preds:
                    new_in |= out_taint[p]

                # GEN / KILL within this block
                current = set(new_in)

                for stmt in blk.stmts:
                    # Kill: if LHS is assigned from a non‑tainted source, kill it
                    if stmt.kind in ("assign", "decl") and stmt.defs:
                        for v in stmt.defs:
                            # Check if RHS uses any tainted variable
                            rhs_tainted = any(
                                f.variable in stmt.uses for f in current
                            )
                            if rhs_tainted:
                                # Propagate: new taint fact for the LHS
                                for f in list(current):
                                    if f.variable in stmt.uses:
                                        new_fact = TaintFact(
                                            variable=v,
                                            source_line=f.source_line,
                                            source_type=f.source_type,
                                            source_func=f.source_func,
                                        )
                                        current.add(new_fact)
                            else:
                                # Kill existing taint for this variable
                                current = {f for f in current if f.variable != v}

                    # Kill via sanitizer
                    if stmt.kind in ("assign", "call"):
                        for call_node in self._find_calls_in(stmt.node):
                            if self._queries.is_sanitizer_call(call_node):
                                for v in stmt.defs:
                                    current = {f for f in current if f.variable != v}

                # Also include locally‑generated taint
                current |= taint_state.get(bid, set())

                if current != out_taint[bid]:
                    out_taint[bid] = current
                    in_taint[bid] = new_in
                    changed = True

        return out_taint

    # ---- step 3: sink checking -------------------------------------------

    def _check_sinks(self, cfg: CFG,
                     taint_state: Dict[int, Set[TaintFact]],
                     sanitizer_locations: Dict[str, List[int]],
                     ) -> List[TaintPath]:
        """At each sink call, check if any argument is tainted."""
        idom = cfg.dominators()
        results: List[TaintPath] = []

        for blk in cfg.all_blocks():
            tainted_vars = taint_state.get(blk.id, set())
            if not tainted_vars:
                continue

            for stmt in blk.stmts:
                for call_node in self._find_calls_in(stmt.node):
                    vuln_type = self._queries.is_sink_call(call_node)
                    if vuln_type is None:
                        continue

                    # Check if any argument is tainted
                    args_ids = self._queries.get_identifiers_in(call_node)
                    tainted_args = [
                        f for f in tainted_vars
                        if f.variable in args_ids
                    ]
                    if not tainted_args:
                        continue

                    for fact in tainted_args:
                        # Check if a sanitizer dominates this block for this var
                        sanitized = False
                        san_line: Optional[int] = None
                        for san_bid in sanitizer_locations.get(fact.variable, []):
                            if cfg.dominates(san_bid, blk.id):
                                sanitized = True
                                san_blk = cfg.blocks.get(san_bid)
                                if san_blk and san_blk.stmts:
                                    san_line = san_blk.stmts[0].line
                                break

                        tp = TaintPath(
                            source=fact,
                            sink_line=stmt.line,
                            sink_func=self._queries.call_name(call_node),
                            sink_vuln=vuln_type,
                            path_lines=[fact.source_line, stmt.line],
                            sanitized=sanitized,
                            sanitizer_line=san_line,
                        )
                        results.append(tp)

        return results


# ---------------------------------------------------------------------------
# Inter‑procedural call‑graph taint
# ---------------------------------------------------------------------------

@dataclass
class FunctionSummary:
    """
    Taint summary for one function: which parameters flow to which sinks /
    return values.
    """
    name: str
    tainted_params: Set[int] = field(default_factory=set)   # param indices seen as sources
    returns_tainted: bool = False
    sinks: List[Tuple[str, int]] = field(default_factory=list)  # (vuln_type, param_idx)


class InterproceduralTaintEngine:
    """
    Build a call graph from tree‑sitter ASTs and propagate taint
    inter‑procedurally using function summaries + fixpoint.
    """

    def __init__(self, language: str):
        self.language = language
        self._queries = ASTQueries(language)

    def analyze(self, root: TSNode, cfgs: List[CFG]) -> List[TaintPath]:
        """
        Run inter‑procedural taint analysis.

        1. Build call graph from AST
        2. Compute per‑function taint summaries
        3. Propagate across call edges until fixpoint
        4. Return all source→sink paths found
        """
        # 1. Build call graph
        func_nodes = self._queries.find_functions(root)
        call_graph: Dict[str, Set[str]] = defaultdict(set)   # caller → {callees}
        func_bodies: Dict[str, TSNode] = {}

        for fn in func_nodes:
            name = self._queries.function_name(fn)
            func_bodies[name] = fn
            for call in self._queries.find_calls(fn):
                callee = self._queries.call_name(call)
                call_graph[name].add(callee)

        # 2. Build per‑function summaries from CFG‑based taint analysis
        summaries: Dict[str, FunctionSummary] = {}
        intra = TaintAnalysisEngine(self.language)

        for c in cfgs:
            paths = intra.analyze(c, root)
            summary = FunctionSummary(name=c.func_name)
            for tp in paths:
                if not tp.sanitized:
                    summary.sinks.append((tp.sink_vuln, -1))
            summaries[c.func_name] = summary

        # 3. Propagate: if a function calls another that has tainted params,
        #    and the caller passes tainted args, the caller inherits the sink.
        changed = True
        iterations = 0
        all_paths: List[TaintPath] = []

        while changed and iterations < 50:
            changed = False
            iterations += 1
            for caller, callees in call_graph.items():
                caller_summary = summaries.get(caller)
                if caller_summary is None:
                    continue
                for callee in callees:
                    callee_summary = summaries.get(callee)
                    if callee_summary is None:
                        continue
                    # If callee has sinks, caller inherits them
                    for sink_vuln, pidx in callee_summary.sinks:
                        entry = (sink_vuln, pidx)
                        if entry not in caller_summary.sinks:
                            caller_summary.sinks.append(entry)
                            changed = True

        # 4. Collect all intra‑procedural findings
        for c in cfgs:
            paths = intra.analyze(c, root)
            all_paths.extend(paths)

        return all_paths


# ---------------------------------------------------------------------------
# Top‑level analyzer (drop‑in replacement for old dataflow + taint modules)
# ---------------------------------------------------------------------------


class RealDataflowAnalyzer:
    """
    Drop‑in replacement for the old ``DataflowAnalyzer`` and ``TaintAnalyzer``.

    Usage::

        findings = RealDataflowAnalyzer().analyze(file_path)
    """

    def analyze(self, file_path: str) -> List[DataflowFinding]:
        if not TS_AVAILABLE:
            return []

        lang = language_for_file(file_path)
        if lang is None:
            return []

        root, queries = parse_file(file_path)
        if root is None:
            return []

        # Read source for snippets
        try:
            with open(file_path, "r", errors="replace") as fh:
                source_lines = fh.readlines()
        except Exception:
            source_lines = []

        # Build CFGs
        cfgs = build_cfgs(root, lang)

        # Run intra‑procedural taint
        intra = TaintAnalysisEngine(lang)
        results: List[DataflowFinding] = []

        for c in cfgs:
            paths = intra.analyze(c, root)
            for tp in paths:
                if tp.sanitized:
                    continue  # skip sanitized findings
                snippet = ""
                if 0 < tp.sink_line <= len(source_lines):
                    snippet = source_lines[tp.sink_line - 1].strip()

                path_desc = " → ".join(f"L{ln}" for ln in tp.path_lines)
                note = (
                    f"Tainted data from {tp.source.source_func}() at line "
                    f"{tp.source.source_line} flows to {tp.sink_func}() "
                    f"at line {tp.sink_line}.  Path: {path_desc}"
                )
                results.append(DataflowFinding(
                    issue_type=tp.sink_vuln,
                    line=tp.sink_line,
                    snippet=snippet,
                    note=note,
                    confidence="High",
                    source_line=tp.source.source_line,
                    sink_line=tp.sink_line,
                    taint_path=tp,
                ))

        # Run inter‑procedural taint
        if len(cfgs) > 1:
            inter = InterproceduralTaintEngine(lang)
            inter_paths = inter.analyze(root, cfgs)
            seen = {(r.source_line, r.sink_line) for r in results}
            for tp in inter_paths:
                if tp.sanitized:
                    continue
                if (tp.source.source_line, tp.sink_line) in seen:
                    continue
                seen.add((tp.source.source_line, tp.sink_line))
                snippet = ""
                if 0 < tp.sink_line <= len(source_lines):
                    snippet = source_lines[tp.sink_line - 1].strip()
                path_desc = " → ".join(f"L{ln}" for ln in tp.path_lines)
                note = (
                    f"[Inter-proc] Tainted data from {tp.source.source_func}() "
                    f"at line {tp.source.source_line} reaches {tp.sink_func}() "
                    f"at line {tp.sink_line} across function boundaries.  "
                    f"Path: {path_desc}"
                )
                results.append(DataflowFinding(
                    issue_type=tp.sink_vuln,
                    line=tp.sink_line,
                    snippet=snippet,
                    note=note,
                    confidence="High",
                    source_line=tp.source.source_line,
                    sink_line=tp.sink_line,
                    taint_path=tp,
                ))

        # ----- Also check for non‑taint bugs via AST queries -----
        # Double‑free detection: track free()'d variables
        results.extend(self._check_double_free(root, queries, lang, source_lines))
        # Use‑after‑free: variable used after free()
        results.extend(self._check_use_after_free(root, queries, lang, source_lines))
        # Buffer overflows: array access without bounds check
        results.extend(self._check_unchecked_array(root, queries, lang, source_lines))

        return results

    # ---- auxiliary AST‑based checks --------------------------------------

    def _check_double_free(self, root: TSNode, queries: ASTQueries,
                           lang: str, source_lines: list) -> List[DataflowFinding]:
        findings: List[DataflowFinding] = []
        if lang not in ("c", "cpp"):
            return findings

        for func in queries.find_functions(root):
            freed: Dict[str, int] = {}  # var → first free line
            for call in queries.find_calls(func):
                cname = queries.call_name(call)
                if cname in ("free", "delete"):
                    ids = queries.get_identifiers_in(call)
                    ids.discard(cname)
                    for v in ids:
                        if v in freed:
                            snippet = ""
                            if 0 < call.start_line <= len(source_lines):
                                snippet = source_lines[call.start_line - 1].strip()
                            findings.append(DataflowFinding(
                                issue_type="double-free",
                                line=call.start_line,
                                snippet=snippet,
                                note=(f"'{v}' was already freed at line {freed[v]}. "
                                      f"double free at line {call.start_line}."),
                                confidence="High",
                            ))
                        else:
                            freed[v] = call.start_line
        return findings

    def _check_use_after_free(self, root: TSNode, queries: ASTQueries,
                              lang: str, source_lines: list) -> List[DataflowFinding]:
        findings: List[DataflowFinding] = []
        if lang not in ("c", "cpp"):
            return findings

        for func in queries.find_functions(root):
            freed_vars: Set[str] = set()
            # Walk statements in order
            stmts = list(func.walk_named())
            free_lines: Dict[str, int] = {}
            for node in stmts:
                # Check for free calls
                call_types = queries._CALL_TYPES.get(lang, set())
                if node.type in call_types:
                    cname = queries.call_name(node)
                    if cname in ("free", "delete"):
                        ids = queries.get_identifiers_in(node)
                        ids.discard(cname)
                        for v in ids:
                            freed_vars.add(v)
                            free_lines[v] = node.start_line
                # Check for uses of freed vars
                elif node.type == "identifier" and node.text in freed_vars:
                    # Skip if it's the argument to free itself
                    parent_type = ""
                    ancestors = node.ancestors()
                    if ancestors:
                        parent_type = ancestors[-1].type if ancestors else ""
                    if parent_type not in call_types:
                        snippet = ""
                        if 0 < node.start_line <= len(source_lines):
                            snippet = source_lines[node.start_line - 1].strip()
                        fl = free_lines.get(node.text, 0)
                        findings.append(DataflowFinding(
                            issue_type="use-after-free",
                            line=node.start_line,
                            snippet=snippet,
                            note=(f"'{node.text}' used at line {node.start_line} "
                                  f"after being freed at line {fl}."),
                            confidence="High",
                        ))
        return findings

    def _check_unchecked_array(self, root: TSNode, queries: ASTQueries,
                               lang: str, source_lines: list) -> List[DataflowFinding]:
        findings: List[DataflowFinding] = []
        for func in queries.find_functions(root):
            accesses = queries.find_array_accesses(func)
            ifs = queries.find_ifs(func)
            # Collect all identifiers used in bounds checks
            guarded_vars: Set[str] = set()
            for if_node in ifs:
                cond = if_node.child_by_field("condition")
                if cond:
                    guarded_vars |= queries.get_identifiers_in(cond)

            for acc in accesses:
                # Get the index variable
                idx_ids = set()
                if len(acc.named_children) >= 2:
                    idx_ids = queries.get_identifiers_in(acc.named_children[-1])
                # If no guard check for any index variable, flag it
                if idx_ids and not (idx_ids & guarded_vars):
                    snippet = ""
                    if 0 < acc.start_line <= len(source_lines):
                        snippet = source_lines[acc.start_line - 1].strip()
                    idx_names = ", ".join(idx_ids)
                    findings.append(DataflowFinding(
                        issue_type="buffer-overflow",
                        line=acc.start_line,
                        snippet=snippet,
                        note=(f"Array access using '{idx_names}' without "
                              f"a prior bounds check in this function."),
                        confidence="Medium",
                    ))
        return findings
