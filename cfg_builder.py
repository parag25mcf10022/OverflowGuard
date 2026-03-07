"""
cfg_builder.py — Control‑Flow Graph construction from tree‑sitter ASTs

Builds a proper CFG for any language supported by :mod:`tree_sitter_engine`.
The CFG is the foundation for real dataflow analysis, taint propagation, and
symbolic execution.

Key data‑structures:

* :class:`BasicBlock`  — a maximal straight‑line sequence of statements with
  no branches except at the end.
* :class:`CFG`         — a graph of basic blocks with entry / exit sentinels,
  dominator tree, and reverse‑post‑order traversal.
"""

from __future__ import annotations

import itertools
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import (
    Any,
    Dict,
    FrozenSet,
    Generator,
    List,
    Optional,
    Set,
    Tuple,
)

from tree_sitter_engine import TSNode, ASTQueries, language_for_file

# ---------------------------------------------------------------------------
# Basic Block & CFG data‑structures
# ---------------------------------------------------------------------------

_next_block_id = itertools.count(0)


def _fresh_id() -> int:
    return next(_next_block_id)


@dataclass
class Statement:
    """A single statement inside a basic block."""
    node: TSNode
    kind: str        # "assign" | "call" | "return" | "decl" | "expr" | "cond" | "other"
    line: int
    text: str        # source snippet (first 200 chars)

    # For assignments — names written / read
    defs: Set[str] = field(default_factory=set)   # variables defined (written)
    uses: Set[str] = field(default_factory=set)   # variables used (read)


@dataclass
class BasicBlock:
    """A maximal straight‑line sequence of statements."""
    id: int = field(default_factory=_fresh_id)
    stmts: List[Statement] = field(default_factory=list)
    succs: List[int] = field(default_factory=list)        # successor block IDs
    preds: List[int] = field(default_factory=list)        # predecessor block IDs
    label: str = ""                                       # human label

    # Dataflow scratch space (populated by DataflowAnalyzer)
    gen: Set[str] = field(default_factory=set)
    kill: Set[str] = field(default_factory=set)
    in_set: Set[Any] = field(default_factory=set)
    out_set: Set[Any] = field(default_factory=set)

    @property
    def is_empty(self) -> bool:
        return not self.stmts


@dataclass
class CFG:
    """A Control‑Flow Graph for one function / method body."""
    blocks: Dict[int, BasicBlock] = field(default_factory=dict)
    entry_id: int = -1
    exit_id: int = -1
    func_name: str = ""
    language: str = ""

    # ---- graph helpers ---------------------------------------------------

    def successors(self, bid: int) -> List[int]:
        return self.blocks[bid].succs

    def predecessors(self, bid: int) -> List[int]:
        return self.blocks[bid].preds

    def all_blocks(self) -> Generator[BasicBlock, None, None]:
        yield from self.blocks.values()

    # ---- Reverse Post‑Order (RPO) ----------------------------------------

    def rpo(self) -> List[int]:
        """Return block IDs in reverse post‑order (useful for dataflow)."""
        visited: Set[int] = set()
        order: List[int] = []

        def dfs(bid: int) -> None:
            if bid in visited:
                return
            visited.add(bid)
            for s in self.blocks[bid].succs:
                dfs(s)
            order.append(bid)

        dfs(self.entry_id)
        order.reverse()
        return order

    # ---- Dominator tree ---------------------------------------------------

    def dominators(self) -> Dict[int, int]:
        """
        Compute the immediate‑dominator map (block_id → idom_id).

        Uses the classic iterative algorithm from Cooper, Harvey & Kennedy.
        """
        rpo_order = self.rpo()
        if not rpo_order:
            return {}

        rpo_index: Dict[int, int] = {bid: i for i, bid in enumerate(rpo_order)}
        idom: Dict[int, int] = {self.entry_id: self.entry_id}

        def intersect(b1: int, b2: int) -> int:
            finger1, finger2 = b1, b2
            while finger1 != finger2:
                while rpo_index.get(finger1, 0) > rpo_index.get(finger2, 0):
                    finger1 = idom.get(finger1, finger1)
                while rpo_index.get(finger2, 0) > rpo_index.get(finger1, 0):
                    finger2 = idom.get(finger2, finger2)
            return finger1

        changed = True
        while changed:
            changed = False
            for bid in rpo_order:
                if bid == self.entry_id:
                    continue
                preds = [p for p in self.blocks[bid].preds if p in idom]
                if not preds:
                    continue
                new_idom = preds[0]
                for p in preds[1:]:
                    new_idom = intersect(new_idom, p)
                if idom.get(bid) != new_idom:
                    idom[bid] = new_idom
                    changed = True

        return idom

    def dominates(self, a: int, b: int) -> bool:
        """Return True if block *a* dominates block *b*."""
        idom = self.dominators()
        cur = b
        while cur != self.entry_id:
            if cur == a:
                return True
            parent = idom.get(cur)
            if parent is None or parent == cur:
                break
            cur = parent
        return cur == a

    # ---- utility ---------------------------------------------------------

    def pretty(self) -> str:
        """Return a human‑readable representation of the CFG."""
        lines: List[str] = [f"CFG for {self.func_name} ({self.language}):"]
        for bid in self.rpo():
            blk = self.blocks[bid]
            label = f"  [{blk.label}]" if blk.label else ""
            lines.append(f"  BB{bid}{label}:")
            for s in blk.stmts:
                lines.append(f"    L{s.line}: {s.kind:<8s} {s.text[:80]}")
            lines.append(f"    → {blk.succs}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# CFG Builder
# ---------------------------------------------------------------------------

# Statement‑level AST node types that split control flow
_BRANCH_TYPES = {
    "if_statement", "if_expression",
    "switch_statement", "switch_expression", "match_expression",
    "conditional_expression", "ternary_expression",
}

_LOOP_TYPES = {
    "for_statement", "for_range_loop", "enhanced_for_statement",
    "for_in_statement", "foreach_statement",
    "while_statement", "while_expression",
    "do_statement", "do_while_statement",
    "repeat_while_statement",
    "loop_expression",  # Rust loop {}
    "for_expression",
}

_JUMP_TYPES = {
    "return_statement", "return_expression",
    "break_statement", "continue_statement",
    "goto_statement",
    "throw_statement", "raise_statement",
}

_TRY_TYPES = {
    "try_statement", "try_expression",
}

_COMPOUND_TYPES = {
    "compound_statement", "block", "statement_block",
    "expression_statement",
}


class CFGBuilder:
    """
    Build a :class:`CFG` from a tree‑sitter AST of a single function body.
    """

    def __init__(self, language: str):
        self.language = language
        self._queries = ASTQueries(language)

    # ==== public API ======================================================

    def build_for_function(self, func_node: TSNode) -> CFG:
        """Build a CFG for one function definition AST node."""
        cfg = CFG(language=self.language)
        cfg.func_name = self._queries.function_name(func_node)

        # Entry & exit sentinels
        entry = BasicBlock(label="ENTRY")
        exit_b = BasicBlock(label="EXIT")
        cfg.blocks[entry.id] = entry
        cfg.blocks[exit_b.id] = exit_b
        cfg.entry_id = entry.id
        cfg.exit_id = exit_b.id

        # Find the function body
        body = func_node.child_by_field("body")
        if body is None:
            # Some grammars don't use 'body' field
            for c in func_node.named_children:
                if c.type in ("compound_statement", "block", "statement_block",
                              "function_body", "expression_list"):
                    body = c
                    break
        if body is None:
            # Single‑expression body (e.g., arrow functions)
            body = func_node

        first_block = BasicBlock()
        cfg.blocks[first_block.id] = first_block
        self._link(entry, first_block)

        # Recursively process the body
        last_blocks = self._process_node(body, first_block, cfg, exit_b)

        # Link any remaining open blocks to EXIT
        for blk in last_blocks:
            if exit_b.id not in blk.succs:
                self._link(blk, exit_b)

        # Clean up unreachable / empty blocks
        self._cleanup(cfg)

        return cfg

    def build_for_file(self, root: TSNode) -> List[CFG]:
        """Build CFGs for every function in the file."""
        funcs = self._queries.find_functions(root)
        cfgs: List[CFG] = []
        for fn in funcs:
            try:
                cfgs.append(self.build_for_function(fn))
            except Exception:
                pass  # skip functions that fail to parse
        return cfgs

    # ==== internal ========================================================

    def _link(self, src: BasicBlock, dst: BasicBlock) -> None:
        if dst.id not in src.succs:
            src.succs.append(dst.id)
        if src.id not in dst.preds:
            dst.preds.append(src.id)

    def _make_stmt(self, node: TSNode) -> Statement:
        """Wrap an AST node into a :class:`Statement` with def/use info."""
        kind = self._classify(node)
        stmt = Statement(
            node=node, kind=kind, line=node.start_line,
            text=node.text[:200],
        )
        # Extract defs / uses
        if kind == "assign":
            lhs, rhs = self._queries.extract_lhs_rhs(node)
            if lhs:
                stmt.defs.add(lhs)
            if rhs:
                stmt.uses = self._queries.get_identifiers_in(rhs) - stmt.defs
        elif kind == "call":
            stmt.uses = self._queries.get_identifiers_in(node)
        elif kind == "return":
            stmt.uses = self._queries.get_identifiers_in(node)
        elif kind == "decl":
            # Variable declarations  — first identifier is the defined var
            ids = list(self._queries.get_identifiers_in(node))
            if ids:
                stmt.defs.add(ids[0])
                stmt.uses = set(ids[1:])
        else:
            stmt.uses = self._queries.get_identifiers_in(node)
        return stmt

    def _classify(self, node: TSNode) -> str:
        assign_types = self._queries._ASSIGN_TYPES.get(self.language, set())
        call_types = self._queries._CALL_TYPES.get(self.language, set())
        if node.type in assign_types:
            return "assign"
        if node.type in call_types:
            return "call"
        if node.type in ("return_statement", "return_expression"):
            return "return"
        if node.type in ("declaration", "local_variable_declaration",
                         "let_declaration", "variable_declaration",
                         "var_declaration", "short_var_declaration",
                         "lexical_declaration", "const_declaration"):
            return "decl"
        return "expr"

    # ---- recursive node processing --------------------------------------

    def _process_node(
        self, node: TSNode, cur_block: BasicBlock,
        cfg: CFG, exit_block: BasicBlock,
        break_target: Optional[BasicBlock] = None,
        continue_target: Optional[BasicBlock] = None,
    ) -> List[BasicBlock]:
        """
        Recursively process *node*, appending statements to *cur_block* and
        creating new blocks for branches / loops.

        Returns the list of blocks that are "open" (fall‑through) at the end.
        """

        # -- compound / block nodes: process children sequentially ----------
        if node.type in ("compound_statement", "block", "statement_block",
                         "program", "module", "translation_unit",
                         "source_file", "function_body", "expression_list"):
            blocks = [cur_block]
            for child in node.named_children:
                next_blocks: List[BasicBlock] = []
                for b in blocks:
                    next_blocks.extend(
                        self._process_node(child, b, cfg, exit_block,
                                           break_target, continue_target)
                    )
                blocks = next_blocks
                if not blocks:
                    break
            return blocks

        # -- expression_statement: unwrap and process inner node -----------
        if node.type == "expression_statement":
            for child in node.named_children:
                return self._process_node(child, cur_block, cfg, exit_block,
                                          break_target, continue_target)
            return [cur_block]

        # -- if / else : split into true / false branches ------------------
        if node.type in _BRANCH_TYPES and node.type not in (
            "conditional_expression", "ternary_expression",
            "switch_statement", "switch_expression", "match_expression",
        ):
            return self._process_if(node, cur_block, cfg, exit_block,
                                     break_target, continue_target)

        # -- switch / match -----------------------------------------------
        if node.type in ("switch_statement", "switch_expression",
                         "match_expression"):
            return self._process_switch(node, cur_block, cfg, exit_block,
                                         break_target, continue_target)

        # -- loops ---------------------------------------------------------
        if node.type in _LOOP_TYPES:
            return self._process_loop(node, cur_block, cfg, exit_block)

        # -- return / throw ------------------------------------------------
        if node.type in ("return_statement", "return_expression",
                         "throw_statement", "raise_statement"):
            cur_block.stmts.append(self._make_stmt(node))
            self._link(cur_block, exit_block)
            return []  # no fall‑through

        # -- break / continue ----------------------------------------------
        if node.type == "break_statement":
            if break_target:
                self._link(cur_block, break_target)
            return []

        if node.type == "continue_statement":
            if continue_target:
                self._link(cur_block, continue_target)
            return []

        # -- try / catch ---------------------------------------------------
        if node.type in _TRY_TYPES:
            return self._process_try(node, cur_block, cfg, exit_block,
                                      break_target, continue_target)

        # -- default: treat as a single statement --------------------------
        cur_block.stmts.append(self._make_stmt(node))
        return [cur_block]

    # ---- if / else -------------------------------------------------------

    def _process_if(
        self, node: TSNode, cur_block: BasicBlock,
        cfg: CFG, exit_block: BasicBlock,
        break_target: Optional[BasicBlock],
        continue_target: Optional[BasicBlock],
    ) -> List[BasicBlock]:
        # Condition goes into cur_block
        cond = node.child_by_field("condition")
        if cond:
            cond_stmt = self._make_stmt(cond)
            cond_stmt.kind = "cond"
            cur_block.stmts.append(cond_stmt)

        # True branch
        true_block = BasicBlock(label="if_true")
        cfg.blocks[true_block.id] = true_block
        self._link(cur_block, true_block)

        consequence = node.child_by_field("consequence") or node.child_by_field("body")
        if consequence is None:
            # pick the first compound/block child after the condition
            for c in node.named_children:
                if c.type in ("compound_statement", "block", "statement_block"):
                    consequence = c
                    break
        open_true = [true_block]
        if consequence:
            open_true = self._process_node(consequence, true_block, cfg,
                                           exit_block, break_target, continue_target)

        # False (else) branch
        open_false: List[BasicBlock] = []
        alternative = node.child_by_field("alternative")
        if alternative is None:
            # Some grammars use an "else_clause" child
            for c in node.named_children:
                if c.type in ("else_clause", "else"):
                    alternative = c
                    break

        if alternative:
            false_block = BasicBlock(label="if_false")
            cfg.blocks[false_block.id] = false_block
            self._link(cur_block, false_block)
            open_false = self._process_node(alternative, false_block, cfg,
                                            exit_block, break_target, continue_target)
        else:
            # No else — cur_block itself falls through
            fall = BasicBlock(label="if_join_noelse")
            cfg.blocks[fall.id] = fall
            self._link(cur_block, fall)
            open_false = [fall]

        # Join
        join = BasicBlock(label="if_join")
        cfg.blocks[join.id] = join
        for b in open_true + open_false:
            self._link(b, join)

        return [join]

    # ---- switch / match --------------------------------------------------

    def _process_switch(
        self, node: TSNode, cur_block: BasicBlock,
        cfg: CFG, exit_block: BasicBlock,
        break_target: Optional[BasicBlock],
        continue_target: Optional[BasicBlock],
    ) -> List[BasicBlock]:
        after_block = BasicBlock(label="switch_after")
        cfg.blocks[after_block.id] = after_block

        # Each case / arm is a branch from cur_block
        open_ends: List[BasicBlock] = []
        has_default = False
        for child in node.named_children:
            if child.type in ("switch_case", "case_clause", "match_arm",
                              "default_case", "switch_default"):
                case_block = BasicBlock(label="case")
                cfg.blocks[case_block.id] = case_block
                self._link(cur_block, case_block)
                open = self._process_node(child, case_block, cfg, exit_block,
                                          after_block, continue_target)
                open_ends.extend(open)
                if child.type in ("default_case", "switch_default"):
                    has_default = True

        if not has_default:
            # Implicit fall‑through when no default
            self._link(cur_block, after_block)

        for b in open_ends:
            self._link(b, after_block)

        return [after_block]

    # ---- loops -----------------------------------------------------------

    def _process_loop(
        self, node: TSNode, cur_block: BasicBlock,
        cfg: CFG, exit_block: BasicBlock,
    ) -> List[BasicBlock]:
        header = BasicBlock(label="loop_header")
        body_block = BasicBlock(label="loop_body")
        after = BasicBlock(label="loop_after")
        for b in (header, body_block, after):
            cfg.blocks[b.id] = b

        # cur → header
        self._link(cur_block, header)

        # Condition (if any) goes into header
        cond = node.child_by_field("condition") or node.child_by_field("update")
        if cond:
            cond_stmt = self._make_stmt(cond)
            cond_stmt.kind = "cond"
            header.stmts.append(cond_stmt)

        # header → body (true), header → after (false)
        self._link(header, body_block)
        self._link(header, after)

        # Process body
        body_ast = node.child_by_field("body")
        if body_ast is None:
            for c in node.named_children:
                if c.type in ("compound_statement", "block", "statement_block",
                              "for_body"):
                    body_ast = c
                    break
        if body_ast:
            open_ends = self._process_node(body_ast, body_block, cfg,
                                           exit_block,
                                           break_target=after,
                                           continue_target=header)
        else:
            open_ends = [body_block]

        # Back‑edge: open ends → header
        for b in open_ends:
            self._link(b, header)

        return [after]

    # ---- try / catch -----------------------------------------------------

    def _process_try(
        self, node: TSNode, cur_block: BasicBlock,
        cfg: CFG, exit_block: BasicBlock,
        break_target: Optional[BasicBlock],
        continue_target: Optional[BasicBlock],
    ) -> List[BasicBlock]:
        after = BasicBlock(label="try_after")
        cfg.blocks[after.id] = after

        open_ends: List[BasicBlock] = []

        # Try body
        try_body = node.child_by_field("body")
        if try_body:
            try_block = BasicBlock(label="try_body")
            cfg.blocks[try_block.id] = try_block
            self._link(cur_block, try_block)
            open_ends.extend(
                self._process_node(try_body, try_block, cfg, exit_block,
                                   break_target, continue_target)
            )

        # Catch / except handlers
        for child in node.named_children:
            if child.type in ("catch_clause", "except_clause", "rescue",
                              "handler"):
                catch_block = BasicBlock(label="catch")
                cfg.blocks[catch_block.id] = catch_block
                self._link(cur_block, catch_block)    # exception edge
                open_ends.extend(
                    self._process_node(child, catch_block, cfg, exit_block,
                                       break_target, continue_target)
                )

        # Finally
        for child in node.named_children:
            if child.type in ("finally_clause", "ensure"):
                finally_block = BasicBlock(label="finally")
                cfg.blocks[finally_block.id] = finally_block
                new_open: List[BasicBlock] = []
                for b in open_ends:
                    self._link(b, finally_block)
                new_open = self._process_node(child, finally_block, cfg,
                                              exit_block, break_target,
                                              continue_target)
                open_ends = new_open

        for b in open_ends:
            self._link(b, after)

        return [after]

    # ---- cleanup ---------------------------------------------------------

    def _cleanup(self, cfg: CFG) -> None:
        """Remove unreachable and empty pass‑through blocks."""
        # Mark reachable
        reachable: Set[int] = set()
        queue = deque([cfg.entry_id])
        while queue:
            bid = queue.popleft()
            if bid in reachable:
                continue
            reachable.add(bid)
            for s in cfg.blocks[bid].succs:
                queue.append(s)

        # Remove unreachable
        for bid in list(cfg.blocks.keys()):
            if bid not in reachable:
                del cfg.blocks[bid]

        # Fix pred lists after removal
        for blk in cfg.blocks.values():
            blk.preds = [p for p in blk.preds if p in cfg.blocks]
            blk.succs = [s for s in blk.succs if s in cfg.blocks]


# ---------------------------------------------------------------------------
# Convenience helper
# ---------------------------------------------------------------------------

def build_cfgs(root: TSNode, language: str) -> List[CFG]:
    """Build CFGs for all functions in the parsed AST *root*."""
    builder = CFGBuilder(language)
    return builder.build_for_file(root)
