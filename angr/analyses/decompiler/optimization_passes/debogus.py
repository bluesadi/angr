import logging

import ailment
from ailment import Expr, Block
from ailment.expression import Load, Const
from ailment.statement import ConditionalJump, Statement, Jump
from unique_log_filter import UniqueLogFilter

from .engine_base import SimplifierAILEngine, SimplifierAILState
from .optimization_pass import OptimizationPass, OptimizationPassStage
from ..ailgraph_walker import AILGraphWalker

_l = logging.getLogger(name=__name__)
_l.addFilter(UniqueLogFilter())


class DebogusAILBlockWalker(ailment.AILBlockWalker):

    def __init__(self):
        super().__init__()
        self.is_bogus = False

    def _handle_Load(self, expr_idx: int, expr: Load, stmt_idx: int, stmt: Statement, block: Block | None):
        if isinstance(expr.addr, ailment.Expr.Const):
            self.is_bogus = True
            # pass
        if stmt.ins_addr == 0x40119b:
            self.is_bogus = True


class Debogus(OptimizationPass):
    """
    Revert bogus control flow obfuscation
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Revert bogus control flow obfuscation"
    DESCRIPTION = __doc__.strip()

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)

        self.analyze()

    def _check(self):
        return True, None

    def _analyze(self, cache=None):
        # return
        removed = set()
        print([hex(block.addr) for block in self._graph.nodes])
        for block in list(self._graph.nodes()):
            if len(block.statements) and block not in removed:
                stmt = block.statements[-1]
                if isinstance(stmt, ConditionalJump):
                    walker = DebogusAILBlockWalker()
                    walker._handle_expr(0, stmt.condition, stmt.idx, stmt, None)
                    if walker.is_bogus:
                        block.statements[-1] = Jump(
                            stmt.idx,
                            stmt.true_target,
                            stmt.true_target_idx,
                            ins_addr=stmt.ins_addr,
                        )
                        addr = stmt.true_target.value if isinstance(stmt.true_target, Const) else None
                        for succ in list(self._graph.successors(block)):
                            if succ.addr != addr:
                                self._remove_block(succ)
                                removed.add(succ)
        update = True
        while update:
            update = False
            for block in list(self._graph.nodes()):
                if block in removed:
                    continue
                if len(list(self._graph.predecessors(block))) == 0 and block.addr != self._func.addr:
                    self._remove_block(block)
                    update = True
                    removed.add(block)
