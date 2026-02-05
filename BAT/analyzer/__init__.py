"""
BAT Analyzer Module

Contains components for:
- AST parsing using libclang
- Taint analysis engine
- Lifetime checking for UAF detection
- Buffer overflow checking
"""

from .ast_parser import ASTParser, FunctionInfo, CallInfo
from .taint_engine import TaintEngine, TaintSource, TaintSink
from .lifetime_checker import LifetimeChecker, LifetimeEvent
from .overflow_checker import OverflowChecker, BufferInfo

__all__ = [
    'ASTParser', 'FunctionInfo', 'CallInfo',
    'TaintEngine', 'TaintSource', 'TaintSink',
    'LifetimeChecker', 'LifetimeEvent',
    'OverflowChecker', 'BufferInfo'
]
