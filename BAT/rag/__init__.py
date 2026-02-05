"""
BAT RAG Module

Contains components for:
- Knowledge base management (CWE, CERT C)
- Retrieval for grounded explanations
"""

from .retriever import KnowledgeRetriever, SecurityKnowledge

__all__ = ['KnowledgeRetriever', 'SecurityKnowledge']
