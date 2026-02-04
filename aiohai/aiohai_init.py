"""
AIOHAI — AI-Operated Home & Office Intelligence Proxy

A layered security architecture for local AI agents:

- core/        : Accessor-agnostic trust infrastructure (HSM, FIDO2, validation, logging)
- integrations/: Domain-specific adapters (Home Assistant, Office/Graph)
- proxy/       : AI-specific enforcement (action parsing, LLM context, execution)
- agent/       : Future: Screen capture, supervised browsing, progressive trust

Version is defined in aiohai.core.version (single source of truth).
"""

from aiohai.core.version import __version__

__all__ = ['__version__']
