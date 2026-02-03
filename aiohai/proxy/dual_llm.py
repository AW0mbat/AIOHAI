#!/usr/bin/env python3
"""Dual LLM Verifier - Secondary LLM safety assessment."""
import logging
logger = logging.getLogger("aiohai.proxy.dual_llm")

try:
    from security.security_components import DualLLMVerifier
except ImportError:
    class DualLLMVerifier:
        def __init__(self, config): raise ImportError("Requires security_components")

__all__ = ['DualLLMVerifier']
