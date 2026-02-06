"""
AIOHAI Proxy — AI-Specific Enforcement Layer

This layer sits between Open WebUI and Ollama, intercepting all requests
and responses. It consumes Core and Integrations to enforce security policy.

Classes:
- UnifiedProxyHandler: HTTP request handler
- UnifiedSecureProxy: Main orchestrator (startup, component wiring)
- SecureExecutor: Sandboxed file/command execution
- ActionParser: Parse <action> blocks from LLM responses
- ApprovalManager: Action approval lifecycle management
- OllamaCircuitBreaker: Prevent thread exhaustion when Ollama is down
- StartupSecurityVerifier: Pre-flight security checks
- DualLLMVerifier: Secondary LLM safety assessment
"""

from aiohai.proxy.server import ThreadedHTTPServer
from aiohai.proxy.handler import UnifiedProxyHandler
from aiohai.proxy.orchestrator import UnifiedSecureProxy
from aiohai.proxy.action_parser import ActionParser
from aiohai.proxy.approval import ApprovalManager
from aiohai.proxy.executor import SecureExecutor
from aiohai.proxy.circuit_breaker import OllamaCircuitBreaker
from aiohai.core.audit.startup import StartupSecurityVerifier
from aiohai.proxy.dual_llm import DualLLMVerifier

__all__ = [
    'ThreadedHTTPServer',
    'UnifiedProxyHandler',
    'UnifiedSecureProxy',
    'ActionParser',
    'ApprovalManager',
    'SecureExecutor',
    'OllamaCircuitBreaker',
    'StartupSecurityVerifier',
    'DualLLMVerifier',
]
