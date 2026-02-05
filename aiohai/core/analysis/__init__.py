"""
Content Analysis — Sanitization, PII protection, static analysis.

Submodules:
- sanitizer: Content sanitization, injection detection, trust levels
- pii_protector: PII detection and redaction
- static_analyzer: Bandit-style static analysis of generated code
- sensitive_ops: Categorize and flag sensitive operations
- credentials: Credential redaction for safe display
- multi_stage: Multi-stage attack pattern detection
"""

from aiohai.core.analysis.sanitizer import (
    ContentSanitizer,
    INJECTION_PATTERNS,
    TrustLevel,
)

from aiohai.core.analysis.pii_protector import (
    PIIProtector,
    PIIType,
    PIIFinding,
)

from aiohai.core.analysis.static_analyzer import (
    StaticSecurityAnalyzer,
    Severity,
    SecurityFinding,
)

from aiohai.core.analysis.sensitive_ops import (
    SensitiveOperationDetector,
)

from aiohai.core.analysis.credentials import (
    CredentialRedactor,
)

from aiohai.core.analysis.multi_stage import (
    MultiStageDetector,
)

# Re-export Verdict from types for backward compat
from aiohai.core.types import Verdict

__all__ = [
    # Sanitizer
    'ContentSanitizer',
    'INJECTION_PATTERNS',
    'TrustLevel',

    # PII
    'PIIProtector',
    'PIIType',
    'PIIFinding',

    # Static analysis
    'StaticSecurityAnalyzer',
    'SensitiveOperationDetector',
    'Severity',
    'Verdict',
    'SecurityFinding',

    # Credentials
    'CredentialRedactor',

    # Multi-stage
    'MultiStageDetector',
]
