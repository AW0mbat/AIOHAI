"""
Content Analysis — Sanitization, PII protection, static analysis.

Submodules:
- sanitizer: Content sanitization, injection detection, trust levels
- pii_protector: PII detection and redaction
- static_analyzer: Bandit-style static analysis, sensitive operation detection
- multi_stage: Multi-stage attack pattern detection

Classes:
- ContentSanitizer: Injection scanning, Unicode normalization, trust levels
- PIIProtector: Redact emails, SSNs, phone numbers, IPs
- StaticSecurityAnalyzer: Bandit-style static analysis of generated code
- SensitiveOperationDetector: Categorize and flag sensitive operations
- MultiStageDetector: Detect reconnaissance → weaponization → execution chains
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
    SensitiveOperationDetector,
    Severity,
    Verdict,
    SecurityFinding,
)

from aiohai.core.analysis.multi_stage import (
    MultiStageDetector,
)

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
    
    # Multi-stage
    'MultiStageDetector',
]
