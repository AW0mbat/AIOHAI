#!/usr/bin/env python3
"""
AIOHAI Core Crypto — Operation Classifier
==========================================
Classifies operations into security tiers (TIER 1-4) based on
action type, target path, and content context.

Used by the approval pipeline to determine what level of
authentication is required before an action can proceed.

Previously defined inline in security/fido2_approval.py.
Extracted as Phase 3 of the monolith → layered architecture migration.

Import from: aiohai.core.crypto.classifier
"""

import re

from aiohai.core.types import ApprovalTier, UserRole


class OperationClassifier:
    """Classifies operations into security tiers."""

    TIER_3_OPS = {'DELETE', 'WRITE_SENSITIVE', 'BULK_OPERATION',
                  'COMMAND_ELEVATED', 'CONFIG_MODIFY'}
    TIER_4_OPS = {'POLICY_MODIFY', 'HSM_MANAGEMENT', 'USER_MANAGEMENT',
                  'SECURITY_DISABLE'}

    SENSITIVE_PATTERNS = [
        r'(?i)\.ssh', r'(?i)\.gnupg', r'(?i)credentials', r'(?i)secrets?',
        r'(?i)password', r'(?i)\.env', r'(?i)private[_\-]?key', r'(?i)token',
        r'(?i)financial', r'(?i)tax', r'(?i)bank', r'(?i)medical',
        r'(?i)health', r'(?i)identity', r'(?i)passport', r'(?i)ssn',
    ]

    # Office document patterns that escalate to TIER_3 (sensitive content context)
    SENSITIVE_DOC_PATTERNS = [
        r'(?i)payroll', r'(?i)salary', r'(?i)employee', r'(?i)personnel',
        r'(?i)hr[_\-\s]', r'(?i)human.?resources', r'(?i)performance.?review',
        r'(?i)medical', r'(?i)health', r'(?i)insurance', r'(?i)benefits',
        r'(?i)tax', r'(?i)financial', r'(?i)budget', r'(?i)invoice',
        r'(?i)contract', r'(?i)legal', r'(?i)nda', r'(?i)confidential',
        r'(?i)customer.?list', r'(?i)client.?data', r'(?i)account',
    ]

    # Action types explicitly classified as Tier 1 (auto-execute eligible)
    TIER_1_OPS = {'LIST', 'READ', 'API_QUERY'}

    # Action types explicitly classified as Tier 2 (software approval)
    TIER_2_OPS = {'WRITE', 'COMMAND', 'DOCUMENT_OP'}

    @classmethod
    def classify(cls, action_type: str, target: str = "",
                 content: str = "") -> ApprovalTier:
        """Classify an operation into a security tier.
        
        Args:
            action_type: The type of operation (e.g. DELETE, WRITE, COMMAND)
            target: The target path or resource
            content: Optional content for context-aware classification
            
        Returns:
            ApprovalTier indicating required approval level.
            Unknown action types default to TIER_3 (fail closed).
        """
        if action_type in cls.TIER_4_OPS:
            return ApprovalTier.TIER_4
        if action_type in cls.TIER_3_OPS or action_type == 'DELETE':
            return ApprovalTier.TIER_3

        # Path-based escalation: sensitive targets → TIER_3 regardless of action type
        if target:
            for pattern in cls.SENSITIVE_PATTERNS:
                if re.search(pattern, target):
                    return ApprovalTier.TIER_3

        # DOCUMENT_OP: minimum TIER_2, escalate to TIER_3 for sensitive doc names
        if action_type == 'DOCUMENT_OP':
            if target:
                for pattern in cls.SENSITIVE_DOC_PATTERNS:
                    if re.search(pattern, target):
                        return ApprovalTier.TIER_3
            return ApprovalTier.TIER_2

        if action_type in cls.TIER_2_OPS:
            return ApprovalTier.TIER_2
        if action_type in cls.TIER_1_OPS:
            return ApprovalTier.TIER_1

        # Unknown action type — fail closed, require FIDO2 approval
        return ApprovalTier.TIER_3

    @classmethod
    def get_required_role(cls, tier: ApprovalTier,
                          target: str = "") -> UserRole:
        """Get the minimum user role required to approve a given tier.
        
        Args:
            tier: The approval tier
            target: Optional target for path-based restrictions
            
        Returns:
            UserRole minimum required for approval
        """
        if tier == ApprovalTier.TIER_4:
            return UserRole.ADMIN
        elif tier == ApprovalTier.TIER_3:
            return UserRole.TRUSTED_ADULT
        elif tier == ApprovalTier.TIER_2:
            return UserRole.RESTRICTED
        return UserRole.GUEST

    @classmethod
    def get_required_authenticator(cls, tier: ApprovalTier) -> str:
        """Get the required authenticator type for a given tier.

        Tier 3: Any FIDO2 authenticator (platform biometric or roaming key)
        Tier 4: Roaming hardware key only (YubiKey/Nitrokey physical tap)

        Returns:
            'any' for Tier 3 (platform or roaming), 'security_key' for Tier 4
        """
        if tier == ApprovalTier.TIER_4:
            return 'security_key'
        return 'any'


__all__ = ['OperationClassifier']
