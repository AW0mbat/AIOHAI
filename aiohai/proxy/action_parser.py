#!/usr/bin/env python3
"""
Action Parser — Parse <action> XML blocks from LLM responses.

Extracts structured action requests from LLM output text.
Each action has a type, optional target, and content body.

Phase 1B: Enhanced to extract richer target info and compute taxonomy
classification (ActionCategory, TargetDomain, ApprovalLevel) for each
parsed action.

Phase 5 extraction from proxy/aiohai_proxy.py.
"""

import re
from typing import Dict, List, Optional

from aiohai.core.types import (
    ActionCategory, TargetDomain, ApprovalLevel, SecurityGate,
)
from aiohai.core.access.target_classifier import TargetClassifier
from aiohai.core.access.tier_matrix import TIER_MATRIX

__all__ = ['ActionParser']


class ActionParser:
    """Parse <action type="..." target="...">content</action> blocks from LLM responses.

    Phase 1B enhancement: each parsed action dict now includes taxonomy fields:
    - 'category': ActionCategory enum
    - 'domain': TargetDomain enum
    - 'approval_level': ApprovalLevel enum
    - 'gate': SecurityGate enum
    - 'hint': str classification hint derived from action type
    """

    PATTERN = re.compile(
        r'<action\s+type="(\w+)"(?:\s+target="([^"]*)")?>(.*?)</action>',
        re.DOTALL | re.IGNORECASE
    )

    # Map legacy action type strings to classification hints
    _HINT_MAP = {
        'READ': 'file', 'WRITE': 'file', 'DELETE': 'file', 'LIST': 'file',
        'FILE_READ': 'file', 'FILE_WRITE': 'file',
        'FILE_DELETE': 'file', 'DIRECTORY_LIST': 'file',
        'COMMAND': 'command', 'COMMAND_EXEC': 'command',
        'API_QUERY': 'api', 'LOCAL_API_QUERY': 'api',
        'DOCUMENT_OP': 'office',
    }

    @staticmethod
    def parse(response: str) -> List[Dict]:
        """Extract all action blocks from a response string.

        Returns a list of dicts with keys:
            type, target, content, raw — original fields
            category, domain, approval_level, gate, hint — taxonomy fields
        """
        actions = []
        for match in ActionParser.PATTERN.finditer(response):
            action_type = match.group(1).upper()
            target = match.group(2) or ""
            content = match.group(3).strip()

            # Classify using the taxonomy pipeline
            category = ActionCategory.from_legacy_action_type(action_type)
            hint = ActionParser._HINT_MAP.get(action_type)
            domain = TargetClassifier.classify(
                target, hint=hint, action_type=action_type)
            approval_level = TIER_MATRIX.lookup(category, domain)

            actions.append({
                'type': action_type,
                'target': target,
                'content': content,
                'raw': match.group(0),
                # Taxonomy fields (Phase 1B)
                'category': category,
                'domain': domain,
                'approval_level': approval_level,
                'gate': approval_level.gate,
                'hint': hint,
            })
        return actions

    @staticmethod
    def classify_action(action_type: str, target: str,
                        content: str = "") -> Dict:
        """Classify a single action into taxonomy fields without parsing XML.

        Useful for re-classifying actions or classifying programmatic actions
        that weren't parsed from LLM output.

        Returns dict with: category, domain, approval_level, gate, hint
        """
        category = ActionCategory.from_legacy_action_type(action_type)
        hint = ActionParser._HINT_MAP.get(action_type)
        domain = TargetClassifier.classify(
            target, hint=hint, action_type=action_type)
        approval_level = TIER_MATRIX.lookup(category, domain)

        return {
            'category': category,
            'domain': domain,
            'approval_level': approval_level,
            'gate': approval_level.gate,
            'hint': hint,
        }

    @staticmethod
    def strip_actions(response: str) -> str:
        """Remove all action blocks from a response, returning clean text."""
        return ActionParser.PATTERN.sub('', response).strip()
