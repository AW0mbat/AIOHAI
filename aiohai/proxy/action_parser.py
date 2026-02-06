#!/usr/bin/env python3
"""
Action Parser — Parse <action> XML blocks from LLM responses.

Extracts structured action requests from LLM output text.
Each action has a type, optional target, and content body.

Phase 5 extraction from proxy/aiohai_proxy.py.
"""

import re
from typing import Dict, List

__all__ = ['ActionParser']


class ActionParser:
    """Parse <action type="..." target="...">content</action> blocks from LLM responses."""

    PATTERN = re.compile(
        r'<action\s+type="(\w+)"(?:\s+target="([^"]*)")?>(.*?)</action>',
        re.DOTALL | re.IGNORECASE
    )

    @staticmethod
    def parse(response: str) -> List[Dict]:
        """Extract all action blocks from a response string.

        Returns a list of dicts with keys: type, target, content, raw.
        """
        actions = []
        for match in ActionParser.PATTERN.finditer(response):
            actions.append({
                'type': match.group(1).upper(),
                'target': match.group(2) or "",
                'content': match.group(3).strip(),
                'raw': match.group(0)
            })
        return actions

    @staticmethod
    def strip_actions(response: str) -> str:
        """Remove all action blocks from a response, returning clean text."""
        return ActionParser.PATTERN.sub('', response).strip()
