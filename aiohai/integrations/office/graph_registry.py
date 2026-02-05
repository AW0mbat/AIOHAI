#!/usr/bin/env python3
"""
AIOHAI Integrations — Office Graph API Registry
=================================================
Security gateway for Microsoft Graph API requests.

Validates endpoints against allow/block lists, enforces scope restrictions,
and applies tier-based approval requirements.

Tier mapping to FIDO2 ApprovalTier:
  standard → TIER_2 (software approval)
  elevated → TIER_2 (software approval)
  critical → TIER_3 (hardware FIDO2 approval required)
  blocked  → rejected (no approval possible)

Follows the same pattern as LocalServiceRegistry for consistency.

Previously defined in proxy/aiohai_proxy.py.
Extracted as Phase 4b of the monolith → layered architecture migration.

Import from: aiohai.integrations.office.graph_registry
"""

import re
from typing import Dict, List, Set, Tuple

from aiohai.core.types import AlertSeverity
from aiohai.core.audit.logger import SecurityLogger
from aiohai.core.patterns import BLOCKED_GRAPH_ENDPOINTS, BLOCKED_GRAPH_SCOPES


class GraphAPIRegistry:
    """
    Security gateway for Microsoft Graph API requests.

    Validates endpoints against allow/block lists, enforces scope restrictions,
    and applies tier-based approval requirements.

    Tier mapping to FIDO2 ApprovalTier:
      standard → TIER_2 (software approval)
      elevated → TIER_2 (software approval)
      critical → TIER_3 (hardware FIDO2 approval required)
      blocked  → rejected (no approval possible)

    Follows the same pattern as LocalServiceRegistry for consistency.
    """

    # Mapping from Graph API tiers to FIDO2 approval tiers
    GRAPH_TO_FIDO2_TIER = {
        'standard': 'TIER_2',
        'elevated': 'TIER_2',
        'critical': 'TIER_3',
    }

    # Tier definitions for Graph API operations
    GRAPH_TIERS = {
        'standard': [
            'GET /me/drive/root/children',
            'GET /me/drive/search',
            'GET /me/drive/items/*/children',
            'GET /me/profile',
        ],
        'elevated': [
            'GET /me/drive/items/*/content',
            'GET /me/drive/root:/*:/content',
            'GET /me/messages',
            'GET /me/calendar/events',
        ],
        'critical': [
            'PUT /me/drive/items/*/content',
            'POST /me/drive/root/children',
            'PATCH /me/drive/items/*',
        ],
    }

    def __init__(self, logger: SecurityLogger, config: Dict = None):
        self.logger = logger
        self._config = config or {}
        self._blocked_patterns = [re.compile(p) for p in BLOCKED_GRAPH_ENDPOINTS]
        self._allowed_scopes = set(self._config.get('scopes', []))
        self._blocked_scopes = BLOCKED_GRAPH_SCOPES

    def validate_request(self, method: str, endpoint: str,
                         token_scopes: Set[str] = None) -> Tuple[bool, str, str]:
        """
        Validate a Graph API request.

        Returns:
            (allowed, tier_or_reason, service_name)
            tier is the FIDO2-mapped tier name (TIER_2, TIER_3) for approved requests
        """
        # 1. Check blocked endpoints
        for pattern in self._blocked_patterns:
            if pattern.search(endpoint):
                self.logger.log_event("GRAPH_API_BLOCKED", AlertSeverity.HIGH,
                                      {'method': method, 'endpoint': endpoint[:100],
                                       'reason': 'Blocked endpoint'})
                return False, f"Endpoint blocked: {endpoint}", ''

        # 2. Check token scopes
        if token_scopes:
            dangerous = token_scopes & self._blocked_scopes
            if dangerous:
                self.logger.log_event("GRAPH_API_SCOPE_BLOCKED", AlertSeverity.HIGH,
                                      {'blocked_scopes': list(dangerous)})
                return False, f"Token has blocked scopes: {', '.join(dangerous)}", ''

        # 3. Determine tier and map to FIDO2
        graph_tier = self._get_tier(method, endpoint)
        fido2_tier = self.GRAPH_TO_FIDO2_TIER.get(graph_tier, 'TIER_2')

        return True, fido2_tier, 'graph_api'

    def _get_tier(self, method: str, endpoint: str) -> str:
        """Classify a Graph API request into a tier."""
        request_str = f"{method.upper()} {endpoint}"

        for tier, patterns in self.GRAPH_TIERS.items():
            for pattern in patterns:
                # Convert simple patterns to regex
                regex = pattern.replace('*', '[^/]+')
                if re.match(regex, request_str, re.I):
                    return tier

        return 'elevated'  # Default to elevated for unknown endpoints

    def validate_scopes(self, token_scopes: Set[str]) -> Tuple[bool, List[str]]:
        """
        Check if a token's scopes are safe to use.

        Returns:
            (safe, list_of_blocked_scopes_found)
        """
        dangerous = token_scopes & self._blocked_scopes
        return len(dangerous) == 0, list(dangerous)


__all__ = ['GraphAPIRegistry']
