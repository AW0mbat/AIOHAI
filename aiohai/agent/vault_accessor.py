"""
Vault Accessor — Future: Secure credential retrieval.

This module will provide:
- Interface to the Vault system for credential retrieval
- FIDO2 approval always required (regardless of accessor)
- Credentials provided to LLM in secure memory, wiped on next turn
- Category-based access rules (passwords, health, financial, identity)

Core services consumed:
- core.crypto.fido_gate.FIDO2ApprovalClient
- core.crypto.hsm_bridge (for key derivation)
- Future: core.vault.VaultManager

Status: PLACEHOLDER
"""

# Placeholder - implementation is future work
