"""Shared analysis utilities used by multiple modules."""

import re


def is_obfuscated(text: str) -> bool:
    """Detect obfuscated commands/scripts using heuristic indicators.

    Returns True if 2+ obfuscation indicators are found:
    - High special character density (>15%)
    - String concatenation patterns
    - Variable assignment + string patterns
    - PowerShell char/int casting with -join
    - Excessive caret escaping (>5)
    - Long base64-like strings (40+ chars)
    """
    if len(text) < 20:
        return False
    indicators = 0
    special = len(re.findall(r'[`$\[\]{}()\\^]', text))
    if len(text) > 0 and special / len(text) > 0.15:
        indicators += 1
    if re.search(r'["\'][^"\']{1,10}["\']\s*\+\s*["\']', text):
        indicators += 1
    if re.search(r'\$\w+\s*=\s*["\'].*["\']\s*;', text):
        indicators += 1
    if re.search(r'\[char\]|\[int\].*-join', text, re.I):
        indicators += 1
    if text.count('^') > 5:
        indicators += 1
    if re.search(r'[A-Za-z0-9+/]{40,}={0,2}', text):
        indicators += 1
    return indicators >= 2


__all__ = ['is_obfuscated']
