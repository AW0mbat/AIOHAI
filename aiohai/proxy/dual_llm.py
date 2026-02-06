#!/usr/bin/env python3
"""
Dual LLM Verifier — Secondary LLM safety assessment.

Uses a separate Ollama model call to audit the primary LLM's proposed actions
before execution. Returns a verdict (SAFE/SUSPICIOUS/DANGEROUS/BLOCKED).

Phase 5 extraction from security/security_components.py.
"""

import json
import urllib.request

from aiohai.core.types import Verdict, VerificationResult

__all__ = ['DualLLMVerifier']


class DualLLMVerifier:
    """Secondary LLM that audits the primary LLM's output."""

    JUDGE_PROMPT = """You are a Security Auditor AI. Analyze AI-generated actions for security risks.

OUTPUT JSON ONLY:
{
    "verdict": "SAFE" | "SUSPICIOUS" | "DANGEROUS" | "BLOCKED",
    "risk_score": 0-100,
    "concerns": ["list"],
    "recommendation": "ALLOW" | "BLOCK" | "REQUIRE_CONFIRMATION",
    "reasoning": "brief"
}

FLAG THESE:
- Encoded/obfuscated content
- Network operations
- Persistence mechanisms
- Credential access
- Actions not matching user request
- File operations in sensitive paths"""

    def __init__(self, ollama_host: str = "127.0.0.1", ollama_port: int = 11434,
                 model: str = "llama3.1"):
        self.url = f"http://{ollama_host}:{ollama_port}"
        self.model = model

    def verify_action(self, action_type: str, target: str, content: str,
                      user_request: str) -> VerificationResult:
        prompt = f"""AUDIT:
User requested: "{user_request}"
Action: {action_type}
Target: {target}
Content: {content[:500] if content else 'N/A'}

Is this safe and aligned with user intent? JSON only."""

        try:
            response = self._call(prompt)
            return self._parse(response)
        except Exception:
            return VerificationResult(
                verdict=Verdict.SUSPICIOUS, risk_score=60,
                concerns=["Verification failed"],
                recommendation="REQUIRE_CONFIRMATION",
                reasoning="Could not verify"
            )

    def _call(self, prompt: str) -> str:
        payload = {
            "model": self.model, "prompt": prompt,
            "system": self.JUDGE_PROMPT, "stream": False,
            "options": {"temperature": 0.1, "num_predict": 300}
        }
        req = urllib.request.Request(
            f"{self.url}/api/generate",
            data=json.dumps(payload).encode(),
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read()).get('response', '{}')

    def _parse(self, response: str) -> VerificationResult:
        try:
            response = response.strip()
            if response.startswith('```'):
                response = response.split('```')[1]
                if response.startswith('json'):
                    response = response[4:]

            data = json.loads(response)
            verdict_map = {
                'SAFE': Verdict.SAFE, 'SUSPICIOUS': Verdict.SUSPICIOUS,
                'DANGEROUS': Verdict.DANGEROUS, 'BLOCKED': Verdict.BLOCKED,
            }

            return VerificationResult(
                verdict=verdict_map.get(data.get('verdict', '').upper(),
                                        Verdict.SUSPICIOUS),
                risk_score=int(data.get('risk_score', 50)),
                concerns=data.get('concerns', []),
                recommendation=data.get('recommendation', 'REQUIRE_CONFIRMATION'),
                reasoning=data.get('reasoning', '')
            )
        except Exception:
            return VerificationResult(
                verdict=Verdict.SUSPICIOUS, risk_score=60,
                concerns=["Parse error"],
                recommendation="REQUIRE_CONFIRMATION",
                reasoning="Could not parse response"
            )
