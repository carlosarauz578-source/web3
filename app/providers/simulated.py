"""Deterministic offline reviewer used only when AEGIS_AI_PROVIDER=simulated.

It performs no network access and uses no model: a fixed set of line rules produces
findings that cite real source lines. Every result is labelled as simulated.
"""

from __future__ import annotations

import json
import re

from app.providers.common import ProviderCompletion, ProviderRequest

SIMULATED_PROVIDER_ID = "simulated"
SIMULATED_MODEL = "simulated-rules-v1"

# (pattern, category, severity, explanation, impact, recommendation)
_RULES = (
    (
        re.compile(r"\btx\.origin\b"),
        "auth",
        "high",
        "tx.origin is used, which can be abused through intermediary contracts.",
        "An attacker contract may act with the victim's authority.",
        "Use msg.sender for authorization decisions.",
    ),
    (
        re.compile(r"\bdelegatecall\b"),
        "access_control",
        "high",
        "delegatecall executes foreign code in this contract's storage context.",
        "Untrusted targets can overwrite storage or take control.",
        "Restrict delegatecall targets to fixed, audited implementations.",
    ),
    (
        re.compile(r"\bselfdestruct\b"),
        "access_control",
        "medium",
        "selfdestruct is present and may be reachable without strong access control.",
        "Funds or contract availability can be lost.",
        "Remove it or guard it with strict authorization.",
    ),
    (
        re.compile(r"\beval\s*\("),
        "injection",
        "high",
        "eval() executes dynamically built code.",
        "Attacker-controlled input could execute arbitrary code.",
        "Avoid eval; use a safe parser for the expected format.",
    ),
)


def simulated_status() -> dict[str, str]:
    return {
        "status": "configured",
        "provider": SIMULATED_PROVIDER_ID,
        "model": SIMULATED_MODEL,
    }


def complete_simulated(request: ProviderRequest) -> ProviderCompletion:
    findings = []
    for number, line in enumerate(request.user_content.splitlines(), start=1):
        for pattern, category, severity, explanation, impact, recommendation in _RULES:
            match = pattern.search(line)
            if match is None or len(findings) >= 20:
                continue
            findings.append({
                "category": category,
                "severity": severity,
                "confidence": "low",
                "line_start": number,
                "line_end": number,
                "evidence": match.group(0),
                "explanation": explanation,
                "impact": impact,
                "recommendation": recommendation,
            })
    summary = (
        f"Simulated rule-based review: {len(findings)} pattern match(es). "
        "No AI model was used."
    )
    content = json.dumps({
        "summary": summary,
        "limitations": [
            "Simulated execution: fixed line rules, no AI provider and no tools were used.",
        ],
        "findings": findings,
    })
    return ProviderCompletion(content, SIMULATED_PROVIDER_ID, SIMULATED_MODEL)
