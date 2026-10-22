from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError

from app.agents.contracts import AgentFinding

MAX_VALIDATED_FINDINGS = 20


def validate_review_evidence(source: str, report: Any) -> dict[str, object]:
    if (
        not isinstance(report, dict)
        or not isinstance(report.get("findings"), list)
        or len(report["findings"]) > MAX_VALIDATED_FINDINGS
    ):
        return {
            "agent": "independent_validator",
            "status": "inconclusive",
            "findings": [],
            "limitations": ["The review result does not have a supported finding structure."],
        }

    source_lines = source.splitlines() or [source]
    validated_findings: list[dict[str, object]] = []
    normalized_findings: list[dict[str, object]] = []
    for index, finding in enumerate(report["findings"]):
        if not isinstance(finding, dict):
            return {
                "agent": "independent_validator",
                "status": "inconclusive",
                "findings": validated_findings,
                "limitations": ["A finding was not a structured object."],
            }
        line_start = finding.get("line_start")
        line_end = finding.get("line_end")
        evidence = finding.get("evidence")
        valid_span = (
            type(line_start) is int
            and type(line_end) is int
            and 1 <= line_start <= line_end <= len(source_lines)
        )
        cited_text = (
            "\n".join(source_lines[line_start - 1:line_end])
            if valid_span
            else ""
        )
        supported = isinstance(evidence, str) and bool(evidence) and evidence in cited_text
        validated_findings.append({
            "finding_index": index,
            "evidence_status": "supported" if supported else "rejected",
            "finding_status": "unconfirmed" if supported else "rejected",
            "line_start": line_start if type(line_start) is int else None,
            "line_end": line_end if type(line_end) is int else None,
        })
        limitations = report.get("limitations", [])
        if (
            not isinstance(finding.get("category"), str)
            or not isinstance(finding.get("severity"), str)
            or finding.get("severity") not in {
                "critical",
                "high",
                "medium",
                "low",
                "informational",
            }
            or not isinstance(finding.get("explanation"), str)
            or not isinstance(evidence, str)
            or not valid_span
            or not isinstance(limitations, list)
            or not all(isinstance(item, str) for item in limitations)
        ):
            return {
                "agent": "independent_validator",
                "status": "inconclusive",
                "findings": validated_findings,
                "normalized_findings": normalized_findings,
                "limitations": ["A finding did not meet the normalized evidence contract."],
            }
        normalized = {
            "id": finding.get("id") if isinstance(finding.get("id"), str) else str(uuid.uuid4()),
            "finding_type": finding["category"],
            "severity": finding["severity"],
            "description": finding["explanation"],
            "evidence": evidence,
            "file": finding.get("file") if isinstance(finding.get("file"), str) else None,
            "line_start": line_start,
            "line_end": line_end,
            "network": None,
            "reference": None,
            "source_agent": "code_auditor",
            "verification_method": "exact_source_line_citation",
            "validation_status": "pending" if supported else "rejected",
            "limitations": limitations[:10],
            "observed_at": datetime.now(UTC),
        }
        try:
            normalized_findings.append(
                AgentFinding.model_validate(normalized).model_dump(mode="json")
            )
        except ValidationError:
            return {
                "agent": "independent_validator",
                "status": "inconclusive",
                "findings": validated_findings,
                "normalized_findings": normalized_findings,
                "limitations": ["A finding did not meet the normalized evidence contract."],
            }

    return {
        "agent": "independent_validator",
        "status": "completed",
        "validation_scope": "source_citation_only",
        "findings": validated_findings,
        "normalized_findings": normalized_findings,
        "limitations": [
            "A supported citation does not establish that a reported vulnerability is real.",
            "No independent provider or runtime analysis was performed.",
        ],
    }
