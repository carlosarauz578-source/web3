from __future__ import annotations

from typing import Any

from app.agents.blockchain_analyst import analyze_network_health
from app.agents.code_auditor import review_code
from app.agents.independent_validator import validate_review_evidence
from app.providers import execution_mode

VALIDATOR_SCOPE = (
    "Deterministic check that each cited line range contains the cited evidence; "
    "it does not validate vulnerability semantics and does not use a second provider."
)

def classify_execution(status: object, simulated: bool = False) -> str:
    """Unambiguous label: simulated | real | inconclusive | failed.

    `real` requires a completed operation; a missing configuration or connection
    (inconclusive) and an attempted-but-failed operation never carry it.
    """
    if status == "failed":
        return "failed"
    if status != "completed":
        return "inconclusive"
    return "simulated" if simulated else "real"


TASK_AGENT_REGISTRY = {
    "blockchain_health": ("blockchain_analyst",),
    "validate_review": ("independent_validator",),
    "code_review": ("code_auditor", "independent_validator"),
}


def execute_task(task_type: str, inputs: dict[str, Any]) -> dict[str, object]:
    if task_type not in TASK_AGENT_REGISTRY:
        raise ValueError("Task is not registered.")
    if task_type == "blockchain_health":
        result = analyze_network_health(inputs["network"])
        mode = classify_execution(result["status"])
        result = {**result, "execution_mode": mode}
        return {
            "status": result["status"],
            "execution_mode": mode,
            "subtasks": [result],
        }
    if task_type == "validate_review":
        validated = validate_review_evidence(inputs["source"], inputs["report"])
        mode = classify_execution(validated["status"])
        result = {**validated, "execution_mode": mode, "scope": VALIDATOR_SCOPE}
        return {
            "status": result["status"],
            "execution_mode": mode,
            "subtasks": [result],
        }
    if task_type == "code_review":
        report, provider, model = review_code(inputs["source"])
        simulated = execution_mode(provider) == "simulated"
        mode = classify_execution("completed", simulated)
        validated = validate_review_evidence(inputs["source"], report)
        validation = {
            **validated,
            "execution_mode": classify_execution(validated["status"]),
            "scope": VALIDATOR_SCOPE,
        }
        run_status = (
            "completed" if validation["status"] == "completed" else "inconclusive"
        )
        return {
            "execution_mode": (
                mode if run_status == "completed" else classify_execution(run_status)
            ),
            "status": run_status,
            "subtasks": [
                {
                    "agent": "code_auditor",
                    "status": "completed",
                    "result": report,
                    "provider": provider,
                    "model": model,
                    "execution_mode": mode,
                },
                validation,
            ],
        }
    raise ValueError("Registered task has no executor.")
