from __future__ import annotations

import json

import pytest

from app.agents import blockchain_analyst, code_auditor, independent_validator, orchestrator
from app.providers import ProviderSensitiveContent
from app.sensitive_data import (
    REDACTED_SENSITIVE_CONTENT,
    contains_sensitive_content_in_value,
    redact_sensitive_content_in_value,
)


def test_code_auditor_blocks_recognized_sensitive_content_before_provider(monkeypatch):
    provider_calls = []
    monkeypatch.setattr(
        code_auditor,
        "complete",
        lambda **_kwargs: provider_calls.append(True),
    )
    synthetic_secret = "password=synthetic-no-leak-marker"

    with pytest.raises(ProviderSensitiveContent) as error:
        code_auditor.review_code(synthetic_secret)

    assert synthetic_secret not in str(error.value)
    assert provider_calls == []


def test_sensitive_redaction_handles_nested_maps_and_json_without_mutating_input():
    digest = "a" * 64
    value = {
        "source_sha256": digest,
        "code": "contract Lab {}",
        "result": [{
            "metadata": {
                "password": "synthetic-nested-value",
                "token": "ghp_" + "a" * 24,
            },
        }],
    }

    redacted = redact_sensitive_content_in_value(value)

    assert contains_sensitive_content_in_value(value)
    assert redacted["source_sha256"] == digest
    assert redacted["code"] == "contract Lab {}"
    redacted_metadata = redacted["result"][0]["metadata"]
    assert redacted_metadata == {
        REDACTED_SENSITIVE_CONTENT: REDACTED_SENSITIVE_CONTENT,
        "token": REDACTED_SENSITIVE_CONTENT,
    }
    assert value["result"][0]["metadata"]["password"] == "synthetic-nested-value"


def test_sensitive_redaction_parses_nested_json_strings():
    original = json.dumps({
        "report": json.dumps({"findings": [{"api_key": "synthetic-json-value"}]}),
        "message": "clean",
    })

    redacted = redact_sensitive_content_in_value(original)
    parsed_outer = json.loads(redacted)
    parsed_inner = json.loads(parsed_outer["report"])
    legitimate_json = json.dumps({"message": "clean", "count": 1})

    assert contains_sensitive_content_in_value(original)
    assert parsed_inner["findings"][0][REDACTED_SENSITIVE_CONTENT] == (
        REDACTED_SENSITIVE_CONTENT
    )
    assert parsed_outer["message"] == "clean"
    assert "synthetic-json-value" not in redacted
    assert not contains_sensitive_content_in_value(legitimate_json)
    assert redact_sensitive_content_in_value(legitimate_json) == legitimate_json


def test_duplicate_json_keys_fail_closed_without_losing_earlier_values():
    original = (
        '{"password":"synthetic-first-value",'
        '"password":""}'
    )

    assert contains_sensitive_content_in_value(original)
    assert redact_sensitive_content_in_value(original) == REDACTED_SENSITIVE_CONTENT


def test_sensitive_dictionary_keys_are_redacted_recursively():
    sensitive_key = "api_key=synthetic-sensitive-key"
    original = {
        "outer": [{
            sensitive_key: "metadata",
            "safe": {"status": "clean"},
        }],
    }

    redacted = redact_sensitive_content_in_value(original)
    serialized = json.dumps(redacted)

    assert contains_sensitive_content_in_value(original)
    assert sensitive_key not in str(redacted)
    assert sensitive_key not in serialized
    assert redacted["outer"][0][REDACTED_SENSITIVE_CONTENT] == REDACTED_SENSITIVE_CONTENT
    assert redacted["outer"][0]["safe"] == {"status": "clean"}


def test_sensitive_redaction_fails_closed_on_deep_python_values():
    value = {"password": "synthetic-deep-value"}
    for _ in range(2_000):
        value = {"nested": value}

    redacted = redact_sensitive_content_in_value(value)

    assert redacted == REDACTED_SENSITIVE_CONTENT


def test_sha256_fields_and_legitimate_content_are_preserved():
    digest = "B" * 64
    value = {
        "id": "c" * 64,
        "source_sha256": digest,
        "evidence_sha256": "d" * 64,
        "result_sha256": "e" * 64,
        "source": "contract Lab {}",
        "token": "ERC20",
    }

    assert not contains_sensitive_content_in_value(value)
    assert redact_sensitive_content_in_value(value) == value
    assert redact_sensitive_content_in_value("f" * 64) == "f" * 64
    credential_digest = {"api_key_sha256": digest}
    assert not contains_sensitive_content_in_value(credential_digest)
    assert redact_sensitive_content_in_value(credential_digest) == credential_digest
    assert redact_sensitive_content_in_value({
        "private_key": "0x" + "a" * 64,
    }) == {REDACTED_SENSITIVE_CONTENT: REDACTED_SENSITIVE_CONTENT}


def test_validator_only_verifies_source_citations():
    source = "contract Example {\n  function f() public {}\n}"
    report = {
        "findings": [
            {
                "id": "f-1",
                "category": "access_control",
                "severity": "medium",
                "explanation": "Review access to this function.",
                "line_start": 2,
                "line_end": 2,
                "evidence": "function f() public {}",
            },
            {
                "id": "f-2",
                "category": "other",
                "severity": "low",
                "explanation": "Evidence is not present.",
                "line_start": 3,
                "line_end": 3,
                "evidence": "fabricated",
            },
        ],
        "limitations": ["Test report."],
    }

    result = independent_validator.validate_review_evidence(source, report)

    assert result["status"] == "completed"
    assert result["validation_scope"] == "source_citation_only"
    assert result["findings"] == [
        {
            "finding_index": 0,
            "evidence_status": "supported",
            "finding_status": "unconfirmed",
            "line_start": 2,
            "line_end": 2,
        },
        {
            "finding_index": 1,
            "evidence_status": "rejected",
            "finding_status": "rejected",
            "line_start": 3,
            "line_end": 3,
        },
    ]
    assert "does not establish" in result["limitations"][0]
    assert result["normalized_findings"][0]["validation_status"] == "pending"
    assert result["normalized_findings"][1]["validation_status"] == "rejected"
    assert result["normalized_findings"][0]["source_agent"] == "code_auditor"


def test_blockchain_analyst_reports_limited_rpc_provenance(monkeypatch):
    monkeypatch.setattr(
        blockchain_analyst,
        "evm_status",
        lambda network: {"network": network, "status": "connected", "chain_id": 1},
    )

    result = blockchain_analyst.analyze_network_health("ethereum")

    assert result["status"] == "completed"
    assert result["source"] == "operator_configured_read_only_rpc"
    assert result["observation"]["chain_id"] == 1
    assert "no account" in result["limitations"][0]


def test_blockchain_analyst_does_not_claim_unconfigured_network_verified(monkeypatch):
    monkeypatch.setattr(
        blockchain_analyst,
        "evm_status",
        lambda network: {"network": network, "status": "not_configured"},
    )

    result = blockchain_analyst.analyze_network_health("ethereum")

    assert result["status"] == "inconclusive"
    assert result["observation"]["status"] == "not_configured"


def test_orchestrator_dispatches_only_registered_tasks(monkeypatch):
    monkeypatch.setattr(
        orchestrator,
        "analyze_network_health",
        lambda network: {"agent": "blockchain_analyst", "status": "inconclusive"},
    )

    assert orchestrator.execute_task(
        "blockchain_health",
        {"network": "ethereum"},
    ) == {
        "status": "inconclusive",
        "execution_mode": "inconclusive",
        "subtasks": [
            {
                "agent": "blockchain_analyst",
                "status": "inconclusive",
                "execution_mode": "inconclusive",
            }
        ],
    }
    try:
        orchestrator.execute_task("arbitrary_command", {})
    except ValueError as error:
        assert str(error) == "Task is not registered."
    else:
        raise AssertionError("Unregistered tasks must be rejected.")
