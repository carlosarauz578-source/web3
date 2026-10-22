from __future__ import annotations

import socket
import uuid
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app import database
from app.main import app
from app.providers import ProviderCompletion, ProviderTimeout, execution_mode

VULNERABLE_SOURCE = (
    "contract Lab {\n"
    "    function owner() public view returns (bool) {\n"
    "        return tx.origin == msg.sender;\n"
    "    }\n"
    "    function run(address target, bytes memory data) public {\n"
    "        target.delegatecall(data);\n"
    "    }\n"
    "}\n"
)
CLEAN_SOURCE = "contract Clean {\n    uint256 public value;\n}\n"


@pytest.fixture
def flow(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "flow.db")
    monkeypatch.setenv("AEGIS_BOOTSTRAP_TOKEN", "bootstrap-test-secret-with-32-chars")
    monkeypatch.setenv("AEGIS_COOKIE_SECURE", "false")
    for name in ("AEGIS_AI_API_KEY", "AEGIS_AI_MODEL", "AEGIS_AI_API_URL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AEGIS_AI_PROVIDER", "simulated")

    def no_network(*args, **kwargs):
        raise AssertionError("network access is not allowed in these tests")

    monkeypatch.setattr(socket, "create_connection", no_network)
    database.init_db()
    client = TestClient(app)
    assert client.post(
        "/api/auth/bootstrap",
        json={
            "bootstrap_token": "bootstrap-test-secret-with-32-chars",
            "organization_name": "Flow Org",
            "email": "admin@example.test",
            "password": "long-test-password-1",
        },
    ).status_code == 201
    project = client.post("/api/projects", json={"name": "Lab"}).json()
    return SimpleNamespace(client=client, project=project)


def start_run(client, project_id, source, *, consent=True, key=None):
    return client.post(
        "/api/agent-runs",
        json={
            "task_type": "code_review",
            "project_id": project_id,
            "source": source,
            "acknowledge_external_ai": consent,
            "idempotency_key": key or str(uuid.uuid4()),
        },
    )


def login(email, password):
    client = TestClient(app)
    assert client.post(
        "/api/auth/login", json={"email": email, "password": password}
    ).status_code == 200
    return client


def test_full_flow_with_simulated_provider_is_labelled_and_persisted(flow):
    response = start_run(flow.client, flow.project["id"], VULNERABLE_SOURCE)

    assert response.status_code == 201
    run = response.json()
    assert run["status"] == "completed"
    assert run["execution_mode"] == "simulated"
    auditor, validator = {item["agent"]: item for item in run["subtasks"]}.values()
    assert auditor["agent"] == "code_auditor"
    assert auditor["status"] == "completed"
    assert auditor["execution_mode"] == "simulated"
    assert auditor["result"]["provider"] == "simulated"
    report = auditor["result"]["result"]
    assert report["tools_executed"] == []
    findings = report["findings"]
    assert {item["evidence"] for item in findings} == {"tx.origin", "delegatecall"}
    assert {item["line_start"] for item in findings} == {3, 6}
    assert validator["agent"] == "independent_validator"
    assert validator["status"] == "completed"
    assert "second provider" in validator["result"]["scope"]
    assert [item["evidence_status"] for item in validator["result"]["findings"]] == [
        "supported",
        "supported",
    ]

    later = flow.client.get(f"/api/agent-runs/{run['id']}").json()
    assert later["status"] == "completed"
    assert later["execution_mode"] == "simulated"
    assert [item["agent"] for item in later["subtasks"]] == [
        item["agent"] for item in run["subtasks"]
    ]
    assert later["result"] == run["result"]
    listed = flow.client.get(
        "/api/agent-runs", params={"project_id": flow.project["id"]}
    ).json()["items"]
    assert [item["id"] for item in listed] == [run["id"]]
    assert listed[0]["execution_mode"] == "simulated"

    with database.connect() as connection:
        stored_run = connection.execute(
            "SELECT status, task_type FROM agent_runs WHERE id=?", (run["id"],)
        ).fetchone()
        stored_subtasks = connection.execute(
            "SELECT agent_name, status FROM agent_subtasks WHERE run_id=? ORDER BY agent_name",
            (run["id"],),
        ).fetchall()
        stored_input = connection.execute(
            "SELECT source_text FROM agent_run_inputs WHERE run_id=?", (run["id"],)
        ).fetchone()
    assert tuple(stored_run) == ("completed", "code_review")
    assert [tuple(row) for row in stored_subtasks] == [
        ("code_auditor", "completed"),
        ("independent_validator", "completed"),
    ]
    assert stored_input["source_text"] == VULNERABLE_SOURCE


def test_clean_source_completes_without_findings(flow):
    run = start_run(flow.client, flow.project["id"], CLEAN_SOURCE).json()

    assert run["status"] == "completed"
    assert run["execution_mode"] == "simulated"
    auditor = next(item for item in run["subtasks"] if item["agent"] == "code_auditor")
    report = auditor["result"]["result"]
    assert report["findings"] == []
    assert "No AI model was used" in report["summary"]


def test_idempotent_retry_returns_same_run_and_charges_once(flow):
    key = str(uuid.uuid4())
    first = start_run(flow.client, flow.project["id"], VULNERABLE_SOURCE, key=key).json()
    second = start_run(flow.client, flow.project["id"], VULNERABLE_SOURCE, key=key).json()

    assert second["id"] == first["id"]
    usage = flow.client.get("/api/usage").json()["usage"]
    assert usage["ai_reviews"]["user"]["consumed"] == 1
    assert usage["agent_runs"]["user"]["consumed"] == 1


def test_missing_consent_and_secret_input_do_not_create_runs(flow):
    assert start_run(
        flow.client, flow.project["id"], CLEAN_SOURCE, consent=False
    ).status_code == 400
    assert start_run(
        flow.client, flow.project["id"], "password=synthetic-flow-secret"
    ).status_code == 422
    assert flow.client.get("/api/agent-runs").json()["items"] == []


def test_provider_failure_is_a_safe_failed_run_and_persisted(flow, monkeypatch):
    def timeout(**kwargs):
        raise ProviderTimeout

    monkeypatch.setattr("app.agents.code_auditor.complete", timeout)
    response = start_run(flow.client, flow.project["id"], VULNERABLE_SOURCE)

    assert response.status_code == 201
    run = response.json()
    assert run["status"] == "failed"
    assert run["result"]["error_kind"] == ProviderTimeout.kind
    statuses = {item["agent"]: item["status"] for item in run["subtasks"]}
    assert statuses == {"code_auditor": "failed", "independent_validator": "inconclusive"}
    assert "Traceback" not in response.text
    assert flow.client.get(f"/api/agent-runs/{run['id']}").json()["status"] == "failed"


def test_unconfigured_real_provider_fails_closed_and_is_not_labelled_real(flow, monkeypatch):
    monkeypatch.setenv("AEGIS_AI_PROVIDER", "openai")
    run = start_run(flow.client, flow.project["id"], CLEAN_SOURCE).json()

    assert run["status"] == "failed"
    assert run["result"]["error_kind"] == "not_configured"
    assert run["execution_mode"] == "failed"
    assert "findings" not in str(run["result"])
    by_agent = {item["agent"]: item for item in run["subtasks"]}
    assert by_agent["code_auditor"]["status"] == "failed"
    assert by_agent["code_auditor"]["execution_mode"] == "failed"
    assert by_agent["independent_validator"]["status"] == "inconclusive"
    assert by_agent["independent_validator"]["execution_mode"] == "inconclusive"

    stored = flow.client.get(f"/api/agent-runs/{run['id']}").json()
    assert stored["execution_mode"] == "failed"
    assert {i["agent"]: i["execution_mode"] for i in stored["subtasks"]} == {
        "code_auditor": "failed",
        "independent_validator": "inconclusive",
    }


def test_blockchain_health_without_rpc_is_inconclusive_not_real(flow, monkeypatch):
    monkeypatch.delenv("AEGIS_EVM_RPC_URLS", raising=False)
    monkeypatch.delenv("AEGIS_STELLAR_RPC_URL", raising=False)
    response = flow.client.post(
        "/api/agent-runs",
        json={
            "task_type": "blockchain_health",
            "project_id": flow.project["id"],
            "network": "ethereum",
            "idempotency_key": str(uuid.uuid4()),
        },
    )

    assert response.status_code == 201
    run = response.json()
    assert run["status"] == "inconclusive"
    assert run["execution_mode"] == "inconclusive"
    assert run["subtasks"][0]["execution_mode"] == "inconclusive"
    stored = flow.client.get(f"/api/agent-runs/{run['id']}").json()
    assert stored["status"] == "inconclusive"
    assert stored["execution_mode"] == "inconclusive"
    assert stored["subtasks"][0]["status"] == "inconclusive"
    assert stored["subtasks"][0]["execution_mode"] == "inconclusive"


def test_blockchain_health_is_real_only_when_the_check_completed(monkeypatch):
    from app.agents import orchestrator

    monkeypatch.setattr(
        orchestrator,
        "analyze_network_health",
        lambda network: {"agent": "blockchain_analyst", "status": "completed"},
    )
    assert orchestrator.execute_task("blockchain_health", {"network": "ethereum"})[
        "execution_mode"
    ] == "real"


def test_classification_never_marks_unfinished_work_real():
    from app.agents.orchestrator import classify_execution

    assert classify_execution("completed") == "real"
    assert classify_execution("completed", simulated=True) == "simulated"
    assert classify_execution("inconclusive") == "inconclusive"
    assert classify_execution("running") == "inconclusive"
    assert classify_execution("failed", simulated=True) == "failed"


def test_fabricated_provider_citation_is_rejected(flow, monkeypatch):
    fabricated = (
        '{"summary":"s","limitations":[],"findings":[{"category":"auth","severity":"high",'
        '"confidence":"high","line_start":1,"line_end":1,"evidence":"not in source",'
        '"explanation":"e","impact":"i","recommendation":"r"}]}'
    )
    monkeypatch.setattr(
        "app.agents.code_auditor.complete",
        lambda **kwargs: ProviderCompletion(fabricated, "simulated", "simulated-rules-v1"),
    )
    run = start_run(flow.client, flow.project["id"], CLEAN_SOURCE).json()

    assert run["status"] == "failed"
    assert run["result"]["error_kind"] == "invalid_response"


def test_runs_are_isolated_by_project_membership_and_organization(flow):
    run = start_run(flow.client, flow.project["id"], VULNERABLE_SOURCE).json()
    created = flow.client.post(
        "/api/users",
        json={
            "email": "member@example.test",
            "password": "member-test-password-1",
            "role": "collaborator",
        },
    ).json()
    outsider = login(created["email"], "member-test-password-1")
    assert outsider.get(f"/api/agent-runs/{run['id']}").status_code == 404
    assert outsider.get("/api/agent-runs").json()["items"] == []
    assert start_run(outsider, flow.project["id"], CLEAN_SOURCE).status_code == 404

    assert flow.client.post(
        f"/api/projects/{flow.project['id']}/members", json={"user_id": created["id"]}
    ).status_code == 201
    # A member may run reviews in the project but cannot read another user's run.
    assert outsider.get(f"/api/agent-runs/{run['id']}").status_code == 404
    assert start_run(outsider, flow.project["id"], CLEAN_SOURCE).status_code == 201

    other_org = flow.client.post(
        "/api/organizations",
        json={
            "name": "Other Org",
            "admin_email": "other-admin@example.test",
            "admin_password": "other-admin-password-1",
        },
    ).json()
    other = login(other_org["administrator"]["email"], "other-admin-password-1")
    assert other.get(f"/api/agent-runs/{run['id']}").status_code == 404
    assert other.get("/api/agent-runs").json()["items"] == []


def test_unauthenticated_requests_are_rejected(flow):
    anonymous = TestClient(app)
    assert anonymous.get("/api/agent-runs").status_code == 401
    assert start_run(anonymous, flow.project["id"], CLEAN_SOURCE).status_code == 401


def test_execution_mode_mapping_only_marks_the_simulated_provider():
    assert execution_mode("simulated") == "simulated"
    assert execution_mode("openai-compatible") == "real"
    assert execution_mode("gemini") == "real"
    assert execution_mode("groq") == "real"


def test_dashboard_exposes_the_agent_flow_and_the_mode_distinction(flow):
    page = flow.client.get("/").text

    for element_id in ("agent-flow-form", "agent-flow-source", "agent-flow-list"):
        assert f'id="{element_id}"' in page
    assert "SIMULADO" in page and "REAL" in page
    assert "innerHTML" not in page


def test_dashboard_static_wiring_for_the_agent_flow(flow):
    import re

    page = flow.client.get("/").text
    used = set(re.findall(r'\$\("(agent-flow-[a-z-]+)"\)', page))
    assert {"agent-flow-form", "agent-flow-submit", "agent-flow-status"} <= used
    for element_id in used:
        assert page.count(f'id="{element_id}"') == 1, element_id

    for event in ('"agent-flow-form").addEventListener("submit"',
                  '"agent-flow-refresh").addEventListener("click"',
                  '"agent-flow-project").addEventListener("change"'):
        assert event in page
    submit = page.split('$("agent-flow-form").addEventListener("submit"', 1)[1]
    submit = submit.split('$("agent-flow-refresh")', 1)[0]
    # the button is always re-enabled and server details are not echoed on 5xx/422
    assert "finally" in submit and "button.disabled = projects.length === 0" in submit
    assert "No se pudo completar la ejecución." in submit
    assert "error.message" in submit and "error.status === 422" in submit

    for label in ("SIMULADO", "REAL", "INCONCLUSO", "FALLIDO"):
        assert label in page
