from fastapi.testclient import TestClient
from app.main import app, audit_source, sha256_text
client = TestClient(app)
def test_health_not_production():
    r=client.get('/api/health'); assert r.status_code==200 and r.json()['production_ready'] is False
def test_security_headers():
    r=client.get('/api/health'); assert r.headers['x-content-type-options']=='nosniff'; assert r.headers['x-frame-options']=='DENY'; assert "default-src 'self'" in r.headers['content-security-policy']
def test_requires_authorization_ack():
    r=client.post('/api/audits',json={'filename':'Test.sol','source':'pragma solidity ^0.8.20; contract Test {}','acknowledge_lab_only':False}); assert r.status_code==400
def test_only_solidity():
    r=client.post('/api/audits',json={'filename':'test.py','source':'print(1)','acknowledge_lab_only':True}); assert r.status_code==400
def test_hash_deterministic():
    assert sha256_text('abc')==sha256_text('abc') and sha256_text('abc')!=sha256_text('abd')
def test_no_fake_success_when_slither_missing(monkeypatch):
    import app.main as m
    monkeypatch.setattr(m.shutil,'which',lambda _:None)
    r=audit_source('pragma solidity ^0.8.20; contract Lab {}','Lab.sol')
    assert r['status']=='tool_unavailable' and 'no se declara seguro' in r['message'].lower()

def test_audit_records_persist_in_sqlite(tmp_path, monkeypatch):
    import app.main as m
    monkeypatch.setattr(m, "DB_PATH", tmp_path / "test.db")
    m.init_db()
    monkeypatch.setattr(m, "audit_source", lambda source, filename: {
        "status": "completed", "engine": "test-double", "findings": [],
        "message": "resultado de prueba", "source_sha256": m.sha256_text(source), "duration_ms": 1
    })
    response = client.post("/api/audits", json={
        "filename": "Lab.sol", "source": "contract Lab {}", "acknowledge_lab_only": True
    })
    assert response.status_code == 200
    run_id = response.json()["id"]
    assert m.get_record(run_id)["filename"] == "Lab.sol"
    assert client.get(f"/api/evidence/{run_id}").status_code == 200
    assert len(client.get(f"/api/evidence/{run_id}").json()["events"]) == 1

def test_approval_is_recorded_and_cannot_be_overwritten(tmp_path, monkeypatch):
    import app.main as m
    monkeypatch.setattr(m, "DB_PATH", tmp_path / "approval.db")
    m.init_db()
    monkeypatch.setattr(m, "audit_source", lambda source, filename: {
        "status": "completed", "engine": "test-double", "findings": [],
        "message": "resultado de prueba", "source_sha256": m.sha256_text(source), "duration_ms": 1
    })
    result = client.post("/api/audits", json={
        "filename": "Lab.sol", "source": "contract Lab {}", "acknowledge_lab_only": True
    }).json()
    approval = {"reviewer": "Reviewer QA", "decision": "approve", "reason": "Prueba automatizada de flujo."}
    assert client.post(f"/api/audits/{result['id']}/approval", json=approval).status_code == 200
    assert client.post(f"/api/audits/{result['id']}/approval", json=approval).status_code == 409
    evidence = client.get(f"/api/evidence/{result['id']}").json()
    assert len(evidence["events"]) == 2
    assert evidence["events"][1]["previous_hash"] == evidence["events"][0]["event_hash"]
