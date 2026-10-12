import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fastapi.testclient import TestClient
import correlator
import web

def test_bruteforce_threshold_and_ordinary_event():
    failed = {'event': {'action': 'login.failed'}}
    assert correlator.classify(failed, 4)[0] == []
    assert correlator.classify(failed, 5)[0] == ['T1110']
    assert correlator.classify({'event': {'action': 'session.connect'}})[0] == []

def test_token_reuse_requires_exact_password_and_remote_host():
    token = {'id': 'T1', 'value': 'a' * 32, 'origin': 'web01:history'}
    e = {'event': {'action': 'login.success'}, 'honeypot': {'name': 'db-prod01'}, 'user': {'password': token['value']}}
    techniques, alerts = correlator.classify(e, registry=[token])
    assert 'T1021.004' in techniques
    assert alerts[0]['type'] == 'credential-reuse'
    e['user']['password'] = 'incorrect'
    assert not correlator.classify(e, registry=[token])[1]

def test_retry_deduplication_and_password_redaction(tmp_path, monkeypatch):
    monkeypatch.setattr(correlator, 'DB', tmp_path / 'events.sqlite')
    monkeypatch.setattr(correlator, 'REGISTRY', tmp_path / 'absent')
    e = {'@timestamp': '2026-10-12T10:00:00Z', 'source': {'ip': '10.66.0.50'}, 'user': {'password': 'training-secret'}, 'event': {'action': 'login.failed'}}
    with correlator.connection() as db:
        assert correlator.ingest_one(db, e)
        assert not correlator.ingest_one(db, e)
        payload = db.execute('SELECT payload FROM events').fetchone()[0]
        assert 'training-secret' not in payload
        assert db.execute('SELECT count(*) FROM events').fetchone()[0] == 1

def test_tools_and_probe_detection():
    for name in web.TOOLS:
        assert web.detect_tool(name + '/test') == name
    assert web.detect_tool('Mozilla/5.0') == 'unknown'
    assert web.probe_kind("id=1 union select 1") == 'sqli-probe'
    assert web.probe_kind('id=1%20union%20select%201') == 'sqli-probe'
    assert web.probe_kind('id=1') == 'http-request'

def test_portal_does_not_reflect_html_and_logs_only_bounded_input(tmp_path, monkeypatch):
    monkeypatch.setattr(web, 'LOG', tmp_path / 'web.json')
    client = TestClient(web.app)
    r = client.post('/admin', content='username=%3Cscript%3Ealert(1)%3C/script%3E&password=test')
    assert r.status_code == 401
    assert '<script>' not in r.text
    assert json.loads((tmp_path / 'web.json').read_text())['action'] == 'web-login-failed'
    assert client.post('/admin', content='x' * 9000).status_code == 413

def test_git_path_cannot_escape_repository(tmp_path, monkeypatch):
    monkeypatch.setattr(web, 'DATA', tmp_path)
    (tmp_path / 'repo' / '.git').mkdir(parents=True)
    (tmp_path / 'private').write_text('must remain private')
    assert web.fake_git('../../private').status_code == 404

def test_ingest_rejects_unauthenticated_client(monkeypatch):
    monkeypatch.setattr(correlator, 'KEY', 'test-ingestion-key')
    client = TestClient(correlator.app)
    assert client.post('/ingest', content='{}').status_code == 401
    assert client.get('/api/campaigns').status_code == 401
