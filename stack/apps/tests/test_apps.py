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


def test_out_of_scope_sources_are_dropped(tmp_path, monkeypatch):
    monkeypatch.setattr(correlator, 'DB', tmp_path / 'e.sqlite')
    monkeypatch.setattr(correlator, 'REGISTRY', tmp_path / 'absent')
    base = {'@timestamp': '2026-10-12T10:00:00Z', 'event': {'action': 'login.failed'}}
    with correlator.connection() as db:
        assert correlator.ingest_one(db, {**base, 'source': {'ip': '10.66.0.50'}})      # attacker
        assert not correlator.ingest_one(db, {**base, 'source': {'ip': '10.0.2.15'}})    # NAT noise
        assert not correlator.ingest_one(db, {**base, 'source': {'ip': 'fe80::2'}})      # link-local
        assert db.execute('SELECT count(*) FROM events').fetchone()[0] == 1


def test_expanded_attack_rules():
    def t(cmd):
        return correlator.classify({'event': {'action': 'command.input'},
                                    'process': {'command_line': cmd}})[0]
    assert 'T1049' in t('netstat -tlnp')
    assert 'T1087' in t('cat /etc/passwd')
    assert 'T1053.003' in t('crontab -l')
    assert 'T1070.003' in t('history -c')
    assert 'T1016' in t('ip addr show')
    assert 'T1098.004' in t('echo key >> ~/.ssh/authorized_keys')


def test_catalog_covers_every_classifiable_technique():
    # every id a rule can emit must have a human label for the UI matrix
    rule_ids = {r['id'] for r in correlator.RULES['commands']}
    hardcoded = {'T1110', 'T1078', 'T1190', 'T1552.001', 'T1046', 'T1021.002', 'T1021.004'}
    assert (rule_ids | hardcoded) <= set(correlator.CATALOG)


def test_alerts_collected_and_deduplicated(tmp_path, monkeypatch):
    monkeypatch.setattr(correlator, 'DB', tmp_path / 'e.sqlite')
    monkeypatch.setattr(correlator, 'REGISTRY', tmp_path / 'absent')
    token = {'id': 'T1', 'value': 'b' * 32, 'origin': 'srv-web01:/root/.bash_history'}
    ev = lambda ts: {'@timestamp': ts, 'source': {'ip': '10.66.0.50'},
                     'event': {'action': 'login.success'}, 'honeypot': {'name': 'db-prod01'},
                     'user': {'password': token['value']}}
    with correlator.connection() as db:
        monkeypatch.setattr(correlator, 'REGISTRY', tmp_path / 'reg.yml')
        (tmp_path / 'reg.yml').write_text(json.dumps([token]))
        correlator.ingest_one(db, ev('2026-10-12T10:00:00Z'))
        correlator.ingest_one(db, ev('2026-10-12T10:05:00Z'))  # same reuse, different event
        alerts = correlator.collect_alerts(db)
    reuse = [a for a in alerts if a['type'] == 'credential-reuse']
    assert len(reuse) == 1 and reuse[0]['severity'] == 'high' and reuse[0]['target'] == 'db-prod01'


def test_lateral_edges_from_reuse_alerts():
    camps = [{'alerts': [{'type': 'credential-reuse', 'origin': 'srv-web01:/root/.bash_history',
                          'target': 'db-prod01'}]}]
    hosts, edges = correlator.lateral_data(camps)
    assert ('srv-web01', 'db-prod01') in edges and 'db-prod01' in hosts
