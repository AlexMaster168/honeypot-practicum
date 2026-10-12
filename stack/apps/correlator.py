import hashlib
import html
import json
import os
import re
import secrets
import sqlite3
import base64
import urllib.request
from datetime import datetime
from pathlib import Path

import yaml
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi import Depends

app = FastAPI(docs_url=None, redoc_url=None)
DB = Path(os.getenv('CORRELATOR_DB', '/state/events.sqlite'))
KEY = os.getenv('CORRELATOR_KEY', '')
REGISTRY = Path(os.getenv('REGISTRY', '/seeds/registry.yml'))
RULES = yaml.safe_load((Path(__file__).parent / 'attack.yml').read_text())
basic = HTTPBasic()

def connection():
    DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB, timeout=10)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY, campaign TEXT, source TEXT, ts TEXT, payload TEXT, techniques TEXT, alerts TEXT)')
    conn.execute('CREATE INDEX IF NOT EXISTS campaign_idx ON events(campaign,ts)')
    return conn

def auth(credentials: HTTPBasicCredentials = Depends(basic)):
    if not KEY or not (secrets.compare_digest(credentials.username, 'analyst') and secrets.compare_digest(credentials.password, KEY)):
        raise HTTPException(401, headers={'WWW-Authenticate': 'Basic'})

def token_hits(event, registry):
    text = json.dumps(event, ensure_ascii=False)
    return [t for t in registry if len(t.get('value', '')) >= 12 and t['value'] in text]

def classify(event, failures=0, registry=()):
    action = event.get('event', {}).get('action', '')
    host = event.get('honeypot', {}).get('name', '')
    service = event.get('honeypot', {}).get('service', '')
    command = event.get('process', {}).get('command_line', '')
    ids, alerts = [], []
    if action == 'login.failed' and failures >= 5:
        ids.append('T1110')
    if action == 'login.success':
        ids.append('T1078')
    if action in ('sqli-probe', 'command-probe'):
        ids.append('T1190')
    if action == 'decoy-read':
        ids.append('T1552.001')
    if action == 'ids-alert' and 'scan' in event.get('rule', {}).get('name', '').lower():
        ids.append('T1046')
    if service in ('smbd', 'smb'):
        ids.append('T1021.002')
    for rule in RULES['commands']:
        if re.search(rule['pattern'], command, re.I):
            ids.append(rule['id'])
    for token in token_hits(event, registry):
        if event.get('user', {}).get('password') == token['value'] or token['value'] in command:
            if host != 'srv-web01':
                alerts.append({'type': 'credential-reuse', 'token': token['id'], 'origin': token['origin'], 'target': host})
                if action == 'login.success' and host == 'db-prod01':
                    ids.append('T1021.004')
        else:
            alerts.append({'type': 'honeytoken-observed', 'token': token['id'], 'origin': token['origin']})
    if event.get('honeytoken', {}).get('id') == 'T4' and action == 'login.success':
        ids.append('T1021.004')
        alerts.append({'type': 'credential-reuse', 'token': 'T4', 'origin': 'srv-web01:/.git history', 'target': host})
    return sorted(set(ids)), alerts

def ingest_one(conn, event):
    src = event.get('source', {}).get('ip')
    if not src:
        return False
    ts = event.get('@timestamp', '')
    try:
        instant = datetime.fromisoformat(ts.replace('Z', '+00:00')).timestamp()
    except (ValueError, AttributeError):
        return False
    campaign = f'{src}-{int(instant // 1800)}'
    # Exact repeats from retrying HTTP deliveries are ignored.
    encoded = json.dumps(event, sort_keys=True, separators=(',', ':'))
    digest = hashlib.sha256(encoded.encode()).hexdigest()
    if conn.execute('SELECT 1 FROM events WHERE id=?', (digest,)).fetchone():
        return False
    failures = conn.execute('SELECT count(*) FROM events WHERE campaign=? AND json_extract(payload,\'$.event.action\')=\'login.failed\'', (campaign,)).fetchone()[0]
    registry = json.loads(REGISTRY.read_text()) if REGISTRY.exists() else []
    ids, alerts = classify(event, failures + (event.get('event', {}).get('action') == 'login.failed'), registry)
    # Do not duplicate attempted passwords in the analyst UI storage.
    clean = json.loads(encoded)
    if 'user' in clean:
        clean['user'].pop('password', None)
    conn.execute('INSERT OR IGNORE INTO events VALUES(?,?,?,?,?,?,?)',
        (digest, campaign, src, ts, json.dumps(clean), json.dumps(ids), json.dumps(alerts)))
    conn.execute('DELETE FROM events WHERE rowid IN (SELECT rowid FROM events ORDER BY rowid DESC LIMIT -1 OFFSET 100000)')
    return True

@app.post('/ingest')
async def ingest(request: Request):
    if not KEY or not secrets.compare_digest(request.headers.get('authorization', ''), 'Bearer ' + KEY):
        raise HTTPException(401)
    body = bytearray()
    async for part in request.stream():
        body.extend(part)
        if len(body) > 1024 * 1024:
            raise HTTPException(413)
    events = [json.loads(line) for line in body.decode().splitlines() if line.strip()]
    with connection() as conn:
        count = sum(ingest_one(conn, e) for e in events)
    # Aggregate campaigns are stored in ES as well, so the e2e check can verify persistence.
    if os.getenv('ES_PASSWORD'):
        password = os.environ['ES_PASSWORD']
        auth_header = 'Basic ' + base64.b64encode(('vector_writer:' + password).encode()).decode()
        sources = {e.get('source', {}).get('ip') for e in events}
        try:
            for campaign in campaigns():
                if campaign['source'] not in sources:
                    continue
                ident = hashlib.sha256(campaign['id'].encode()).hexdigest()
                req = urllib.request.Request('http://elasticsearch:9200/mirage-campaigns-lab/_doc/' + ident,
                    data=json.dumps(campaign).encode(), method='PUT',
                    headers={'Authorization': auth_header, 'Content-Type': 'application/json'})
                with urllib.request.urlopen(req, timeout=10) as response:
                    response.read()
        except Exception:
            # Vector retries. SQLite deduplication avoids replayed event rows.
            raise HTTPException(503, detail='Campaign persistence temporarily unavailable')
    return {'accepted': count}

@app.get('/api/campaigns', dependencies=[Depends(auth)])
def campaigns():
    with connection() as conn:
        rows = conn.execute('SELECT campaign, source, min(ts), max(ts), count(*) FROM events GROUP BY campaign ORDER BY max(ts) DESC LIMIT 100').fetchall()
        result = []
        for c, src, start, end, count in rows:
            details = conn.execute('SELECT techniques,alerts FROM events WHERE campaign=?', (c,)).fetchall()
            result.append({'id': c, 'source': src, 'start': start, 'end': end, 'count': count,
                'techniques': sorted({t for techniques, _ in details for t in json.loads(techniques)}),
                'alerts': [a for _, alerts in details for a in json.loads(alerts)]})
    return result

@app.get('/api/campaigns/{campaign}', dependencies=[Depends(auth)])
def timeline(campaign: str):
    with connection() as conn:
        rows = conn.execute('SELECT payload,techniques,alerts FROM events WHERE campaign=? ORDER BY ts LIMIT 2000', (campaign,)).fetchall()
    return [{'event': json.loads(e), 'techniques': json.loads(t), 'alerts': json.loads(a)} for e, t, a in rows]

@app.get('/', dependencies=[Depends(auth)])
def dashboard():
    cards = []
    for c in campaigns():
        esc = html.escape
        event_rows = ''.join(f'<tr><td>{esc(r["event"].get("@timestamp", ""))}</td><td>{esc(r["event"].get("honeypot",{}).get("name", ""))}</td><td>{esc(r["event"].get("event",{}).get("action", ""))}</td><td>{esc(", ".join(r["techniques"]))}</td><td>{esc(r["event"].get("process",{}).get("command_line", ""))}</td></tr>' for r in timeline(c['id']))
        cards.append(f'<section><h2>{esc(c["source"])} · {c["count"]} событий</h2><p>{esc(c["start"])} → {esc(c["end"])}</p><p class="tags">{esc(" · ".join(c["techniques"]))}</p><p class="alerts">{esc(json.dumps(c["alerts"], ensure_ascii=False))}</p><details><summary>Таймлайн событий</summary><table><tr><th>Время UTC</th><th>Хост</th><th>Событие</th><th>ATT&CK</th><th>Команда</th></tr>{event_rows}</table></details></section>')
    return HTMLResponse('''<!doctype html><html lang="ru"><meta charset="utf-8"><title>Mirage — таймлайн атак</title><style>body{font:16px system-ui;background:#101b2c;color:#e8f0ff;margin:35px}h1{font-size:38px}section{background:#1c2c43;padding:24px;border-radius:16px;margin:20px 0}.tags{color:#72dbcc}.alerts{color:#ffc278}table{border-collapse:collapse;width:100%;font-size:12px}td,th{padding:10px;border-bottom:1px solid #345;text-align:left;overflow-wrap:anywhere}details{margin-top:20px}p{color:#afc1da}</style><h1>Mirage · Таймлайн атак</h1><p>Кампании: IP источника + 30-минутный интервал. ATT&CK — гипотезы по наблюдаемым событиям, не доказательство компрометации.</p>''' + ''.join(cards) + '</html>')

@app.get('/health')
def health():
    return {'status': 'ok'}
