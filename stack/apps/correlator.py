import hashlib
import html
import ipaddress
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
CATALOG = RULES.get('catalog', {})
# Only traffic sourced inside the honeynet is an attack. This drops the VM's own
# NAT address (10.0.2.x) and link-local IPv6 that Suricata also sees, so the
# timeline shows campaigns, not background noise. Set MIRAGE_SCOPE='' to disable.
SCOPE = os.getenv('MIRAGE_SCOPE', '10.66.0.0/24')
ALERT_WEBHOOK = os.getenv('ALERT_WEBHOOK', '')
SEVERITY = {'credential-reuse': 'high', 'honeytoken-observed': 'medium'}
TACTICS = ['Reconnaissance', 'Initial Access', 'Credential Access', 'Discovery',
           'Lateral Movement', 'Persistence', 'Privilege Escalation',
           'Defense Evasion', 'Command and Control', 'Exfiltration']
basic = HTTPBasic()


def in_scope(ip):
    if not SCOPE:
        return True
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(SCOPE)
    except ValueError:
        return False


def connection():
    DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB, timeout=10)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY, campaign TEXT, source TEXT, ts TEXT, payload TEXT, techniques TEXT, alerts TEXT)')
    conn.execute('CREATE INDEX IF NOT EXISTS campaign_idx ON events(campaign,ts)')
    conn.execute('CREATE TABLE IF NOT EXISTS dispatched(digest TEXT PRIMARY KEY)')
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
    if not src or not in_scope(src):
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


def dispatch_alerts(conn):
    """Best-effort push of new, not-yet-sent alerts to ALERT_WEBHOOK.

    The isolated lab has no egress, so this normally no-ops; it exists so the
    same build alerts for real when pointed at a reachable sink. Each unique
    alert is sent at most once (tracked in the dispatched table)."""
    if not ALERT_WEBHOOK:
        return 0
    sent = 0
    for alert in collect_alerts(conn):
        digest = hashlib.sha256(json.dumps(alert, sort_keys=True).encode()).hexdigest()
        if conn.execute('SELECT 1 FROM dispatched WHERE digest=?', (digest,)).fetchone():
            continue
        try:
            req = urllib.request.Request(ALERT_WEBHOOK, data=json.dumps(alert).encode(),
                headers={'Content-Type': 'application/json'}, method='POST')
            urllib.request.urlopen(req, timeout=5).read()
        except Exception:
            continue  # webhook unreachable (expected in the offline lab)
        conn.execute('INSERT OR IGNORE INTO dispatched VALUES(?)', (digest,))
        sent += 1
    return sent


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
        dispatch_alerts(conn)
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


def collect_alerts(conn):
    """Distinct alerts across all campaigns, newest first, with severity + timing."""
    rows = conn.execute('SELECT campaign, source, ts, alerts FROM events WHERE alerts != \'[]\' ORDER BY ts').fetchall()
    seen, out = set(), []
    for campaign, source, ts, alerts in rows:
        for a in json.loads(alerts):
            sig = json.dumps({k: a.get(k) for k in ('type', 'token', 'target')}, sort_keys=True)
            if sig in seen:
                continue
            seen.add(sig)
            out.append({**a, 'campaign': campaign, 'source': source, 'ts': ts,
                        'severity': SEVERITY.get(a.get('type'), 'low')})
    out.sort(key=lambda a: a['ts'], reverse=True)
    return out


def lateral_data(camps):
    """Nodes seen and credential-reuse edges, for the lateral-movement graph."""
    hosts, edges = set(), set()
    for c in camps:
        for a in c['alerts']:
            if a.get('type') == 'credential-reuse':
                origin = a.get('origin', '').split(':')[0] or 'srv-web01'
                target = a.get('target', '')
                hosts.update([origin, target])
                edges.add((origin, target))
    return hosts, edges


@app.get('/api/campaigns', dependencies=[Depends(auth)])
def api_campaigns():
    return campaigns()


@app.get('/api/alerts', dependencies=[Depends(auth)])
def api_alerts():
    with connection() as conn:
        return collect_alerts(conn)


@app.get('/api/campaigns/{campaign}', dependencies=[Depends(auth)])
def timeline(campaign: str):
    with connection() as conn:
        rows = conn.execute('SELECT payload,techniques,alerts FROM events WHERE campaign=? ORDER BY ts LIMIT 2000', (campaign,)).fetchall()
    return [{'event': json.loads(e), 'techniques': json.loads(t), 'alerts': json.loads(a)} for e, t, a in rows]


def render_alerts(alerts):
    if not alerts:
        return '<section class="ok">Активных алертов нет.</section>'
    rows = ''.join(
        f'<div class="alert sev-{html.escape(a["severity"])}">'
        f'<b>{html.escape(a["type"])}</b> · токен {html.escape(str(a.get("token", "")))} '
        f'· источник {html.escape(a.get("origin", ""))} → цель <b>{html.escape(a.get("target", ""))}</b> '
        f'<span class="ts">{html.escape(a["ts"][:19])}</span></div>'
        for a in alerts)
    return f'<section class="alerts-box"><h2>⚠ Алерты ({len(alerts)})</h2>{rows}</section>'


def render_graph(hosts, edges):
    pos = {'attacker': (70, 90), 'srv-web01': (300, 40), 'db-prod01': (300, 140), 'fs01': (540, 90)}
    nodes = ['attacker'] + [h for h in ('srv-web01', 'db-prod01', 'fs01') if h in hosts]
    # attacker always reaches the first web host; reuse edges come from alerts
    draw = {('attacker', 'srv-web01')} | set(edges)
    svg = ['<svg viewBox="0 0 640 190" width="100%" style="max-width:640px">',
           '<defs><marker id="a" markerWidth="9" markerHeight="9" refX="8" refY="3" orient="auto">'
           '<path d="M0,0 L0,6 L8,3 z" fill="#ff8f6b"/></marker></defs>']
    for src, dst in draw:
        if src in pos and dst in pos:
            x1, y1 = pos[src]
            x2, y2 = pos[dst]
            svg.append(f'<line x1="{x1+28}" y1="{y1}" x2="{x2-34}" y2="{y2}" stroke="#ff8f6b" '
                       f'stroke-width="2" marker-end="url(#a)"/>')
    for n in {p for edge in draw for p in edge} | set(nodes):
        if n not in pos:
            continue
        x, y = pos[n]
        fill = '#b23b3b' if n == 'attacker' else '#2d6cdf'
        svg.append(f'<rect x="{x-34}" y="{y-16}" width="68" height="32" rx="8" fill="{fill}"/>'
                   f'<text x="{x}" y="{y+5}" text-anchor="middle" font-size="11" fill="#fff">{n}</text>')
    svg.append('</svg>')
    return '<section><h2>Боковое перемещение</h2>' + ''.join(svg) + '</section>'


def render_matrix(seen):
    cols = []
    for tactic in TACTICS:
        techs = [(tid, meta) for tid, meta in CATALOG.items() if meta.get('tactic') == tactic]
        if not techs:
            continue
        cells = ''.join(
            f'<div class="tech {"hit" if tid in seen else ""}" title="{html.escape(meta["name"])}">{tid}</div>'
            for tid, meta in techs)
        cols.append(f'<div class="col"><h4>{html.escape(tactic)}</h4>{cells}</div>')
    return f'<section><h2>ATT&CK · покрытие ({len(seen)} техник)</h2><div class="matrix">{"".join(cols)}</div></section>'


@app.get('/', dependencies=[Depends(auth)])
def dashboard():
    camps = campaigns()
    with connection() as conn:
        alerts = collect_alerts(conn)
    seen = {t for c in camps for t in c['techniques']}
    hosts, edges = lateral_data(camps)
    esc = html.escape
    cards = []
    for c in camps:
        event_rows = ''.join(
            f'<tr><td>{esc(r["event"].get("@timestamp", ""))}</td>'
            f'<td>{esc(r["event"].get("honeypot", {}).get("name", ""))}</td>'
            f'<td>{esc(r["event"].get("event", {}).get("action", ""))}</td>'
            f'<td>{esc(", ".join(r["techniques"]))}</td>'
            f'<td>{esc(r["event"].get("process", {}).get("command_line", ""))}</td></tr>'
            for r in timeline(c['id']))
        reuse = len([a for a in c['alerts'] if a.get('type') == 'credential-reuse'])
        badge = f' <span class="badge">{reuse}× reuse</span>' if reuse else ''
        cards.append(
            f'<section><h2>{esc(c["source"])} · {c["count"]} событий{badge}</h2>'
            f'<p>{esc(c["start"])} → {esc(c["end"])}</p>'
            f'<p class="tags">{esc(" · ".join(c["techniques"]))}</p>'
            f'<details><summary>Таймлайн событий</summary><table>'
            f'<tr><th>Время UTC</th><th>Хост</th><th>Событие</th><th>ATT&CK</th><th>Команда</th></tr>'
            f'{event_rows}</table></details></section>')
    style = '''<style>
    body{font:16px system-ui;background:#101b2c;color:#e8f0ff;margin:0;padding:35px;max-width:1100px;margin:auto}
    h1{font-size:34px;margin-bottom:4px}h2{font-size:20px}
    section{background:#1c2c43;padding:20px 24px;border-radius:16px;margin:18px 0}
    .tags{color:#72dbcc}.intro{color:#9fb2cf}
    .alerts-box{background:#2a1c24;border:1px solid #4a2b35}
    .alert{padding:8px 0;border-bottom:1px solid #3a2730}.alert:last-child{border:0}
    .sev-high b{color:#ff6b6b}.sev-medium b{color:#ffc278}.ts{color:#88a;float:right;font-size:12px}
    .ok{color:#72dbcc}
    .badge{background:#b23b3b;color:#fff;font-size:12px;padding:2px 8px;border-radius:10px;vertical-align:middle}
    .matrix{display:flex;gap:10px;overflow-x:auto}.col{min-width:120px}.col h4{margin:0 0 6px;font-size:12px;color:#9fb2cf}
    .tech{background:#13203a;color:#5e7599;font-size:11px;padding:5px 6px;border-radius:5px;margin-bottom:4px}
    .tech.hit{background:#1f6f52;color:#eafff4;font-weight:600}
    table{border-collapse:collapse;width:100%;font-size:12px}
    td,th{padding:9px;border-bottom:1px solid #345;text-align:left;overflow-wrap:anywhere}
    details{margin-top:14px}p{color:#afc1da}</style>'''
    head = ('<h1>Mirage · Таймлайн атак</h1>'
            '<p class="intro">Кампании: IP источника + 30-минутное окно. '
            'ATT&CK — гипотезы по наблюдаемым событиям, не доказательство компрометации.</p>')
    body = (render_alerts(alerts) + render_graph(hosts, edges) +
            render_matrix(seen) + ''.join(cards))
    return HTMLResponse('<!doctype html><html lang="ru"><meta charset="utf-8">'
                        '<title>Mirage — таймлайн атак</title>' + style + head + body + '</html>')


@app.get('/health')
def health():
    return {'status': 'ok'}
