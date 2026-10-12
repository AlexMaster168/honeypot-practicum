"""A simulated business portal. All leaked data is synthetic; no code is executed."""
import asyncio
import gzip
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
DATA = Path(os.getenv('SEEDS', '/seeds'))
LOG = Path(os.getenv('WEB_LOG', '/logs/web.json'))
TOOLS = ('sqlmap', 'nikto', 'gobuster', 'ffuf', 'nmap', 'hydra', 'wpscan')
HOME = '''<!doctype html><html lang="ru"><meta charset="utf-8"><title>Рога и Копыта — сотрудники</title>
<style>body{font:18px system-ui;background:#edf2f8;color:#152740;margin:0}header{background:#152740;color:white;padding:30px}main{max-width:850px;margin:45px auto;padding:25px;background:white;border-radius:15px}a{color:#126da0}input,button{padding:12px;margin:7px}footer{color:#778;margin-top:40px}</style>
<header>Рога и Копыта · Корпоративный портал</header><main><h1>Рабочее пространство</h1><p>Новости, заявки и справочники для сотрудников.</p>
<h2>Объявления</h2><p>Плановое обслуживание сервера резервных копий — пятница, 22:00.</p><p>Согласуйте доступ к архивам с отделом ИТ.</p>
<a href="/admin">Вход для сотрудников</a><footer>ИТ-служба · srv-web01 · build 2024.11</footer></main></html>'''

def detect_tool(ua: str) -> str:
    return next((name for name in TOOLS if name in ua.lower()), 'unknown')

def probe_kind(text: str) -> str:
    from urllib.parse import unquote_plus
    text = unquote_plus(text)
    if re.search(r"(?i)(union\s+select|or\s+1\s*=\s*1|sleep\s*\(|'\s*or\s*')", text):
        return 'sqli-probe'
    if re.search(r'(?i)(\$\(|;\s*(id|cat|wget|curl)|/etc/passwd|\.\./)', text):
        return 'command-probe'
    return 'http-request'

@app.middleware('http')
async def record(request: Request, call_next):
    ua = request.headers.get('user-agent', '')[:1024]
    tool = detect_tool(ua)
    response = await call_next(request)
    body = getattr(request.state, 'submitted', {})
    event = {'timestamp': datetime.now(timezone.utc).isoformat(), 'src_ip': request.client.host,
             'method': request.method, 'path': request.url.path[:2048], 'query': request.url.query[:4096],
             'status': response.status_code, 'tool': tool, 'user_agent': ua,
             'action': probe_kind(request.url.query), **body}
    if request.url.path in ('/.env', '/backup.sql.gz') or request.url.path.startswith('/.git/'):
        event['action'] = 'decoy-read'
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open('a') as f:
        f.write(json.dumps(event) + '\n')
    # A bounded delay is applied only to clearly labelled scanner traffic.
    if tool != 'unknown':
        await asyncio.sleep(0.15)
    response.headers['Server'] = 'nginx/1.22.1'
    return response

@app.get('/')
def home():
    return HTMLResponse(HOME)

@app.get('/admin')
def login_page():
    return HTMLResponse(HOME.replace('<h1>Рабочее пространство</h1>',
        '<h1>Вход для сотрудников</h1><form method="post"><input name="username" placeholder="Логин"><input name="password" type="password" placeholder="Пароль"><button>Войти</button></form>'))

@app.post('/admin')
async def login(request: Request):
    from urllib.parse import parse_qs
    from html import escape
    # Avoid unbounded request buffering; scanners can submit arbitrary bodies.
    body = bytearray()
    async for part in request.stream():
        body.extend(part)
        if len(body) > 8192:
            return Response(status_code=413)
    fields = parse_qs(body.decode(errors='replace'))
    user = fields.get('username', [''])[0][:256]
    pwd = fields.get('password', [''])[0][:256]
    request.state.submitted = {'username': user, 'password': pwd, 'action': 'web-login-failed'}
    return HTMLResponse(f'<h1>Вход не выполнен</h1><p>Проверьте учётные данные: {escape(user)}</p>', status_code=401)

@app.get('/.env')
def environment():
    return Response((DATA / 'web.env').read_bytes(), media_type='text/plain')

@app.get('/backup.sql.gz')
def backup():
    return Response(gzip.compress(b'-- synthetic training backup\nCREATE TABLE customers(id INT, name TEXT);\n'), media_type='application/gzip')

@app.get('/.git/{item:path}')
def fake_git(item: str):
    root = (DATA / 'repo' / '.git').resolve()
    path = (root / item).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        return Response(status_code=404)
    return Response(path.read_bytes(), media_type='application/octet-stream')

@app.get('/api/customers')
def customers(request: Request):
    if probe_kind(request.url.query) == 'sqli-probe':
        return JSONResponse({'error': "SQL syntax near SELECT (MariaDB 10.11)", 'rows': []}, status_code=500)
    return {'rows': [{'id': 1, 'name': 'Training Customer'}]}

@app.get('/health')
def health():
    return {'status': 'ok'}
