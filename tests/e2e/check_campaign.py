"""Run on mirage: ensure an actual campaign has >=8 candidate techniques and token reuse."""
import base64
import json
import urllib.request
from pathlib import Path

values = dict(line.split('=', 1) for line in Path('/opt/mirage/stack/.env').read_text().splitlines())
auth = base64.b64encode(('analyst:' + values['CORRELATOR_KEY']).encode()).decode()
request = urllib.request.Request('http://192.168.56.10:8088/api/campaigns', headers={'Authorization': 'Basic ' + auth})
campaigns = json.load(urllib.request.urlopen(request, timeout=15))
matches = [c for c in campaigns if c['source'] == '10.66.0.50' and len(c['techniques']) >= 8 and any(a['type'] == 'credential-reuse' for a in c['alerts'])]
if not matches:
    raise SystemExit('FAIL: no complete campaign found; run attacker/run-all.sh in lab mode')
print(json.dumps(matches[0], indent=2))
es_auth = base64.b64encode(('elastic:' + values['ELASTIC_PASSWORD']).encode()).decode()
query = json.dumps({'query': {'term': {'id.keyword': matches[0]['id']}}}).encode()
es_request = urllib.request.Request('http://localhost:9200/mirage-campaigns-lab/_search', data=query,
    headers={'Authorization': 'Basic ' + es_auth, 'Content-Type': 'application/json'})
# Elasticsearch intentionally has no host-published port. Probe through its container instead.
import subprocess
probe = ['docker', 'exec', '-i', 'mirage-elasticsearch-1', 'sh', '-c',
         'curl -fsS -u "elastic:$ELASTIC_PASSWORD" -H "Content-Type: application/json" http://localhost:9200/mirage-campaigns-lab/_search --data-binary @-']
found = json.loads(subprocess.check_output(probe, input=query))
assert found['hits']['total']['value'] >= 1, 'Campaign missing in Elasticsearch'
print('PASS: campaign stored in Elasticsearch, >=8 techniques, credential reuse detected')
