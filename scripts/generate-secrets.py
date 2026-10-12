"""Run on mirage as root. Keep management credentials outside the shared project."""
import os
import secrets
from pathlib import Path

out = Path('/opt/mirage/stack/.env')
out.parent.mkdir(parents=True, exist_ok=True)
old = out.read_text() if out.exists() else ''
names = ('ELASTIC_PASSWORD', 'KIBANA_PASSWORD', 'VECTOR_PASSWORD', 'KIBANA_KEY', 'CORRELATOR_KEY')
missing = [name for name in names if not any(line.startswith(name + '=') for line in old.splitlines())]
if missing:
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, 'w') as f:
        for name in missing:
            f.write(f'{name}={secrets.token_hex(24)}\n')
    print('created')
else:
    print('present')
