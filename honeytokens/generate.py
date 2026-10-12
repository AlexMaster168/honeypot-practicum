"""Generate synthetic bait once. Run on mirage, never on a real service."""
import argparse
import json
import pickle
import secrets
import stat
import subprocess
import time
from pathlib import Path

def insert(tree, path, data):
    parts = path.strip('/').split('/')
    node = tree
    for part in parts[:-1]:
        child = next((c for c in node[7] if c[0] == part), None)
        if child is None:
            child = [part, 1, 0, 0, 4096, stat.S_IFDIR | 0o755, time.time(), [], None, None]
            node[7].append(child)
        if child[1] != 1:
            raise ValueError(f'non-directory in seed path: {path}')
        node = child
    node[7][:] = [c for c in node[7] if c[0] != parts[-1]]
    node[7].append([parts[-1], 2, 0, 0, len(data), stat.S_IFREG | 0o644, time.time(), data, None, None])

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', default='/opt/mirage/stack/seeds')
    ap.add_argument('--base', required=True)
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    registry = out / 'registry.yml'
    if registry.exists():
        tokens = json.loads(registry.read_text())
    else:
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'deploy@training', '-f', str(out / 'deploy_key')], check=True)
        tokens = [
            {'id': 'T1', 'value': secrets.token_hex(16), 'origin': 'srv-web01:/root/.bash_history'},
            {'id': 'T2', 'value': secrets.token_hex(16), 'origin': 'srv-web01:/var/www/.env'},
            {'id': 'T3', 'value': 'AKIA' + secrets.token_hex(10).upper()[:16], 'origin': 'srv-web01:/.env (synthetic AWS ID)'},
            {'id': 'T4', 'value': (out / 'deploy_key.pub').read_text().split()[1], 'origin': 'srv-web01:/.git history/deploy_key'},
        ]
        registry.write_text(json.dumps(tokens, indent=2))
    t = {x['id']: x['value'] for x in tokens}
    env = f'APP_ENV=production\nDB_HOST=10.66.0.20\nDB_USER=backup\nDB_PASSWORD={t["T2"]}\nAWS_ACCESS_KEY_ID={t["T3"]}\n'
    (out / 'web.env').write_text(env)
    repo = out / 'repo'
    if not (repo / '.git').exists():
        repo.mkdir(exist_ok=True)
        subprocess.run(['git', 'init', '-q', str(repo)], check=True)
        (repo / 'deploy_key').write_bytes((out / 'deploy_key').read_bytes())
        (repo / 'README.md').write_text('Deploy to deploy@10.66.0.20\n')
        git = ['git', '-C', str(repo), '-c', 'user.name=Training', '-c', 'user.email=training@example.invalid']
        subprocess.run(git + ['add', '.'], check=True)
        subprocess.run(git + ['commit', '-qm', 'Initial deployment'], check=True)
        (repo / 'deploy_key').unlink()
        subprocess.run(git + ['add', '-u'], check=True)
        subprocess.run(git + ['commit', '-qm', 'Remove key from current checkout'], check=True)
        subprocess.run(git + ['update-server-info'], check=True)
    os_release = b'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nNAME="Debian GNU/Linux"\nVERSION_ID="12"\n'
    for host in ('web01', 'db01'):
        tree = pickle.loads(Path(args.base).read_bytes()) # only bundled trusted Cowrie data
        insert(tree, '/etc/os-release', os_release)
        if host == 'web01':
            insert(tree, '/root/.bash_history', f"ssh backup@10.66.0.20\n# backup password: {t['T1']}\nmysql -h 10.66.0.20 -u backup -p'{t['T1']}'\n".encode())
            insert(tree, '/var/www/.env', env.encode())
        else:
            customers = b'id,name,email\n1,Training Customer,customer@example.invalid\n'
            readme = b'Archive: \\10.66.0.30\\Backups\nFinance share is on fs01.\n'
            # Place the bait in each user's login cwd. The Debian "backup" system user
            # lands in /var/backups, not /home/backup, so the attacker's relative
            # `cat customers.csv` only works if the file is there too.
            for home in ('/var/backups', '/home/backup', '/home/deploy', '/root'):
                insert(tree, f'{home}/customers.csv', customers)
                insert(tree, f'{home}/README.txt', readme)
        (out / f'{host}.pickle').write_bytes(pickle.dumps(tree))
    (out / 'db-userdb.txt').write_text(f"backup:x:{t['T1']}\n")
    print('Synthetic seeds ready (values omitted)')

if __name__ == '__main__':
    main()
