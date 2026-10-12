from pathlib import Path
import subprocess
import re
import yaml

config = yaml.safe_load(Path('/etc/suricata/suricata.yaml').read_text())
config['vars']['address-groups']['HOME_NET'] = '[10.66.0.0/24]'
config['default-rule-path'] = '/var/lib/suricata/rules'
config['rule-files'] = ['suricata.rules', '/etc/suricata/rules/mirage.rules']
config['af-packet'] = [{'interface': 'honeynet', 'cluster-id': 99, 'cluster-type': 'cluster_flow', 'defrag': True}]
tls = config['app-layer']['protocols']['tls']
tls['ja3-fingerprints'] = True
# JA4 is enabled only on versions whose packaged configuration supports it.
version = subprocess.check_output(['suricata', '--build-info'], text=True).splitlines()[0]
if int(re.search(r'version (\d+)', version).group(1)) >= 8:
    tls['ja4-fingerprints'] = True
for output in config['outputs']:
    if 'eve-log' in output:
        eve = output['eve-log']
        eve['enabled'] = True
        eve['filename'] = 'eve.json'
        eve['filemode'] = '644'
        eve['types'] = ['alert', {'tls': {'extended': True}}, 'http', 'flow']
path = Path('/etc/suricata/mirage.yaml')
text = '%YAML 1.1\n---\n' + yaml.safe_dump(config, sort_keys=False)
if not path.exists() or path.read_text() != text:
    path.write_text(text)
    print('changed')
else:
    print('present')
print(subprocess.check_output(['suricata', '--build-info'], text=True).splitlines()[0])
