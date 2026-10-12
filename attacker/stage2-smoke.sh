#!/usr/bin/env bash
# Stage 2 smoke test, run on Kali in lab mode: every trap answers and looks like its fake host.
# Each section prints a "### name" header; scripts/termshot.py turns sections into README screenshots.
set -u
WEB=10.66.0.10 DB=10.66.0.20 FS=10.66.0.30
HERE="$(cd "$(dirname "$0")" && pwd)"
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5)

echo "### nmap"
echo "\$ nmap -sV -Pn -p 21,22,135,445,1433,3306,3389,5900,6379 $WEB $DB $FS"
nmap -sV -Pn -n --open -p 21,22,135,445,1433,3306,3389,5900,6379 $WEB $DB $FS \
  | grep -E "^Nmap scan report|^PORT|/tcp|Service Info"

echo "### hydra"
echo "\$ hydra -l root -P passwords-small.txt ssh://$WEB"
hydra -l root -P "$HERE/wordlists/passwords-small.txt" -t 4 -f "ssh://$WEB" 2>&1 | grep -E "\[22\]\[ssh\]|attempts|successfully|valid password"

echo "### ssh-web01"
echo "\$ sshpass -p 123456 ssh root@$WEB 'hostname; id; uname -a; cat /etc/os-release | head -2'"
sshpass -p 123456 ssh "${SSH_OPTS[@]}" root@$WEB 'hostname; id; uname -a; cat /etc/os-release | head -2' 2>&1

echo "### ssh-db01"
echo "\$ sshpass -p 123456 ssh root@$DB true   # weak creds must NOT work on db-prod01"
sshpass -p 123456 ssh "${SSH_OPTS[@]}" root@$DB true 2>&1 && echo "LOGGED IN (unexpected)" || echo "denied, exit=$?"

echo "### smb"
echo "\$ smbclient -L //$FS -N"
smbclient -L "//$FS" -N 2>&1 | head -15

echo "### misc"
echo "\$ redis AUTH / mysql login / rdp+vnc banners"
printf 'AUTH s3cr3t\r\nQUIT\r\n' | timeout 5 nc -n $DB 6379
mysql --skip-ssl -h $DB -u root -proot -e 'select 1' 2>&1 | head -1
echo -n "VNC banner: "; timeout 3 nc -n $DB 5900 </dev/null | head -c 12; echo
