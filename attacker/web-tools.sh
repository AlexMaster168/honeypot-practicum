#!/usr/bin/env bash
set -eu
OUT=/tmp/mirage-tool-check
mkdir -p "$OUT"
printf 'admin\n.env\nbackup.sql.gz\n.git/HEAD\n' > "$OUT/paths.txt"
gobuster dir -u http://10.66.0.10 -w "$OUT/paths.txt" -t 2 --timeout 5s -q
timeout 45 sqlmap -u 'http://10.66.0.10/api/customers?id=1' --batch --level 1 --risk 1 --technique B --timeout 3 --retries 0 --threads 1 --output-dir "$OUT/sqlmap" || true
timeout 30 nikto -h http://10.66.0.10 -maxtime 25 || true
