#!/usr/bin/env bash
# Run on mirage: a throwaway container on each trap network must not reach the internet,
# the other traps or the management address.
DB_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' mirage-cowrie-db01-1)
echo "\$ check-isolation.sh   (probe container attached to each trap network)"
printf "%-16s %-26s %s\n" NETWORK TARGET RESULT

# positive control: proves the probe itself can see an open port
docker network create isotest >/dev/null
docker run -d --rm --name isotest-srv --network isotest alpine:3.20 nc -lk -p 9000 >/dev/null
sleep 1
if docker run --rm --network isotest alpine:3.20 nc -z -w 3 isotest-srv 9000 >/dev/null 2>&1; then
  r="OPEN  (control, expected)"; else r="blocked  <-- PROBE BROKEN"; fi
printf "%-16s %-26s %s\n" isotest "isotest-srv:9000" "$r"
docker rm -f isotest-srv >/dev/null; docker network rm isotest >/dev/null

for net in mirage_web01 mirage_canary mirage_fs01; do
  for target in "1.1.1.1:80" "$DB_IP:2222" "192.168.56.10:22"; do
    h=${target%:*} p=${target#*:}
    if docker run --rm --network $net alpine:3.20 nc -z -w 3 $h $p >/dev/null 2>&1; then r="OPEN  <-- LEAK"; else r="blocked"; fi
    printf "%-16s %-26s %s\n" $net "$target" "$r"
  done
done
