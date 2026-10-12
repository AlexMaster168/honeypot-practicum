#!/usr/bin/env bash
# Run on mirage: what each trap logged about a given attacker IP (default: Kali).
SRC="${1:-10.66.0.50}"
D=/srv/mirage/data
echo "\$ trap-events.sh $SRC"
printf "%-14s %-8s %s\n" TRAP EVENTS "TOP EVENT TYPES"
for t in web01 db01; do
  f=$D/cowrie-$t/log/cowrie/cowrie.json
  n=$(sudo jq -c "select(.src_ip==\"$SRC\")" $f 2>/dev/null | wc -l)
  top=$(sudo jq -r "select(.src_ip==\"$SRC\") | .eventid" $f 2>/dev/null | sort | uniq -c | sort -rn | head -4 | awk '{printf "%s=%s ",$2,$1}')
  printf "%-14s %-8s %s\n" "cowrie-$t" "$n" "$top"
done
f=$D/opencanary/opencanary.json
n=$(sudo jq -c "select(.src_host==\"$SRC\")" $f | wc -l)
top=$(sudo jq -r "select(.src_host==\"$SRC\") | .dst_port" $f | sort | uniq -c | sort -rn | awk '{printf "port%s=%s ",$2,$1}')
printf "%-14s %-8s %s\n" opencanary "$n" "$top"
f=$D/dionaea/log/dionaea.json
n=$(sudo jq -c "select(.src_ip==\"$SRC\")" $f | wc -l)
top=$(sudo jq -r "select(.src_ip==\"$SRC\") | \"\(.connection.protocol // \"?\")\"" $f | sort | uniq -c | sort -rn | head -4 | awk '{printf "%s=%s ",$2,$1}')
printf "%-14s %-8s %s\n" dionaea "$n" "$top"
echo
echo "\$ last successful logins (cowrie):"
sudo jq -r "select(.eventid==\"cowrie.login.success\") | \"\(.timestamp[0:19])  \(.src_ip) -> \(.sensor // \"?\")  \(.username):\(.password)\"" \
  $D/cowrie-*/log/cowrie/cowrie.json | tail -3
echo "\$ commands typed (cowrie):"
sudo jq -r "select(.eventid==\"cowrie.command.input\") | \"\(.timestamp[11:19])  \(.input)\"" $D/cowrie-web01/log/cowrie/cowrie.json | tail -5
