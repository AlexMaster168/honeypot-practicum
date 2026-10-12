#!/usr/bin/env bash
set -euo pipefail
echo '=== Containers ==='
docker ps --format '{{.Names}} {{.Status}}'
echo '=== Elasticsearch ==='
docker exec mirage-elasticsearch-1 sh -c 'curl -fsS -u "elastic:$ELASTIC_PASSWORD" http://localhost:9200/_cluster/health'
echo
docker exec mirage-elasticsearch-1 sh -c 'curl -fsS -u "elastic:$ELASTIC_PASSWORD" "http://localhost:9200/mirage-events-*/_count"'
echo
docker exec mirage-elasticsearch-1 sh -c 'curl -fsS -u "elastic:$ELASTIC_PASSWORD" "http://localhost:9200/mirage-events-*/_search?size=1"'
echo
echo '=== Vector ==='
docker logs --tail 15 mirage-vector-1 2>&1
