#!/bin/sh
set -eu
api() {
  curl -fsS -u "elastic:$ELASTIC_PASSWORD" -H 'Content-Type: application/json' "$@"
}
api -X POST http://elasticsearch:9200/_security/user/kibana_system/_password -d "{\"password\":\"$KIBANA_PASSWORD\"}"
api -X PUT http://elasticsearch:9200/_security/role/mirage_ingest -d '{"cluster":["monitor"],"indices":[{"names":["mirage-events-*","mirage-campaigns-*"],"privileges":["create_index","write","view_index_metadata"]}]}'
api -X PUT http://elasticsearch:9200/_security/user/vector_writer -d "{\"password\":\"$VECTOR_PASSWORD\",\"roles\":[\"mirage_ingest\"]}"
api -X PUT http://elasticsearch:9200/_index_template/mirage --data-binary @/tpl.json
api -X PUT http://elasticsearch:9200/_index_template/mirage-campaigns -d '{"index_patterns":["mirage-campaigns-*"],"template":{"settings":{"number_of_shards":1,"number_of_replicas":0}}}'
echo ' Security users and index template ready'
