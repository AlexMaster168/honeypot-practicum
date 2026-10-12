#!/usr/bin/env python3
"""Generate kibana-export.ndjson: a data view + an attack-overview dashboard.

Legacy agg-based visualizations are used on purpose: their visState is compact and
stable across Kibana 8.x, unlike by-value Lens panels. Import with:
  POST /api/saved_objects/_import?overwrite=true  (multipart, file=@kibana-export.ndjson)
"""
import json

DV_ID = "mirage-events"
INDEX_REF = [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
              "type": "index-pattern", "id": DV_ID}]
SEARCH_SOURCE = json.dumps({
    "query": {"query": "", "language": "kuery"},
    "filter": [],
    "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
})


def vis(vid, title, vis_state):
    return {
        "type": "visualization", "id": vid,
        "attributes": {
            "title": title, "description": "",
            "visState": json.dumps(vis_state), "uiStateJSON": "{}", "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": SEARCH_SOURCE},
        },
        "references": INDEX_REF, "version": "1",
    }


def terms(field, size=10, order_by="1", schema="bucket"):
    return {"id": "2", "enabled": True, "type": "terms", "schema": schema,
            "params": {"field": field, "orderBy": order_by, "order": "desc",
                       "size": size, "otherBucket": False, "missingBucket": False}}


count = {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}}

visuals = [
    vis("mirage-total", "Total events", {
        "title": "Total events", "type": "metric",
        "aggs": [count],
        "params": {"metric": {"metricColorMode": "None", "style": {"fontSize": 60}}}}),
    vis("mirage-by-dataset", "Events over time by trap", {
        "title": "Events over time by trap", "type": "histogram",
        "aggs": [count,
                 {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
                  "params": {"field": "@timestamp", "interval": "auto"}},
                 {"id": "3", "enabled": True, "type": "terms", "schema": "group",
                  "params": {"field": "event.dataset", "orderBy": "1", "order": "desc", "size": 5}}],
        "params": {"type": "histogram", "grid": {"categoryLines": False},
                   "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom",
                                     "show": True, "scale": {"type": "linear"}}],
                   "valueAxes": [{"id": "ValueAxis-1", "position": "left", "show": True,
                                  "scale": {"type": "linear", "mode": "normal"}}],
                   "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                                     "data": {"label": "Count", "id": "1"}, "valueAxis": "ValueAxis-1"}],
                   "legendPosition": "right"}}),
    vis("mirage-by-host", "Events by fake host", {
        "title": "Events by fake host", "type": "pie",
        "aggs": [count, terms("honeypot.name", 6, schema="segment")],
        "params": {"type": "pie", "isDonut": True, "legendPosition": "right", "labels": {"show": True}}}),
    vis("mirage-top-src", "Top attacker IPs", {
        "title": "Top attacker IPs", "type": "table",
        "aggs": [count, terms("source.ip", 15)], "params": {"perPage": 10, "showTotal": True}}),
    vis("mirage-top-creds", "Top credentials tried", {
        "title": "Top credentials tried", "type": "table",
        "aggs": [count,
                 {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
                  "params": {"field": "user.name", "orderBy": "1", "order": "desc", "size": 10}},
                 {"id": "3", "enabled": True, "type": "terms", "schema": "bucket",
                  "params": {"field": "user.password", "orderBy": "1", "order": "desc", "size": 10}}],
        "params": {"perPage": 10, "showTotal": True}}),
    vis("mirage-top-cmds", "Commands run in SSH", {
        "title": "Commands run in SSH", "type": "table",
        "aggs": [count, terms("process.command_line", 15)], "params": {"perPage": 10, "showTotal": True}}),
    vis("mirage-top-svc", "Targeted services", {
        "title": "Targeted services", "type": "table",
        "aggs": [count, terms("honeypot.service", 15)], "params": {"perPage": 10, "showTotal": True}}),
]

# Tables use Kibana's stable renderer for the total and time buckets.
for obj in visuals:
    if obj["id"] in ("mirage-total", "mirage-by-dataset"):
        state = json.loads(obj["attributes"]["visState"])
        state["type"] = "table"
        state["params"] = {"perPage": 10, "showTotal": False}
        for agg in state["aggs"]:
            if agg["schema"] in ("segment", "group"):
                agg["schema"] = "bucket"
        obj["attributes"]["visState"] = json.dumps(state)

# Dashboard grid: 48-col wide.
layout = [
    ("mirage-total",      0,  0, 12, 8),
    ("mirage-by-host",   12,  0, 12, 8),
    ("mirage-by-dataset",24,  0, 24, 8),
    ("mirage-top-src",    0,  8, 16, 12),
    ("mirage-top-creds", 16,  8, 16, 12),
    ("mirage-top-svc",   32,  8, 16, 12),
    ("mirage-top-cmds",   0, 20, 48, 12),
]
panels, refs = [], []
for i, (vid, x, y, w, h) in enumerate(layout):
    pref = f"panel_{i}"
    panels.append({"version": "8.15.0", "type": "visualization",
                   "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i)},
                   "panelIndex": str(i), "embeddableConfig": {}, "panelRefName": pref})
    refs.append({"name": f"{pref}", "type": "visualization", "id": vid})

dashboard = {
    "type": "dashboard", "id": "mirage-overview",
    "attributes": {
        "title": "Mirage - Attack Overview",
        "description": "Who hit the honeynet, with what creds, against which fake host.",
        "panelsJSON": json.dumps(panels),
        "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
        "timeRestore": True, "timeFrom": "now-24h", "timeTo": "now",
        "refreshInterval": {"pause": True, "value": 10000},
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})},
        "version": 1,
    },
    "references": refs, "version": "1",
}

data_view = {
    "type": "index-pattern", "id": DV_ID,
    "attributes": {"title": "mirage-events-*", "timeFieldName": "@timestamp",
                   "name": "mirage-events"},
    "references": [], "version": "1",
}

with open("kibana-export.ndjson", "w", encoding="utf-8", newline="\n") as f:
    for obj in [data_view, *visuals, dashboard]:
        obj.pop("version", None)
        obj["coreMigrationVersion"] = "8.15.3"
        obj["typeMigrationVersion"] = {"index-pattern": "7.11.0", "visualization": "8.3.0", "dashboard": "8.9.0"}[obj["type"]]
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")
print("wrote kibana-export.ndjson:", 2 + len(visuals), "objects")
