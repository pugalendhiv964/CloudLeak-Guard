import html
import json

def findings_to_json(findings):
    return json.dumps(findings, indent=2, ensure_ascii=False)

def findings_to_html(findings):
    rows = []
    for f in findings:
        cells = [f.get(k, "") for k in ("severity", "title", "category", "file", "description", "remediation")]
        rows.append("<tr>" + "".join(f"<td>{html.escape(str(cell))}</td>" for cell in cells) + "</tr>")
    return """<!doctype html><html><head><meta charset="utf-8"><title>CloudLeak Guard report</title>
<style>body{font:15px Arial,sans-serif;margin:2rem;color:#222}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:8px;text-align:left;vertical-align:top}th{background:#f2f2f2}td{overflow-wrap:anywhere}</style>
</head><body><h1>CloudLeak Guard report</h1><p>Static prototype report. Validate findings before acting on them.</p>
<table><thead><tr><th>Severity</th><th>Finding</th><th>Category</th><th>File</th><th>Description</th><th>Suggested fix</th></tr></thead><tbody>""" + "".join(rows) + "</tbody></table></body></html>"

def _key(f):
    return (f.get("rule_id"), f.get("file"), f.get("title"))

def compare_findings(before, after):
    before_map = {_key(f): f for f in before}
    after_map = {_key(f): f for f in after}
    return {
        "resolved": [before_map[k] for k in before_map.keys() - after_map.keys()],
        "remaining": [after_map[k] for k in before_map.keys() & after_map.keys()],
        "introduced": [after_map[k] for k in after_map.keys() - before_map.keys()],
    }
