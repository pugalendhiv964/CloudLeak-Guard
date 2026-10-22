import json
from datetime import datetime, timezone
from html import escape

def _normalize_file(value):
    return str(value or "").replace("\\\\", "/").lstrip("./")

def _normalize_finding(item):
    item = dict(item)
    item["file"] = _normalize_file(item.get("file", ""))
    item.setdefault("resource", "")
    item.setdefault("rule_id", "UNKNOWN")
    item.setdefault("title", item["rule_id"])
    item.setdefault("severity", "Info")
    item.setdefault("message", "")
    item.setdefault("recommendation", "")
    item.setdefault("source", "Unknown")
    return item

def _summary(findings):
    result = {"total": len(findings), "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for item in findings:
        severity = item.get("severity", "Info")
        result[severity if severity in result else "Info"] += 1
    return result

def build_report(findings, scan_info=None, target="Terraform"):
    normalized = [_normalize_finding(item) for item in findings]
    return {
        "report_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": str(target),
        "summary": _summary(normalized),
        "scan_info": scan_info or {},
        "findings": normalized,
    }

def report_to_json(report):
    return json.dumps(report, indent=2, ensure_ascii=False)

def report_to_html(report):
    findings = [_normalize_finding(item) for item in report.get("findings", [])]
    summary = report.get("summary") or _summary(findings)
    summary_html = "".join(f"<li><strong>{escape(str(k))}:</strong> {v}</li>" for k, v in summary.items())
    rows = []
    for item in findings:
        keys = ("severity", "rule_id", "title", "file", "resource", "message", "recommendation")
        cells = "".join(f"<td>{escape(str(item.get(k, '')))}</td>" for k in keys)
        rows.append(f"<tr>{cells}</tr>")
    if not rows:
        rows = ['<tr><td colspan="7">No findings reported.</td></tr>']
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>CloudLeak Guard Report</title>
<style>
body{{font-family:Arial,sans-serif;max-width:1400px;margin:32px auto;padding:0 18px;color:#172033}}
table{{border-collapse:collapse;width:100%;font-size:14px}}th,td{{border:1px solid #d7dce5;padding:10px;text-align:left;vertical-align:top;overflow-wrap:anywhere}}
th{{background:#eef2f7}}tr:nth-child(even){{background:#fafbfc}}.note{{padding:12px;border:1px solid #d7dce5;border-radius:8px;margin:18px 0}}
</style></head><body><h1>CloudLeak Guard</h1><p>Static Terraform security scan report</p>
<div class="note"><strong>Target:</strong> {escape(str(report.get('target', 'Terraform')))}<br>
<strong>Generated:</strong> {escape(str(report.get('generated_at', 'Unknown')))}<br>
This report is an aid to review, not a guarantee that the configuration is secure.</div>
<h2>Summary</h2><ul>{summary_html}</ul><h2>Findings</h2>
<table><thead><tr><th>Severity</th><th>Rule</th><th>Title</th><th>File</th><th>Resource</th><th>Message</th><th>Recommendation</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></body></html>"""

def _extract_findings(report):
    if isinstance(report, list):
        return [_normalize_finding(x) for x in report if isinstance(x, dict)]
    if isinstance(report, dict) and isinstance(report.get("findings", []), list):
        return [_normalize_finding(x) for x in report.get("findings", []) if isinstance(x, dict)]
    raise ValueError("Report must be a JSON object containing findings or a list of findings.")

def _key(item):
    return item.get("fingerprint") or "|".join(str(item.get(k, "")) for k in ("source", "rule_id", "file", "resource", "title"))

def compare_reports(previous_report, current_report):
    old = {_key(x): x for x in _extract_findings(previous_report)}
    new = {_key(x): x for x in _extract_findings(current_report)}
    return {
        "resolved": [old[k] for k in sorted(old.keys() - new.keys())],
        "remaining": [new[k] for k in sorted(old.keys() & new.keys())],
        "introduced": [new[k] for k in sorted(new.keys() - old.keys())],
        "note": "Resolved means absent from the current report, not independently verified as fixed.",
    }

# Backward compatibility for existing tests and code
def compare_findings(previous_findings, current_findings):
    result = compare_reports(previous_findings, current_findings)

    return {
        "resolved": result["resolved"],
        "remaining": result["remaining"],
        "introduced": result["introduced"],
    }
