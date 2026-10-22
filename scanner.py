import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}


def _fingerprint(rule_id, file_name, resource=""):
    normalized_file = str(file_name).replace("\\", "/").lstrip("./")
    raw = f"{rule_id}|{normalized_file}|{resource}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _blocks(text, keyword):
    """Extract balanced HCL-style blocks; this is not a complete HCL parser."""
    pattern = re.compile(
        rf'\b{re.escape(keyword)}\s+"([^"]+)"\s+"([^"]+)"\s*\{{',
        re.IGNORECASE,
    )
    results = []
    for match in pattern.finditer(text):
        start = match.end()
        depth, quote, escaped, i = 1, None, False, start
        while i < len(text) and depth:
            char = text[i]
            if quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
            else:
                if char in ('"', "'"):
                    quote = char
                elif char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
            i += 1
        if depth == 0:
            results.append({"type": match.group(1), "name": match.group(2), "body": text[start:i - 1]})
    return results


def _attribute(body, name):
    match = re.search(
        rf'(?m)^\s*{re.escape(name)}\s*=\s*(?:"([^"]*)"|([^\s#]+))',
        body,
    )
    if not match:
        return None
    return match.group(1) if match.group(1) is not None else match.group(2)


def _has_tags(body):
    match = re.search(r"\btags\s*=\s*\{([^}]*)\}", body, re.DOTALL)
    if not match:
        return False
    tags = match.group(1)
    return all(
        re.search(rf"""["']?{tag}["']?\s*=""", tags, re.IGNORECASE)
        for tag in ("Environment", "Owner")
    )


def _finding(rule_id, title, severity, file_name, resource, message, recommendation, source="CloudLeak Guard"):
    return {
        "rule_id": rule_id, "title": title, "severity": severity,
        "file": file_name, "resource": resource, "message": message,
        "recommendation": recommendation, "source": source,
        "fingerprint": _fingerprint(rule_id, file_name, resource),
    }


def _custom_scan(text, relative_file):
    findings = []
    resources = _blocks(text, "resource")

    encrypted_buckets = set()
    for item in resources:
        if item["type"] == "aws_s3_bucket_server_side_encryption_configuration":
            bucket_ref = _attribute(item["body"], "bucket")
            if bucket_ref:
                encrypted_buckets.add(bucket_ref.strip())

    for item in resources:
        resource_type, name, body = item["type"], item["name"], item["body"]
        resource_id = f"{resource_type}.{name}"

        if resource_type == "aws_security_group":
            for ingress in re.finditer(r"\bingress\s*\{", body, re.IGNORECASE):
                start = ingress.end()
                depth, i = 1, start
                while i < len(body) and depth:
                    if body[i] == "{":
                        depth += 1
                    elif body[i] == "}":
                        depth -= 1
                    i += 1
                if depth:
                    continue
                rule_body = body[start:i - 1]
                from_port = _attribute(rule_body, "from_port")
                to_port = _attribute(rule_body, "to_port")
                cidr_match = re.search(r"\bcidr_blocks\s*=\s*\[([^\]]*)\]", rule_body, re.DOTALL)
                cidrs = cidr_match.group(1) if cidr_match else ""
                if (from_port == "22" or to_port == "22") and re.search(r"""["']0\.0\.0\.0/0["']""", cidrs):
                    findings.append(_finding(
                        "CLG001", "SSH exposed to the internet", "High", relative_file,
                        resource_id, "An ingress rule appears to allow SSH from any IPv4 address.",
                        "Restrict SSH to trusted IP addresses or use a secure management service.",
                    ))

        if resource_type == "aws_s3_bucket":
            bucket_refs = {f"aws_s3_bucket.{name}.id", f"aws_s3_bucket.{name}.arn"}
            if not (bucket_refs & encrypted_buckets):
                findings.append(_finding(
                    "CLG002", "S3 encryption needs verification", "Medium", relative_file,
                    resource_id, "No matching separate S3 encryption configuration was detected.",
                    "Verify that server-side encryption is configured. Review related Terraform resources before treating this as a confirmed issue.",
                ))

        if resource_type in {"aws_instance", "aws_s3_bucket"} and not _has_tags(body):
            findings.append(_finding(
                "CLG003", "Required resource tags may be missing", "Low", relative_file,
                resource_id, "The resource block does not visibly define both Environment and Owner tags.",
                "Add the tags required by your policy, or review whether tags are supplied elsewhere.",
            ))

        if resource_type == "aws_instance":
            instance_type = _attribute(body, "instance_type")
            if instance_type and re.search(
    r"^(?:[a-z]+)?(?:[2-9]\d|[1-9]\d{2,})?xlarge$|^(?:[a-z]+\d+\.)?\d+xlarge$|\.metal$",
    instance_type,
    re.IGNORECASE,
):
                findings.append(_finding(
                    "CLG004", "Large EC2 instance type", "Low", relative_file, resource_id,
                    f"Instance type '{instance_type}' may have a high cost.",
                    "Confirm that this instance size is necessary for the workload and budget.",
                ))
    return findings


def _run_checkov(directory):
    executable = shutil.which("checkov")
    if not executable:
        return [], "Checkov is not installed; custom rules only."
    try:
        result = subprocess.run(
            [executable, "-d", str(directory), "--framework", "terraform", "-o", "json", "--quiet", "--soft-fail"],
            capture_output=True, text=True, timeout=120, check=False,
        )
        output = result.stdout.strip()
        if not output:
            return [], "Checkov returned no JSON output; custom rules only."
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return [], "Checkov output could not be parsed; custom rules only."
        reports = data if isinstance(data, list) else [data]
        findings = []
        for report in reports:
            if not isinstance(report, dict):
                continue
            results = report.get("results", {})
            if not isinstance(results, dict):
                continue
            for item in results.get("failed_checks", []):
                if not isinstance(item, dict):
                    continue
                check_id = item.get("check_id", "CHECKOV")
                file_name = str(item.get("file_path", "")).replace("\\", "/")
                resource = item.get("resource", "")
                severity = str(item.get("severity") or "Medium").capitalize()
                if severity not in SEVERITY_ORDER:
                    severity = "Medium"
                findings.append({
                    "rule_id": check_id,
                    "title": item.get("check_name", check_id),
                    "severity": severity,
                    "file": file_name,
                    "resource": resource,
                    "message": item.get("check_name", "Checkov check failed."),
                    "recommendation": item.get("guideline") or "Review the Checkov check and remediation guidance.",
                    "source": "Checkov",
                    "fingerprint": _fingerprint(check_id, file_name, resource),
                })
        return findings, "Checkov scan completed."
    except subprocess.TimeoutExpired:
        return [], "Checkov timed out; custom rules only."
    except OSError:
        return [], "Checkov could not run; custom rules only."


def scan_directory(directory):
    directory = Path(directory)
    tf_files = sorted(directory.rglob("*.tf"))
    findings = []
    for file_path in tf_files:
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
            relative_file = file_path.relative_to(directory).as_posix()
            findings.extend(_custom_scan(text, relative_file))
        except OSError:
            continue

    checkov_findings, checkov_status = _run_checkov(directory)
    findings.extend(checkov_findings)
    unique = {}
    for finding in findings:
        key = (finding.get("rule_id"), str(finding.get("file", "")).replace("\\", "/"), finding.get("resource", ""))
        unique[key] = finding

    findings = sorted(unique.values(), key=lambda item: (
        SEVERITY_ORDER.get(item.get("severity"), 4),
        item.get("file", ""), item.get("rule_id", ""), item.get("resource", ""),
    ))
    info = {
        "files_scanned": len(tf_files),
        "checkov_status": checkov_status,
        "scanner": "CloudLeak Guard",
        "notes": [
            "Custom rules are heuristic checks, not a complete Terraform/HCL parser.",
            "Related Terraform resources may affect whether a finding is a true issue.",
            "Checkov findings appear only when Checkov is installed and returns valid JSON.",
            "A clean scan is not proof that a configuration is secure.",
        ],
    }
    return findings, info


def custom_scan(source, relative_file="main.tf"):
    from pathlib import Path

    path = Path(source) if isinstance(source, (str, Path)) else None

    # Support the folder-based interface used by older tests.
    if path is not None and path.is_dir():
        findings = []
        tf_files = sorted(path.rglob("*.tf"))

        for file_path in tf_files:
            try:
                text = file_path.read_text(
                    encoding="utf-8",
                    errors="replace"
                )
                relative = file_path.relative_to(path).as_posix()
                findings.extend(_custom_scan(text, relative))
            except OSError:
                continue

        # Preserve legacy rule IDs expected by existing tests.
        legacy_ids = {
            "CLG001": "CLG-AWS-SSH-OPEN",
            "CLG002": "CLG-AWS-S3-ENCRYPTION",
            "CLG003": "CLG-TAGS-REQUIRED",
            "CLG004": "CLG-COST-LARGE-INSTANCE",
        }

        for finding in findings:
            finding["rule_id"] = legacy_ids.get(
                finding["rule_id"], finding["rule_id"]
            )

        return {"files_scanned": len(tf_files)}, findings

    if path is not None and path.is_file():
        text = path.read_text(encoding="utf-8", errors="replace")
        return {}, _custom_scan(text, path.name)

    return {}, _custom_scan(str(source), relative_file)
