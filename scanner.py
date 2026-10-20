from pathlib import Path
import json
import re
import shutil
import subprocess

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

def _finding(rule_id, title, severity, category, file, description, remediation):
    return {
        "rule_id": rule_id, "title": title, "severity": severity,
        "category": category, "file": str(file), "description": description,
        "remediation": remediation,
    }

def custom_scan(root: Path):
    findings = []
    tf_files = sorted(root.rglob("*.tf"))
    for path in tf_files:
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        relative = str(path.relative_to(root))
        # Intentionally conservative text-based checks for a beginner prototype.
        if re.search(r'(?s)from_port\s*=\s*22.*?to_port\s*=\s*22.*?cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]', source) or re.search(r'(?s)cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\].*?from_port\s*=\s*22.*?to_port\s*=\s*22', source):
            findings.append(_finding(
                "CLG-AWS-SSH-OPEN", "SSH exposed to the internet", "High", "Security", relative,
                "A Terraform text pattern suggests port 22 may be open to 0.0.0.0/0. Verify the security-group rule and its scope.",
                "Restrict SSH to a trusted IP range or use a managed access method such as a bastion or session service."
            ))
        # Check S3 bucket resource blocks for a simple missing-encryption heuristic.
        for match in re.finditer(r'resource\s+"aws_s3_bucket"\s+"([^"]+)"\s*\{', source):
            start = match.start()
            next_resource = re.search(r'\nresource\s+"', source[match.end():])
            end = match.end() + next_resource.start() if next_resource else len(source)
            block = source[start:end]
            if "server_side_encryption_configuration" not in block:
                findings.append(_finding(
                    "CLG-AWS-S3-ENCRYPTION", "S3 encryption configuration not found", "Medium", "Security", relative,
                    f"Bucket resource '{match.group(1)}' does not visibly configure server-side encryption in this resource block. Encryption may be configured elsewhere or by provider defaults.",
                    "Explicitly configure server-side encryption and verify the effective bucket encryption settings."
                ))
        # Tag heuristic for selected resource blocks.
        for match in re.finditer(r'resource\s+"(aws_instance|aws_s3_bucket)"\s+"([^"]+)"\s*\{', source):
            start = match.start()
            next_resource = re.search(r'\nresource\s+"', source[match.end():])
            end = match.end() + next_resource.start() if next_resource else len(source)
            block = source[start:end]
            missing = [tag for tag in ("Environment", "Owner") if not re.search(rf'["\']?{tag}["\']?\s*=', block)]
            if missing:
                findings.append(_finding(
                    "CLG-TAGS-REQUIRED", "Required ownership tags may be missing", "Low", "Governance", relative,
                    f"Resource '{match.group(2)}' does not visibly define these policy tags: {', '.join(missing)}.",
                    "Add Environment and Owner tags according to your team's tagging policy."
                ))
        # Policy-based cost risk only: no price or savings claim.
        if re.search(r'instance_type\s*=\s*"[^"]*(?:\.24xlarge|\.16xlarge|\.12xlarge|\.8xlarge)"', source):
            findings.append(_finding(
                "CLG-COST-LARGE-INSTANCE", "Large compute instance needs review", "Medium", "Cost policy", relative,
                "A large instance size matched the prototype's review heuristic. Whether it is wasteful depends on workload, region, and duration.",
                "Confirm the workload needs this size; consider a smaller approved type for development and test environments."
            ))
    return tf_files, findings

def checkov_scan(root: Path):
    executable = shutil.which("checkov")
    if not executable:
        return [], "not installed"
    try:
        proc = subprocess.run(
            [executable, "-d", str(root), "--framework", "terraform", "-o", "json", "--quiet"],
            capture_output=True, text=True, timeout=120, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [], f"error: {exc}"
    raw = proc.stdout.strip()
    if not raw:
        return [], "ran; no JSON output"
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return [], "ran; output could not be parsed"
    normalized = []
    blocks = data if isinstance(data, list) else [data]
    for block in blocks:
        if not isinstance(block, dict):
            continue
        for item in block.get("results", {}).get("failed_checks", []) or []:
            check_id = str(item.get("check_id", "CHECKOV"))
            level = str(item.get("severity") or "MEDIUM").upper()
            severity = {"CRITICAL":"Critical","HIGH":"High","MEDIUM":"Medium","LOW":"Low","INFO":"Info"}.get(level, "Medium")
            file_path = str(item.get("file_path") or "Terraform file")
            normalized.append(_finding(
                check_id, str(item.get("check_name") or check_id), severity, "Checkov", file_path,
                str(item.get("guideline") or item.get("description") or "Checkov reported a failed Terraform policy check."),
                "Review the Checkov guideline and update the Terraform configuration; re-scan after making the change."
            ))
    return normalized, f"ran (exit code {proc.returncode})"

def scan_directory(root, run_checkov=True):
    root = Path(root)
    files, findings = custom_scan(root)
    checkov_status = "disabled"
    if run_checkov:
        extra, checkov_status = checkov_scan(root)
        findings.extend(extra)
    # Deduplicate by stable identity.
    unique = {}
    for item in findings:
        key = (item["rule_id"], item["file"], item["title"])
        unique[key] = item
    result = sorted(unique.values(), key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["file"], f["title"]))
    return result, {"files_checked": len(files), "checkov": checkov_status}
