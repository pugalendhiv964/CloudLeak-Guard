import json
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
import streamlit as st
from scanner import scan_directory
from report_generator import build_report, report_to_json, report_to_html, compare_reports

st.set_page_config(page_title="CloudLeak Guard", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
.block-container {padding-top: 1.6rem; padding-bottom: 2rem;}
.hero {padding: 1.4rem 1.6rem; border: 1px solid rgba(128,128,128,.25); border-radius: 16px; margin-bottom: 1rem;}
div[data-testid="stMetric"] {border: 1px solid rgba(128,128,128,.2); padding: .8rem; border-radius: 12px;}
</style>
""", unsafe_allow_html=True)
st.markdown("""
<div class="hero">
<h1>🛡️ CloudLeak Guard</h1>
<div>Static security checks for Terraform configurations — before deployment.</div>
<div>No AWS infrastructure is created by this app.</div>
</div>
""", unsafe_allow_html=True)

with st.sidebar:
    st.header("Scan configuration")
    mode = st.radio("Choose input", ["Upload Terraform ZIP", "Use a sample"])
    st.caption("ZIP limits: 10 MB, 200 Terraform files, 1 MB per file.")
    st.caption("Do not upload secrets, credentials, or private keys.")

def safe_extract_tf_zip(uploaded, destination):
    payload = uploaded.getvalue()
    if len(payload) > 10 * 1024 * 1024:
        raise ValueError("ZIP exceeds the 10 MB upload limit.")
    count = total = 0
    root = Path(destination).resolve()
    try:
        with zipfile.ZipFile(uploaded) as archive:
            for info in archive.infolist():
                if info.is_dir() or not info.filename.lower().endswith(".tf"):
                    continue
                member = PurePosixPath(info.filename.replace("\\\\", "/"))
                if member.is_absolute() or ".." in member.parts:
                    raise ValueError("ZIP contains an unsafe file path.")
                count += 1
                if count > 200:
                    raise ValueError("ZIP contains more than 200 .tf files.")
                if info.file_size > 1024 * 1024:
                    raise ValueError(f"{info.filename} exceeds the 1 MB file limit.")
                total += info.file_size
                if total > 20 * 1024 * 1024:
                    raise ValueError("Combined Terraform files exceed 20 MB.")
                target = (root / Path(*member.parts)).resolve()
                if root not in target.parents:
                    raise ValueError("ZIP contains a path outside the extraction folder.")
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as src, target.open("wb") as dst:
                    dst.write(src.read())
    except zipfile.BadZipFile as exc:
        raise ValueError("The uploaded file is not a valid ZIP archive.") from exc
    if count == 0:
        raise ValueError("No .tf files were found in the ZIP.")
    return count

def sample_options():
    root = Path("samples")
    return [(p.name, p) for p in sorted(root.iterdir()) if p.is_dir() and list(p.rglob("*.tf"))] if root.exists() else []

if "scan_result" not in st.session_state:
    st.session_state.scan_result = None
if "scan_error" not in st.session_state:
    st.session_state.scan_error = None

if mode == "Upload Terraform ZIP":
    upload = st.file_uploader("Upload a ZIP containing Terraform files", type=["zip"])
    run = st.button("🔍 Scan Terraform", type="primary", disabled=upload is None)
    if run and upload:
        with tempfile.TemporaryDirectory(prefix="clg_") as temp:
            try:
                n = safe_extract_tf_zip(upload, temp)
                with st.spinner("Scanning Terraform files…"):
                    findings, info = scan_directory(Path(temp))
                st.session_state.scan_result = build_report(findings, info, upload.name)
                st.session_state.scan_error = None
                st.success(f"Scanned {n} Terraform file(s).")
            except (ValueError, OSError) as exc:
                st.session_state.scan_error = str(exc)
else:
    samples = sample_options()
    if not samples:
        st.warning("No sample folders containing .tf files were found in samples/.")
        st.stop()
    selected = st.selectbox("Sample configuration", [name for name, _ in samples])
    if st.button("🔍 Scan sample", type="primary"):
        try:
            folder = dict(samples)[selected]
            findings, info = scan_directory(folder)
            st.session_state.scan_result = build_report(findings, info, f"Sample: {selected}")
            st.session_state.scan_error = None
        except Exception as exc:
            st.session_state.scan_error = str(exc)

if st.session_state.scan_error:
    st.error(st.session_state.scan_error)

report = st.session_state.scan_result
if report:
    summary = report.get("summary", {})
    st.subheader("Scan summary")
    cols = st.columns(5)
    cols[0].metric("Total findings", summary.get("total", 0))
    cols[1].metric("High", summary.get("High", 0))
    cols[2].metric("Medium", summary.get("Medium", 0))
    cols[3].metric("Low", summary.get("Low", 0))
    cols[4].metric("Files scanned", report.get("scan_info", {}).get("files_scanned", 0))
    info = report.get("scan_info", {})
    st.caption(f"Target: {report.get('target')} · Checkov: {info.get('checkov_status', 'unknown')} · Generated: {report.get('generated_at')}")
    with st.expander("Scan limitations and status"):
        st.write("Static analysis is not a guarantee of security.")
        for note in info.get("notes", []):
            st.write(f"• {note}")

    findings = report.get("findings", [])
    st.subheader("Findings")
    if not findings:
        st.success("No findings were reported by enabled checks. This does not prove the configuration is secure.")
    else:
        left, right = st.columns([2, 1])
        search = left.text_input("Search findings", placeholder="Rule, title, file, or resource")
        severities = right.multiselect("Severity", ["High", "Medium", "Low", "Info"], default=["High", "Medium", "Low", "Info"])
        visible = [f for f in findings if f.get("severity", "Info") in severities and search.lower() in " ".join(str(f.get(k, "")) for k in ("rule_id", "title", "file", "resource", "message")).lower()]
        st.caption(f"Showing {len(visible)} of {len(findings)} findings")
        for item in visible:
            title = f"{item.get('severity', 'Info')} · {item.get('rule_id', 'RULE')} · {item.get('title', 'Finding')}"
            with st.expander(title, expanded=item.get("severity") == "High"):
                st.write(item.get("message", "No description available."))
                st.markdown(f"**File:** `{item.get('file', 'Unknown')}`")
                st.markdown(f"**Resource:** `{item.get('resource') or 'Not identified'}`")
                st.markdown(f"**Recommendation:** {item.get('recommendation', 'Review manually.')}")
                st.caption(f"Source: {item.get('source', 'Unknown')} · Fingerprint: {item.get('fingerprint', '')[:16]}…")

    st.subheader("Export reports")
    a, b = st.columns(2)
    a.download_button("Download JSON report", report_to_json(report), "cloudleak_guard_report.json", "application/json")
    b.download_button("Download HTML report", report_to_html(report), "cloudleak_guard_report.html", "text/html")

    st.subheader("Compare with a previous report")
    previous = st.file_uploader("Upload previous CloudLeak Guard JSON report", type=["json"], key="previous")
    if previous:
        try:
            old = json.loads(previous.getvalue().decode("utf-8"))
            comparison = compare_reports(old, report)
            a, b, c = st.columns(3)
            a.metric("Resolved", len(comparison["resolved"]))
            b.metric("Remaining", len(comparison["remaining"]))
            c.metric("Introduced", len(comparison["introduced"]))
            with st.expander("Comparison details"):
                st.markdown("**Resolved (absent from new report)**")
                st.json(comparison["resolved"])
                st.markdown("**Remaining**")
                st.json(comparison["remaining"])
                st.markdown("**Introduced**")
                st.json(comparison["introduced"])
            st.caption("Resolved means absent from the newer report; it is not independent proof of remediation.")
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            st.error(f"Could not compare reports: {exc}")

st.divider()
st.caption("CloudLeak Guard · Terraform static analysis · Review findings before deployment.")
