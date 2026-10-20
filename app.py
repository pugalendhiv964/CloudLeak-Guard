from pathlib import Path
import tempfile
import zipfile
import json
import streamlit as st
from scanner import scan_directory
from report_generator import findings_to_html, findings_to_json, compare_findings

st.set_page_config(page_title="CloudLeak Guard", page_icon="🛡️", layout="wide")
st.title("🛡️ CloudLeak Guard")
st.caption("Local-first Terraform checks for security, configuration, and policy-based cost risks.")
st.info("Prototype notice: this tool uses static checks. It does not deploy infrastructure, estimate exact cloud bills, or replace a full security review.")

with st.sidebar:
    st.header("Scan options")
    run_checkov = st.checkbox("Run Checkov (if installed)", value=True)
    st.caption("Custom checks work without Checkov. Checkov findings are added when its CLI is available.")

uploaded = st.file_uploader("Upload a ZIP containing Terraform (.tf) files", type=["zip"])
st.markdown("Or try one of the bundled examples below.")
sample_root = Path(__file__).parent / "samples"
c1, c2 = st.columns(2)
with c1:
    if st.button("Scan risky example", use_container_width=True):
        st.session_state["sample_to_scan"] = str(sample_root / "risky")
with c2:
    if st.button("Scan safe example", use_container_width=True):
        st.session_state["sample_to_scan"] = str(sample_root / "safe")

scan_path = None
temp_context = None
if uploaded is not None:
    temp_context = tempfile.TemporaryDirectory(prefix="cloudleak_")
    root = Path(temp_context.name)
    try:
        with zipfile.ZipFile(uploaded) as zf:
            # Reject path traversal entries and extract only Terraform source files.
            for info in zf.infolist():
                candidate = Path(info.filename)
                if candidate.is_absolute() or ".." in candidate.parts:
                    continue
                if info.is_dir():
                    continue
                if candidate.suffix.lower() == ".tf":
                    target = root / candidate.name
                    target.write_bytes(zf.read(info))
        scan_path = root
    except zipfile.BadZipFile:
        st.error("That ZIP file could not be read. Please upload a valid ZIP.")
elif st.session_state.get("sample_to_scan"):
    scan_path = Path(st.session_state["sample_to_scan"])

if scan_path is not None:
    with st.spinner("Scanning Terraform files..."):
        findings, metadata = scan_directory(scan_path, run_checkov=run_checkov)
    st.session_state["last_findings"] = findings
    st.session_state["last_metadata"] = metadata
    st.session_state.pop("sample_to_scan", None)
    if temp_context:
        temp_context.cleanup()

if "last_findings" in st.session_state:
    findings = st.session_state["last_findings"]
    metadata = st.session_state.get("last_metadata", {})
    critical = sum(f["severity"] == "Critical" for f in findings)
    high = sum(f["severity"] == "High" for f in findings)
    medium = sum(f["severity"] == "Medium" for f in findings)
    low = sum(f["severity"] == "Low" for f in findings)
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total findings", len(findings))
    m2.metric("Critical / High", critical + high)
    m3.metric("Medium", medium)
    m4.metric("Low / Info", low + sum(f["severity"] == "Info" for f in findings))
    st.caption(f"Files checked: {metadata.get('files_checked', 0)} · Checkov: {metadata.get('checkov', 'not run')}")
    if findings:
        st.subheader("Findings")
        severities = ["All", "Critical", "High", "Medium", "Low", "Info"]
        chosen = st.selectbox("Filter by severity", severities)
        visible = findings if chosen == "All" else [f for f in findings if f["severity"] == chosen]
        for f in visible:
            with st.expander(f"{f['severity']} · {f['title']} · {f['file']}"):
                st.write(f["description"])
                st.markdown(f"**Suggested fix:** {f['remediation']}")
                st.caption(f"Rule: {f['rule_id']} | Category: {f['category']}")
    else:
        st.success("No findings from the enabled checks. This is not a guarantee that the configuration is secure.")
    st.download_button("Download JSON report", findings_to_json(findings), "cloudleak-report.json", "application/json")
    st.download_button("Download HTML report", findings_to_html(findings), "cloudleak-report.html", "text/html")

st.divider()
st.subheader("Compare before and after")
st.caption("Upload two JSON reports exported by this app to see which findings were resolved or introduced.")
before_file = st.file_uploader("Before report (JSON)", type=["json"], key="before_json")
after_file = st.file_uploader("After report (JSON)", type=["json"], key="after_json")
if st.button("Compare reports"):
    if not before_file or not after_file:
        st.warning("Upload both a before and an after JSON report.")
    else:
        try:
            before = json.load(before_file)
            after = json.load(after_file)
            comparison = compare_findings(before, after)
            a, b, c = st.columns(3)
            a.metric("Resolved", len(comparison["resolved"]))
            b.metric("Still present", len(comparison["remaining"]))
            c.metric("New findings", len(comparison["introduced"]))
            st.json(comparison)
        except (ValueError, TypeError) as exc:
            st.error(f"Could not compare these reports: {exc}")
