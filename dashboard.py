import streamlit as st
import requests
import pandas as pd
import base64
from pathlib import Path

# Page Configuration
st.set_page_config(
    page_title="Project Akatya - Ransomware Defense",
    page_icon="🛡️",
    layout="wide"
)

# Custom Styling
st.markdown("""
<style>
    .main-header {
        font-size: 26px;
        font-weight: 700;
        color: #1E3A8A;
        margin-bottom: 2px;
    }
    .sub-header {
        font-size: 14px;
        color: #4B5563;
        margin-bottom: 20px;
    }
    .metric-card {
        background-color: #F8FAFC;
        border-radius: 8px;
        padding: 12px;
        border: 1px solid #E2E8F0;
    }
</style>
""", unsafe_allow_html=True)

# Sidebar Configuration
st.sidebar.image("https://img.icons8.com/color/96/shield.png", width=64)
st.sidebar.title("System Control")
SERVER_URL = st.sidebar.text_input("FastAPI Backend URL", value="http://127.0.0.1:8000").rstrip("/")

# Check Backend Status
try:
    health_resp = requests.get(f"{SERVER_URL}/", timeout=3)
    if health_resp.status_code == 200:
        st.sidebar.success("● Cloud Backend Online")
    else:
        st.sidebar.error("● Backend Offline (Bad Response)")
except Exception:
    st.sidebar.error("● Backend Offline (Connection Failed)")

if st.sidebar.button("🔄 Refresh Data"):
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.markdown("**Project Akatya Architecture**")
st.sidebar.caption("• Zero-Trust Asymmetric Vault\n• Heuristic Kill-Switch (psutil)\n• Supabase Object Storage & DB\n• Section 65B Digital Evidence")

# Main Header
st.markdown('<div class="main-header">🛡️ Project Akatya — Ransomware-Resilient Backup & Legal Reporting</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Host-Based Real-Time Ransomware Defense & Judicial Evidence Pipeline (Section 65B IT Act 2000)</div>', unsafe_allow_html=True)


# Helper Functions
def fetch_endpoints():
    try:
        r = requests.get(f"{SERVER_URL}/api/endpoints", timeout=5)
        return r.json().get("endpoints", []) if r.status_code == 200 else []
    except Exception:
        return []


def fetch_incidents():
    try:
        r = requests.get(f"{SERVER_URL}/api/incidents", timeout=5)
        return r.json() if r.status_code == 200 else []
    except Exception:
        return []


endpoints = fetch_endpoints()
incidents = fetch_incidents()

# Top Metrics Row
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("Connected Endpoints", len(endpoints))
with col2:
    st.metric("Detected Attack Incidents", len(incidents))
with col3:
    neutralized_count = sum(1 for i in incidents if i.get("process_killed"))
    st.metric("Attacks Neutralized", neutralized_count)
with col4:
    reports_count = sum(1 for i in incidents if i.get("report_generated"))
    st.metric("Section 65B Reports Issued", reports_count)

st.markdown("---")

# ----------------- SECTION 1: LIVE ATTACK ALERT BANNER -----------------
active_attacks = [i for i in incidents if not i.get("report_generated")]

if active_attacks:
    latest = active_attacks[0]
    st.error(f"""
    🚨 **CRITICAL SECURITY ALERT: RANSOMWARE ATTACK INTERCEPTED**
    - **Target Hostname:** `{latest.get('hostname')}` (ID: `{latest.get('endpoint_id')}`)
    - **Timestamp:** `{latest.get('attack_timestamp')}`
    - **Kill-Switch Action:** {'✅ Offending Process KILLED (SIGKILL via psutil)' if latest.get('process_killed') else '⚠️ Process Status Unknown'}
    - **Evidence Collected:** `{latest.get('evidence_count')}` corrupted files cataloged for forensic investigation
    - **Cloud Vault Status:** 🔒 Frozen to prevent backup contamination
    """)

# ----------------- SECTION 2: TABS INTERFACE -----------------
tab_incidents, tab_endpoints, tab_recovery = st.tabs([
    "🚨 Incident Monitor & Section 65B Evidence",
    "💻 Connected Endpoints & Cloud Vault",
    "🔄 Disaster Recovery & File Restoration"
])

# ----- TAB 1: INCIDENTS & LEGAL REPORTS -----
with tab_incidents:
    st.subheader("Incident Log & Digital Forensics")

    if not incidents:
        st.info("No attack incidents recorded. Monitored endpoints are operating normally.")
    else:
        for inc in incidents:
            inc_id = inc["id"]
            timestamp_str = inc.get("attack_timestamp", "")[:19].replace("T", " ")
            status_badge = "🔴 ATTACK INTERCEPTED" if inc.get("process_killed") else "⚠️ ALERT"

            with st.expander(f"{status_badge} — Host: {inc.get('hostname')} | {timestamp_str} UTC", expanded=True):
                col_info, col_actions = st.columns([2, 1])

                with col_info:
                    st.write(f"**Incident ID:** `{inc_id}`")
                    st.write(f"**Endpoint ID:** `{inc.get('endpoint_id')}`")
                    st.write(f"**Process Neutralized:** {'Yes (psutil SIGKILL)' if inc.get('process_killed') else 'No'}")
                    st.write(f"**Digital Evidence Records:** {inc.get('evidence_count')} file(s)")

                with col_actions:
                    # Button to fetch and download Section 65B Legal Certificate PDF
                    report_url = f"{SERVER_URL}/api/incidents/{inc_id}/report"
                    
                    try:
                        pdf_resp = requests.get(report_url, timeout=10)
                        if pdf_resp.status_code == 200:
                            st.download_button(
                                label="📄 Download Section 65B PDF",
                                data=pdf_resp.content,
                                file_name=f"Section_65B_Certificate_{inc_id[:8]}.pdf",
                                mime="application/pdf",
                                key=f"dl_{inc_id}",
                                use_container_width=True
                            )
                        else:
                            st.button("⚠️ Report Unavailable", disabled=True, key=f"err_{inc_id}")
                    except Exception as e:
                        st.caption(f"Error loading report: {e}")

                # Show Evidence Table
                try:
                    det_resp = requests.get(f"{SERVER_URL}/api/incidents/{inc_id}", timeout=5)
                    if det_resp.status_code == 200:
                        ev_list = det_resp.json().get("evidence", [])
                        if ev_list:
                            st.markdown("**Tampered Files & Cryptographic Evidence Hashes:**")
                            df_ev = pd.DataFrame(ev_list)
                            df_ev = df_ev[["corrupted_filepath", "corrupted_hash"]]
                            df_ev.columns = ["Target File Name", "Corrupted File Hash (SHA-256)"]
                            st.dataframe(df_ev, use_container_width=True, hide_index=True)
                except Exception:
                    pass

# ----- TAB 2: ENDPOINTS & BACKUPS -----
with tab_endpoints:
    st.subheader("Registered Machines & Cloud Backups")

    if not endpoints:
        st.info("No endpoints registered yet. Run `agent.py` on target machines to register.")
    else:
        df_ep = pd.DataFrame(endpoints)
        df_ep_display = df_ep[["hostname", "id", "status", "created_at"]]
        df_ep_display.columns = ["Hostname", "Endpoint UUID", "Status", "Registered At"]
        st.dataframe(df_ep_display, use_container_width=True, hide_index=True)

        st.markdown("---")
        st.subheader("Inspect Vault Backups")
        selected_endpoint = st.selectbox(
            "Select Endpoint to inspect backup history:",
            options=[ep["id"] for ep in endpoints],
            format_func=lambda x: f"{next((ep['hostname'] for ep in endpoints if ep['id'] == x), x)} ({x[:8]}...)"
        )

        if selected_endpoint:
            try:
                b_resp = requests.get(f"{SERVER_URL}/api/backups/{selected_endpoint}", timeout=5)
                if b_resp.status_code == 200:
                    backups = b_resp.json().get("backups", [])
                    if backups:
                        df_b = pd.DataFrame(backups)
                        df_b = df_b[["original_path", "version", "file_hash", "backed_up_at"]]
                        df_b.columns = ["File Name", "Append-Only Version", "Clean SHA-256 Hash", "Backed Up At"]
                        st.dataframe(df_b, use_container_width=True, hide_index=True)
                    else:
                        st.info("No files backed up yet for this endpoint.")
            except Exception as e:
                st.error(f"Failed to fetch backups: {e}")

# ----- TAB 3: DISASTER RECOVERY -----
with tab_recovery:
    st.subheader("One-Click Cloud Vault Recovery")
    st.write("Decrypts clean backups from the Supabase Storage bucket using the server's private key and restores uncorrupted files.")

    if not endpoints:
        st.info("No endpoints available for recovery.")
    else:
        rec_endpoint = st.selectbox(
            "Select Target Endpoint for Recovery:",
            options=[ep["id"] for ep in endpoints],
            format_func=lambda x: f"{next((ep['hostname'] for ep in endpoints if ep['id'] == x), x)} ({x})"
        )

        col_rec_btn, col_opt = st.columns([1, 2])
        with col_opt:
            restore_to_sandbox = st.checkbox("Automatically overwrite and restore files directly into ./demo_sandbox", value=True)

        if st.button("🚀 Initiate Cloud Recovery & Decrypt Files", type="primary"):
            with st.spinner("Retrieving ciphertext from Supabase bucket & decrypting with RSA Private Key..."):
                try:
                    rec_resp = requests.post(f"{SERVER_URL}/api/recover/{rec_endpoint}", timeout=20)
                    if rec_resp.status_code == 200:
                        rec_data = rec_resp.json()
                        st.success(f"✅ {rec_data.get('message')}")

                        files = rec_data.get("recovered_files", [])
                        if files:
                            st.markdown(f"**Successfully Decrypted {len(files)} Clean File(s):**")
                            
                            restored_table = []
                            sandbox_path = Path("demo_sandbox")
                            restored_folder = Path("restored_files")
                            restored_folder.mkdir(exist_ok=True)

                            for f_item in files:
                                fname = f_item["filename"]
                                content_bytes = base64.b64decode(f_item["content_b64"])
                                
                                # Always save to restored_files
                                (restored_folder / fname).write_bytes(content_bytes)

                                # Optionally overwrite demo_sandbox
                                if restore_to_sandbox:
                                    (sandbox_path / fname).write_bytes(content_bytes)

                                restored_table.append({
                                    "File Name": fname,
                                    "Version": f"v{f_item['version']}",
                                    "Integrity Verified": "✅ SHA-256 Match" if f_item["hash_verified"] else "❌ Hash Mismatch",
                                    "Clean SHA-256": f_item["sha256"][:24] + "..."
                                })

                            st.dataframe(pd.DataFrame(restored_table), use_container_width=True, hide_index=True)

                            if restore_to_sandbox:
                                st.info("📁 All recovered clean files have been written directly back to `./demo_sandbox`!")
                            else:
                                st.info("📁 Clean files restored to `./restored_files` directory.")
                        else:
                            st.warning("No files found to recover.")
                    else:
                        st.error(f"Recovery failed: {rec_resp.text}")
                except Exception as e:
                    st.error(f"Error communicating with recovery service: {e}")

