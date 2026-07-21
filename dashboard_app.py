import streamlit as st
import pandas as pd
import requests


# set browsers tab/title layout
st.set_page_config(page_title="VulnOps AI — Top Risks", layout="wide")


API_BASE = st.sidebar.text_input("API base URL", value="http://127.0.0.1:8000") ### input sidebar 
limit = st.sidebar.slider("Number of top risks to show", min_value=5, max_value=100, value=20)

st.title("🛡️ VulnOps AI — Top Business Risks")
st.caption("Ranked by weighted risk score: 30% Business Criticality · 25% EPSS · 20% KEV · 15% Internet Exposure · 10% Compensating Controls")

if st.button("Refresh Data", type="primary"):
    st.rerun()

try:
    response = requests.get(f"{API_BASE}/risk/top", params={"limit": limit}, timeout=15)
    response.raise_for_status()
    data = response.json()
except Exception as e:
    st.error(f"Could not reach VulnOps AI API: {e}")
    st.stop()

risks = data["top_risks"]
total_scored = data["total_findings_scored"]

st.metric("Total findings scored", total_scored)

df = pd.DataFrame(risks)

def highlight_risk(row):
    if row["risk_score"] >= 60:
        return ["background-color: #fecaca"] * len(row)
    elif row["risk_score"] >= 40:
        return ["background-color: #fef3c7"] * len(row)
    else:
        return ["background-color: #d1fae5"] * len(row)

styled_df = df.style.apply(highlight_risk, axis=1)

st.dataframe(
    styled_df,
    use_container_width=True,
    column_config={
        "risk_score": st.column_config.ProgressColumn(
            "Risk Score", min_value=0, max_value=100, format="%.1f"
        ),
        "cve_id": "CVE ID",
        "cvss_score": "CVSS",
        "epss_score": st.column_config.NumberColumn("EPSS", format="%.4f"),
        "is_kev": "KEV?",
        "affected_package": "Package",
        "source": "Scanner",
        "repository": "Repository",
    },
)

st.divider()
st.subheader("🔍 Ask a question about a specific finding")

selected_cve = st.selectbox("Choose a CVE to investigate", df["cve_id"].unique() if not df.empty else [])

if st.button("Explain this finding"):
    with st.spinner("Asking VulnOps AI..."):
        try:
            ask_response = requests.post(
                f"{API_BASE}/ask",
                json={"question": f"Explain {selected_cve} and why it might be a priority"},
                timeout=100,
            )
            ask_response.raise_for_status()
            answer = ask_response.json().get("answer", "No answer returned.")
            st.info(answer)
        except requests.exceptions.ReadTimeout:
            st.warning("The request took longer than expected. Try clicking the button again — Gemini's API can be slow on the first call.")
        except Exception as e:
            st.error(f"Something went wrong: {e}")