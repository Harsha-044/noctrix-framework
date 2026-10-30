import streamlit as st
import pandas as pd

# Page Configuration
st.set_page_config(
    page_title="NOCTRIX Security Posture",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Dark Theme & UI Polish CSS (Fixed text visibility)
st.markdown("""
    <style>
    /* Main Background & Font */
    .stApp {
        background-color: #0e1117;
        color: #f0f6fc;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }
    
    /* Header Styling */
    h1, h2, h3 {
        color: #58a6ff !important;
        font-weight: 600;
    }

    /* Metric Cards */
    div[data-testid="metric-container"] {
        background-color: #161b22;
        border: 1px solid #30363d;
        padding: 15px;
        border-radius: 8px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
    }
    div[data-testid="metric-container"] label {
        color: #8b949e !important;
    }
    div[data-testid="metric-container"] div[data-testid="stMetricValue"] {
        color: #f0f6fc !important;
    }

    /* Tables & DataFrames */
    .stDataFrame {
        border: 1px solid #30363d;
        border-radius: 8px;
        background-color: #161b22;
    }
    
    /* Sidebar Styling */
    section[data-testid="stSidebar"] {
        background-color: #161b22;
        border-right: 1px solid #30363d;
    }
    </style>
""", unsafe_allow_html=True)

# Dashboard Header
st.title("NOCTRIX: Non-Human Identity Security Posture")
st.markdown("### Discovery & Risk Metrics")

# Metrics Row
col1, col2, col3 = st.columns(3)
with col1:
    st.metric(label="Total Secrets Discovered", value="19")
with col2:
    st.metric(label="High-Risk Identities", value="0")
with col3:
    st.metric(label="Over-Privileged (Admins)", value="2")

st.markdown("---")
st.markdown("### Exposed Secrets Inventory")

# Sample Inventory Data matching your backend output
data = {
    "Name": [
        "vault-token-noctrix-admin-role-1793380699-hhEjJ8zbqx0ZUdOJPl1o",
        "vault-token-noctrix-admin-role-1793381207-BMayZJAno7MvHZYvW7Au",
        "vault-token-noctrix-admin-role-1793381591-UAMy51JUdyoiMcVHFENH",
        "Leaked Github Token"
    ],
    "Type": ["AWS_ACCESS_KEY", "AWS_ACCESS_KEY", "AWS_ACCESS_KEY", "EXPOSED_GIT_SECRET"],
    "Risk_Score": [15, 15, 15, 10],
    "Is_Admin": [True, True, True, False]
}

df = pd.DataFrame(data)
st.dataframe(df, use_container_width=True)