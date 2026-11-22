import os
from dotenv import load_dotenv
import streamlit as st
import streamlit.components.v1 as components
import pandas as pd
from neo4j import GraphDatabase
from pyvis.network import Network

load_dotenv()

# Page Configuration
st.set_page_config(
    page_title="NOCTRIX Security Posture",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Dark Theme & UI Polish CSS
st.markdown("""
    <style>
    .stApp {
        background-color: #0e1117;
        color: #f0f6fc;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }
    h1, h2, h3 {
        color: #58a6ff !important;
        font-weight: 600;
    }
    div[data-testid="metric-container"] {
        background-color: #161b22;
        border: 1px solid #30363d;
        padding: 15px;
        border-radius: 8px;
    }
    div[data-testid="metric-container"] label {
        color: #8b949e !important;
    }
    div[data-testid="metric-container"] div[data-testid="stMetricValue"] {
        color: #f0f6fc !important;
    }
    section[data-testid="stSidebar"] {
        background-color: #161b22;
        border-right: 1px solid #30363d;
    }
    </style>
""", unsafe_allow_html=True)

# --- Sidebar: Neo4j Connection ---
st.sidebar.header("Neo4j Connection")
neo4j_uri = st.sidebar.text_input("URI", value=os.getenv("NEO4J_URI", "bolt://localhost:7687"))
neo4j_user = st.sidebar.text_input("User", value=os.getenv("NEO4J_USER", "neo4j"))
neo4j_pass = st.sidebar.text_input(
    "Password",
    value=os.getenv("NEO4J_PASSWORD", ""),
    type="password",
)

if st.sidebar.button("Refresh Live Data"):
    st.cache_data.clear()


@st.cache_data(ttl=30)
def fetch_neo4j_data(uri, user, password):
    driver = GraphDatabase.driver(uri, auth=(user, password))
    try:
        with driver.session() as session:
            # 1. Fetch all NHI Identities
            id_result = session.run("""
                MATCH (i:Identity)
                RETURN i.id AS ID,
                       i.name AS Name,
                       i.type AS Type,
                       coalesce(i.riskScore, 0.0) AS Risk_Score,
                       coalesce(i.ghostConfidence, 0.0) AS Ghost_Confidence,
                       coalesce(i.isAdmin, false) AS Is_Admin,
                       coalesce(i.correlatedLeak, false) AS Correlated_Leak,
                       coalesce(i.daysInactive, 0) AS Days_Inactive
                ORDER BY Risk_Score DESC
            """)
            identities_df = pd.DataFrame([dict(r) for r in id_result])

            # 2. Fetch Attack Paths (Identity -> Policy -> Resource)
            path_result = session.run("""
                MATCH (i:Identity)-[:HAS_POLICY]->(p:Policy)-[:CAN_ACCESS]->(r:Resource)
                RETURN i.name AS Identity,
                       i.type AS Identity_Type,
                       coalesce(i.riskScore, 0.0) AS Risk_Score,
                       p.name AS Policy,
                       r.name AS Target_Resource,
                       r.type AS Resource_Type
                ORDER BY Risk_Score DESC
            """)
            paths_df = pd.DataFrame([dict(r) for r in path_result])

            return identities_df, paths_df, None
    except Exception as e:
        return pd.DataFrame(), pd.DataFrame(), str(e)
    finally:
        driver.close()


# --- Dashboard Header ---
st.title("NOCTRIX: Non-Human Identity Security Posture")

df, paths_df, error = fetch_neo4j_data(neo4j_uri, neo4j_user, neo4j_pass)

if error:
    st.error(f"Could not connect to Neo4j: {error}")
    st.info("Verify your Docker container (`noctrix-neo4j`) is running and the password in `.env` matches.")
    st.stop()

if df.empty:
    st.warning("No identities found in Neo4j yet. Run `python main.py` first, then click Refresh Live Data.")
    st.stop()

# --- Sidebar: SOC Triage Filters ---
st.sidebar.markdown("---")
st.sidebar.header("Triage Filters")

hide_vault = st.sidebar.checkbox("Hide Dynamic Vault Tokens", value=False)
selected_types = st.sidebar.multiselect(
    "Identity Type",
    options=sorted(df["Type"].dropna().unique().tolist()),
    default=sorted(df["Type"].dropna().unique().tolist()),
)
min_risk = st.sidebar.slider("Minimum Risk Score", 0, 100, 0)
min_ghost = st.sidebar.slider("Minimum Ghost Confidence (%)", 0, 100, 0)

filtered_df = df[
    (df["Type"].isin(selected_types))
    & (df["Risk_Score"] >= min_risk)
    & (df["Ghost_Confidence"] >= min_ghost)
]
if hide_vault:
    filtered_df = filtered_df[~filtered_df["Name"].str.contains("vault-token-", case=False, na=False)]

# --- Executive KPI Row ---
st.markdown("### Posture Overview")
total_nhis = len(df)
high_risk_count = int((df["Risk_Score"] >= 50).sum())
ghost_count = int((df["Ghost_Confidence"] >= 30).sum())
vault_count = int(df["Name"].str.contains("vault-token-", case=False, na=False).sum())

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total NHIs Discovered", total_nhis)
col2.metric("High-Risk Identities (>=50)", high_risk_count)
col3.metric("Ghost Identities (>=30%)", ghost_count)
col4.metric("Dynamic Vault Tokens", vault_count)

# --- Distribution Charts ---
st.markdown("---")
chart_col1, chart_col2 = st.columns(2)

with chart_col1:
    st.markdown("#### Identities by Type")
    st.bar_chart(df["Type"].value_counts())

with chart_col2:
    st.markdown("#### Risk Severity Breakdown")
    def classify_tier(score):
        if score >= 75:
            return "1. Critical (75-100)"
        if score >= 50:
            return "2. High (50-74)"
        if score >= 25:
            return "3. Medium (25-49)"
        return "4. Low (0-24)"

    tier_counts = df["Risk_Score"].apply(classify_tier).value_counts().sort_index()
    st.bar_chart(tier_counts)

# --- Filterable NHI Inventory ---
st.markdown("---")
st.markdown(f"### Non-Human Identity Inventory ({len(filtered_df)} shown)")

st.dataframe(
    filtered_df,
    use_container_width=True,
    height=420,
    hide_index=True,
    column_config={
        "Risk_Score": st.column_config.ProgressColumn(
            "Risk Score", min_value=0, max_value=100, format="%.1f"
        ),
        "Ghost_Confidence": st.column_config.ProgressColumn(
            "Ghost %", min_value=0, max_value=100, format="%.1f%%"
        ),
    },
)

# --- Neo4j Interactive Attack Path Explorer ---
st.markdown("---")
st.markdown("### Neo4j Interactive Attack Path Explorer (`Identity → Policy → Resource`)")

if paths_df.empty:
    st.info("No active attack paths mapped in Neo4j for the current scan.")
else:
    net = Network(height="480px", width="100%", bgcolor="#0e1117", font_color="#f0f6fc", directed=True)
    net.barnes_hut(gravity=-3000, central_gravity=0.3, spring_length=140)

    for _, row in paths_df.iterrows():
        ident = str(row["Identity"])
        policy = str(row["Policy"])
        resource = str(row["Target_Resource"])
        risk = float(row["Risk_Score"])

        ident_color = "#f85149" if risk >= 50 else "#d29922" if risk >= 25 else "#3fb950"

        net.add_node(ident, label=ident, color=ident_color, title=f"Identity | Risk: {risk}")
        net.add_node(policy, label=policy, color="#58a6ff", shape="box", title="IAM Policy")
        net.add_node(resource, label=resource, color="#a371f7", shape="diamond", title=row["Resource_Type"])

        net.add_edge(ident, policy, label="HAS_POLICY", color="#8b949e")
        net.add_edge(policy, resource, label="CAN_ACCESS", color="#f85149")

    html_graph = net.generate_html()
    components.html(html_graph, height=500, scrolling=False)

    with st.expander("View Raw Attack Path Table"):
        st.dataframe(paths_df, use_container_width=True, hide_index=True)