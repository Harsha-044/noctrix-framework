import streamlit as st
import pandas as pd
from neo4j import GraphDatabase

# Neo4j connection
URI = "bolt://127.0.0.1:7687"
USER = "neo4j"
PASSWORD = "your_password"  # Ensure this matches your active Neo4j password

@st.cache_data
def fetch_identities():
    driver = GraphDatabase.driver(URI, auth=(USER, PASSWORD))
    query = """
    MATCH (i:Identity)
    RETURN i.name AS Name, i.type AS Type, i.riskScore AS Risk_Score, i.isAdmin AS Is_Admin
    ORDER BY i.riskScore DESC
    """
    with driver.session() as session:
        result = session.run(query)
        data = [record.values() for record in result]
        columns = result.keys()
    driver.close()
    return pd.DataFrame(data, columns=columns)

st.set_page_config(page_title="NOCTRIX NHI Dashboard", layout="wide")
st.title("NOCTRIX: Non-Human Identity Security Posture")

# Load Data
try:
    df = fetch_identities()
    
    # Top-Level Metrics
    st.subheader("Discovery & Risk Metrics")
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Secrets Discovered", len(df))
    col2.metric("High-Risk Identities", len(df[df['Risk_Score'] >= 80]) if not df.empty else 0)
    col3.metric("Over-Privileged (Admins)", len(df[df['Is_Admin'] == True]) if not df.empty else 0)

    # Data Table
    st.subheader("Exposed Secrets Inventory")
    if not df.empty:
        st.dataframe(df, use_container_width=True)
    else:
        st.info("No identities found. Run the main pipeline to populate the graph.")

except Exception as e:
    st.error(f"Failed to connect to Neo4j. Ensure the database is running. Error: {e}")