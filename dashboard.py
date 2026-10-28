"""Streamlit dashboard for scoped asset monitoring."""

import streamlit as st

from app import scan_all
from database.db import initialize_database, list_latest_scans, list_recent_changes
from scanner.scope import load_scope

st.set_page_config(page_title="Attack Surface Monitor", page_icon="🛡️", layout="wide")
st.title("Attack Surface Monitor")
st.caption("DNS, TLS certificate, and explicitly configured port status")

initialize_database()
try:
    targets = load_scope()
except (OSError, ValueError) as error:
    st.error(f"Unable to load config.json: {error}")
    st.stop()

st.write(f"Configured assets: {len(targets)}")
if not targets:
    st.info("Add authorized hostnames and individual ports to config.json to begin.")

if st.button("Run scan", type="primary", disabled=not targets):
    with st.spinner("Checking configured assets..."):
        scan_all()
    st.rerun()

st.subheader("Latest results")
scans = list_latest_scans()
if scans:
    st.dataframe(scans, use_container_width=True, hide_index=True)
else:
    st.write("No scans recorded yet.")

st.subheader("Recent changes")
changes = list_recent_changes()
if changes:
    st.dataframe(changes, use_container_width=True, hide_index=True)
else:
    st.write("No changes detected.")