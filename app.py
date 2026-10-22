from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from detector import detect_intrusions

st.set_page_config(
    page_title="Network Intrusion Detection System",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Network Intrusion Detection System")
st.caption("Network traffic analytics, anomaly detection and security monitoring")

st.sidebar.header("Data Source")
uploaded = st.sidebar.file_uploader("Upload traffic CSV", type=["csv"])

if uploaded is not None:
    try:
        raw = pd.read_csv(uploaded)
    except Exception as exc:
        st.error(f"Could not read the CSV file: {exc}")
        st.stop()
else:
    data_path = Path("data/network_traffic.csv")
    if not data_path.exists():
        st.warning("Sample dataset not found. Run: python generate_data.py")
        st.stop()
    raw = pd.read_csv(data_path)

required = {
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "packet_count", "bytes", "connection_attempts",
}
missing = required - set(raw.columns)

if missing:
    st.error(f"CSV is missing required columns: {', '.join(sorted(missing))}")
    st.stop()

raw["timestamp"] = pd.to_datetime(raw["timestamp"], errors="coerce")

numeric_columns = [
    "src_port", "dst_port", "packet_count", "bytes", "connection_attempts"
]
for col in numeric_columns:
    raw[col] = pd.to_numeric(raw[col], errors="coerce")

raw = raw.dropna(
    subset=["timestamp", "src_ip", "dst_ip", "protocol", *numeric_columns]
)

valid = (
    raw["src_port"].between(0, 65535)
    & raw["dst_port"].between(0, 65535)
    & (raw["packet_count"] >= 0)
    & (raw["bytes"] >= 0)
    & (raw["connection_attempts"] >= 0)
)
raw = raw.loc[valid].copy()

if raw.empty:
    st.error("No valid traffic records remain after data validation.")
    st.stop()

df = detect_intrusions(raw)
alerts = df[df["alert"]].copy()

st.sidebar.header("Filters")
protocols = sorted(df["protocol"].astype(str).unique())
selected_protocols = st.sidebar.multiselect(
    "Protocol", protocols, default=protocols
)
severities = st.sidebar.multiselect(
    "Alert severity",
    ["Medium", "High"],
    default=["Medium", "High"],
)

filtered = df[df["protocol"].astype(str).isin(selected_protocols)]
filtered_alerts = filtered[
    filtered["alert"] & filtered["severity"].isin(severities)
]

total = len(filtered)
alert_count = int(filtered["alert"].sum())
alert_rate = alert_count / total * 100 if total else 0
unique_sources = filtered["src_ip"].nunique()

c1, c2, c3, c4 = st.columns(4)
c1.metric("Traffic Records", f"{total:,}")
c2.metric("Detected Alerts", f"{alert_count:,}")
c3.metric("Alert Rate", f"{alert_rate:.1f}%")
c4.metric("Unique Source IPs", f"{unique_sources:,}")

st.divider()

left, right = st.columns(2)

with left:
    st.subheader("Traffic by Protocol")
    protocol_counts = (
        filtered.groupby("protocol").size()
        .reset_index(name="records")
    )
    if not protocol_counts.empty:
        fig = px.pie(
            protocol_counts, names="protocol", values="records", hole=0.45
        )
        st.plotly_chart(fig, use_container_width=True)

with right:
    st.subheader("Detected Alert Categories")
    if filtered_alerts.empty:
        st.info("No alerts match the current filters.")
    else:
        counts = (
            filtered_alerts.groupby("alert_type").size()
            .reset_index(name="count")
        )
        fig = px.bar(
            counts, x="alert_type", y="count", color="alert_type",
            labels={"alert_type": "Alert type", "count": "Events"},
        )
        st.plotly_chart(fig, use_container_width=True)

st.subheader("Network Traffic Over Time")
timeline = (
    filtered.set_index("timestamp")["bytes"]
    .resample("10min").sum()
    .reset_index()
)
if not timeline.empty:
    fig = px.line(
        timeline, x="timestamp", y="bytes", markers=True,
        labels={"bytes": "Bytes transferred", "timestamp": "Time"},
    )
    st.plotly_chart(fig, use_container_width=True)

st.subheader("Security Alerts")
if filtered_alerts.empty:
    st.success("No matching security alerts.")
else:
    display_columns = [
        "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
        "protocol", "packet_count", "bytes", "alert_type", "severity",
    ]
    st.dataframe(
        filtered_alerts[display_columns].sort_values(
            "timestamp", ascending=False
        ),
        use_container_width=True,
        hide_index=True,
    )

st.download_button(
    "Download security alerts CSV",
    data=filtered_alerts.to_csv(index=False).encode("utf-8"),
    file_name="security_alerts.csv",
    mime="text/csv",
)

with st.expander("View traffic data"):
    st.dataframe(filtered, use_container_width=True, hide_index=True)

st.caption(
    "Educational prototype. Alerts are heuristic indicators, not proof of an attack. "
    "This dashboard analyzes uploaded or generated records; it does not capture "
    "live packets automatically."
)
