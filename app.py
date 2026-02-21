"""
Livermorium — Real-Time Network Threat Detection Dashboard

Built by DTU Compute for Cursor Hackathon Baku 2026.
Demonstrates the livermorium library's anomaly detection capabilities
on simulated network traffic data with injected cyber attacks.
"""

import streamlit as st
import numpy as np
import pandas as pd
import time

from livermorium import AnomalyDetector, NetworkSimulator
from livermorium.viz import (
    plot_anomalies,
    threat_gauge,
    metrics_over_time,
    attack_distribution,
    THREAT_COLORS,
)

# ── Page config ──────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="Livermorium | Threat Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ───────────────────────────────────────────────────────────────

st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;600;700&display=swap');

:root {
    --bg: #0a0a0f;
    --card: #111122;
    --cyan: #00d4ff;
    --red: #ff3333;
    --green: #51cf66;
    --yellow: #ffd43b;
    --text: #e0e0e0;
    --muted: #888;
}

.stApp {
    background: linear-gradient(135deg, #0a0a0f 0%, #0d0d1a 50%, #0a0f0a 100%);
}

[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0d0d1a 0%, #111122 100%);
    border-right: 1px solid #1a1a3e;
}

.main-header {
    text-align: center;
    padding: 1rem 0 0.5rem 0;
}
.main-header h1 {
    font-family: 'JetBrains Mono', monospace;
    font-size: 2.4rem;
    background: linear-gradient(90deg, #00d4ff, #51cf66);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin-bottom: 0;
}
.main-header p {
    color: var(--muted);
    font-size: 0.95rem;
    margin-top: 0.3rem;
}

.metric-card {
    background: linear-gradient(135deg, #111122 0%, #1a1a2e 100%);
    border: 1px solid #2a2a4e;
    border-radius: 12px;
    padding: 1.2rem;
    text-align: center;
    transition: border-color 0.3s;
}
.metric-card:hover { border-color: #00d4ff; }
.metric-card .value {
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.8rem;
    font-weight: 700;
}
.metric-card .label {
    color: var(--muted);
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-top: 0.3rem;
}

.alert-box {
    background: rgba(255, 51, 51, 0.1);
    border: 1px solid rgba(255, 51, 51, 0.3);
    border-radius: 8px;
    padding: 0.8rem 1rem;
    margin: 0.4rem 0;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.85rem;
    color: #ff6b6b;
}

.section-title {
    font-family: 'JetBrains Mono', monospace;
    color: #00d4ff;
    font-size: 1.1rem;
    border-bottom: 1px solid #1a1a3e;
    padding-bottom: 0.5rem;
    margin: 1.5rem 0 1rem 0;
}

.team-badge {
    display: inline-block;
    background: linear-gradient(90deg, #00d4ff22, #51cf6622);
    border: 1px solid #00d4ff44;
    border-radius: 20px;
    padding: 0.3rem 1rem;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    color: #00d4ff;
    letter-spacing: 1px;
}

.method-tag {
    display: inline-block;
    background: #1a1a2e;
    border: 1px solid #2a2a4e;
    border-radius: 6px;
    padding: 0.2rem 0.6rem;
    margin: 0.1rem;
    font-size: 0.75rem;
    color: #00d4ff;
    font-family: 'JetBrains Mono', monospace;
}
</style>
""",
    unsafe_allow_html=True,
)

# ── Header ───────────────────────────────────────────────────────────────────

st.markdown(
    """
<div class="main-header">
    <h1>⚛ LIVERMORIUM</h1>
    <p>Intelligent Network Threat Detection System</p>
    <div class="team-badge">DTU COMPUTE · CURSOR HACKATHON BAKU 2026</div>
</div>
""",
    unsafe_allow_html=True,
)

st.markdown("---")

# ── Sidebar Controls ─────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("### ⚙ Detection Configuration")

    st.markdown("**Detection Methods**")
    use_zscore = st.checkbox("Z-Score", value=True)
    use_iqr = st.checkbox("IQR (Interquartile Range)", value=True)
    use_ewma = st.checkbox("EWMA (Exponential Moving Avg)", value=True)
    use_iforest = st.checkbox("Isolation Forest", value=True)

    methods = []
    if use_zscore:
        methods.append("zscore")
    if use_iqr:
        methods.append("iqr")
    if use_ewma:
        methods.append("ewma")
    if use_iforest:
        methods.append("isolation_forest")

    if not methods:
        methods = ["zscore"]
        st.warning("At least one method required. Defaulting to Z-Score.")

    st.markdown("---")

    sensitivity = st.slider(
        "Detection Sensitivity",
        min_value=0.0,
        max_value=1.0,
        value=0.6,
        step=0.05,
        help="Higher = more sensitive (catches more anomalies, more false positives)",
    )

    st.markdown("---")
    st.markdown("**Simulation Parameters**")

    n_points = st.slider("Data Points", 200, 3000, 1000, 100)
    anomaly_ratio = st.slider("Attack Injection Rate", 0.01, 0.20, 0.06, 0.01)
    seed = st.number_input("Random Seed", 0, 9999, 42)

    attack_options = ["ddos", "exfiltration", "port_scan", "slowloris", "cryptomining"]
    selected_attacks = st.multiselect(
        "Attack Types",
        attack_options,
        default=attack_options,
    )

    st.markdown("---")
    run_btn = st.button("🔍 Run Analysis", type="primary", use_container_width=True)

    st.markdown("---")
    st.markdown(
        """
    <div style='text-align:center; color:#555; font-size:0.75rem;'>
        <b>livermorium</b> v0.1.0<br>
        pip install livermorium
    </div>
    """,
        unsafe_allow_html=True,
    )

# ── Analysis ─────────────────────────────────────────────────────────────────

if run_btn or "report" not in st.session_state:
    with st.spinner("Generating network traffic and detecting anomalies..."):
        sim = NetworkSimulator(seed=seed)
        traffic = sim.generate(
            n_points=n_points,
            anomaly_ratio=anomaly_ratio,
            attack_types=selected_attacks if selected_attacks else None,
        )

        detector = AnomalyDetector(methods=methods, sensitivity=sensitivity)
        data_matrix = traffic.to_matrix()
        report = detector.fit_detect(data_matrix)

        st.session_state["traffic"] = traffic
        st.session_state["report"] = report
        st.session_state["methods"] = methods

traffic = st.session_state["traffic"]
report = st.session_state["report"]

# ── Metrics Row ──────────────────────────────────────────────────────────────

color = THREAT_COLORS.get(report.threat_level, "#ffffff")
n_anomalies = int(np.sum(report.anomalies))
n_total = len(report.anomalies)
detection_rate = report.anomaly_ratio * 100
ground_truth = int(np.sum(traffic.anomaly_labels))

col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.markdown(
        f"""<div class="metric-card">
        <div class="value" style="color:{color}">{report.threat_level}</div>
        <div class="label">Threat Level</div>
    </div>""",
        unsafe_allow_html=True,
    )

with col2:
    st.markdown(
        f"""<div class="metric-card">
        <div class="value" style="color:#ff6b6b">{n_anomalies}</div>
        <div class="label">Anomalies Detected</div>
    </div>""",
        unsafe_allow_html=True,
    )

with col3:
    st.markdown(
        f"""<div class="metric-card">
        <div class="value" style="color:#ffd43b">{detection_rate:.1f}%</div>
        <div class="label">Anomaly Rate</div>
    </div>""",
        unsafe_allow_html=True,
    )

with col4:
    st.markdown(
        f"""<div class="metric-card">
        <div class="value" style="color:#00d4ff">{n_total:,}</div>
        <div class="label">Data Points</div>
    </div>""",
        unsafe_allow_html=True,
    )

with col5:
    st.markdown(
        f"""<div class="metric-card">
        <div class="value" style="color:#51cf66">{len(st.session_state['methods'])}</div>
        <div class="label">Active Methods</div>
    </div>""",
        unsafe_allow_html=True,
    )

# ── Threat Gauge + Attack Distribution ───────────────────────────────────────

st.markdown('<div class="section-title">▸ THREAT ASSESSMENT</div>', unsafe_allow_html=True)

gauge_col, dist_col = st.columns([1, 1])

with gauge_col:
    fig_gauge = threat_gauge(report.threat_score, report.threat_level)
    st.plotly_chart(fig_gauge, use_container_width=True)

with dist_col:
    fig_dist = attack_distribution(traffic, report)
    st.plotly_chart(fig_dist, use_container_width=True)

# ── Main Anomaly Detection Chart ─────────────────────────────────────────────

st.markdown('<div class="section-title">▸ ANOMALY DETECTION RESULTS</div>', unsafe_allow_html=True)

fig_anomalies = plot_anomalies(traffic, report)
st.plotly_chart(fig_anomalies, use_container_width=True)

# ── Metrics Over Time ────────────────────────────────────────────────────────

st.markdown('<div class="section-title">▸ ANOMALY METRICS TIMELINE</div>', unsafe_allow_html=True)

fig_metrics = metrics_over_time(traffic, report)
st.plotly_chart(fig_metrics, use_container_width=True)

# ── Per-Method Breakdown ─────────────────────────────────────────────────────

st.markdown('<div class="section-title">▸ METHOD-LEVEL ANALYSIS</div>', unsafe_allow_html=True)

method_cols = st.columns(len(report.details))

for col, (method_name, result) in zip(method_cols, report.details.items()):
    n_detected = int(np.sum(result.is_anomaly))
    avg_score = float(np.mean(result.scores))
    max_score = float(np.max(result.scores))

    with col:
        st.markdown(
            f"""<div class="metric-card">
            <div class="method-tag">{method_name.upper()}</div>
            <div class="value" style="color:#ff6b6b; font-size:1.4rem; margin-top:0.5rem">{n_detected}</div>
            <div class="label">Detections</div>
            <div style="margin-top:0.5rem; font-size:0.8rem; color:#888">
                Avg Score: {avg_score:.3f}<br>
                Max Score: {max_score:.3f}<br>
                Threshold: {result.threshold:.3f}
            </div>
        </div>""",
            unsafe_allow_html=True,
        )

# ── Detection Accuracy ───────────────────────────────────────────────────────

st.markdown('<div class="section-title">▸ DETECTION ACCURACY</div>', unsafe_allow_html=True)

tp = int(np.sum(report.anomalies & traffic.anomaly_labels))
fp = int(np.sum(report.anomalies & ~traffic.anomaly_labels))
fn = int(np.sum(~report.anomalies & traffic.anomaly_labels))
tn = int(np.sum(~report.anomalies & ~traffic.anomaly_labels))

precision = tp / (tp + fp) if (tp + fp) > 0 else 0
recall = tp / (tp + fn) if (tp + fn) > 0 else 0
f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

acc_cols = st.columns(6)
metrics_data = [
    ("True Pos", tp, "#51cf66"),
    ("False Pos", fp, "#ffd43b"),
    ("False Neg", fn, "#ff922b"),
    ("Precision", f"{precision:.1%}", "#00d4ff"),
    ("Recall", f"{recall:.1%}", "#cc5de8"),
    ("F1 Score", f"{f1:.1%}", "#4dabf7"),
]

for col, (label, value, clr) in zip(acc_cols, metrics_data):
    with col:
        st.markdown(
            f"""<div class="metric-card">
            <div class="value" style="color:{clr}; font-size:1.3rem">{value}</div>
            <div class="label">{label}</div>
        </div>""",
            unsafe_allow_html=True,
        )

# ── Alert Log ─────────────────────────────────────────────────────────────────

st.markdown('<div class="section-title">▸ ALERT LOG</div>', unsafe_allow_html=True)

df = traffic.to_dataframe()
alert_df = df[report.anomalies].copy()
alert_df["anomaly_score"] = report.scores[report.anomalies]
alert_df = alert_df.sort_values("anomaly_score", ascending=False)

if not alert_df.empty:
    display_df = alert_df.head(20)[
        ["timestamp", "attack_type", "anomaly_score", "bytes_sent", "bytes_received", "packets", "connections", "latency_ms"]
    ].reset_index(drop=True)
    display_df.columns = ["Timestamp", "Attack Type", "Score", "Bytes Sent", "Bytes Recv", "Packets", "Connections", "Latency (ms)"]
    display_df["Score"] = display_df["Score"].round(3)
    display_df["Latency (ms)"] = display_df["Latency (ms)"].round(1)
    st.dataframe(display_df, use_container_width=True, height=400)
else:
    st.info("No anomalies detected with current configuration.")

# ── Footer ────────────────────────────────────────────────────────────────────

st.markdown("---")
st.markdown(
    """
<div style='text-align:center; color:#555; font-size:0.8rem; padding:1rem 0;'>
    <b>Livermorium v0.1.0</b> · Built with ❤ by <b>DTU Compute</b> · Cursor Hackathon Baku 2026<br>
    Combining Cybersecurity, AI/ML, Statistics & Scientific Computing
</div>
""",
    unsafe_allow_html=True,
)
