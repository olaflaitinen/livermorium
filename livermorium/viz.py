"""Visualization utilities for network traffic and anomaly detection.

Provides publication-quality Plotly figures with a cybersecurity-themed
dark aesthetic, suitable for dashboards and presentations.
"""

import numpy as np
import plotly.graph_objects as go
from plotly.subplots import make_subplots


CYBER_COLORS = {
    "cyan": "#00d4ff",
    "red": "#ff3333",
    "green": "#51cf66",
    "yellow": "#ffd43b",
    "purple": "#cc5de8",
    "orange": "#ff922b",
    "blue": "#4dabf7",
    "bg": "#0a0a0a",
    "card_bg": "#111122",
    "text": "#e0e0e0",
}

THREAT_COLORS = {
    "NORMAL": "#51cf66",
    "LOW": "#ffd43b",
    "MEDIUM": "#ff922b",
    "HIGH": "#ff6b6b",
    "CRITICAL": "#ff0000",
}


def _apply_dark_layout(fig: go.Figure, height: int = 600, title: str = "") -> go.Figure:
    fig.update_layout(
        title=dict(text=title, font=dict(size=18, color=CYBER_COLORS["cyan"])),
        template="plotly_dark",
        height=height,
        paper_bgcolor=CYBER_COLORS["bg"],
        plot_bgcolor=CYBER_COLORS["bg"],
        font=dict(color=CYBER_COLORS["text"], family="Consolas, monospace"),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        margin=dict(l=50, r=30, t=60, b=30),
    )
    return fig


def plot_traffic(traffic_data, title: str = "Network Traffic Monitor") -> go.Figure:
    df = traffic_data.to_dataframe()

    fig = make_subplots(
        rows=3,
        cols=1,
        shared_xaxes=True,
        vertical_spacing=0.06,
        subplot_titles=("Bytes Sent / Received", "Packets & Connections", "Latency (ms)"),
        row_heights=[0.4, 0.3, 0.3],
    )

    fig.add_trace(
        go.Scatter(
            x=df["timestamp"], y=df["bytes_sent"], name="Bytes Sent",
            line=dict(color=CYBER_COLORS["cyan"], width=1),
        ),
        row=1, col=1,
    )
    fig.add_trace(
        go.Scatter(
            x=df["timestamp"], y=df["bytes_received"], name="Bytes Recv",
            line=dict(color=CYBER_COLORS["red"], width=1),
        ),
        row=1, col=1,
    )
    fig.add_trace(
        go.Scatter(
            x=df["timestamp"], y=df["packets"], name="Packets",
            line=dict(color=CYBER_COLORS["green"], width=1),
        ),
        row=2, col=1,
    )
    fig.add_trace(
        go.Scatter(
            x=df["timestamp"], y=df["connections"], name="Connections",
            line=dict(color=CYBER_COLORS["yellow"], width=1),
        ),
        row=2, col=1,
    )
    fig.add_trace(
        go.Scatter(
            x=df["timestamp"], y=df["latency_ms"], name="Latency",
            line=dict(color=CYBER_COLORS["purple"], width=1),
        ),
        row=3, col=1,
    )

    return _apply_dark_layout(fig, height=700, title=title)


def plot_anomalies(traffic_data, report, title: str = "Anomaly Detection Results") -> go.Figure:
    df = traffic_data.to_dataframe()
    anomalies = report.anomalies
    scores = report.scores

    fig = make_subplots(
        rows=4,
        cols=1,
        shared_xaxes=True,
        vertical_spacing=0.05,
        subplot_titles=(
            "Network Traffic (Bytes)",
            "Connections & Packets",
            "Latency (ms)",
            "Anomaly Score",
        ),
        row_heights=[0.3, 0.25, 0.2, 0.25],
    )

    fig.add_trace(
        go.Scatter(
            x=df["timestamp"], y=df["bytes_sent"], name="Bytes Sent",
            line=dict(color=CYBER_COLORS["cyan"], width=1), opacity=0.7,
        ),
        row=1, col=1,
    )
    fig.add_trace(
        go.Scatter(
            x=df["timestamp"], y=df["bytes_received"], name="Bytes Recv",
            line=dict(color=CYBER_COLORS["blue"], width=1), opacity=0.7,
        ),
        row=1, col=1,
    )

    if np.any(anomalies):
        anom_df = df[anomalies]
        fig.add_trace(
            go.Scatter(
                x=anom_df["timestamp"], y=anom_df["bytes_received"],
                mode="markers", name="Anomaly",
                marker=dict(
                    color=CYBER_COLORS["red"], size=8, symbol="x",
                    line=dict(width=1, color="#ff6666"),
                ),
            ),
            row=1, col=1,
        )

    fig.add_trace(
        go.Scatter(
            x=df["timestamp"], y=df["connections"], name="Connections",
            line=dict(color=CYBER_COLORS["yellow"], width=1), opacity=0.7,
        ),
        row=2, col=1,
    )
    fig.add_trace(
        go.Scatter(
            x=df["timestamp"], y=df["packets"], name="Packets",
            line=dict(color=CYBER_COLORS["green"], width=1), opacity=0.7,
        ),
        row=2, col=1,
    )

    fig.add_trace(
        go.Scatter(
            x=df["timestamp"], y=df["latency_ms"], name="Latency",
            line=dict(color=CYBER_COLORS["purple"], width=1), opacity=0.7,
        ),
        row=3, col=1,
    )

    bar_colors = [CYBER_COLORS["red"] if a else "#1a1a2e" for a in anomalies]
    fig.add_trace(
        go.Bar(
            x=df["timestamp"], y=scores, name="Score",
            marker_color=bar_colors, opacity=0.85,
        ),
        row=4, col=1,
    )

    return _apply_dark_layout(fig, height=900, title=title)


def threat_gauge(threat_score: float, threat_level: str) -> go.Figure:
    color = THREAT_COLORS.get(threat_level, "#ffffff")

    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=threat_score * 100,
            number=dict(suffix="%", font=dict(size=36, color=color)),
            title=dict(
                text=f"Threat Level: {threat_level}",
                font=dict(size=16, color=CYBER_COLORS["text"]),
            ),
            gauge=dict(
                axis=dict(range=[0, 100], tickcolor="#555"),
                bar=dict(color=color),
                bgcolor="#1a1a2e",
                bordercolor="#333",
                steps=[
                    dict(range=[0, 20], color="#0d2818"),
                    dict(range=[20, 40], color="#2d2a0a"),
                    dict(range=[40, 60], color="#2d1a0a"),
                    dict(range=[60, 80], color="#2d0a0a"),
                    dict(range=[80, 100], color="#3d0000"),
                ],
                threshold=dict(
                    line=dict(color="#ff0000", width=3),
                    thickness=0.8,
                    value=threat_score * 100,
                ),
            ),
        )
    )

    fig.update_layout(
        height=250,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=CYBER_COLORS["text"]),
        margin=dict(l=30, r=30, t=60, b=20),
    )
    return fig


def metrics_over_time(traffic_data, report, window: int = 20) -> go.Figure:
    df = traffic_data.to_dataframe()
    scores = report.scores

    kernel = np.ones(window) / window
    rolling_anomaly_rate = np.convolve(
        report.anomalies.astype(float), kernel, mode="same"
    )

    fig = go.Figure()

    fig.add_trace(
        go.Scatter(
            x=df["timestamp"], y=scores,
            name="Anomaly Score", fill="tozeroy",
            line=dict(color=CYBER_COLORS["red"], width=1),
            fillcolor="rgba(255, 107, 107, 0.15)",
        )
    )
    fig.add_trace(
        go.Scatter(
            x=df["timestamp"], y=rolling_anomaly_rate,
            name="Rolling Anomaly Rate",
            line=dict(color=CYBER_COLORS["yellow"], width=2, dash="dash"),
            yaxis="y2",
        )
    )

    fig.update_layout(
        yaxis=dict(title="Anomaly Score"),
        yaxis2=dict(title="Anomaly Rate", overlaying="y", side="right", range=[0, 1]),
    )

    return _apply_dark_layout(fig, height=300, title="Anomaly Metrics Over Time")


def attack_distribution(traffic_data, report) -> go.Figure:
    """Pie chart showing distribution of detected attack types."""
    df = traffic_data.to_dataframe()

    if "attack_type" not in df.columns:
        return go.Figure()

    detected = df[report.anomalies & (df["attack_type"] != "")]
    if detected.empty:
        return go.Figure()

    counts = detected["attack_type"].value_counts()

    colors_map = {
        "ddos": CYBER_COLORS["red"],
        "exfiltration": CYBER_COLORS["orange"],
        "port_scan": CYBER_COLORS["yellow"],
        "slowloris": CYBER_COLORS["purple"],
        "cryptomining": CYBER_COLORS["cyan"],
    }
    pie_colors = [colors_map.get(name, CYBER_COLORS["blue"]) for name in counts.index]

    fig = go.Figure(
        go.Pie(
            labels=counts.index,
            values=counts.values,
            marker=dict(colors=pie_colors, line=dict(color="#222", width=2)),
            textfont=dict(color="white"),
            hole=0.4,
        )
    )

    fig.update_layout(
        height=300,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=CYBER_COLORS["text"]),
        margin=dict(l=20, r=20, t=40, b=20),
        title=dict(text="Attack Type Distribution", font=dict(color=CYBER_COLORS["cyan"], size=16)),
        showlegend=True,
        legend=dict(font=dict(size=11)),
    )
    return fig
