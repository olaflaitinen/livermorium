"""
Livermorium - Intelligent Cybersecurity Anomaly Detection Library

Developed by DTU Compute for Cursor Hackathon Baku 2026.

Combines Statistical Analysis, Machine Learning, Scientific Computing,
and Cybersecurity expertise to deliver real-time network threat detection.

Quick start::

    from livermorium import AnomalyDetector, NetworkSimulator

    sim = NetworkSimulator(seed=42)
    data = sim.generate(n_points=1000, anomaly_ratio=0.05)

    detector = AnomalyDetector(
        methods=["zscore", "isolation_forest", "ewma"],
        sensitivity=0.7,
    )
    report = detector.fit_detect(data.to_matrix())

    from livermorium.viz import plot_anomalies
    fig = plot_anomalies(data, report)
    fig.show()
"""

__version__ = "0.1.0"
__author__ = "DTU Compute"

from livermorium.detector import AnomalyDetector, AnomalyReport
from livermorium.stream import NetworkSimulator, StreamProcessor, TrafficData
from livermorium.stats import (
    ZScoreDetector,
    IQRDetector,
    EWMADetector,
    DetectionResult,
)
from livermorium.models import IsolationForestModel
from livermorium.viz import (
    plot_anomalies,
    plot_traffic,
    threat_gauge,
    metrics_over_time,
    attack_distribution,
)

__all__ = [
    "AnomalyDetector",
    "AnomalyReport",
    "NetworkSimulator",
    "StreamProcessor",
    "TrafficData",
    "ZScoreDetector",
    "IQRDetector",
    "EWMADetector",
    "IsolationForestModel",
    "DetectionResult",
    "plot_anomalies",
    "plot_traffic",
    "threat_gauge",
    "metrics_over_time",
    "attack_distribution",
]
