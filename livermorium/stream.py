"""Network traffic simulation and streaming data processing.

Generates realistic network traffic patterns with injected cyber attacks,
useful for testing and demonstrating anomaly detection capabilities.
"""

import numpy as np
import pandas as pd
from dataclasses import dataclass
from typing import Optional, List


@dataclass
class TrafficData:
    """Container for simulated network traffic data."""
    timestamps: np.ndarray
    bytes_sent: np.ndarray
    bytes_received: np.ndarray
    packets: np.ndarray
    connections: np.ndarray
    latency: np.ndarray
    anomaly_labels: np.ndarray
    attack_types: Optional[np.ndarray] = None

    def to_matrix(self) -> np.ndarray:
        return np.column_stack([
            self.bytes_sent,
            self.bytes_received,
            self.packets,
            self.connections,
            self.latency,
        ])

    def to_dataframe(self) -> pd.DataFrame:
        df = pd.DataFrame({
            "timestamp": self.timestamps,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "packets": self.packets,
            "connections": self.connections,
            "latency_ms": self.latency,
            "is_anomaly": self.anomaly_labels,
        })
        if self.attack_types is not None:
            df["attack_type"] = self.attack_types
        return df


ATTACK_PROFILES = {
    "ddos": {
        "bytes_received": (10, 50),
        "packets": (20, 100),
        "connections": (5, 20),
        "latency": (3, 10),
    },
    "exfiltration": {
        "bytes_sent": (15, 80),
        "connections": (2, 5),
    },
    "port_scan": {
        "connections": (30, 100),
        "packets": (10, 30),
        "bytes_sent": (1.5, 3),
    },
    "slowloris": {
        "latency": (5, 20),
        "connections": (3, 8),
    },
    "cryptomining": {
        "bytes_sent": (3, 8),
        "bytes_received": (3, 8),
        "latency": (2, 5),
    },
}


class NetworkSimulator:
    """Generates realistic network traffic with optional cyber-attack injection.

    Parameters
    ----------
    seed : int, optional
        Random seed for reproducibility.
    """

    def __init__(self, seed: Optional[int] = None):
        self.rng = np.random.RandomState(seed)

    def generate(
        self,
        n_points: int = 1000,
        anomaly_ratio: float = 0.05,
        attack_types: Optional[List[str]] = None,
        start_time: str = "2026-02-21 09:00",
        freq: str = "5s",
    ) -> TrafficData:
        if attack_types is None:
            attack_types = list(ATTACK_PROFILES.keys())

        t = np.arange(n_points)
        hour_cycle = np.sin(2 * np.pi * t / 288) * 0.3 + 1.0

        bytes_sent = self.rng.exponential(500, n_points) * hour_cycle + 200
        bytes_received = self.rng.exponential(800, n_points) * hour_cycle + 300
        packets = (self.rng.poisson(50, n_points) * hour_cycle).astype(float)
        connections = (self.rng.poisson(10, n_points) * hour_cycle).astype(float)
        latency = self.rng.gamma(2, 10, n_points) + 5

        anomaly_labels = np.zeros(n_points, dtype=bool)
        attack_labels = np.full(n_points, "", dtype=object)
        n_anomalies = int(n_points * anomaly_ratio)

        if n_anomalies > 0:
            anomaly_indices = self.rng.choice(n_points, n_anomalies, replace=False)
            anomaly_indices.sort()

            for idx in anomaly_indices:
                attack = self.rng.choice(attack_types)
                profile = ATTACK_PROFILES.get(attack, {})
                window = min(5, n_points - idx)

                for feature, (low, high) in profile.items():
                    multiplier = self.rng.uniform(low, high)
                    if feature == "bytes_sent":
                        bytes_sent[idx : idx + window] *= multiplier
                    elif feature == "bytes_received":
                        bytes_received[idx : idx + window] *= multiplier
                    elif feature == "packets":
                        packets[idx : idx + window] *= multiplier
                    elif feature == "connections":
                        connections[idx : idx + window] *= multiplier
                    elif feature == "latency":
                        latency[idx : idx + window] *= multiplier

                anomaly_labels[idx : idx + window] = True
                attack_labels[idx : idx + window] = attack

        timestamps = pd.date_range(start=start_time, periods=n_points, freq=freq)

        return TrafficData(
            timestamps=timestamps.values,
            bytes_sent=np.maximum(0, bytes_sent),
            bytes_received=np.maximum(0, bytes_received),
            packets=np.maximum(0, packets).astype(int),
            connections=np.maximum(0, connections).astype(int),
            latency=np.maximum(1, latency),
            anomaly_labels=anomaly_labels,
            attack_types=attack_labels,
        )


class StreamProcessor:
    """Processes streaming data points through the anomaly detector.

    Maintains a sliding window buffer and triggers detection
    once enough data has been accumulated.
    """

    def __init__(self, detector, window_size: int = 100):
        self.detector = detector
        self.window_size = window_size
        self.buffer: list = []
        self.fitted = False

    def process(self, data_point: np.ndarray) -> Optional[dict]:
        self.buffer.append(data_point)

        if len(self.buffer) < self.window_size:
            return None

        window = np.array(self.buffer[-self.window_size :])

        if not self.fitted:
            self.detector.fit(window)
            self.fitted = True

        report = self.detector.detect(window)

        return {
            "is_anomaly": bool(report.anomalies[-1]),
            "score": float(report.scores[-1]),
            "threat_level": report.threat_level,
            "threat_score": float(report.threat_score),
        }

    def reset(self):
        self.buffer.clear()
        self.fitted = False
