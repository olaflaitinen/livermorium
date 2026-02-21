"""Vercel serverless function for Livermorium anomaly detection API."""

from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import json
import sys
import os
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from livermorium import AnomalyDetector, NetworkSimulator


def _parse_int(val, default):
    try:
        return int(val[0]) if val else default
    except (ValueError, IndexError):
        return default


def _parse_float(val, default):
    try:
        return float(val[0]) if val else default
    except (ValueError, IndexError):
        return default


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)

        n_points = _parse_int(query.get("n"), 800)
        n_points = max(100, min(n_points, 3000))
        anomaly_ratio = _parse_float(query.get("ratio"), 0.06)
        sensitivity = _parse_float(query.get("sensitivity"), 0.6)
        seed = _parse_int(query.get("seed"), 42)

        raw_methods = query.get("methods", ["zscore,isolation_forest,ewma"])
        methods = [m.strip() for m in raw_methods[0].split(",") if m.strip()]
        valid = {"zscore", "iqr", "ewma", "isolation_forest"}
        methods = [m for m in methods if m in valid] or ["zscore", "isolation_forest"]

        raw_attacks = query.get("attacks", ["ddos,exfiltration,port_scan,slowloris,cryptomining"])
        attacks = [a.strip() for a in raw_attacks[0].split(",") if a.strip()]

        sim = NetworkSimulator(seed=seed)
        traffic = sim.generate(
            n_points=n_points,
            anomaly_ratio=anomaly_ratio,
            attack_types=attacks if attacks else None,
        )

        detector = AnomalyDetector(methods=methods, sensitivity=sensitivity)
        matrix = traffic.to_matrix()
        report = detector.fit_detect(matrix)

        tp = int(np.sum(report.anomalies & traffic.anomaly_labels))
        fp = int(np.sum(report.anomalies & ~traffic.anomaly_labels))
        fn = int(np.sum(~report.anomalies & traffic.anomaly_labels))
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        attack_counts = {}
        if traffic.attack_types is not None:
            df_attacks = traffic.attack_types[report.anomalies]
            for a in df_attacks:
                if a:
                    attack_counts[a] = attack_counts.get(a, 0) + 1

        method_details = {}
        for name, result in report.details.items():
            method_details[name] = {
                "n_detected": int(np.sum(result.is_anomaly)),
                "avg_score": round(float(np.mean(result.scores)), 4),
                "max_score": round(float(np.max(result.scores)), 4),
                "threshold": round(float(result.threshold), 4),
            }

        ts_strings = [str(t)[:19] for t in traffic.timestamps]

        response = {
            "threat_level": report.threat_level,
            "threat_score": round(float(report.threat_score), 4),
            "anomaly_ratio": round(float(report.anomaly_ratio), 4),
            "n_anomalies": int(np.sum(report.anomalies)),
            "n_total": n_points,
            "methods_used": methods,
            "timestamps": ts_strings,
            "bytes_sent": [round(float(v), 1) for v in traffic.bytes_sent],
            "bytes_received": [round(float(v), 1) for v in traffic.bytes_received],
            "packets": traffic.packets.tolist(),
            "connections": traffic.connections.tolist(),
            "latency": [round(float(v), 1) for v in traffic.latency],
            "ground_truth": traffic.anomaly_labels.tolist(),
            "detected": report.anomalies.tolist(),
            "scores": [round(float(v), 4) for v in report.scores],
            "attack_types": traffic.attack_types.tolist() if traffic.attack_types is not None else [],
            "attack_counts": attack_counts,
            "method_details": method_details,
            "accuracy": {
                "tp": tp, "fp": fp, "fn": fn,
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1": round(f1, 4),
            },
        }

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "s-maxage=60, stale-while-revalidate")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())
