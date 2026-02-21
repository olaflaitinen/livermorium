"""Core anomaly detection engine with ensemble capabilities.

Orchestrates multiple detection strategies from Statistics and ML,
combining them via weighted voting for robust threat identification.
"""

import numpy as np
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from livermorium.stats import (
    BaseDetector,
    DetectionResult,
    ZScoreDetector,
    IQRDetector,
    EWMADetector,
)
from livermorium.models import IsolationForestModel


METHODS = {
    "zscore": ZScoreDetector,
    "iqr": IQRDetector,
    "ewma": EWMADetector,
    "isolation_forest": IsolationForestModel,
}


@dataclass
class AnomalyReport:
    """Comprehensive anomaly detection report."""
    anomalies: np.ndarray
    scores: np.ndarray
    details: Dict[str, DetectionResult]
    anomaly_ratio: float
    threat_level: str
    threat_score: float


class AnomalyDetector:
    """Ensemble anomaly detector combining multiple strategies.

    Parameters
    ----------
    methods : list of str
        Detection methods to use. Options: 'zscore', 'iqr', 'ewma', 'isolation_forest'.
    sensitivity : float
        Detection sensitivity from 0.0 (very lenient) to 1.0 (very strict).
    method_params : dict, optional
        Per-method parameter overrides, e.g. ``{'zscore': {'threshold': 2.5}}``.
    """

    def __init__(
        self,
        methods: Optional[List[str]] = None,
        sensitivity: float = 0.5,
        method_params: Optional[Dict[str, Dict[str, Any]]] = None,
    ):
        if methods is None:
            methods = ["zscore", "isolation_forest"]
        if method_params is None:
            method_params = {}

        self.sensitivity = sensitivity
        self.detectors: Dict[str, BaseDetector] = {}

        for method in methods:
            if method not in METHODS:
                raise ValueError(
                    f"Unknown method: {method}. Available: {list(METHODS.keys())}"
                )
            params = method_params.get(method, {})
            self.detectors[method] = METHODS[method](**params)

    def fit(self, data: np.ndarray) -> "AnomalyDetector":
        for detector in self.detectors.values():
            detector.fit(data)
        return self

    def detect(self, data: np.ndarray) -> AnomalyReport:
        results: Dict[str, DetectionResult] = {}
        vote_matrix = []
        score_matrix = []

        for name, detector in self.detectors.items():
            result = detector.detect(data)
            results[name] = result
            vote_matrix.append(result.is_anomaly.astype(float))
            max_score = np.max(result.scores)
            normalized = result.scores / max_score if max_score > 0 else result.scores
            score_matrix.append(normalized)

        vote_matrix = np.array(vote_matrix)
        score_matrix = np.array(score_matrix)

        threshold_frac = 1.0 - self.sensitivity
        min_votes = max(1, int(len(self.detectors) * threshold_frac))

        votes = np.sum(vote_matrix, axis=0)
        combined_anomalies = votes >= min_votes
        combined_scores = np.mean(score_matrix, axis=0)

        anomaly_ratio = float(np.mean(combined_anomalies))

        if np.any(combined_anomalies):
            threat_score = float(np.mean(combined_scores[combined_anomalies]))
        else:
            threat_score = 0.0

        threat_level = self._classify_threat(threat_score)

        return AnomalyReport(
            anomalies=combined_anomalies,
            scores=combined_scores,
            details=results,
            anomaly_ratio=anomaly_ratio,
            threat_level=threat_level,
            threat_score=threat_score,
        )

    def fit_detect(self, data: np.ndarray) -> AnomalyReport:
        self.fit(data)
        return self.detect(data)

    @staticmethod
    def _classify_threat(score: float) -> str:
        if score > 0.8:
            return "CRITICAL"
        if score > 0.6:
            return "HIGH"
        if score > 0.4:
            return "MEDIUM"
        if score > 0.2:
            return "LOW"
        return "NORMAL"
