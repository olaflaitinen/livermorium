"""Machine Learning based anomaly detection models.

Leverages DTU Compute's AI/ML research for intelligent threat detection.
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from livermorium.stats import BaseDetector, DetectionResult


class IsolationForestModel(BaseDetector):
    """Isolation Forest based anomaly detection.

    Uses random partitioning to isolate anomalies - points that are
    easier to isolate are more likely to be anomalous.
    """

    def __init__(
        self,
        contamination: float = 0.05,
        n_estimators: int = 100,
        random_state: int = 42,
    ):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=random_state,
        )

    def fit(self, data: np.ndarray) -> "IsolationForestModel":
        if data.ndim == 1:
            data = data.reshape(-1, 1)
        self.model.fit(data)
        return self

    def detect(self, data: np.ndarray) -> DetectionResult:
        if data.ndim == 1:
            data = data.reshape(-1, 1)
        predictions = self.model.predict(data)
        scores = -self.model.score_samples(data)
        is_anomaly = predictions == -1

        if np.any(~is_anomaly):
            threshold = float(np.percentile(scores[~is_anomaly], 95))
        else:
            threshold = float(np.median(scores))

        return DetectionResult(
            is_anomaly=is_anomaly,
            scores=scores,
            threshold=threshold,
            method="isolation_forest",
        )
