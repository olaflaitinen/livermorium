"""Statistical anomaly detection methods.

Combines DTU Compute's expertise in Statistics and Scientific Computing
to provide robust outlier detection algorithms.
"""

import numpy as np
from dataclasses import dataclass
from abc import ABC, abstractmethod


@dataclass
class DetectionResult:
    """Result from an anomaly detection method."""
    is_anomaly: np.ndarray
    scores: np.ndarray
    threshold: float
    method: str


class BaseDetector(ABC):
    """Abstract base class for all anomaly detectors."""

    @abstractmethod
    def fit(self, data: np.ndarray) -> "BaseDetector":
        pass

    @abstractmethod
    def detect(self, data: np.ndarray) -> DetectionResult:
        pass

    def fit_detect(self, data: np.ndarray) -> DetectionResult:
        self.fit(data)
        return self.detect(data)


class ZScoreDetector(BaseDetector):
    """Z-score based anomaly detection using Gaussian assumption."""

    def __init__(self, threshold: float = 3.0):
        self.threshold = threshold
        self.mean_ = None
        self.std_ = None

    def fit(self, data: np.ndarray) -> "ZScoreDetector":
        self.mean_ = np.mean(data, axis=0)
        self.std_ = np.std(data, axis=0)
        self.std_ = np.where(self.std_ == 0, 1e-10, self.std_)
        return self

    def detect(self, data: np.ndarray) -> DetectionResult:
        scores = np.abs((data - self.mean_) / self.std_)
        if scores.ndim > 1:
            scores = np.max(scores, axis=1)
        is_anomaly = scores > self.threshold
        return DetectionResult(
            is_anomaly=is_anomaly,
            scores=scores,
            threshold=self.threshold,
            method="zscore",
        )


class IQRDetector(BaseDetector):
    """Interquartile Range based anomaly detection."""

    def __init__(self, factor: float = 1.5):
        self.factor = factor
        self.q1_ = None
        self.q3_ = None
        self.iqr_ = None

    def fit(self, data: np.ndarray) -> "IQRDetector":
        self.q1_ = np.percentile(data, 25, axis=0)
        self.q3_ = np.percentile(data, 75, axis=0)
        self.iqr_ = self.q3_ - self.q1_
        return self

    def detect(self, data: np.ndarray) -> DetectionResult:
        lower = self.q1_ - self.factor * self.iqr_
        upper = self.q3_ + self.factor * self.iqr_

        if data.ndim > 1:
            below = np.any(data < lower, axis=1)
            above = np.any(data > upper, axis=1)
            dist_lower = np.maximum(0, lower - data)
            dist_upper = np.maximum(0, data - upper)
            scores = np.max(dist_lower + dist_upper, axis=1)
        else:
            below = data < lower
            above = data > upper
            scores = np.maximum(0, lower - data) + np.maximum(0, data - upper)

        is_anomaly = below | above
        max_iqr = np.max(self.iqr_) if np.ndim(self.iqr_) > 0 else self.iqr_
        if max_iqr > 0:
            scores = scores / max_iqr

        return DetectionResult(
            is_anomaly=is_anomaly,
            scores=scores,
            threshold=self.factor,
            method="iqr",
        )


class EWMADetector(BaseDetector):
    """Exponentially Weighted Moving Average anomaly detection.

    Particularly effective for streaming data with temporal dependencies.
    """

    def __init__(self, alpha: float = 0.3, threshold: float = 3.0):
        self.alpha = alpha
        self.threshold = threshold
        self.ewma_ = None
        self.ewmstd_ = None

    def fit(self, data: np.ndarray) -> "EWMADetector":
        if data.ndim == 1:
            data = data.reshape(-1, 1)
        n = len(data)
        self.ewma_ = np.zeros_like(data, dtype=float)
        ewmvar = np.zeros_like(data, dtype=float)

        self.ewma_[0] = data[0]
        for i in range(1, n):
            self.ewma_[i] = self.alpha * data[i] + (1 - self.alpha) * self.ewma_[i - 1]
            diff = data[i] - self.ewma_[i - 1]
            ewmvar[i] = (1 - self.alpha) * (ewmvar[i - 1] + self.alpha * diff ** 2)

        self.ewmstd_ = np.sqrt(ewmvar)
        return self

    def detect(self, data: np.ndarray) -> DetectionResult:
        if data.ndim == 1:
            data = data.reshape(-1, 1)
        if self.ewma_ is None:
            self.fit(data)

        deviations = np.abs(data - self.ewma_)
        safe_std = np.where(self.ewmstd_ > 0, self.ewmstd_, 1e-10)
        scores = deviations / safe_std

        if scores.ndim > 1:
            scores = np.max(scores, axis=1)
        is_anomaly = scores > self.threshold

        return DetectionResult(
            is_anomaly=is_anomaly,
            scores=scores,
            threshold=self.threshold,
            method="ewma",
        )
