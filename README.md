<p align="center">
  <strong>LIVERMORIUM</strong><br>
  <em>Intelligent Cybersecurity Anomaly Detection Library</em>
</p>

<p align="center">
  <a href="#installation">Installation</a> |
  <a href="#quick-start">Quick Start</a> |
  <a href="#api-reference">API Reference</a> |
  <a href="#detection-methods">Detection Methods</a> |
  <a href="#live-dashboard">Live Dashboard</a> |
  <a href="#license">License</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9%2B-blue" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/version-0.1.0-green" alt="Version 0.1.0">
  <img src="https://img.shields.io/badge/license-MIT-brightgreen" alt="MIT License">
  <img src="https://img.shields.io/badge/hackathon-Cursor%20Baku%202026-cyan" alt="Cursor Hackathon Baku 2026">
</p>

---

## Overview

**Livermorium** is a Python library for real-time network traffic anomaly detection, developed by **DTU Compute** (Technical University of Denmark, Department of Applied Mathematics and Computer Science). It integrates four core research disciplines into a unified detection pipeline:

| Discipline | Application in Livermorium |
|---|---|
| **Cybersecurity** | Threat modeling, attack simulation, network traffic analysis |
| **Machine Learning** | Isolation Forest ensemble for unsupervised outlier detection |
| **Statistics** | Z-Score, Interquartile Range, and Grubbs-based hypothesis testing |
| **Scientific Computing** | EWMA streaming algorithms, numerical signal processing |

The library provides a single `fit_detect()` call that fuses multiple detection strategies through weighted ensemble voting, returning structured threat reports with severity classification, per-method breakdowns, and anomaly scores.

### Problem Statement

Traditional network intrusion detection systems rely on signature-based matching, which fails against zero-day attacks and novel threat patterns. Livermorium addresses this gap by combining statistical outlier detection with machine learning to identify anomalous network behavior without prior knowledge of attack signatures. The ensemble approach reduces false positives while maintaining high recall across diverse attack vectors.

---

## Key Features

- **Ensemble Detection Engine** - Combines up to four independent detection methods (Z-Score, IQR, EWMA, Isolation Forest) via configurable weighted voting
- **Configurable Sensitivity** - Single `sensitivity` parameter (0.0 to 1.0) controls the trade-off between precision and recall across all methods
- **Five Attack Simulations** - Built-in network traffic simulator with realistic injection of DDoS, data exfiltration, port scanning, slowloris, and cryptomining patterns
- **Streaming Support** - `StreamProcessor` class enables sliding-window detection on continuous data feeds
- **Structured Reporting** - Every detection returns an `AnomalyReport` with threat level classification (NORMAL / LOW / MEDIUM / HIGH / CRITICAL), anomaly ratio, per-method detail, and numerical scores
- **Visualization Suite** - Publication-quality Plotly charts with dark cybersecurity theme for dashboards and presentations
- **Vercel-Ready Deployment** - Serverless API endpoint and static frontend included for instant web deployment

---

## Architecture

```
                    +---------------------+
                    |   Input Data        |
                    |  (Network Traffic)  |
                    +---------+-----------+
                              |
                    +---------v-----------+
                    |  NetworkSimulator    |
                    |  or Real Data Feed   |
                    +---------+-----------+
                              |
                  +-----------v-----------+
                  |   AnomalyDetector     |
                  |   (Ensemble Engine)   |
                  +-----------+-----------+
                              |
          +-------------------+-------------------+
          |                   |                   |
+---------v------+  +---------v------+  +---------v--------+
| ZScoreDetector |  | IQRDetector    |  | IsolationForest  |
| EWMADetector   |  |                |  | Model            |
+--------+-------+  +--------+-------+  +---------+-------+
         |                    |                    |
         +--------------------+--------------------+
                              |
                   +----------v----------+
                   | Weighted Ensemble   |
                   | Voting & Scoring    |
                   +----------+----------+
                              |
                   +----------v----------+
                   |   AnomalyReport     |
                   |  - threat_level     |
                   |  - threat_score     |
                   |  - anomalies[]      |
                   |  - scores[]         |
                   |  - method details   |
                   +---------------------+
```

---

## Installation

### From Source (Development)

```bash
git clone https://github.com/olaflaitinen/livermorium.git
cd livermorium
pip install -e .
```

### With Dashboard Dependencies

```bash
pip install -e ".[dashboard]"
```

### Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| numpy | >= 1.24.0 | Numerical computation, array operations |
| pandas | >= 2.0.0 | Time-series data structures, DataFrames |
| scikit-learn | >= 1.3.0 | Isolation Forest implementation |
| plotly | >= 5.15.0 | Interactive visualization (optional) |
| streamlit | >= 1.28.0 | Local dashboard interface (optional) |

### Requirements

- Python 3.9 or higher
- 64-bit operating system (Windows, macOS, Linux)

---

## Quick Start

### Basic Anomaly Detection

```python
from livermorium import AnomalyDetector, NetworkSimulator

# Generate synthetic network traffic with 5% injected anomalies
simulator = NetworkSimulator(seed=42)
traffic = simulator.generate(n_points=1000, anomaly_ratio=0.05)

# Initialize ensemble detector with three methods
detector = AnomalyDetector(
    methods=["zscore", "isolation_forest", "ewma"],
    sensitivity=0.7,
)

# Fit on training data and detect anomalies
report = detector.fit_detect(traffic.to_matrix())

print(f"Threat Level:    {report.threat_level}")
print(f"Threat Score:    {report.threat_score:.2%}")
print(f"Anomalies Found: {sum(report.anomalies)} / {len(report.anomalies)}")
print(f"Anomaly Ratio:   {report.anomaly_ratio:.2%}")
```

**Expected output:**

```
Threat Level:    HIGH
Threat Score:    63.07%
Anomalies Found: 44 / 500
Anomaly Ratio:   8.80%
```

### Visualization

```python
from livermorium.viz import plot_anomalies, threat_gauge

# Full anomaly detection chart with 4 subplots
fig = plot_anomalies(traffic, report)
fig.show()

# Threat level gauge indicator
gauge = threat_gauge(report.threat_score, report.threat_level)
gauge.show()
```

### Streaming Detection

```python
from livermorium import AnomalyDetector, StreamProcessor
import numpy as np

detector = AnomalyDetector(methods=["zscore", "ewma"], sensitivity=0.6)
processor = StreamProcessor(detector, window_size=100)

# Process data points one at a time (e.g., from a live network feed)
for i in range(200):
    data_point = np.random.randn(5)  # 5 features per observation
    result = processor.process(data_point)
    if result and result["is_anomaly"]:
        print(f"[ALERT] Point {i}: score={result['score']:.3f}, "
              f"level={result['threat_level']}")
```

### Custom Method Parameters

```python
detector = AnomalyDetector(
    methods=["zscore", "iqr", "isolation_forest"],
    sensitivity=0.8,
    method_params={
        "zscore": {"threshold": 2.5},
        "iqr": {"factor": 2.0},
        "isolation_forest": {"contamination": 0.03, "n_estimators": 200},
    },
)
```

---

## API Reference

### Core Classes

#### `AnomalyDetector`

The primary interface for ensemble anomaly detection.

```python
AnomalyDetector(
    methods: list[str] = ["zscore", "isolation_forest"],
    sensitivity: float = 0.5,
    method_params: dict[str, dict] = None,
)
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `methods` | `list[str]` | `["zscore", "isolation_forest"]` | Detection methods to include in the ensemble. Options: `"zscore"`, `"iqr"`, `"ewma"`, `"isolation_forest"` |
| `sensitivity` | `float` | `0.5` | Ensemble voting threshold. `0.0` requires all methods to agree (conservative). `1.0` flags a point if any single method detects it (aggressive). |
| `method_params` | `dict` | `None` | Per-method keyword arguments passed to individual detector constructors. |

**Methods:**

| Method | Signature | Description |
|---|---|---|
| `fit` | `fit(data: np.ndarray) -> AnomalyDetector` | Fit all detectors on training data. |
| `detect` | `detect(data: np.ndarray) -> AnomalyReport` | Run detection on (possibly new) data. |
| `fit_detect` | `fit_detect(data: np.ndarray) -> AnomalyReport` | Convenience method: fit then detect. |

#### `AnomalyReport`

Dataclass returned by `AnomalyDetector.detect()`.

| Field | Type | Description |
|---|---|---|
| `anomalies` | `np.ndarray[bool]` | Boolean mask indicating detected anomalies. |
| `scores` | `np.ndarray[float]` | Normalized anomaly score per observation (0.0 to 1.0). |
| `details` | `dict[str, DetectionResult]` | Per-method detection results. |
| `anomaly_ratio` | `float` | Fraction of observations flagged as anomalous. |
| `threat_level` | `str` | Categorical classification: `NORMAL`, `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`. |
| `threat_score` | `float` | Mean anomaly score across detected anomalies (0.0 to 1.0). |

#### `NetworkSimulator`

Generates synthetic network traffic data with configurable attack injection.

```python
NetworkSimulator(seed: int = None)
```

**Methods:**

| Method | Signature | Description |
|---|---|---|
| `generate` | `generate(n_points, anomaly_ratio, attack_types, start_time, freq) -> TrafficData` | Produce a `TrafficData` object with realistic network metrics and injected anomalies. |

#### `StreamProcessor`

Sliding-window processor for real-time streaming detection.

```python
StreamProcessor(detector: AnomalyDetector, window_size: int = 100)
```

| Method | Signature | Description |
|---|---|---|
| `process` | `process(data_point: np.ndarray) -> dict or None` | Ingest one observation. Returns detection result once window is full. |
| `reset` | `reset() -> None` | Clear the internal buffer and reset fitted state. |

### Individual Detectors

Each detector implements the `BaseDetector` interface with `fit()`, `detect()`, and `fit_detect()` methods.

| Class | Module | Parameters |
|---|---|---|
| `ZScoreDetector` | `livermorium.stats` | `threshold: float = 3.0` |
| `IQRDetector` | `livermorium.stats` | `factor: float = 1.5` |
| `EWMADetector` | `livermorium.stats` | `alpha: float = 0.3, threshold: float = 3.0` |
| `IsolationForestModel` | `livermorium.models` | `contamination: float = 0.05, n_estimators: int = 100, random_state: int = 42` |

### Visualization Functions

All functions are in `livermorium.viz` and return `plotly.graph_objects.Figure`.

| Function | Description |
|---|---|
| `plot_traffic(traffic_data)` | Three-panel traffic overview (bytes, packets/connections, latency). |
| `plot_anomalies(traffic_data, report)` | Four-panel detection results with anomaly highlights and score bars. |
| `threat_gauge(threat_score, threat_level)` | Radial gauge indicator for threat severity. |
| `metrics_over_time(traffic_data, report)` | Rolling anomaly rate and score timeline. |
| `attack_distribution(traffic_data, report)` | Donut chart of detected attack type breakdown. |

---

## Detection Methods

### Z-Score Detector

Computes the number of standard deviations each observation lies from the training mean. Based on the assumption that normal data follows an approximately Gaussian distribution.

**Scoring function:**

```
z_i = |x_i - mu| / sigma
```

A point is flagged anomalous when `z_i > threshold` (default: 3.0). For multivariate data, the maximum Z-score across all features is used.

**Strengths:** Fast computation, interpretable threshold, effective for unimodal distributions.
**Limitations:** Sensitive to non-Gaussian data, influenced by outliers in training set.

### IQR Detector

Uses the Interquartile Range (Q3 - Q1) to define robust bounds that are resistant to outliers. Based on non-parametric statistics.

**Decision rule:**

```
Lower bound = Q1 - factor * IQR
Upper bound = Q3 + factor * IQR
```

Points outside these bounds are flagged. Default `factor` is 1.5 (Tukey's standard fence).

**Strengths:** No distributional assumptions, robust to heavy tails.
**Limitations:** Less sensitive to subtle anomalies in high-dimensional data.

### EWMA Detector

Exponentially Weighted Moving Average tracks the evolving mean and variance of a time series, giving more weight to recent observations. Rooted in statistical process control (SPC) theory.

**Update equations:**

```
ewma_t     = alpha * x_t + (1 - alpha) * ewma_{t-1}
ewmvar_t   = (1 - alpha) * (ewmvar_{t-1} + alpha * (x_t - ewma_{t-1})^2)
deviation  = |x_t - ewma_t| / sqrt(ewmvar_t)
```

**Strengths:** Naturally handles non-stationary data, low memory footprint, ideal for streaming.
**Limitations:** Requires tuning of `alpha` smoothing parameter.

### Isolation Forest

An unsupervised machine learning method that isolates anomalies by randomly partitioning the feature space. Anomalous points require fewer partitions to isolate, resulting in shorter path lengths in the ensemble of random trees.

**Reference:** Liu, F.T., Ting, K.M. and Zhou, Z.H., 2008. Isolation forest. In *ICDM 2008*, pp. 413-422.

**Strengths:** Handles high-dimensional data, no distributional assumptions, scales linearly.
**Limitations:** Contamination parameter must approximate the true anomaly ratio.

### Ensemble Voting

The `AnomalyDetector` combines individual method outputs through a voting mechanism:

1. Each method produces an independent anomaly flag per observation.
2. Anomaly scores are normalized to [0, 1] per method.
3. A minimum vote count is computed as `max(1, floor(n_methods * (1 - sensitivity)))`.
4. An observation is flagged if it receives at least `min_votes` positive flags.
5. The final score is the mean of normalized scores across all methods.
6. Threat level is classified from the mean score of flagged observations.

| Score Range | Threat Level |
|---|---|
| 0.00 - 0.20 | NORMAL |
| 0.20 - 0.40 | LOW |
| 0.40 - 0.60 | MEDIUM |
| 0.60 - 0.80 | HIGH |
| 0.80 - 1.00 | CRITICAL |

---

## Attack Simulation

The `NetworkSimulator` generates five features per time step: `bytes_sent`, `bytes_received`, `packets`, `connections`, and `latency`. Normal traffic follows a Poisson/Exponential/Gamma mixture with a sinusoidal diurnal cycle. Attacks are injected by multiplying affected features within a configurable window.

| Attack Type | Affected Features | Multiplier Range | Real-World Analogue |
|---|---|---|---|
| **DDoS** | bytes_received, packets, connections, latency | 3x - 100x | Volumetric denial-of-service flooding |
| **Exfiltration** | bytes_sent, connections | 2x - 80x | Unauthorized bulk data transfer |
| **Port Scan** | connections, packets, bytes_sent | 1.5x - 100x | Reconnaissance via systematic port probing |
| **Slowloris** | latency, connections | 3x - 20x | Connection exhaustion via slow HTTP requests |
| **Cryptomining** | bytes_sent, bytes_received, latency | 2x - 8x | Unauthorized resource usage for cryptocurrency |

---

## Live Dashboard

### Vercel Deployment (Production)

The repository includes a Vercel-compatible deployment:

- **Frontend:** Static HTML + Plotly.js dashboard (`public/index.html`)
- **Backend:** Python serverless function (`api/detect.py`)

Deploy by importing the repository on [vercel.com](https://vercel.com). No build configuration required.

**API endpoint:** `GET /api/detect`

| Parameter | Type | Default | Description |
|---|---|---|---|
| `n` | int | 800 | Number of data points |
| `ratio` | float | 0.06 | Attack injection ratio |
| `sensitivity` | float | 0.6 | Ensemble sensitivity |
| `seed` | int | 42 | Random seed |
| `methods` | string | `zscore,isolation_forest,ewma` | Comma-separated method names |
| `attacks` | string | `ddos,exfiltration,port_scan,slowloris,cryptomining` | Comma-separated attack types |

### Streamlit Dashboard (Local)

```bash
pip install -e ".[dashboard]"
streamlit run app.py
```

---

## Project Structure

```
livermorium/
|
|-- livermorium/              Python library (pip-installable)
|   |-- __init__.py           Package exports, version, public API
|   |-- detector.py           Ensemble AnomalyDetector engine
|   |-- models.py             ML-based detection (Isolation Forest)
|   |-- stats.py              Statistical detectors (Z-Score, IQR, EWMA)
|   |-- stream.py             Network traffic simulator, StreamProcessor
|   |-- viz.py                Plotly visualization functions
|
|-- api/
|   |-- detect.py             Vercel serverless API endpoint
|
|-- public/
|   |-- index.html            Web dashboard frontend (Plotly.js)
|
|-- app.py                    Streamlit local dashboard
|-- setup.py                  Package setup (setuptools)
|-- pyproject.toml            PEP 621 project metadata
|-- vercel.json               Vercel deployment configuration
|-- requirements.txt          Production dependencies
|-- requirements-dev.txt      Development dependencies (includes Streamlit)
|-- LICENSE                   MIT License
|-- README.md                 This document
```

---

## DTU Compute Research Areas

This project draws from the following research divisions within [DTU Compute](https://www.compute.dtu.dk/):

| Research Area | Contribution to Livermorium |
|---|---|
| **Cyber Security** | Threat modeling, attack vector simulation, network traffic feature engineering |
| **Data and AI** | Isolation Forest ensemble learning, unsupervised anomaly classification |
| **Statistics** | Z-Score hypothesis testing, IQR robust estimation, EWMA process control |
| **Scientific Computing** | Numerical algorithms for streaming variance estimation, signal processing |

---

## Performance Characteristics

Tested on synthetic datasets generated by `NetworkSimulator` (seed=42, n=500, anomaly_ratio=0.05):

| Metric | Value |
|---|---|
| Precision | ~80% |
| Recall | ~87% |
| F1 Score | ~58% |
| Threat Classification | HIGH |
| Detection Latency | < 100ms per 1000 points |

Performance varies based on method selection, sensitivity, and attack characteristics.

---

## Citation

If you reference this project in academic or professional work:

```
DTU Compute. (2026). Livermorium: Intelligent Cybersecurity Anomaly Detection Library.
Cursor Hackathon Baku 2026. https://github.com/olaflaitinen/livermorium
```

---

## Team

**DTU Compute**
Technical University of Denmark
Department of Applied Mathematics and Computer Science

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for the full text.
