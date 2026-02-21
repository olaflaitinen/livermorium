# Livermorium

**Intelligent Cybersecurity Anomaly Detection Library**

> Built by **DTU Compute** for Cursor Hackathon Baku 2026

Livermorium combines DTU Compute's expertise in **Cybersecurity**, **AI/Machine Learning**, **Statistics**, and **Scientific Computing** into a single Python library for real-time network threat detection.

## Core Feature

**Real-time network traffic anomaly detection** using an ensemble of statistical and ML methods - detects DDoS attacks, data exfiltration, port scanning, slowloris attacks, and cryptomining patterns.

## Installation

```bash
pip install -e .
```

Or install with the dashboard:

```bash
pip install -e ".[dashboard]"
```

## Quick Start

```python
from livermorium import AnomalyDetector, NetworkSimulator

# Simulate network traffic with injected attacks
sim = NetworkSimulator(seed=42)
data = sim.generate(n_points=1000, anomaly_ratio=0.05)

# Detect anomalies with ensemble methods
detector = AnomalyDetector(
    methods=["zscore", "isolation_forest", "ewma"],
    sensitivity=0.7,
)
report = detector.fit_detect(data.to_matrix())

print(f"Threat Level: {report.threat_level}")
print(f"Anomalies Found: {sum(report.anomalies)}")
print(f"Threat Score: {report.threat_score:.2%}")

# Visualize results
from livermorium.viz import plot_anomalies
fig = plot_anomalies(data, report)
fig.show()
```

## Run the Dashboard

```bash
streamlit run app.py
```

## Detection Methods

| Method | Area | Description |
|--------|------|-------------|
| Z-Score | Statistics | Gaussian assumption outlier detection |
| IQR | Statistics | Non-parametric outlier detection |
| EWMA | Scientific Computing | Exponentially weighted streaming detection |
| Isolation Forest | Machine Learning | Tree-based anomaly isolation |

## Simulated Attack Types

- **DDoS** - Massive traffic volume spikes
- **Exfiltration** - Unusual outbound data transfer
- **Port Scan** - High connection count bursts
- **Slowloris** - Latency degradation attacks
- **Cryptomining** - Symmetric traffic patterns

## Project Structure

```
livermorium/
├── livermorium/           # pip-installable library
│   ├── __init__.py        # Package exports
│   ├── detector.py        # Ensemble anomaly detector
│   ├── models.py          # ML-based detection (Isolation Forest)
│   ├── stats.py           # Statistical detectors (Z-Score, IQR, EWMA)
│   ├── stream.py          # Network traffic simulator
│   └── viz.py             # Plotly visualization utilities
├── app.py                 # Streamlit dashboard demo
├── setup.py               # Package setup
├── pyproject.toml         # Modern Python packaging
└── requirements.txt       # Dependencies
```

## DTU Compute Research Areas Combined

1. **Cybersecurity** - Network threat modeling and attack simulation
2. **AI / Machine Learning** - Isolation Forest anomaly detection
3. **Statistics** - Z-Score, IQR, and EWMA statistical methods
4. **Scientific Computing** - Numerical algorithms and data pipelines

## Team

**DTU Compute** - Technical University of Denmark, Department of Applied Mathematics and Computer Science

## License

MIT
