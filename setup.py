from setuptools import setup, find_packages

setup(
    name="livermorium",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "numpy>=1.24.0",
        "pandas>=2.0.0",
        "scikit-learn>=1.3.0",
        "plotly>=5.15.0",
    ],
    extras_require={
        "dashboard": ["streamlit>=1.28.0"],
    },
    python_requires=">=3.9",
    author="DTU Compute",
    description="Intelligent cybersecurity anomaly detection combining Statistics, ML, and Scientific Computing",
)
