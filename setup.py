from setuptools import setup, find_packages

setup(
    name="iot_watchtower",
    version="0.1",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "dash==2.14.0",
        "plotly==5.18.0",
        "pandas==2.2.0",
        "numpy==1.24.3",
        "dash-bootstrap-components==1.5.0"
    ],
    python_requires=">=3.8",
)