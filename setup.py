from setuptools import setup, find_packages

setup(
    name="iot-security-simulation",
    version="0.1.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "numpy>=1.21.0",
        "pandas>=1.3.0",
        "scikit-learn>=0.24.2",
        "scipy>=1.7.0",
        "matplotlib>=3.4.2",
        "seaborn>=0.11.1",
        "elasticsearch>=7.17.0",
        "requests>=2.26.0",
        "python-dotenv>=0.19.0",
        "plotly>=5.1.0",
        "dash>=2.0.0",
        "networkx>=2.6.2",
        "PyYAML>=5.4.1",
        "jsonschema>=3.2.0"
    ],
    python_requires=">=3.8",
    author="Your Name",
    author_email="your.email@example.com",
    description="IoT network security simulation with attack detection",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/iot-security-simulation",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
)