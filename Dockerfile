FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements files
COPY requirements.txt .
COPY src/monitoring/requirements.txt monitoring-requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir -r monitoring-requirements.txt

# Copy source code
COPY src/ ./src/

# Copy configuration
COPY docker-compose.yml .

# Set environment variables
ENV PYTHONPATH=/app

CMD ["python", "src/run_attack_simulation.py"]