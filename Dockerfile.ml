# Dockerfile for ML Inference Service

FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir flask scikit-learn numpy pandas requests

# Copy application code
COPY config/ ./config/
COPY ml_service/ ./ml_service/
COPY utils/ ./utils/
COPY models/ ./models/

# Expose port
EXPOSE 5000

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV ML_SERVICE_HOST=0.0.0.0
ENV ML_SERVICE_PORT=5000

# Run the service
CMD ["python", "ml_service/inference_server.py"]
