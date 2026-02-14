# Vestigia Production Docker Image
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (for layer caching)
# Make sure you create this file first (see below)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories and set permissions
RUN mkdir -p data backups logs
RUN useradd -m -u 1000 vestigia && \
    chown -R vestigia:vestigia /app

USER vestigia

# Expose Streamlit port
EXPOSE 8501

# Health check - Updated to use your actual vestigia_core.py file
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl --fail http://localhost:8501/_stcore/health || exit 1

# Default command: Launches your Dashboard
CMD ["streamlit", "run", "web_ui/vestigia_dashboard.py", "--server.port=8501", "--server.address=0.0.0.0"]

# Labels
LABEL maintainer="security@company.com" \
      version="1.0" \
      description="Vestigia - Immutable AI Observability Dashboard"
