# Base Image with Python 3.11
FROM python:3.11-slim-bullseye

# Install necessary system packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    curl \
    git \
    nmap \
    unzip \
    ca-certificates \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei from ProjectDiscovery Release
ENV NUCLEI_VERSION=v3.1.8
RUN wget -q "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION#v}_linux_amd64.zip" \
    && unzip "nuclei_${NUCLEI_VERSION#v}_linux_amd64.zip" nuclei \
    && mv nuclei /usr/local/bin/ \
    && rm "nuclei_${NUCLEI_VERSION#v}_linux_amd64.zip"

# Download nuclei templates base signature repository
RUN nuclei -update-templates || true

# Set up working directory inside the container
WORKDIR /app

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source tasks code
COPY . .

# Run Celery worker command on startup
CMD ["celery", "-A", "tasks", "worker", "--loglevel=info"]
