FROM python:3.12-slim

# build-essential + python3-dev: netifaces (discovery_monitor) builds a C extension.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        nmap \
        iputils-ping \
        net-tools \
        iproute2 \
        arp-scan \
        build-essential \
        python3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY fyp_agent/requirements.txt ./requirements-agent.txt
COPY discovery_monitor/requirements.txt ./requirements-discovery.txt

RUN pip install --no-cache-dir \
    -r requirements-agent.txt \
    -r requirements-discovery.txt

COPY fyp_agent/ ./fyp_agent/
COPY discovery_monitor/ ./discovery_monitor/

ENV FYP_AGENT_STATE_DIR=/data
ENV FYP_AGENT_LOG_LEVEL=INFO

VOLUME ["/data"]

ENTRYPOINT ["python", "-m", "fyp_agent"]
