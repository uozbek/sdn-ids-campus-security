#!/bin/bash
# ============================================
# SDN-IDS Quick Start Script
# ============================================

set -e

echo "============================================"
echo "SDN-IDS Quick Start"
echo "============================================"

# Check requirements
echo "[1/6] Checking requirements..."
command -v docker >/dev/null 2>&1 || { echo "Docker is required but not installed. Aborting." >&2; exit 1; }
command -v containerlab >/dev/null 2>&1 || { echo "Containerlab is required but not installed. Aborting." >&2; exit 1; }

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Pull Docker images
echo "[2/6] Pulling Docker images..."
docker pull martimy/ryu-flowmanager:latest
docker pull python:3.10-slim
docker pull wbitt/network-multitool:alpine-minimal

# Reset any existing configuration
echo "[3/6] Cleaning up existing configuration..."
sudo containerlab destroy --topo sdn-ids.clab.yml 2>/dev/null || true
sudo bash reset-ovs.sh 2>/dev/null || true

# Setup OVS switches
echo "[4/6] Setting up OVS switches..."
sudo bash setup-ovs.sh

# Deploy topology
echo "[5/6] Deploying Containerlab topology..."
sudo containerlab deploy --topo sdn-ids.clab.yml

# Wait for services to start
echo "[6/6] Waiting for services to start..."
sleep 10

# Health checks
echo ""
echo "============================================"
echo "Health Checks"
echo "============================================"

echo -n "ML Service: "
if curl -s http://172.10.10.100:5000/health | grep -q "healthy"; then
    echo "OK"
else
    echo "STARTING (may take a few minutes)"
fi

echo -n "Controller: "
if curl -s http://172.10.10.10:8080/stats/switches | grep -q "\["; then
    echo "OK"
else
    echo "STARTING"
fi

echo ""
echo "============================================"
echo "SDN-IDS System is Ready!"
echo "============================================"
echo ""
echo "Access points:"
echo "  - FlowManager UI: http://172.10.10.10:8080"
echo "  - ML Service API: http://172.10.10.100:5000"
echo ""
echo "Quick commands:"
echo "  - View controller logs: docker logs -f clab-sdn-ids-ctrl"
echo "  - View ML logs: docker logs -f clab-sdn-ids-ml_service"
echo "  - Run tests: python3 tests/run_tests.py"
echo "  - Start attack: docker exec clab-sdn-ids-attacker1 python3 /attack/ddos_simulator.py 192.168.11.6 -a syn"
echo ""
echo "To stop: sudo containerlab destroy --topo sdn-ids.clab.yml"
echo "============================================"
