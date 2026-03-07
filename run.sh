#!/bin/bash
set -e

cleanup() {
    echo "Shutting down..."
    sudo kill -SIGTERM "$PID" 2>/dev/null
    wait "$PID" 2>/dev/null
    exit 0
}

trap cleanup SIGINT SIGTERM

sudo ./main &
PID=$!
sleep 1
sudo ip addr add 10.0.0.1/24 dev tun1
sudo ip link set tun1 up
wait $PID
