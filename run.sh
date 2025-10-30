#!/usr/bin/env bash
# run.sh - build and run the traffic analyzer + Rich dashboard
# Usage: ./run.sh [iface] [interval] [topn]
IFACE=${1:-eth0}
INTERVAL=${2:-5}
TOPN=${3:-10}
REFRESH=${4:-2}   # dashboard refresh per second
TTL=${5:-15}      # dashboard ttl for flows (seconds)

set -e

if ! command -v clang >/dev/null 2>&1; then
  echo "clang not found. Please install clang and libbpf headers."
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 not found. Please install Python 3."
  exit 1
fi
if ! python3 -c "import rich" >/dev/null 2>&1; then
  echo "Python package 'rich' not found. Install with: pip3 install rich"
  exit 1
fi

echo "Compiling BPF object..."
clang -O2 -g -target bpf -c traffic_kern.c -o traffic_kern.o

echo "Compiling userspace program..."
clang -O2 -g traffic_user.c -o traffic_user -lbpf -lelf

echo "Starting traffic_user and dashboard..."
if [ "$(id -u)" -ne 0 ]; then
  echo "Running traffic_user with sudo; you may be prompted for a password."
  sudo ./traffic_user -i "${IFACE}" -t "${INTERVAL}" -n "${TOPN}" | python3 dashboard.py --top "${TOPN}" --refresh "${REFRESH}" --ttl "${TTL}"
else
  ./traffic_user -i "${IFACE}" -t "${INTERVAL}" -n "${TOPN}" | python3 dashboard.py --top "${TOPN}" --refresh "${REFRESH}" --ttl "${TTL}"
fi
