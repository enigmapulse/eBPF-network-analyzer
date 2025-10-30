#!/usr/bin/env bash
# run.sh - build and run the traffic analyzer
# Usage: ./run.sh [iface] [interval] [topn]
IFACE=${1:-eth0}
INTERVAL=${2:-5}
TOPN=${3:-10}

set -e

# Check root - we will use sudo if not root
if ! command -v clang >/dev/null 2>&1; then
  echo "clang not found. Please install clang and libbpf headers."
  exit 1
fi

echo "Compiling BPF object..."
clang -O2 -g -target bpf -c traffic_kern.c -o traffic_kern.o

echo "Compiling userspace program..."
clang -O2 -g traffic_user.c -o traffic_user -lbpf -lelf

if [ "$(id -u)" -ne 0 ]; then
  echo "Not running as root; will use sudo to run the program."
  sudo ./traffic_user -i "${IFACE}" -t "${INTERVAL}" -n "${TOPN}"
else
  ./traffic_user -i "${IFACE}" -t "${INTERVAL}" -n "${TOPN}"
fi
