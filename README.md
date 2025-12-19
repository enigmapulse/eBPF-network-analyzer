# eBPF Network Analyzer

A lightweight Linux network monitoring tool built using **eBPF** to capture and analyze
network events at the kernel level with minimal performance overhead.

This project explores how eBPF programs can safely run inside the Linux kernel to provide
real-time observability into network traffic without modifying kernel source code.

---

## Motivation

Traditional user-space network monitoring tools often suffer from:
- High context-switch overhead
- Limited visibility into kernel-level events
- Performance penalties under high traffic

eBPF enables running sandboxed programs directly inside the kernel, making it possible
to observe low-level network behavior efficiently and safely.  
This project was built to understand and apply eBPF for **real-time network analysis**.

---

## Features

- Kernel-level packet and event monitoring using eBPF
- Minimal overhead data collection
- Safe execution via eBPF verifier
- User-space aggregation and visualization
- Python-based tooling for deployment and analysis

---

## High-Level Design

1. **eBPF Programs (Kernel Space)**
   - Attached to networking hooks
   - Collect packet-level and flow-level metrics
   - Emit data using eBPF maps

2. **User-Space Components**
   - Load and manage eBPF programs
   - Read data from eBPF maps
   - Aggregate and process metrics

3. **Visualization & Analysis**
   - Python scripts to parse collected data
   - Basic dashboards / summaries for traffic analysis

This separation allows efficient kernel execution while keeping analysis flexible in
user space.

---

## Tech Stack

- **C** — eBPF program implementation
- **Linux** — kernel execution environment
- **eBPF** — kernel-level observability
- **Python** — user-space tooling and visualization

---

