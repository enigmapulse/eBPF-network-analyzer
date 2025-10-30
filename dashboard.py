#!/usr/bin/env python3
# dashboard.py - live Rich dashboard for the traffic analyzer
# Usage: ./dashboard.py --top 10 --refresh 2 --ttl 15
from rich.live import Live
from rich.table import Table
from rich import box
import json, sys, time, argparse, threading, queue

parser = argparse.ArgumentParser()
parser.add_argument("--top", type=int, default=10, help="Top N flows to display")
parser.add_argument("--refresh", type=float, default=2.0, help="Screen refresh rate (Hz)")
parser.add_argument("--ttl", type=float, default=15.0, help="Seconds to keep a flow without updates")
args = parser.parse_args()

line_q = queue.Queue()

def stdin_reader(q):
    """Read lines from stdin and push into queue (runs in background)."""
    for ln in sys.stdin:
        q.put(ln)
    # EOF -> put sentinel
    q.put(None)

t = threading.Thread(target=stdin_reader, args=(line_q,), daemon=True)
t.start()

# store flows keyed by (src,dst,proto,sport,dport)
flows = {}  # key -> {pkts, bytes, pps, bps, last}

def render_table(data, topn):
    table = Table(title="Live Traffic Monitor", box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("PKTS", justify="right", style="cyan", no_wrap=True)
    table.add_column("BYTES", justify="right", style="cyan", no_wrap=True)
    table.add_column("PPS", justify="right", style="magenta")
    table.add_column("BPS", justify="right", style="magenta")
    table.add_column("PROTO", style="yellow")
    table.add_column("FLOW (src:sp → dst:dp)", style="green", overflow="fold")
    table.add_column("%", justify="right", style="red")

    for i, (k, v) in enumerate(data[:topn]):
        (src, dst, proto, sport, dport) = k
        flowname = f"{src}:{sport} → {dst}:{dport}"
        table.add_row(
            str(v["pkts"]),
            str(v["bytes"]),
            f"{v.get('pps', 0):.2f}",
            f"{v.get('bps', 0):.2f}",
            proto,
            flowname,
            f"{v.get('pct', 0.0):.2f}"
        )
    return table

def process_line(line):
    """Parse a JSON line and merge into flows."""
    try:
        obj = json.loads(line)
    except Exception:
        return
    # expected keys from traffic_user: src, dst, proto, sport, dport, pkts (or pkts), bytes (or bytes), pps, bps, pct
    src = obj.get("src") or obj.get("ip") or "0.0.0.0"
    dst = obj.get("dst") or obj.get("ip") or "0.0.0.0"
    proto = obj.get("proto", "UNK")
    sport = int(obj.get("sport", 0) or 0)
    dport = int(obj.get("dport", 0) or 0)
    pkts = int(obj.get("pkts", obj.get("cnt", 0)) or 0)
    bytes_ = int(obj.get("bytes", 0) or 0)
    pps = float(obj.get("pps", 0.0) or 0.0)
    bps = float(obj.get("bps", 0.0) or 0.0)
    pct = float(obj.get("pct", 0.0) or 0.0)

    key = (src, dst, proto, sport, dport)
    now = time.time()
    entry = flows.get(key)
    if entry is None:
        flows[key] = {"pkts": pkts, "bytes": bytes_, "pps": pps, "bps": bps, "last": now, "pct": pct}
    else:
        # accumulate counts and bytes, update pps/bps to the most recent value
        entry["pkts"] += pkts
        entry["bytes"] += bytes_
        entry["pps"] = pps
        entry["bps"] = bps
        entry["last"] = now
        entry["pct"] = pct

def purge_stale(ttl):
    now = time.time()
    to_del = [k for k, v in flows.items() if (now - v.get("last", 0)) > ttl]
    for k in to_del:
        del flows[k]

def main_loop(topn, refresh, ttl):
    refresh_interval = 1.0 / max(0.1, refresh)
    with Live(render_table([], topn), refresh_per_second=max(1, int(refresh)), screen=False) as live:
        eof_received = False
        while True:
            # pull all queued lines
            while True:
                try:
                    item = line_q.get_nowait()
                except queue.Empty:
                    break
                if item is None:
                    eof_received = True
                    break
                process_line(item)
            # purge stale entries
            purge_stale(ttl)
            # compute percent column (by pkts)
            total_pkts = sum(v["pkts"] for v in flows.values()) or 1
            data = []
            for k, v in flows.items():
                v["pct"] = (v["pkts"] * 100.0) / total_pkts
                data.append((k, v))
            # sort by pkts desc
            data.sort(key=lambda kv: kv[1]["pkts"], reverse=True)
            live.update(render_table(data, topn))
            if eof_received:
                break
            time.sleep(refresh_interval)

if __name__ == "__main__":
    try:
        main_loop(args.top, args.refresh, args.ttl)
    except KeyboardInterrupt:
        pass
