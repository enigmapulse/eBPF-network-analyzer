from rich.live import Live
from rich.table import Table
import json, sys, time

def render_table(data):
    table = Table(title="Live Traffic Monitor", expand=True)
    table.add_column("COUNT", justify="right", style="cyan")
    table.add_column("PROTO", style="magenta")
    table.add_column("DEST_IP", style="green")
    table.add_column("DPORT", justify="right", style="yellow")
    for row in data[:10]:
        table.add_row(str(row["cnt"]), row["proto"], row["ip"], str(row["dport"]))
    return table

def main():
    data = []
    with Live(render_table(data), refresh_per_second=2) as live:
        for line in sys.stdin:
            try:
                row = json.loads(line.strip())
                # Merge by (proto, ip, dport)
                key = (row["proto"], row["ip"], row["dport"])
                for r in data:
                    if (r["proto"], r["ip"], r["dport"]) == key:
                        r["cnt"] += row["cnt"]
                        break
                else:
                    data.append(row)
                data.sort(key=lambda x: -x["cnt"])
                live.update(render_table(data))
            except json.JSONDecodeError:
                pass
            time.sleep(0.1)

if __name__ == "__main__":
    main()
