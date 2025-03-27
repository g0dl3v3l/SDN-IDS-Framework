# dashboard_live_tail.py

import os
import time
import json
from collections import defaultdict
from rich.live import Live
from rich.table import Table
from rich.console import Console

LOG_DIR = "logs"
REFRESH_INTERVAL = 1.0  # seconds

console = Console()

def parse_log_file(filepath):
    """
    Parse a JSON log file to extract live packet statistics.
    Returns total packets, total bytes, flags seen, last timestamp.
    """
    packets = 0
    total_bytes = 0
    flags_seen = set()
    last_ts = "N/A"

    try:
        with open(filepath, "r") as f:
            lines = f.readlines()

            # Skip initial JSON array opening
            lines = [line.strip().rstrip(",") for line in lines if line.strip().startswith("{")]
            for line in lines:
                try:
                    pkt = json.loads(line)
                    packets += 1
                    total_bytes += pkt.get("pkt_len", 0)
                    flags_seen.add(pkt.get("tcp_flags", ""))
                    last_ts = pkt.get("timestamp", last_ts)
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        pass

    return packets, total_bytes, flags_seen, last_ts


def generate_dashboard():
    """
    Generates a Rich table displaying current statistics for each log file/interface.
    """
    table = Table(title="📡 eBPF Flow Monitor (Live Tail)", expand=True)
    table.add_column("Interface", style="bold cyan")
    table.add_column("Packets", justify="right")
    table.add_column("Bytes", justify="right")
    table.add_column("Flags Seen", justify="left")
    table.add_column("Last Timestamp", justify="right")

    for fname in os.listdir(LOG_DIR):
        if fname.endswith(".jsonl"):
            iface = fname.split(".")[0]
            path = os.path.join(LOG_DIR, fname)
            packets, total_bytes, flags, last_ts = parse_log_file(path)
            flag_str = ", ".join(sorted(flags))[:20] + ("…" if len(flags) > 20 else "")
            table.add_row(
                str(iface),
                str(packets),
                str(total_bytes),
                str(flag_str),
                str(last_ts)
            )
    return table


def main():
    if not os.path.exists(LOG_DIR):
        console.print(f"[red]Log directory '{LOG_DIR}' does not exist![/red]")
        return

    console.print(f"[green]🔍 Tailing logs in '{LOG_DIR}'...[/green]")

    with Live(generate_dashboard(), refresh_per_second=1, screen=True) as live:
        try:
            while True:
                time.sleep(REFRESH_INTERVAL)
                live.update(generate_dashboard())
        except KeyboardInterrupt:
            console.print("\n[bold red]Keyboard interrupt received. Exiting...[/bold red]")


if __name__ == "__main__":
    main()
