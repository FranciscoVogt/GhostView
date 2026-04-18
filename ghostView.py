#!/usr/bin/env python3

import argparse
import threading
import time
import struct
import csv
import curses
from collections import deque
from typing import Dict, Optional
from scapy.all import Ether, IP, Raw, sendp, sniff, conf

# Custom EtherTypes used for identifying probes and telemetry responses
ETH_TYPE_SEND = 0x1234
ETH_TYPE_RECV = 0x1235

# Default configuration values
DEFAULT_SEND_IF = "enp6s0f0"
DEFAULT_RECV_IF = "enp6s0f1"
IP_SRC = "172.168.0.1"
IP_DST = "172.168.0.2"
MONITOR_H_LEN = 50
DEFAULT_EWMA_ALPHA = 0.3 # Smoothing factor for the Exponential Weighted Moving Average
SAMPLES_KEEP = 8         # Number of historical samples to keep for linear regression

# Global dictionaries to store statistics for flows and ports
flows_stats, ports_stats = {}, {}
# Lock to ensure thread-safe updates to the statistics dictionaries
stats_lock = threading.Lock()
log_handle, log_writer = None, None
log_lock = threading.Lock()

# Class to track and calculate throughput statistics for a single entity (flow or port)
class CounterStat:
    def __init__(self):
        self.lock = threading.Lock()
        # A double-ended queue to store a rolling window of (timestamp, byte_count) tuples
        self.samples = deque(maxlen=SAMPLES_KEEP)
        self.instant_mbps: float = 0.0
        self.regress_mbps: float = 0.0
        self.ewma_mbps: float = 0.0
        self.last_seen_wall: float = 0.0

    # Updates the statistics based on new telemetry data received
    def update(self, bytes_val: int, ts_ns: int, wall_time: float, alpha: float):
        with self.lock:
            # Record the real-world time this update was received (for inactivity timeouts)
            self.last_seen_wall = wall_time
            
            # Anti-stagnation check: If we have samples and the new data is identical to the last one
            # (meaning time/bytes haven't advanced in the switch), traffic has stopped.
            if self.samples and self.samples[-1] == (ts_ns, bytes_val):
                self.instant_mbps = 0.0
                self.regress_mbps = 0.0
                # Smoothly decay the EWMA to zero
                self.ewma_mbps = alpha * 0.0 + (1 - alpha) * self.ewma_mbps
                return

            # Append the new valid sample to the historical deque
            self.samples.append((ts_ns, bytes_val))

            # We need at least two samples to calculate a delta (speed)
            if len(self.samples) >= 2:
                # Extract the two most recent samples
                (t1, b1), (t2, b2) = (self.samples[-2], self.samples[-1])
                delta_bytes = b2 - b1
                # delta_ns = b2 - b1 # Erro de digitação corrigido para t2 - t1
                delta_ns = t2 - t1
                
                # Check to prevent division by zero in case of identical timestamps
                if delta_ns > 0:
                    # 1. Instantaneous Throughput calculation (Mbps)
                    self.instant_mbps = (delta_bytes * 8 / delta_ns) * 1000.0
                    
                    # 2. Linear Regression Throughput calculation over the entire sample window
                    xs, ys = [s[0] for s in self.samples], [s[1] for s in self.samples]
                    n = len(xs)
                    mean_x, mean_y = sum(xs)/n, sum(ys)/n
                    # Compute slope (m) = Sum((x - mean_x) * (y - mean_y)) / Sum((x - mean_x)^2)
                    num = sum((xs[i]-mean_x)*(ys[i]-mean_y) for i in range(n))
                    den = sum((xs[i]-mean_x)**2 for i in range(n))
                    # Convert bytes/ns slope to Mbps
                    self.regress_mbps = (num / den) * 8000.0 if den > 0 else 0.0
                else:
                    # Fallback if time didn't advance but bytes changed (very rare hardware glitch)
                    self.instant_mbps = 0.0
                    self.regress_mbps = 0.0

                # 3. Update the Exponential Weighted Moving Average
                self.ewma_mbps = alpha * self.instant_mbps + (1 - alpha) * self.ewma_mbps

# --- Auxiliares ---

# Reads the configuration file and extracts the target flows, ports, and probe periods
def parse_flows_file(path: str):
    flows = []
    try:
        with open(path, "r") as f:
            for raw in f:
                line = raw.strip()
                # Skip empty lines and comments
                if not line or line.startswith("#"): continue
                # Parse comma-separated key=value strings into a dictionary
                kv = {p.split("=")[0].strip(): p.split("=")[1].strip() for p in line.split(",") if "=" in p}
                flows.append({"flow": int(kv["flow"]), "port": int(kv["port"]), "period": float(kv["period"])})
    except: pass
    return flows

# Extracts telemetry metrics from the raw bytes of the received packet
def parse_monitor_h(raw: bytes, off: int):
    # Unpack bytes_flow and bytes_port (8 bytes each, unsigned long long)
    b_f, b_p = struct.unpack("!QQ", raw[off:off+16])
    # Read the timestamp as a 6-byte big-endian integer
    ts_ns = int.from_bytes(raw[off+16:off+22], "big")
    # Unpack the queue depth (4 bytes, unsigned int) skipping the 20-byte gap
    q_f = struct.unpack("!I", raw[off+42:off+46])[0]
    return {"bytes_flow": b_f, "bytes_port": b_p, "timestamp_ns": ts_ns, "qDepth_flow": q_f}

# --- Threads ---

# Thread responsible for injecting probe requests into the network
def flow_sender_thread(iface: str, flow_cfg: Dict, stop_event: threading.Event):
    # Pack the instruction header: Flow ID (4B), Port ID (4B), and a custom flag (2B)
    inst = struct.pack("!IIH", flow_cfg["flow"], flow_cfg["port"], (flow_cfg["port"] & 0x1FF) << 7)
    # Assemble the probe packet (Ether / Raw instruction / IPv4 / Raw dummy payload)
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff", type=ETH_TYPE_SEND) / Raw(inst + bytes(IP(src=IP_SRC, dst=IP_DST)/Raw(load="MON"*20)))
    period = flow_cfg["period"]
    
    # Loop continuously, sending the probe and sleeping for the specified period
    while not stop_event.is_set():
        sendp(pkt, iface=iface, verbose=False)
        time.sleep(period)

# Thread responsible for sniffing and processing incoming telemetry responses
def receiver_thread(iface: str, stop_event: threading.Event, alpha: float):
    # Berkeley Packet Filter (BPF) to capture only GhostView telemetry packets
    bpf = f"ether proto 0x{ETH_TYPE_RECV:04x}"
    
    # Callback function executed for every captured packet
    def _prn(pkt):
        raw = bytes(pkt)
        try:
            # Extract Flow ID and Port ID from the custom header located right after Ethernet
            idx_f, idx_p = struct.unpack("!II", raw[14:22])
            # Calculate IPv4 header length dynamically based on the IHL field
            ihl = (raw[24] & 0x0F) * 4
            # Parse the actual telemetry data which starts immediately after the IPv4 header
            mh = parse_monitor_h(raw, 24 + ihl)
            wall = time.time()
            
            # Thread-safely update both the flow and port statistics objects
            with stats_lock:
                for d, i, v in [(flows_stats, idx_f, mh["bytes_flow"]), (ports_stats, idx_p, mh["bytes_port"])]:
                    if i not in d: d[i] = CounterStat()
                    d[i].update(v, mh["timestamp_ns"], wall, alpha)
        except: return
    
    # Start the Scapy sniffer (blocking call that runs until stop_event is set)
    sniff(iface=iface, prn=_prn, filter=bpf, store=False, stop_filter=lambda x: stop_event.is_set())

# --- Dashboard ---

# Thread responsible for rendering the live terminal UI using curses
def dashboard_loop(refresh_interval: float, inactive_timeout: float):
    def _draw(stdscr):
        # Make getch() non-blocking
        stdscr.nodelay(True)
        # Hide the terminal cursor
        curses.curs_set(0)
        
        # Main drawing loop
        while True:
            stdscr.erase()
            max_y, max_x = stdscr.getmaxyx()
            now = time.time()
            try:
                # Print dashboard header with current time
                stdscr.addstr(0, 0, f"GhostView Dashboard - {time.strftime('%H:%M:%S')}"[:max_x-1])
                hdr = f"{'ID':<5} {'LastBytes':>12} {'LastTs(ns)':>18} {'Inst(Mbps)':>12} {'Reg(Mbps)':>12} {'EWMA(Mbps)':>12} {'Seen(s)':>8}"
                row = 2
                
                # Iterate and print stats for both Flows and Ports
                for label, stats_dict in [("Flows:", flows_stats), ("Ports:", ports_stats)]:
                    if row >= max_y - 1: break
                    # Section label
                    stdscr.addstr(row, 0, label[:max_x-1], curses.A_BOLD); row += 1
                    # Table headers
                    stdscr.addstr(row, 0, hdr[:max_x-1], curses.A_UNDERLINE); row += 1
                    
                    with stats_lock:
                        for fid, st in sorted(stats_dict.items()):
                            last_seen = now - st.last_seen_wall
                            # Hide entries that haven't received updates within the inactive_timeout
                            if last_seen > inactive_timeout: continue
                            if row >= max_y - 1: break
                            
                            with st.lock:
                                # Extract latest sample data if available
                                lb = st.samples[-1][1] if st.samples else 0
                                lts = st.samples[-1][0] if st.samples else 0
                                # Format the row displaying IDs, Counters, and calculated Throughputs
                                line = f"{fid:<5} {lb:>12d} {lts:>18d} {st.instant_mbps:>12.2f} {st.regress_mbps:>12.2f} {st.ewma_mbps:>12.2f} {last_seen:>8.1f}"
                                stdscr.addstr(row, 0, line[:max_x-1])
                                row += 1
                    row += 1
            except curses.error: pass
            
            # Render changes to the screen
            stdscr.refresh()
            time.sleep(refresh_interval)
            
            # Check for user input; exit if 'q' is pressed
            if stdscr.getch() == ord('q'): return
    
    # Initialize and wrap the curses environment safely
    curses.wrapper(_draw)

def main():
    # Setup command-line argument parsing
    parser = argparse.ArgumentParser()
    # Mode selector: Send probes, receive telemetry, or do both
    parser.add_argument("--mode", choices=["send", "recv", "both"], default="both")
    parser.add_argument("--send-if", "-s", default=DEFAULT_SEND_IF)
    parser.add_argument("--recv-if", "-r", default=DEFAULT_RECV_IF)
    parser.add_argument("--file", "-f", required=True)
    parser.add_argument("--refresh", type=float, default=0.5)
    parser.add_argument("--inactive", type=float, default=10.0)
    args = parser.parse_args()

    # Disable Scapy verbose output
    conf.verb = 0
    stop_event = threading.Event()
    flows = parse_flows_file(args.file)

    # Launch sending threads if the mode permits
    if args.mode in ["send", "both"]:
        for f in flows:
            threading.Thread(target=flow_sender_thread, args=(args.send_if, f, stop_event), daemon=True).start()

    # Launch receiving thread and dashboard if the mode permits
    if args.mode in ["recv", "both"]:
        threading.Thread(target=receiver_thread, args=(args.recv_if, stop_event, DEFAULT_EWMA_ALPHA), daemon=True).start()
        try: dashboard_loop(args.refresh, args.inactive)
        except KeyboardInterrupt: pass
    else:
        # If in 'send' mode only, keep the main thread alive indefinitely
        try:
            while True: time.sleep(1)
        except KeyboardInterrupt: pass

    # Signal all running threads to shut down gracefully
    stop_event.set()

if __name__ == "__main__":
    main()
