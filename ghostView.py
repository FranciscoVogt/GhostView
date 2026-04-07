#!/usr/bin/env python3
"""
ghostView.py - Versão Corrigida para Dados Estáticos
- Detecta quando a telemetria (bytes/timestamp) para de avançar.
- Zera o throughput mesmo se os pacotes probe continuarem chegando.
"""

import argparse
import threading
import time
import struct
import csv
import curses
from collections import deque
from typing import Dict, Optional
from scapy.all import Ether, IP, Raw, sendp, sniff, conf

# EtherTypes
ETH_TYPE_SEND = 0x1234
ETH_TYPE_RECV = 0x1235

# Defaults
DEFAULT_SEND_IF = "enp6s0f0"
DEFAULT_RECV_IF = "enp6s0f1"
IP_SRC = "172.168.0.1"
IP_DST = "172.168.0.2"
MONITOR_H_LEN = 50
DEFAULT_EWMA_ALPHA = 0.3
SAMPLES_KEEP = 8

flows_stats, ports_stats = {}, {}
stats_lock = threading.Lock()
log_handle, log_writer = None, None
log_lock = threading.Lock()

class CounterStat:
    def __init__(self):
        self.lock = threading.Lock()
        self.samples = deque(maxlen=SAMPLES_KEEP)
        self.instant_mbps: float = 0.0
        self.regress_mbps: float = 0.0
        self.ewma_mbps: float = 0.0
        self.last_seen_wall: float = 0.0

    def update(self, bytes_val: int, ts_ns: int, wall_time: float, alpha: float):
        with self.lock:
            self.last_seen_wall = wall_time
            
            # Se já temos samples e o dado novo é identico ao último (estagnado)
            if self.samples and self.samples[-1] == (ts_ns, bytes_val):
                self.instant_mbps = 0.0
                self.regress_mbps = 0.0
                # O EWMA também deve tender a zero
                self.ewma_mbps = alpha * 0.0 + (1 - alpha) * self.ewma_mbps
                return

            self.samples.append((ts_ns, bytes_val))

            if len(self.samples) >= 2:
                (t1, b1), (t2, b2) = (self.samples[-2], self.samples[-1])
                delta_bytes = b2 - b1
                delta_ns = b2 - b1 # Erro de digitação corrigido para t2 - t1
                delta_ns = t2 - t1
                
                if delta_ns > 0:
                    # Cálculo normal
                    self.instant_mbps = (delta_bytes * 8 / delta_ns) * 1000.0
                    
                    # Regressão Linear
                    xs, ys = [s[0] for s in self.samples], [s[1] for s in self.samples]
                    n = len(xs)
                    mean_x, mean_y = sum(xs)/n, sum(ys)/n
                    num = sum((xs[i]-mean_x)*(ys[i]-mean_y) for i in range(n))
                    den = sum((xs[i]-mean_x)**2 for i in range(n))
                    self.regress_mbps = (num / den) * 8000.0 if den > 0 else 0.0
                else:
                    # Se o tempo não avançou mas os bytes mudaram (raro), ou dados iguais
                    self.instant_mbps = 0.0
                    self.regress_mbps = 0.0

                # Atualiza EWMA
                self.ewma_mbps = alpha * self.instant_mbps + (1 - alpha) * self.ewma_mbps

# --- Auxiliares ---

def parse_flows_file(path: str):
    flows = []
    try:
        with open(path, "r") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"): continue
                kv = {p.split("=")[0].strip(): p.split("=")[1].strip() for p in line.split(",") if "=" in p}
                flows.append({"flow": int(kv["flow"]), "port": int(kv["port"]), "period": float(kv["period"])})
    except: pass
    return flows

def parse_monitor_h(raw: bytes, off: int):
    b_f, b_p = struct.unpack("!QQ", raw[off:off+16])
    ts_ns = int.from_bytes(raw[off+16:off+22], "big")
    q_f = struct.unpack("!I", raw[off+42:off+46])[0]
    return {"bytes_flow": b_f, "bytes_port": b_p, "timestamp_ns": ts_ns, "qDepth_flow": q_f}

# --- Threads ---

def flow_sender_thread(iface: str, flow_cfg: Dict, stop_event: threading.Event):
    inst = struct.pack("!IIH", flow_cfg["flow"], flow_cfg["port"], (flow_cfg["port"] & 0x1FF) << 7)
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff", type=ETH_TYPE_SEND) / Raw(inst + bytes(IP(src=IP_SRC, dst=IP_DST)/Raw(load="MON"*20)))
    period = flow_cfg["period"]
    while not stop_event.is_set():
        sendp(pkt, iface=iface, verbose=False)
        time.sleep(period)

def receiver_thread(iface: str, stop_event: threading.Event, alpha: float):
    bpf = f"ether proto 0x{ETH_TYPE_RECV:04x}"
    def _prn(pkt):
        raw = bytes(pkt)
        try:
            idx_f, idx_p = struct.unpack("!II", raw[14:22])
            ihl = (raw[24] & 0x0F) * 4
            mh = parse_monitor_h(raw, 24 + ihl)
            wall = time.time()
            with stats_lock:
                for d, i, v in [(flows_stats, idx_f, mh["bytes_flow"]), (ports_stats, idx_p, mh["bytes_port"])]:
                    if i not in d: d[i] = CounterStat()
                    d[i].update(v, mh["timestamp_ns"], wall, alpha)
        except: return
    sniff(iface=iface, prn=_prn, filter=bpf, store=False, stop_filter=lambda x: stop_event.is_set())

# --- Dashboard ---

def dashboard_loop(refresh_interval: float, inactive_timeout: float):
    def _draw(stdscr):
        stdscr.nodelay(True)
        curses.curs_set(0)
        while True:
            stdscr.erase()
            max_y, max_x = stdscr.getmaxyx()
            now = time.time()
            try:
                stdscr.addstr(0, 0, f"GhostView Dashboard - {time.strftime('%H:%M:%S')}"[:max_x-1])
                hdr = f"{'ID':<5} {'LastBytes':>12} {'LastTs(ns)':>18} {'Inst(Mbps)':>12} {'Reg(Mbps)':>12} {'EWMA(Mbps)':>12} {'Seen(s)':>8}"
                row = 2
                for label, stats_dict in [("Flows:", flows_stats), ("Ports:", ports_stats)]:
                    if row >= max_y - 1: break
                    stdscr.addstr(row, 0, label[:max_x-1], curses.A_BOLD); row += 1
                    stdscr.addstr(row, 0, hdr[:max_x-1], curses.A_UNDERLINE); row += 1
                    with stats_lock:
                        for fid, st in sorted(stats_dict.items()):
                            last_seen = now - st.last_seen_wall
                            if last_seen > inactive_timeout: continue
                            if row >= max_y - 1: break
                            
                            with st.lock:
                                lb = st.samples[-1][1] if st.samples else 0
                                lts = st.samples[-1][0] if st.samples else 0
                                line = f"{fid:<5} {lb:>12d} {lts:>18d} {st.instant_mbps:>12.2f} {st.regress_mbps:>12.2f} {st.ewma_mbps:>12.2f} {last_seen:>8.1f}"
                                stdscr.addstr(row, 0, line[:max_x-1])
                                row += 1
                    row += 1
            except curses.error: pass
            stdscr.refresh()
            time.sleep(refresh_interval)
            if stdscr.getch() == ord('q'): return
    curses.wrapper(_draw)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["send", "recv", "both"], default="both")
    parser.add_argument("--send-if", "-s", default=DEFAULT_SEND_IF)
    parser.add_argument("--recv-if", "-r", default=DEFAULT_RECV_IF)
    parser.add_argument("--file", "-f", required=True)
    parser.add_argument("--refresh", type=float, default=0.5)
    parser.add_argument("--inactive", type=float, default=10.0)
    args = parser.parse_args()

    conf.verb = 0
    stop_event = threading.Event()
    flows = parse_flows_file(args.file)

    if args.mode in ["send", "both"]:
        for f in flows:
            threading.Thread(target=flow_sender_thread, args=(args.send_if, f, stop_event), daemon=True).start()

    if args.mode in ["recv", "both"]:
        threading.Thread(target=receiver_thread, args=(args.recv_if, stop_event, DEFAULT_EWMA_ALPHA), daemon=True).start()
        try: dashboard_loop(args.refresh, args.inactive)
        except KeyboardInterrupt: pass
    else:
        try:
            while True: time.sleep(1)
        except KeyboardInterrupt: pass

    stop_event.set()

if __name__ == "__main__":
    main()
