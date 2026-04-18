#!/usr/bin/env python3
"""
ghostSim.py - Simulator of GhostView data plane
"""

import argparse
import threading
import time
import struct
import random
from scapy.all import Ether, IP, Raw, sendp, conf

# Custom EtherType used by the controller to identify telemetry response packets
ETH_TYPE_RECV = 0x1235
# Default virtual interface for injecting simulated packets
DEFAULT_IFACE = "veth0" 
# Default target throughput for the simulation if random mode is not enabled
DEFAULT_SIMULATED_MBPS = 500.0

# Reads and parses the experiment configuration file containing flow, port, and period details
def parse_flows_file(path: str):
    flows = []
    try:
        with open(path, "r") as f:
            for raw in f:
                line = raw.strip()
                # Ignore empty lines and comments
                if not line or line.startswith("#"): continue
                # Parse key-value pairs separated by commas (e.g., flow=4078, port=133)
                kv = {p.split("=")[0].strip(): p.split("=")[1].strip() for p in line.split(",") if "=" in p}
                # Store the extracted parameters as a dictionary
                flows.append({"flow": int(kv["flow"]), "port": int(kv["port"]), "period": float(kv["period"])})
    except Exception as e:
        print(f"Erro ao ler arquivo: {e}")
    return flows

# Thread function that continuously generates simulated telemetry packets for a specific flow
def simulator_thread(iface: str, flow_cfg: dict, stop_event: threading.Event, simulated_mbps: float):
    # Extract flow parameters
    flow_id = flow_cfg["flow"]
    port_id = flow_cfg["port"]
    period = flow_cfg["period"]
    
    # Initialize telemetry counters
    bytes_flow = 0
    bytes_port = 0
    q_depth = 0
    
    # Create the 10-byte custom header expected by the receiver (!IIH = 4 bytes + 4 bytes + 2 bytes)
    custom_hdr = struct.pack("!IIH", flow_id, port_id, 0)
    # Create a dummy 20-byte IPv4 header to align with the receiver's offset parsing logic
    ip_hdr = bytes(IP(src="172.168.0.2", dst="172.168.0.1"))
    
    last_time = time.time()
    
    # Run the simulation loop until the main thread signals to stop
    while not stop_event.is_set():
        start_time = time.time()
        
        # Calculate the REAL elapsed time to guarantee accurate throughput calculation
        # This prevents drift caused by minor inaccuracies in time.sleep()
        delta_t = start_time - last_time
        if delta_t <= 0:
            delta_t = period 
            
        last_time = start_time
        
        # Dynamically calculate how many bytes should have been transmitted in the elapsed time
        bytes_to_add = int((simulated_mbps * 1000000 / 8) * delta_t)
        bytes_flow += bytes_to_add
        # Add the flow bytes to the port bytes, plus a simulated overhead/background traffic
        bytes_port += bytes_to_add + int(15000 * delta_t) 
        
        # Generate a high-precision system timestamp in nanoseconds and mask it to 48 bits (6 bytes)
        ts_ns = int(start_time * 1000000000) & 0xFFFFFFFFFFFF
        ts_bytes = ts_ns.to_bytes(6, byteorder="big")
        
        # Simulate a fluctuating queue depth value (loops 0-99)
        q_depth = (q_depth + 1) % 100 
        
        # --- Assemble the Monitor Header (46 bytes total) ---
        # 1. Flow bytes and Port bytes (16 bytes, unsigned long long '!QQ')
        part1 = struct.pack("!QQ", bytes_flow, bytes_port) 
        # 2. Timestamp (6 bytes, big-endian)
        part2 = ts_bytes 
        # 3. Padding to simulate the gap between offsets 22 and 42 (20 bytes of zeros)
        pad = b'\x00' * 20 
        # 4. Queue depth (4 bytes, unsigned int '!I')
        part3 = struct.pack("!I", q_depth) 
        
        monitor_hdr = part1 + part2 + pad + part3
        
        # Construct the final Scapy packet with the expected EtherType and the custom payload
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:00:00:00:00:02", type=ETH_TYPE_RECV)
        pkt = pkt / Raw(load=custom_hdr + ip_hdr + monitor_hdr)
        
        # Inject the packet directly into the specified network interface
        sendp(pkt, iface=iface, verbose=False)
        
        # Calculate execution time of this iteration to adjust the sleep duration accurately
        elapsed = time.time() - start_time
        sleep_time = max(0, period - elapsed)
        time.sleep(sleep_time)

def main():
    # Setup command-line arguments
    parser = argparse.ArgumentParser(description="Simulador de Plano de Dados P4")
    parser.add_argument("--iface", "-i", default=DEFAULT_IFACE, help="Interface de injeção")
    parser.add_argument("--file", "-f", required=True, help="Arquivo de configuração")
    # Flag to enable random throughput generation instead of the fixed default rate
    parser.add_argument("--random-rate", action="store_true", help="Usa taxas aleatórias para cada fluxo/porta")
    args = parser.parse_args()

    # Disable Scapy's default verbose output
    conf.verb = 0
    # Event object to cleanly shutdown all threads
    stop_event = threading.Event()
    # Load flows from the provided configuration file
    flows = parse_flows_file(args.file)
    
    if not flows: 
        print("Nenhum fluxo carregado.")
        return

    print(f"[*] Iniciando injeção de pacotes na interface '{args.iface}'")
    
    # Check if the user requested random throughput rates
    if args.random_rate:
        print("[*] Modo Aleatório: ATIVADO. Cada fluxo terá sua própria taxa.")
    else:
        print(f"[*] Modo Fixo: ATIVADO. Todos os fluxos usarão {DEFAULT_SIMULATED_MBPS} Mbps.")

    threads = []
    # Initialize and start a separate worker thread for each configured flow
    for f in flows:
        # Determine the target throughput rate for this specific flow
        if args.random_rate:
            rate = random.uniform(10.0, 1000.0) # Pick a random value between 10 and 1000 Mbps
        else:
            rate = DEFAULT_SIMULATED_MBPS
            
        print(f"    -> Iniciando fluxo {f['flow']} (porta {f['port']}) com taxa alvo de {rate:.2f} Mbps")
        
        # Start the thread, passing the calculated rate
        t = threading.Thread(target=simulator_thread, args=(args.iface, f, stop_event, rate), daemon=True)
        t.start()
        threads.append(t)

    # Main loop to keep the program running until interrupted by the user
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        # Catch Ctrl+C and signal all threads to terminate gracefully
        print("\n[!] Encerrando...")
        stop_event.set()

if __name__ == "__main__":
    main()
