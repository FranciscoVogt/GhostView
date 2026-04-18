#!/usr/bin/env python3
"""
ghostSim.py - Simulador Dinâmico do Plano de Dados
"""

import argparse
import threading
import time
import struct
import random
from scapy.all import Ether, IP, Raw, sendp, conf

ETH_TYPE_RECV = 0x1235
DEFAULT_IFACE = "veth0" 
DEFAULT_SIMULATED_MBPS = 500.0

def parse_flows_file(path: str):
    flows = []
    try:
        with open(path, "r") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"): continue
                kv = {p.split("=")[0].strip(): p.split("=")[1].strip() for p in line.split(",") if "=" in p}
                flows.append({"flow": int(kv["flow"]), "port": int(kv["port"]), "period": float(kv["period"])})
    except Exception as e:
        print(f"Erro ao ler arquivo: {e}")
    return flows

def simulator_thread(iface: str, flow_cfg: dict, stop_event: threading.Event, simulated_mbps: float):
    flow_id = flow_cfg["flow"]
    port_id = flow_cfg["port"]
    period = flow_cfg["period"]
    
    bytes_flow = 0
    bytes_port = 0
    q_depth = 0
    
    custom_hdr = struct.pack("!IIH", flow_id, port_id, 0)
    ip_hdr = bytes(IP(src="172.168.0.2", dst="172.168.0.1"))
    
    last_time = time.time()
    
    while not stop_event.is_set():
        start_time = time.time()
        
        # Calcula o tempo REAL que passou para garantir precisão na banda
        delta_t = start_time - last_time
        if delta_t <= 0:
            delta_t = period 
            
        last_time = start_time
        
        # Conversão dinâmica baseada no tempo real e na taxa ESPECÍFICA deste fluxo
        bytes_to_add = int((simulated_mbps * 1000000 / 8) * delta_t)
        bytes_flow += bytes_to_add
        bytes_port += bytes_to_add + int(15000 * delta_t) # Overhead simulado na porta
        
        ts_ns = int(start_time * 1000000000) & 0xFFFFFFFFFFFF
        ts_bytes = ts_ns.to_bytes(6, byteorder="big")
        
        q_depth = (q_depth + 1) % 100 
        
        part1 = struct.pack("!QQ", bytes_flow, bytes_port) 
        part2 = ts_bytes 
        pad = b'\x00' * 20 
        part3 = struct.pack("!I", q_depth) 
        
        monitor_hdr = part1 + part2 + pad + part3
        
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:00:00:00:00:02", type=ETH_TYPE_RECV)
        pkt = pkt / Raw(load=custom_hdr + ip_hdr + monitor_hdr)
        
        sendp(pkt, iface=iface, verbose=False)
        
        elapsed = time.time() - start_time
        sleep_time = max(0, period - elapsed)
        time.sleep(sleep_time)

def main():
    parser = argparse.ArgumentParser(description="Simulador de Plano de Dados P4")
    parser.add_argument("--iface", "-i", default=DEFAULT_IFACE, help="Interface de injeção")
    parser.add_argument("--file", "-f", required=True, help="Arquivo de configuração")
    parser.add_argument("--random-rate", action="store_true", help="Usa taxas aleatórias para cada fluxo/porta")
    args = parser.parse_args()

    conf.verb = 0
    stop_event = threading.Event()
    flows = parse_flows_file(args.file)
    
    if not flows: 
        print("Nenhum fluxo carregado.")
        return

    print(f"[*] Iniciando injeção de pacotes na interface '{args.iface}'")
    if args.random_rate:
        print("[*] Modo Aleatório: ATIVADO. Cada fluxo terá sua própria taxa.")
    else:
        print(f"[*] Modo Fixo: ATIVADO. Todos os fluxos usarão {DEFAULT_SIMULATED_MBPS} Mbps.")

    threads = []
    for f in flows:
        # Define a taxa: aleatória se a flag foi passada, senão usa o padrão
        if args.random_rate:
            rate = random.uniform(10.0, 1000.0) # Sorteia entre 10 e 1000 Mbps
        else:
            rate = DEFAULT_SIMULATED_MBPS
            
        print(f"    -> Iniciando fluxo {f['flow']} (porta {f['port']}) com taxa alvo de {rate:.2f} Mbps")
        
        t = threading.Thread(target=simulator_thread, args=(args.iface, f, stop_event, rate), daemon=True)
        t.start()
        threads.append(t)

    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Encerrando...")
        stop_event.set()

if __name__ == "__main__":
    main()
