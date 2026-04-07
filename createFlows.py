import argparse
import os
import random
import zlib
import socket
import subprocess
import time
from scapy.all import Ether, IP, UDP, Raw, wrpcap

def generate_random_mac():
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(5))

def compute_crc12(dst_ip):
    ip_bytes = socket.inet_aton(dst_ip)
    crc32 = zlib.crc32(ip_bytes) & 0xFFFFFFFF
    return crc32 & 0xFFF

def generate_udp_packets(src_mac, dst_mac, dst_ip, count=1000, pkt_size=1000):
    packets = []
    payload_size = pkt_size - 14 - 20 - 8
    payload = Raw(load=bytes([random.randint(0, 255) for _ in range(payload_size)]))
    for _ in range(count):
        pkt = Ether(src=src_mac, dst=dst_mac) / IP(src="10.0.0.1", dst=dst_ip) / UDP(sport=1234, dport=4321) / payload
        packets.append(pkt)
    return packets

def main():
    parser = argparse.ArgumentParser(description="Generate PCAPs and replay flows with duration control.")
    parser.add_argument("-nFlows", nargs="+", type=int, required=True, help="Number of flows followed by Mbps values.")
    parser.add_argument("-intf", default="enp6s0f1", help="Network interface (default: enp6s0f1)")
    parser.add_argument("--duration", type=int, help="Duration to run the traffic in seconds. If not set, runs indefinitely.")
    args = parser.parse_args()

    nflows = args.nFlows[0]
    throughputs = args.nFlows[1:]

    if len(throughputs) != nflows:
        print("❌ Error: Number of Mbps values must match number of flows")
        return

    # Geração dos PCAPs
    for i in range(nflows):
        dst_ip = f"10.0.0.{i+1}"
        src_mac = generate_random_mac()
        dst_mac = "ff:ff:ff:ff:ff:ff"
        crc12 = compute_crc12(dst_ip)
        
        print(f"[Flow {i+1}] DST IP: {dst_ip}, CRC12: {crc12}")
        pcap_file = f"flow{i+1}.pcap"
        pkts = generate_udp_packets(src_mac, dst_mac, dst_ip)
        wrpcap(pcap_file, pkts)

    processes = []
    print(f"\n🚀 Starting tcpreplay on interface {args.intf}...")
    
    try:
        for i in range(nflows):
            # Comando formatado como lista para o subprocess
            cmd = [
                "sudo", "tcpreplay",
                f"--intf1={args.intf}",
                "--loop=0", # Loop infinito enquanto o processo estiver vivo
                f"--mbps={throughputs[i]}",
                f"flow{i+1}.pcap"
            ]
            # Popen inicia o processo sem bloquear a execução do script Python
            p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            processes.append(p)
            print(f"  [+] Flow {i+1} started (PID: {p.pid}) at {throughputs[i]} Mbps")

        if args.duration:
            print(f"\n⏱️  Traffic will run for {args.duration} seconds...")
            time.sleep(args.duration)
        else:
            print("\n♾️  Running indefinitely. Press Ctrl+C to stop.")
            while True:
                time.sleep(1)

    except KeyboardInterrupt:
        print("\n\n🛑 Stopping traffic (Manual interrupt)...")
    finally:
        # Garante que todos os processos sejam encerrados ao final
        for p in processes:
            p.terminate()
        
        # Opcional: limpeza forçada caso o tcpreplay ignore o terminate
        os.system(f"sudo pkill -f tcpreplay")
        print("✅ All flows stopped.")

if __name__ == "__main__":
    main()
