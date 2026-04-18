import argparse
import os
import random
import zlib
import socket
import subprocess
import time
from scapy.all import Ether, IP, UDP, Raw, wrpcap

# Generates a random locally administered MAC address
def generate_random_mac():
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(5))

# Computes a 12-bit Flow ID based on the Destination IP's CRC32
def compute_crc12(dst_ip):
    # Convert the IP address string into packed 32-bit binary format
    ip_bytes = socket.inet_aton(dst_ip)
    # Calculate the CRC32 checksum of the IP bytes
    crc32 = zlib.crc32(ip_bytes) & 0xFFFFFFFF
    # Apply a bitmask (0xFFF) to isolate and return only the last 12 bits
    return crc32 & 0xFFF

# Generates a list of UDP packets populated with random payload data
def generate_udp_packets(src_mac, dst_mac, dst_ip, count=1000, pkt_size=1000):
    packets = []
    # Calculate payload size by subtracting standard header sizes: Ethernet (14), IPv4 (20), and UDP (8)
    payload_size = pkt_size - 14 - 20 - 8
    # Create a payload of random bytes to pad the packet up to the requested size
    payload = Raw(load=bytes([random.randint(0, 255) for _ in range(payload_size)]))
    
    # Build the requested number of identical packets
    for _ in range(count):
        pkt = Ether(src=src_mac, dst=dst_mac) / IP(src="10.0.0.1", dst=dst_ip) / UDP(sport=1234, dport=4321) / payload
        packets.append(pkt)
    return packets

def main():
    # Setup command-line argument parsing
    parser = argparse.ArgumentParser(description="Generate PCAPs and replay flows with duration control.")
    # Expects the total number of flows followed by their respective throughput targets in Mbps
    parser.add_argument("-nFlows", nargs="+", type=int, required=True, help="Number of flows followed by Mbps values.")
    parser.add_argument("-intf", default="enp6s0f1", help="Network interface (default: enp6s0f1)")
    parser.add_argument("--duration", type=int, help="Duration to run the traffic in seconds. If not set, runs indefinitely.")
    args = parser.parse_args()

    # Extract the flow count and the list of Mbps speeds from the arguments
    nflows = args.nFlows[0]
    throughputs = args.nFlows[1:]

    # Validate that the user provided exactly one throughput value per flow
    if len(throughputs) != nflows:
        print("❌ Error: Number of Mbps values must match number of flows")
        return

    # --- PCAP Generation Phase ---
    for i in range(nflows):
        # Assign a sequential Destination IP for each flow (e.g., 10.0.0.1, 10.0.0.2)
        dst_ip = f"10.0.0.{i+1}"
        src_mac = generate_random_mac()
        dst_mac = "ff:ff:ff:ff:ff:ff" # Broadcast MAC address
        
        # Calculate the 12-bit Flow ID to be used and monitored by GhostView
        crc12 = compute_crc12(dst_ip)
        
        print(f"[Flow {i+1}] DST IP: {dst_ip}, CRC12: {crc12}")
        pcap_file = f"flow{i+1}.pcap"
        
        # Generate the packets and save them to a PCAP file for this specific flow
        pkts = generate_udp_packets(src_mac, dst_mac, dst_ip)
        wrpcap(pcap_file, pkts)

    processes = []
    print(f"\n🚀 Starting tcpreplay on interface {args.intf}...")
    
    try:
        # --- Traffic Replay Phase ---
        for i in range(nflows):
            # Format the tcpreplay command as a list for the subprocess module
            cmd = [
                "sudo", "tcpreplay",
                f"--intf1={args.intf}",
                "--loop=0", # Infinite loop: replay the PCAP continuously until killed
                f"--mbps={throughputs[i]}", # Throttle the replay to the specified Mbps
                f"flow{i+1}.pcap"
            ]
            # Execute the command asynchronously (non-blocking) discarding standard output/error
            p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            processes.append(p)
            print(f"  [+] Flow {i+1} started (PID: {p.pid}) at {throughputs[i]} Mbps")

        # --- Duration Control ---
        if args.duration:
            print(f"\n⏱️  Traffic will run for {args.duration} seconds...")
            time.sleep(args.duration) # Keep the main thread alive for the set duration
        else:
            print("\n♾️  Running indefinitely. Press Ctrl+C to stop.")
            while True:
                time.sleep(1) # Keep the main thread alive indefinitely

    except KeyboardInterrupt:
        # Gracefully handle user interruption (Ctrl+C)
        print("\n\n🛑 Stopping traffic (Manual interrupt)...")
    finally:
        # --- Cleanup Phase ---
        # Ensure all spawned tcpreplay child processes are cleanly terminated
        for p in processes:
            p.terminate()
        
        # Optional: Forcefully kill any stray tcpreplay processes just in case 'terminate' fails
        os.system(f"sudo pkill -f tcpreplay")
        print("✅ All flows stopped.")

if __name__ == "__main__":
    main()
