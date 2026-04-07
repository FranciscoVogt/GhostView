# GhostView

**GhostView** is a high-fidelity monitoring strategy based on the **Egress pipeline** of programmable switches (Intel Tofino). It allows for real-time tracking of network metrics such as throughput, queue depth, and Inter-Packet Gap (IPG) for specific flows and ports.

The core idea is to keep monitoring all flows and ports in the background and write this telemetry information into monitoring packets (probes) when requested.

## Requirements

* **SDE Version:** Tested on `9.13.x` (compatible with `9.12.x`).
* **Environment:** A Tofino-based switch and a Monitoring Server (connected directly to the switch).
* **Dependencies:** Python 3.x, Scapy, and `tcpreplay`.

## Pre-usage Setup

1. **Prepare Terminals:** Open one terminal for the Tofino switch and two terminals for the monitoring server.
2. **Clone Repository:** Clone this project in both the Tofino environment and the monitoring server.
3. **Environment:** Set the SDE bash environment variables on the Tofino switch.

## Architecture & Integration

GhostView is designed to be modular. You can integrate our egress monitoring block into your existing P4 code.

### P4 Data Plane Requirements
To support GhostView, your P4 code must:
* **Recognize Probes:** The parser must identify the custom monitoring header. Probes use a specific **EtherType (`0x1234`)**. 
* **Maintain IP sequence:** Even with the custom monitoring header, the packet maintains a standard IPv4 sequence internally.
* **Forwarding Logic:** The Ingress pipeline must be capable of understanding and forwarding these probes to the monitoring server. By default, probes target the IP `172.168.0.2`.
* **Egress Processing:** The monitoring data is filled into the probe headers at the Egress pipeline to ensure the most accurate metadata (queues, egress timestamps).

## Usage Guide

### 1. Tofino Setup (Switch Side)

We provide a functional example featuring a simple IPv4 Exact Match forwarding table in the Ingress and GhostView in the Egress.

1. **Configure Rules:** Edit `controlPlane.py` with your forwarding rules (if necessary).
2. **Configure Ports:** Edit `portConfigs` to match your physical setup.
3. **Run the Switch:**
   ```bash
   ./run.sh
   ```
   *This script compiles the P4 code, sets up ports, and populates the tables.*

### 2. Traffic Generation (Server Side)

Use the `createFlows.py` script to generate the traffic you want to monitor. 

* **Flow IDs:** In this implementation, Flow IDs are generated as the **CRC32 of the Destination IP, truncated to 12 bits**.
* **Customization:** While we use the 12-bit truncated CRC32 for simplicity, the architecture can be adapted to any other flow key (like a 5-tuple hash).

```bash
# Example: Generate 3 flows at 10Mbps, 20Mbps, and 15Mbps
sudo python3 createFlows.py -nFlows 3 10 20 15 -intf enp6s0f1
```

### 3. Monitoring Dashboard (GhostView)

Run `ghostView.py` to start the live monitoring dashboard. This script sends probes and collects telemetry data.

```bash
# Example execution
sudo python3 ghostView.py --mode both --send-if enp6s0f1 --recv-if enp6s0f1 --file experiment.txt
```

#### Configuration File (`experiment.txt`)
The file defines which flows (by their 12-bit CRC32 ID) and ports to monitor, along with the probe periodicity:
```text
flow=4078, port=133, period=0.01
flow=3668, port=135, period=0.01
flow=3778, port=134, period=0.01
```

## Dashboard Metrics

The dashboard displays real-time statistics for both Flows and Ports:

* **Inst (Mbps):** Instantaneous throughput between the last two probes.
* **Reg (Mbps):** Throughput calculated via linear regression over the sample window for higher precision.
* **EWMA (Mbps):** Exponential Weighted Moving Average to smooth out visual spikes.
* **Seen (s):** Time elapsed since the last probe was received.

**Zero-traffic Detection:** The dashboard automatically detects if traffic has stopped. If probes arrive but the telemetry data (bytes/timestamps) remains static, or if probes stop arriving entirely, the throughput is automatically reset to `0.00` to reflect the current network state.
