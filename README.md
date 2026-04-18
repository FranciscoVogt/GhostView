# GhostView: Enabling Deep Visibility in Programmable Data Planes with Minimal Server Overhead.

**Abstract:** GhostView is a high-fidelity monitoring strategy based on the **Egress pipeline** of programmable switches (Intel Tofino). It allows for real-time tracking of network metrics such as throughput, queue depth, and Inter-Packet Gap (IPG) for specific flows and ports. The core idea is to continuously monitor all flows and ports in the background (data plane) and embed this telemetry information into monitoring packets (probes) only when requested by the controller.

---

## Structure of the readme.md

This repository is organized as follows to facilitate the evaluation process:
1. **Considered Badges:** Evaluation claims and targeted badges.
2. **Basic Information:** Environment and hardware requirements.
3. **Dependencies:** Required libraries and packages.
4. **Main Components:** Description of the repository's core files and scripts.
5. **Security Concerns:** Warnings about execution permissions.
6. **Installation:** Initial setup steps.
7. **Minimal Test:** Execution in a simulated environment (Local/No Tofino hardware required).
8. **Experiments:** Execution in the real environment (Intel Tofino Switch).
9. **Dashboard Metrics:** Explanation of the displayed results.
10. **Team:** List of authors and contributors.
11. **License:** Usage license.

---

## Considered Badges

The badges considered for this artifact are: 
* **Artifacts Available** (SeloD)
* **Artifacts Functional** (SeloF)
* **Artifacts Sustainable** (SeloS)
* **Reproducible Experiments** (SeloR)

*Note to reviewers: Due to the dependence on specific hardware (Intel Tofino Switch) for full reproduction, we provide a data plane simulator. This ensures that reviewers can fully evaluate the logical functionality, metric calculations, and the control interface (dashboard) even without access to the physical switch.*

---

## Basic Information

GhostView features two execution modes. The requirements vary depending on the chosen mode:

**1. Simulated Mode (Minimal Test):**
* **Hardware:** Any standard computer or virtual machine (1GB RAM and 1 CPU core are sufficient).
* **OS:** Linux (Tested on Ubuntu 18.04 / 20.04 / 22.04).

**2. Tofino Mode (Full Experiment):**
* **Hardware:** A programmable switch based on the Intel Tofino ASIC and a Monitoring Server connected directly to the switch.
* **OS (Switch):** Configured Intel SDE environment.
* **OS (Server):** Standard Linux.

---

## Dependencies

**Software and Libraries (For both modes):**
* Python 3.6 or higher.
* Scapy (`pip3 install scapy`).
* `tcpreplay` (Only for traffic generation in Tofino Mode).
* `curses` library (Usually native to Python on Linux).

**Intel SDE (Only for Tofino Mode):**
* SDE Version: Tested on `9.13.x` (compatible with `9.12.x`).

---

## Main Components

The repository consists of several core files that orchestrate the monitoring system:

* **`controlPlane.py`**: The P4 control plane code. It contains routing configurations based on IP addresses. In the real environment mode, this must be edited to reflect your desired routing setup.
* **`createFlows.py`**: An auxiliary script to generate traffic flows (for the real environment mode) using `tcpreplay`. When a flow is created, this script calculates the CRC32 of the Destination IP (truncated to 12 bits) to act as the Flow ID. This ID must be used in the configuration file if you wish to monitor that flow. *Note: This logic can be easily customized to use the CRC32 of the 5-tuple or any other flow key.*
* **`experiment.txt`**: The configuration file required for both the switch and simulated modes. It contains the list of flows and ports to be monitored, along with their probe periodicity. (Format: `flow=4078, port=133, period=0.01`, one per line).
* **`ghostView.p4`**: The example P4 code containing the GhostView module implemented in the egress pipeline.
* **`ghostView.py`**: The monitoring dashboard that runs on the server. It is responsible for sending monitoring probes, receiving the telemetry responses, and displaying the real-time results.
* **`portConfigs`**: The switch port configuration file. In the real environment mode, this must be edited to configure the available/used physical ports in your setup.
* **`run.sh`**: A shell script that compiles, executes, and configures the switch, leaving it ready for testing.

---

## Security Concerns

For the Python scripts to successfully inject and capture packets directly on the network interfaces (whether physical or virtual), **superuser (`sudo`) privileges are mandatory**. 

Additionally, creating virtual interfaces (`veth`) in the Minimal Test requires administrative permissions. The provided scripts do not make any permanent changes to the file system or network configurations beyond the creation of the temporary virtual interface pair.

---

## Installation

Open the terminal in your Linux environment (Server or Local Machine) and execute the following commands:
```bash
# Clone the repository
git clone [https://github.com/FranciscoVogt/GhostView.git](https://github.com/FranciscoVogt/GhostView.git)
cd GhostView

# Install system packages and Python dependencies
sudo apt-get update
sudo apt-get install tcpreplay python3-pip
sudo pip3 install scapy
```

---

## Minimal Test

To allow reviewers to observe the functionality of the controller and the dashboard without requiring Tofino hardware, we provide the `ghostSim.py` simulator. This script emulates the behavior of the switch's Data Plane, generating telemetry based on a configuration file.

**Step 1: Create virtual interfaces (Virtual Cables)**
To emulate packet transmission and reception without loopback duplication, we will create a `veth` pair:
```bash
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth0 up
sudo ip link set veth1 up
```

**Step 2: Create the flow configuration file**
Create a file named `experiment.txt` in the project directory with the following content:
```text
flow=4078, port=133, period=0.01
flow=3668, port=135, period=0.01
flow=3778, port=134, period=0.01
```

**Step 3: Run the Switch Simulator (Terminal 1)**
This script will inject the simulated telemetry into the `veth0` interface.
```bash
# Runs generating a fixed default rate of 500 Mbps for all flows
sudo python3 ghostSim.py -i veth0 -f experiment.txt

# (Optional) Add the --random-rate flag for random throughputs (10 ~ 1000 Mbps)
# sudo python3 ghostSim.py -i veth0 -f experiment.txt --random-rate
```

**Step 4: Run the GhostView Dashboard (Terminal 2)**
The controller will listen on the `veth1` interface (the other end of the virtual cable).
```bash
sudo python3 ghostView.py --mode recv --recv-if veth1 -f experiment.txt
```
*Expected Result:* A terminal-based interface (`curses`) will open, displaying real-time metrics for the configured flows and ports. This validates the calculation logic (Instantaneous, Regression, and EWMA). Press `q` to exit.

---

## Experiments

This section describes the execution in the real environment (Intel Tofino Switch), allowing reviewers to validate the article's claims regarding the Data Plane implementation.

### Claim #1: High-Fidelity Monitoring in the Egress Pipeline

The P4 code is designed to: (1) Recognize Probes (EtherType `0x1234`), (2) Forward them in the Ingress to the target IP `172.168.0.2`, and (3) Populate the telemetry data in the Egress pipeline.

**Step 1: Tofino Setup (Switch Side)**
1. Edit `controlPlane.py` and `portConfigs` to match your physical setup.
2. Set the SDE bash environment variables.
3. Compile and run the switch:
```bash
./run.sh
```

**Step 2: Traffic Generation (Monitoring Server - Terminal 1)**
Use the `createFlows.py` script to generate the traffic you want to monitor. The Flow IDs are generated via the CRC32 of the Destination IP (truncated to 12 bits).
```bash
# Generates 3 flows at 10Mbps, 20Mbps, and 15Mbps on the enp6s0f1 interface
sudo python3 createFlows.py -nFlows 3 10 20 15 -intf enp6s0f1
```

**Step 3: GhostView Dashboard Execution (Monitoring Server - Terminal 2)**
With traffic flowing through the switch, start sending probes and receiving telemetry.
```bash
sudo python3 ghostView.py --mode both --send-if enp6s0f0 --recv-if enp6s0f1 --file experiment.txt
```
*Expected Result:* The dashboard will display the real-time throughput of the flows processed by the switch's ASIC. If the traffic generation (Step 2) is stopped, the dashboard will automatically detect the inactivity and reset the throughput to zero.

---

### Dashboard Metrics (Legend)
Regardless of the mode (Simulated or Tofino), the dashboard displays the following statistics:
* **Inst (Mbps):** Instantaneous throughput calculated between the last two telemetry samples.
* **Reg (Mbps):** Throughput calculated via linear regression over the sample window (higher precision).
* **EWMA (Mbps):** Exponential Weighted Moving Average (visual smoothing).
* **Seen (s):** Time elapsed since the last probe was received.

---

## Team

* Francisco Germano Vogt
* Leonardo Henrique Guimaraes
* Zhiheng Yang
* Fabricio Eduardo Rodriguez Cesen
* Sergio Rossi Brito da Silva
* Marcelo Caggiani Luielli
* Chrysa Papagianni
* Christian Esteve Rothenberg

---

## LICENSE

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
