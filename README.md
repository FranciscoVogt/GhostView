# GhostView

This is the code implementing GhostView, a monitoring strategy based on the eggress pipeline to monitor informations like throughput, queues, IPG, etc from flows and ports. The code keep monitoring all flows and ports, and write this information in the monitoring packets when requested.

## Requisits:
SDE version tested: 9.13, but should work at 9.12.

Python3 and some libraries.

tcpreplay.

## Pre-usage:
Prepare three terminals: one at Tofino, and two at the monitoring server (a server connected directly to the tofino)

Clone the project at both environments.

Set the SDE bash at tofino.


## Usage 

The idea is that you can copy our eggress pipeline code at your code and monitor the informations with our hosts scripts. However, to be able to do it, your ingress pipeline should be able to understand and forward our monitoring packets. The monitoring packets are encapsulated at ethernet (ethertype=0x1234), and have a specific IP of "172.168.0.2" (can be changed). You should be able to parser the monitoring packet, and forward it to the monitoring server. Other packets can be forwarded normally, without any change.


### Starting by our code:

To give an simple example about how to use the GhostView monitoring, we prepared a simple P4 code containing a simple forwarding table in the ingress pipeline, and GhostView at the egress pipeline.
