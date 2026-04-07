from netaddr import IPAddress


p4 = bfrt.ghostView.pipe

#table for forwarding and flow identification
fwd_table = p4.SwitchIngress.forward


#forwarding for the monitoring packets 
fwd_table.add_with_send(dst_addr = IPAddress('172.168.0.2'), port = 135)


#fowrading for normal flows
fwd_table.add_with_send(dst_addr = IPAddress('10.0.0.1'), port = 134)
fwd_table.add_with_send(dst_addr = IPAddress('10.0.0.2'), port = 134)
fwd_table.add_with_send(dst_addr = IPAddress('10.0.0.3'), port = 134)


bfrt.complete_operations()



