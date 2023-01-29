import scapy.all as scapy

packet = scapy.IP(dst="8.8.8.8/32") / scapy.ICMP()
packet.show()
ans, unans = scapy.sr(packet, timeout=3)

print(ans[0])
print(type(ans[0]))
