import scapy.all as scapy


def process_pcap(file_name):
    print('Opening {}...'.format(file_name))

    count = 0
    interesting_packet_count = 0

    interesting_packets = []
    for (pkt_data, pkt_metadata,) in scapy.RawPcapReader(file_name):
        count += 1

        ether_pkt = scapy.IP(pkt_data)
        #ether_pkt = scapy.Ether(pkt_data)
        #ip_pkt = ether_pkt[scapy.IP]
        """
        if 'type' not in ether_pkt.fields:
            # LLC frames will have 'len' instead of 'type'.
            # We disregard those
            continue
        if ether_pkt.type != 0x0800:
            # disregard non-IPv4 packets
            continue
        if ip_pkt.proto != 1:
            # Ignore non-TCP packet
            continue
        """
        interesting_packet_count += 1
        interesting_packets.append(ether_pkt)

    print('{} contains {} packets ({} interesting)'.
          format(file_name, count, interesting_packet_count))

    return interesting_packets


packets = process_pcap("generated_icmp_commands.pcap")
#packets = process_pcap("custom_pings.pcapng")

processed_packets = []
for pkt in packets:
    pkt[scapy.IP].src = "100.71.74.120"
    pkt[scapy.IP].dst = "8.8.8.8"
    pkt[scapy.ICMP].type = 8
    #pkt[scapy.ICMP].id = 0
    #pkt[scapy.ICMP].seq = 0
    #pkt[scapy.IP].id = 1

    pkt = pkt[scapy.IP]
    #del pkt[scapy.IP].len
    del pkt[scapy.IP].chksum
    del pkt[scapy.ICMP].chksum

    pkt.show2()

    processed_packets.append(pkt)

ans, unans = scapy.sr(processed_packets, timeout=5)
print(ans)
print(unans)
