import argparse
import os
import sys

from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr


def process_pcap(file_name):
    print('Opening {}...'.format(file_name))

    count = 0
    interesting_packet_count = 0

    interesting_packets = []
    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
        count += 1

        ether_pkt = Ether(pkt_data)
        if 'type' not in ether_pkt.fields:
            # LLC frames will have 'len' instead of 'type'.
            # We disregard those
            continue

        if ether_pkt.type != 0x0800:
            # disregard non-IPv4 packets
            continue
        ip_pkt = ether_pkt[IP]
        if ip_pkt.proto != 1:
            # Ignore non-TCP packet
            continue
        interesting_packet_count += 1
        interesting_packets.append(ether_pkt)

    print('{} contains {} packets ({} interesting)'.
          format(file_name, count, interesting_packet_count))

    return interesting_packets


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap', metavar='<pcap file name>',
                        help='pcap file to parse', required=True)
    args = parser.parse_args()

    file_name = args.pcap
    if not os.path.isfile(file_name):
        print('"{}" does not exist'.format(file_name), file=sys.stderr)
        sys.exit(-1)

    packets = process_pcap(file_name)
    test_packet = packets[4]
    test_packet = test_packet[IP]
    del test_packet.chksum
    test_packet.src = "130.231.202.234"
    test_packet.dst = "8.8.8.8"
    test_packet.show()
    ans, unans = sr(test_packet, timeout=3)
    print(ans)
    print(unans)
    sys.exit(0)
