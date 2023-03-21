#!/bin/python3

import argparse
import os
import sys
import ipaddress
import random
import math

packets_per_request = 5


def generate_summaries(ip_list, n, protocols):
    summaries = []
    ctr = 0
    while ctr < n:
        ip1, ip2 = random.choices(ip_list, k=2)
        random_id, random_seq = random.randint(
            0, 65535), random.randint(0, 65535)
        random_length = random.choice([76, 100])
        summaries.append(
            "{} → {} ICMP {} (ping) request id={:#06x}, seq={}".format(
                ip1, ip2, random_length, random_id, random_seq))
        summaries.append(
            "{} → {} ICMP {} (ping) reply id={:#06x}, seq={}".format(
                ip2, ip1, random_length, random_id, random_seq))
        ctr += 2
    return summaries


def load_ips(ip_file):
    ips = []
    with open(ip_file, "r") as f:
        for line in f:
            ips.extend(ipaddress.ip_network(line.strip()).hosts())

    return ips


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='PacketGenerator', description="Generate network packets")
    parser.add_argument(
        '--ip_file', metavar='<ip file path>',
        help='config file to read IPs for the generated packets',
        required=True)
    parser.add_argument(
        '-n', '--number-of-packets', metavar='<number of packets>',
        help='number of packets to generate', default=10)
    parser.add_argument(
        '-p', "--protocols", metavar='<protocols>', action="store",
        default=["icmp"],
        help='list of protocols to generate (must be from [icmp,dns,http])',
        nargs="*", choices=["icmp", "dns", "http"])
    parser.add_argument(
        "--scenario", metavar='<scenario>', action="store", default=None,
        help='specific scenario to generate network flow for (must be from [normal, ping_of_death, ping_smurf,\n ping_flood, dns_flood, dns_spoof])',
        nargs="*", choices=["normal", "ping_of_death", "ping_smurf", "ping_flood",
                            "dns_flood", "dns_spoof"])
    parser.add_argument(
        '--replay_packets', metavar='<replay packets>',
        action="store_const", const=True, default=False,
        help='whether to replay packets on the network after generating them',
        required=False)
    args = parser.parse_args()

    ips = load_ips(args.ip_file)

    summaries = generate_summaries(
        ips, n=args.number_of_packets, protocols=args.protocols)

    print(summaries)
