#!/bin/python3

import argparse
import os
import sys
import ipaddress
import random
import math

import toml
import openai

from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP
from scapy.utils import wrpcap
import scapy.all as scapy

packets_per_request = 5


def load_toml(ip_file):
    network_ips = []
    victim_ip = ""
    attacker_ip = ""
    with open(ip_file, "r") as f:
        data = toml.load(f)
        for ip_desc in data['network']['ip']:
            network_ips.extend(ipaddress.ip_network(ip_desc.strip()).hosts())
        victim_ip = ipaddress.ip_network(data['victim']['ip'].strip()).hosts()
        attacker_ip = ipaddress.ip_network(
            data['attacker']['ip'].strip()).hosts()

    return network_ips, victim_ip, attacker_ip


def generate_normal_summaries(ip_list, n, protocols):
    summaries = []
    ctr = 0
    while ctr < math.ceil(n/5)*5:
        proto = random.choice(protocols)
        if proto == "icmp":
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
        elif proto == "dns":
            ip1, ip2 = random.choices(ip_list, k=2)
            random_id = random.randint(
                0, 65535)
            random_length = random.choice([76, 100])
            summaries.append(
                "{} → {} DNS {} STANDARD query {:#06x} A www.google.com OPT".format(
                    ip1, ip2, random_length, random_id))
            summaries.append(
                "{} → {} DNS {} STANDARD query response {:#06x} A www.google.com A 8.8.8.8 OPT".format(
                    ip1, ip2, random_length, random_id))
            ctr += 2
    return summaries


def generate_ping_flood_summaries(ip_list, n, victim_ip, attacker_ip):
    summaries = []
    ctr = 0
    while ctr < math.ceil(n/5)*5:
        malicious = random.choices([True, False], weights=[0.7, 0.3], k=1)
        if malicious[0]:
            random_id, random_seq = random.randint(
                0, 65535), random.randint(0, 65535)
            random_length = random.choice([76, 100])
            summaries.append(
                "{} → {} ICMP {} (ping) request id={:#06x}, seq={}".format(
                    attacker_ip, victim_ip, random_length, random_id, random_seq))
            ctr += 1
        else:
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


def generate_packets(summaries):
    ctr = 0
    packets = []
    prompt = ""
    for summary in summaries:
        prompt += summary + "\n"
        ctr += 1
        if ctr == 5:
            ctr = 0
            prompt += "\n\n###\n\n"
            completion = openai.Completion.create(
                engine="babbage:ft-ubicomp-2023-02-28-16-59-27", prompt=prompt,
                max_tokens=1600, stop="###")
            code_to_exec = completion.choices[0].text
            code_to_exec += "\n\npackets.extend(pkt_list)\n"
            try:
                exec(code_to_exec)
            except:
                print(code_to_exec)
                #pass
            prompt = ""
    return packets


def write_pcap(packets, output_path):
    with open(output_path, "wb") as f:
        wrpcap(f, packets)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='PacketGenerator', description="Generate network packets")
    parser.add_argument(
        '--ip_file', metavar='<ip file path>',
        help='config file to read IPs for the generated packets (TOML format)',
        required=True)
    parser.add_argument(
        '--output_file', metavar='<output file path>',
        help='path of output .pcap file (defaults to synthetic_traffic.pcap)',
        default="./synthetic_traffic.pcap")
    parser.add_argument(
        '-n', '--number-of-packets', metavar='<number of packets>',
        help='number of packets to generate', default=10, type=int)
    parser.add_argument(
        '-p', "--protocols", metavar='<protocols>', action="store",
        default=["icmp"],
        help='list of protocols to generate (must be from [icmp,dns,http])',
        nargs="*", choices=["icmp", "dns", "http"])
    parser.add_argument(
        "--scenario", metavar='<scenario>', action="store", default=["normal"],
        help='specific scenario to generate network flow for (must be from [normal, ping_of_death, ping_smurf,\n ping_flood, dns_flood, dns_spoof])',
        nargs=1, choices=["normal", "ping_of_death", "ping_smurf", "ping_flood",
                          "dns_flood", "dns_spoof"])
    parser.add_argument(
        '--replay_packets', metavar='<replay packets>',
        action="store_const", const=True, default=False,
        help='whether to replay packets on the network after generating them',
        required=False)
    args = parser.parse_args()

    network_ips, victim_ip, attacker_ip = load_toml(args.ip_file)

    if args.scenario[0] == "normal":
        summaries = generate_normal_summaries(
            network_ips, n=args.number_of_packets, protocols=args.protocols)
    elif args.scenario[0] == "ping_flood":
        summaries = generate_ping_flood_summaries(
            network_ips, args.number_of_packets, victim_ip[0], attacker_ip[0])
    print("Generated {} summaries. Using OpenAI API to generate packets...".format(
        len(summaries)))
    for summary in summaries:
        print(summary)

    packets = generate_packets(summaries)

    print(
        "Generated {} packets. Writing them to {} ...".format(
            len(packets),
            args.output_file))

    write_pcap(packets, args.output_file)
    print("Done!")
