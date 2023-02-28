import argparse
import os
import sys

packets_per_request = 10


def generate_summaries(n=100, protocols=["icmp"]):
    with open("data/text/three_summaries.txt", "r") as f:
        packet_summaries = f.read().splitlines()

    prompts
    for i in range(n/packets_per_request + 1):
        pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='PacketGenerator', description="Generate network packets")
    parser.add_argument('--ip_file', metavar='<ip file path>',
                        help='file to read IPs from', required=True)
    parser.add_argument(
        '-n', '--number-of-packets', metavar='<number of packets>',
        help='number of packets to generate', default=100)
    parser.add_argument(
        '-p', "--protocols", metavar='<protocols>', action="store",
        default=["icmp"],
        help='list of protocols to genderate (must be from [icmp,dns,http])',
        nargs="*", choices=["icmp", "dns", "http"])
    args = parser.parse_args()

    print(args)
