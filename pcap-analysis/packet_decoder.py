import argparse
import os
import sys
import binascii

from scapy.utils import import_hexcap, wrpcap
from scapy.layers.inet import ICMP, IP
from scapy.sendrecv import sr

import numpy as np
from PIL import Image


def process_npy(file_name, rgb=False, save_images=False, path=""):
    print('Opening {}...'.format(file_name))

    images = np.load(file_name)

    gray_images = []
    if rgb == True:
        for i, img in enumerate(images):
            img = np.moveaxis(img, 0, -1)
            img *= 255
            img = img.astype(np.uint8)
            gray_img = Image.fromarray(img.astype("uint8")).convert("L")
            if save_images:
                gray_img.save(os.path.join(path, str(i)+".png"))
            gray_images.append(np.array(gray_img.getdata()))
    else:
        for i, img in enumerate(images):
            img = img.reshape(img.shape[1:])
            img = img/2 + 0.5
            img *= 255
            gray_img = Image.fromarray(img.astype("uint8"), mode="L")
            if save_images:
                gray_img.save(os.path.join(path, str(i)+".png"))
            gray_images.append(np.array(gray_img.getdata()))

    return gray_images


def img2packet(images, packet_size=84):
    packets = []
    for img in images:
        s = bytes(list(img[:packet_size]))
        packet = IP(s)
        packets.append(packet)
    return packets


def img2packet2(images, packet_size=84, d=2):
    packets = []
    for img in images:
        img = img.reshape(32, 32)
        packet_bytes = []
        i, j = 0, 0
        for byte_index in range(packet_size):
            first_aggregate = img[i:i+d, j:j+d].mean()
            first_aggregate = int(first_aggregate/16) * 16

            second_aggregate = img[i:i+d, j+d:j+2*d].mean()
            second_aggregate = int(second_aggregate/16)

            packet_bytes.append(first_aggregate+second_aggregate)

            j += d*2
            if j >= 32:
                j = 0
                i += d

        s = bytes(packet_bytes)
        packet = IP(s)
        packets.append(packet)
    return packets


def post_process_packets(packets):
    processed_packets = []
    for packet in packets:
        packet.version = 4
        packet.ihl = 5
        packet.len = 84
        packet.frag = 0
        packet.proto = "icmp"
        #del packet[ICMP].chksum
        processed_packets.append(packet)

    return processed_packets


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Packet decoder')
    parser.add_argument('--numpy', metavar='<numpy file name>',
                        help='numpy file to parse', required=True)
    parser.add_argument(
        '--rgb', metavar='<rgb flag>', action="store_const", const=True,
        default=False, help='flag for when data is in rgb', required=False)
    parser.add_argument(
        '--post_process', metavar='<post process>', action="store_const",
        const=True, default=False,
        help='whether to post process the packet (set some fields manually)',
        required=False)
    parser.add_argument(
        '--test_packets', metavar='<test packet>', action="store_const",
        const=True, default=False,
        help='whether to send some sample packets throught Scapy to test',
        required=False)
    parser.add_argument(
        '--alternative_encoding', metavar='<alternative encoding>',
        action="store_const", const=True, default=False,
        help='whether to use the PAC-GAN alternative encoding technique',
        required=False)
    parser.add_argument(
        '--save_images', metavar='<save images>',
        action="store_const", const=True, default=False,
        help='whether to save images to file',
        required=False)
    args = parser.parse_args()

    file_name = args.numpy
    if not os.path.isfile(file_name):
        print('"{}" does not exist'.format(file_name), file=sys.stderr)
        sys.exit(-1)

    img_out_path = os.path.join(
        "data", "decoder", "image", file_name.split(".")[0].split("/")[-1])
    packet_imgs = process_npy(
        file_name, args.rgb, args.save_images, img_out_path)

    if args.alternative_encoding:
        packets = img2packet2(packet_imgs)

    else:
        packets = img2packet(packet_imgs)

    print("\nSample packet (without post processing):\n")
    packets[0].show()
    if args.post_process:
        packets = post_process_packets(packets)
        print("\nSample packet (after post processing):\n")
        packets[0].show()

    pcap_out_path = os.path.join("data", "decoder", "pcap", file_name.split(".")[
        0].split("/")[-1]+".pcap")
    print('Writing pcap output to {}...'.format(pcap_out_path))
    with open(pcap_out_path, "wb") as f:
        wrpcap(f, packets)

    if args.test_packets:
        test_packets = packets[:100]
        for packet in test_packets:
            packet.show()
            packet.src = "130.231.202.234"
            packet.dst = "8.8.8.8"
            del packet.chksum
        ans, unans = sr(test_packets, timeout=3, verbose=3)
        print("\nAnswered:\n")
        ans.summary()
        print("\nUnanswered:\n")
        unans.summary()
    sys.exit(0)
